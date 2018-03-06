package zcash

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/OpenBazaar/multiwallet/keys"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// TODO: Move this all to multiwallet
type TxStore interface {
	Ingest(txn client.Transaction, raw []byte) error
}

type txStore struct {
	params     *chaincfg.Params
	db         wallet.Datastore
	keyManager *keys.KeyManager
}

func NewTxStore(params *chaincfg.Params, db wallet.Datastore, km *keys.KeyManager) (TxStore, error) {
	return &txStore{
		params:     params,
		db:         db,
		keyManager: km,
	}, nil
}

// TODO: Check if we've already processed this txn, and update height accordingly
// TODO: Check for double-spends
// TODO: Check txn is relevant
func (t *txStore) Ingest(txn client.Transaction, raw []byte) error {
	if err := validTxn(txn); err != nil {
		return err
	}

	hash, err := chainhash.NewHashFromStr(txn.Txid)
	if err != nil {
		return err
	}

	if existing, err := t.db.Txns().Get(*hash); err == nil && (existing.Height > 0 || (existing.Height == 0 && txn.BlockHeight == 0)) {
		// We've already processed this txn
		return nil
	}

	// TODO: Check if it is a relevant txn, and only store that.

	// Update utxos, and calculate value
	value := t.storeUtxos(txn, hash)

	// Update stxos, and calculate value
	v2, err := t.storeStxos(txn, hash)
	if err != nil {
		log.Errorf("unable to store stxos for %v: %v", txn.Txid, err)
	}
	value += v2

	// Store the transaction
	// TODO: Calculate watchOnly here
	watchOnly := false
	t.db.Txns().Put(raw, hash.String(), value, txn.BlockHeight, time.Unix(txn.Time, 0), watchOnly)

	return nil
}

// validTxn validates a transaction based on rules from zcash protocol spec,
// section 6.1
// TODO: Check outputs/inputs
func validTxn(txn client.Transaction) error {
	if txn.Version < 1 {
		return fmt.Errorf("transaction version must be greater than or equal to 1")
	}

	if len(txn.Inputs) == 0 {
		// this is not always true (see joinSplits)
		return fmt.Errorf("transaction has no inputs")
	}
	return nil
}

func (t *txStore) storeUtxos(txn client.Transaction, hash *chainhash.Hash) int {
	var value int
	addrs := keysToAddresses(t.params, t.keyManager.GetKeys())
	for _, output := range txn.Outputs {
		for _, addr := range addrs {
			encodedAddr := addr.EncodeAddress()
			// TODO: This equality check is probably too simplistic
			matched := false
			for _, a := range output.ScriptPubKey.Addresses {
				if encodedAddr == a {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}

			if err := t.keyManager.MarkKeyAsUsed(addr.ScriptAddress()); err != nil {
				log.Errorf("could not mark key as used %v: %v", addr, err)
			}

			scriptBytes, err := hex.DecodeString(output.ScriptPubKey.Hex)
			if err != nil {
				log.Errorf("could not decode utxo for %v: %v", addr, err)
				continue
			}

			// Save the new utxo
			utxo := wallet.Utxo{
				Op:           wire.OutPoint{Hash: *hash, Index: uint32(output.N)},
				AtHeight:     int32(txn.BlockHeight),
				Value:        int64(output.Value * 1e8), // TODO: Eugh. Floats :(
				ScriptPubkey: scriptBytes,               // TODO: Don't think this is right...
				WatchOnly:    false,
			}
			if err := t.db.Utxos().Put(utxo); err != nil {
				log.Errorf("could save utxo for %v: %v", addr, err)
			}

			value += int(utxo.Value)
		}
	}
	return value
}

// TODO: Update existing stxo height, if it already exists.
func (t *txStore) storeStxos(txn client.Transaction, hash *chainhash.Hash) (int, error) {
	utxos, err := t.db.Utxos().GetAll()
	if err != nil {
		return 0, err
	}

	stxos, err := t.db.Stxos().GetAll()
	if err != nil {
		return 0, err
	}

	var value int
	for _, input := range txn.Inputs {
		// Have we already seen this stxo?
		if stxo, ok := hasMatchingStxo(stxos, hash); ok {
			// Update the existing stxo
			stxo.SpendHeight = int32(txn.BlockHeight)
			err = t.db.Stxos().Put(stxo)
			if err != nil {
				log.Errorf("could save stxo: %v", err)
			}
			// TODO: Handle watchOnly here
			continue
		}

		// Does it match a utxo?
		for i, utxo := range utxos {
			if input.Txid != utxo.Op.Hash.String() || uint32(input.Vout) != utxo.Op.Index {
				continue
			}
			err = t.db.Stxos().Put(wallet.Stxo{
				Utxo:        utxo,
				SpendHeight: int32(txn.BlockHeight),
				SpendTxid:   *hash,
			})
			if err != nil {
				log.Errorf("could save stxo: %v", err)
			}
			err = t.db.Utxos().Delete(utxo)
			if err != nil {
				log.Errorf("could delete utxo: %v", err)
			}
			// We're done with this utxo, no need to check it again.
			utxos = append(utxos[:i], utxos[i+1:]...)
			if !utxo.WatchOnly {
				value -= int(utxo.Value)
			}
			break
		}
	}
	return value, nil
}

func hasMatchingStxo(stxos []wallet.Stxo, hash *chainhash.Hash) (wallet.Stxo, bool) {
	for _, stxo := range stxos {
		if stxo.SpendTxid.IsEqual(hash) {
			return stxo, true
		}
	}
	return wallet.Stxo{}, false
}
