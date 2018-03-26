package zcash

import (
	"bytes"
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

	// Check to see if this is a double spend
	doubleSpends, err := t.CheckDoubleSpends(txn)
	if err != nil {
		return err
	}
	if len(doubleSpends) > 0 {
		// First seen rule
		if txn.BlockHeight == 0 {
			return nil
		} else {
			// Mark any unconfirmed doubles as dead
			for _, double := range doubleSpends {
				t.markAsDead(double)
			}
		}
	}

	// Update utxos, and calculate value
	value, isRelevant, watchOnly := t.storeUtxos(txn, hash)

	// Update stxos, and calculate value
	value2, isRelevant2, watchOnly2, err := t.storeStxos(txn, hash)
	if err != nil {
		log.Errorf("unable to store stxos for %v: %v", txn.Txid, err)
	}
	value += value2
	isRelevant = isRelevant || isRelevant2
	watchOnly = watchOnly || watchOnly2
	if !isRelevant {
		return nil
	}

	// Store the transaction
	return t.db.Txns().Put(raw, hash.String(), value, txn.BlockHeight, time.Unix(txn.Time, 0), watchOnly)
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

func (t *txStore) storeUtxos(txn client.Transaction, hash *chainhash.Hash) (value int, isRelevant, watchOnly bool) {
	addrs, _ := keysToAddresses(t.params, t.keyManager.GetKeys())
	for _, output := range txn.Outputs {
		for _, addr := range addrs {
			encodedAddr := addr.EncodeAddress()
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
				ScriptPubkey: scriptBytes,
				WatchOnly:    false,
			}
			if err := t.db.Utxos().Put(utxo); err != nil {
				log.Errorf("could save utxo for %v: %v", addr, err)
			}

			value += int(utxo.Value)
			isRelevant = true
		}

		// TODO: Check watched scripts here
	}
	return value, isRelevant, watchOnly
}

func (t *txStore) storeStxos(txn client.Transaction, hash *chainhash.Hash) (value int, isRelevant, watchOnly bool, err error) {
	utxos, err := t.db.Utxos().GetAll()
	if err != nil {
		return 0, false, false, err
	}

	stxos, err := t.db.Stxos().GetAll()
	if err != nil {
		return 0, false, false, err
	}

	for _, input := range txn.Inputs {
		// Have we already seen this stxo?
		if stxo, ok := hasMatchingStxo(stxos, hash); ok {
			// Update the existing stxo
			stxo.SpendHeight = int32(txn.BlockHeight)
			err = t.db.Stxos().Put(stxo)
			if err != nil {
				log.Errorf("could save stxo: %v", err)
			}
			isRelevant = true
			watchOnly = watchOnly || stxo.Utxo.WatchOnly
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
			isRelevant = true
			watchOnly = watchOnly || utxo.WatchOnly
			break
		}
	}
	return value, isRelevant, watchOnly, nil
}

func hasMatchingStxo(stxos []wallet.Stxo, hash *chainhash.Hash) (wallet.Stxo, bool) {
	for _, stxo := range stxos {
		if stxo.SpendTxid.IsEqual(hash) {
			return stxo, true
		}
	}
	return wallet.Stxo{}, false
}

// GetDoubleSpends takes a transaction and compares it with
// all transactions in the db.  It returns a slice of all txids in the db
// which are double spent by the received tx.
func (t *txStore) CheckDoubleSpends(arg client.Transaction) ([]string, error) {
	var dubs []string // slice of all double-spent txs
	txs, err := t.db.Txns().GetAll(true)
	if err != nil {
		return dubs, err
	}
	for _, compTx := range txs {
		if compTx.Height < 0 {
			continue
		}
		r := bytes.NewReader(compTx.Bytes)
		msgTx := wire.NewMsgTx(1)
		msgTx.BtcDecode(r, 1, wire.WitnessEncoding)
		compTxid := msgTx.TxHash()
		for _, argIn := range arg.Inputs {
			// iterate through inputs of comp
			argInTxid, err := chainhash.NewHashFromStr(argIn.Txid)
			if err != nil {
				return nil, err
			}
			argInOutPoint := wire.NewOutPoint(argInTxid, uint32(argIn.Vout))
			for _, compIn := range msgTx.TxIn {
				if outpointsEqual(*argInOutPoint, compIn.PreviousOutPoint) && compTxid.String() != arg.Txid {
					// found double spend
					dubs = append(dubs, compTxid.String())
					break // back to argIn loop
				}
			}
		}
	}
	return dubs, nil
}

func (t *txStore) markAsDead(txid string) error {
	stxos, err := t.db.Stxos().GetAll()
	if err != nil {
		return err
	}
	markStxoAsDead := func(s wallet.Stxo) error {
		err := t.db.Stxos().Delete(s)
		if err != nil {
			return err
		}
		err = t.db.Txns().UpdateHeight(s.SpendTxid, -1)
		if err != nil {
			return err
		}
		return nil
	}
	for _, s := range stxos {
		// If an stxo is marked dead, move it back into the utxo table
		if txid == s.SpendTxid.String() {
			if err := markStxoAsDead(s); err != nil {
				return err
			}
			if err := t.db.Utxos().Put(s.Utxo); err != nil {
				return err
			}
		}
		// If a dependency of the spend is dead then mark the spend as dead
		if txid == s.Utxo.Op.Hash.String() {
			if err := markStxoAsDead(s); err != nil {
				return err
			}
			if err := t.markAsDead(s.SpendTxid.String()); err != nil {
				return err
			}
		}
	}
	utxos, err := t.db.Utxos().GetAll()
	if err != nil {
		return err
	}
	// Dead utxos should just be deleted
	for _, u := range utxos {
		if txid == u.Op.Hash.String() {
			err := t.db.Utxos().Delete(u)
			if err != nil {
				return err
			}
		}
	}

	txidHash, err := chainhash.NewHashFromStr(txid)
	if err != nil {
		return err
	}
	t.db.Txns().UpdateHeight(*txidHash, -1)
	return nil
}
