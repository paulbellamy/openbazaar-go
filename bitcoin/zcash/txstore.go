package zcash

import (
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
	db wallet.Datastore
}

func NewTxStore(params *chaincfg.Params, db wallet.Datastore, km *keys.KeyManager) (TxStore, error) {
	return &txStore{db: db}, nil
}

// TODO: Generate a raw, "wire" txn here, eugh. maybe just nil for now, This is the downside of using the insight api, is we don't get the raw txn data. (but we can ask for it)
// TODO: Check if we've already processed this txn
// TODO: Check for double-spends
// TODO: Check txn is relevant
func (t *txStore) Ingest(txn client.Transaction, raw []byte) error {
	if err := validTxn(txn); err != nil {
		return err
	}
	return t.db.Txns().Put(nil, "", 0, 0, time.Time{}, false)
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

func insightToWire(txn client.Transaction) *wire.MsgTx {
	wireTx := wire.NewMsgTx(int32(txn.Version))
	for range txn.Inputs {
		hash, _ := chainhash.NewHashFromStr("")
		index := uint32(0)
		signatureScript := []byte{}
		witness := [][]byte{}
		txIn := wire.NewTxIn(
			wire.NewOutPoint(hash, index),
			signatureScript,
			witness,
		)
		wireTx.AddTxIn(txIn)
	}
	return wireTx
}
