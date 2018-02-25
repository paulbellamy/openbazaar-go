package zcash

import (
	"fmt"
	"testing"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func TestTxStoreIngestAddsTxnsToDB(t *testing.T) {
	var txns []wallet.Txn
	db := &FakeDatastore{
		txns: &FakeTxns{
			get: func(txid chainhash.Hash) (wallet.Txn, error) {
				return wallet.Txn{}, fmt.Errorf("not found")
			},
			put: func(txn []byte, txid string, value, height int, timestamp time.Time, watchOnly bool) error {
				txns = append(txns, wallet.Txn{})
				return nil
			},
		},
	}
	txStore, err := NewTxStore(nil, db, nil)
	if err != nil {
		t.Fatal(err)
	}

	txn := client.Transaction{
		Version: 1,
		Inputs: []client.Input{
			{},
		},
	}
	if err := txStore.Ingest(txn, nil); err != nil {
		t.Fatal(err)
	}

	if len(txns) != 1 {
		t.Errorf("Expected 1 txn, got: %d", len(txns))
	}
}

func TestTxStoreIngestIgnoresDuplicates(t *testing.T) {
	var txns []wallet.Txn
	db := &FakeDatastore{
		txns: &FakeTxns{
			get: func(txid chainhash.Hash) (wallet.Txn, error) {
				for _, txn := range txns {
					if txn.Txid == txid.String() {
						return txn, nil
					}
				}
				return wallet.Txn{}, fmt.Errorf("not found")
			},
			put: func(txn []byte, txid string, value, height int, timestamp time.Time, watchOnly bool) error {
				txns = append(txns, wallet.Txn{Txid: txid})
				return nil
			},
		},
	}
	txStore, err := NewTxStore(nil, db, nil)
	if err != nil {
		t.Fatal(err)
	}

	txn := client.Transaction{
		Txid:    "a",
		Version: 1,
		Inputs: []client.Input{
			{},
		},
	}
	for i := 0; i < 2; i++ {
		if err := txStore.Ingest(txn, nil); err != nil {
			t.Fatal(err)
		}
	}

	if len(txns) != 1 {
		t.Errorf("Expected 1 txn, got: %d", len(txns))
	}
}

func TestTxStoreIngestRejectsInvalidTxns(t *testing.T) {
	txStore, err := NewTxStore(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		err string
		txn client.Transaction
	}{
		{
			err: "transaction version must be greater than or equal to 1",
			txn: client.Transaction{Version: 0},
		},
		{
			err: "transaction has no inputs",
			txn: client.Transaction{Version: 1},
		},
		/*
			{
				err: "transaction with one or more coinbase inputs must have no transparent outputs",
				txn: client.Transaction{
					Version: 1,
					Inputs:  []client.Input{{IsCoinbase: true}},
					Outputs: []client.Output{{}},
				},
			},
		*/
		// TODO: nJoinSplit handling
		// TODO: Other rules inherited from Bitcoin
	} {
		t.Run(tc.err, func(t *testing.T) {
			err := txStore.Ingest(tc.txn, nil)
			if err == nil {
				t.Errorf("Did not reject invalid txn")
			}
			if err.Error() != tc.err {
				t.Errorf("Expected %q error, got: %q", tc.err, err.Error())
			}
		})
	}
}
