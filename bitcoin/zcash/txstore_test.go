package zcash

import (
	"testing"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	wallet "github.com/OpenBazaar/wallet-interface"
)

func TestTxStoreIngestAddsTxnsToDB(t *testing.T) {
	var txns []wallet.Txn
	db := &FakeDatastore{
		txns: &FakeTxns{
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
