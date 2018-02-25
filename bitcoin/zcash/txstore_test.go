package zcash

import (
	"fmt"
	"testing"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/OpenBazaar/multiwallet/keys"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	b39 "github.com/tyler-smith/go-bip39"
)

func TestTxStoreIngestAddsTxnsToDB(t *testing.T) {
	// TODO: This setup/stubbing is getting onerous. Refactor it out.
	var txns []wallet.Txn
	db := &FakeDatastore{
		utxos: &FakeUtxos{
			put: func(utxo wallet.Utxo) error { return nil },
		},
		txns: &FakeTxns{
			get: func(txid chainhash.Hash) (wallet.Txn, error) {
				return wallet.Txn{}, fmt.Errorf("not found")
			},
			put: func(txn []byte, txid string, value, height int, timestamp time.Time, watchOnly bool) error {
				txns = append(txns, wallet.Txn{})
				return nil
			},
		},
		keys: &FakeKeystore{
			getAll: func() ([]wallet.KeyPath, error) {
				return []wallet.KeyPath{{wallet.EXTERNAL, 0}}, nil
			},
			getLastKeyIndex: func(p wallet.KeyPurpose) (int, bool, error) { return 0, false, nil },
			getLookaheadWindows: func() map[wallet.KeyPurpose]int {
				return map[wallet.KeyPurpose]int{wallet.EXTERNAL: keys.LOOKAHEADWINDOW}
			},
			markKeyAsUsed: func(scriptAddress []byte) error { return nil },
		},
	}
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(db.Keys(), config.Params, mPrivKey, keys.Zcash)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, db, keyManager)
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
		keys: &FakeKeystore{
			getAll: func() ([]wallet.KeyPath, error) {
				return []wallet.KeyPath{{wallet.EXTERNAL, 0}}, nil
			},
			getLastKeyIndex: func(p wallet.KeyPurpose) (int, bool, error) { return 0, false, nil },
			getLookaheadWindows: func() map[wallet.KeyPurpose]int {
				return map[wallet.KeyPurpose]int{wallet.EXTERNAL: keys.LOOKAHEADWINDOW}
			},
			markKeyAsUsed: func(scriptAddress []byte) error { return nil },
		},
	}
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(db.Keys(), config.Params, mPrivKey, keys.Zcash)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, db, keyManager)
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

func TestTxStoreIngestUpdatesUtxos(t *testing.T) {
	var utxos []wallet.Utxo
	var usedKeys []string
	db := &FakeDatastore{
		utxos: &FakeUtxos{
			put: func(utxo wallet.Utxo) error {
				utxos = append(utxos, utxo)
				return nil
			},
		},
		txns: &FakeTxns{
			get: func(txid chainhash.Hash) (wallet.Txn, error) {
				return wallet.Txn{}, fmt.Errorf("not found")
			},
			put: func(txn []byte, txid string, value, height int, timestamp time.Time, watchOnly bool) error {
				return nil
			},
		},
		keys: &FakeKeystore{
			getAll: func() ([]wallet.KeyPath, error) {
				return []wallet.KeyPath{{wallet.EXTERNAL, 0}}, nil
			},
			getLastKeyIndex: func(p wallet.KeyPurpose) (int, bool, error) { return 0, false, nil },
			getLookaheadWindows: func() map[wallet.KeyPurpose]int {
				return map[wallet.KeyPurpose]int{wallet.EXTERNAL: keys.LOOKAHEADWINDOW}
			},
			markKeyAsUsed: func(scriptAddress []byte) error {
				usedKeys = append(usedKeys, string(scriptAddress))
				return nil
			},
		},
	}
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(db.Keys(), config.Params, mPrivKey, keys.Zcash)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, db, keyManager)
	if err != nil {
		t.Fatal(err)
	}
	keys := keyManager.GetKeys()
	if len(keys) == 0 {
		t.Fatal(err)
	}
	address := keyToAddress(keys[0], config.Params)

	txn := client.Transaction{
		Version: 1,
		Inputs: []client.Input{
			{},
		},
		Outputs: []client.Output{
			{
				ScriptPubKey: client.OutScript{
					Addresses: []string{address.EncodeAddress()},
					Type:      "pubkeyhash",
				},
				Value: 1.234,
				N:     0,
			},
		},
	}
	if err := txStore.Ingest(txn, nil); err != nil {
		t.Fatal(err)
	}

	if len(utxos) != 1 {
		t.Errorf("Expected 1 utxo, got: %d", len(utxos))
	}

	if len(usedKeys) != 1 {
		t.Errorf("Expected to mark key as used")
	}
}
