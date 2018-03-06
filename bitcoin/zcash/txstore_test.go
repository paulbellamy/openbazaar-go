package zcash

import (
	"encoding/hex"
	"testing"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/OpenBazaar/multiwallet/keys"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	b39 "github.com/tyler-smith/go-bip39"
)

func TestTxStoreIngestAddsTxnsToDB(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, keys.Zcash)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
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

	txns, err := config.DB.Txns().GetAll(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 {
		t.Errorf("Expected 1 txn, got: %d", len(txns))
	}
}

func TestTxStoreIngestIgnoresDuplicates(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, keys.Zcash)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
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

	txns, err := config.DB.Txns().GetAll(true)
	if err != nil {
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

func TestTxStoreIngestUpdatesUtxos(t *testing.T) {
	var usedKeys int
	config := testConfig(t)
	config.DB.(*FakeDatastore).keys = &FakeKeys{
		markKeyAsUsed: func(scriptAddress []byte) error {
			usedKeys++
			return nil
		},
	}
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, keys.Zcash)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
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

	utxos, err := config.DB.Utxos().GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(utxos) != 1 {
		t.Errorf("Expected 1 utxo, got: %d", len(utxos))
	}

	if usedKeys != 1 {
		t.Errorf("Expected to mark key as used")
	}
}

func TestTxStoreIngestAddsStxos(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, keys.Zcash)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}
	keys := keyManager.GetKeys()
	if len(keys) == 0 {
		t.Fatal(err)
	}
	address := keyToAddress(keys[0], config.Params)

	// Set up a previous txn where we received some utxos
	outScript := client.OutScript{
		Script:    client.Script{Hex: "abcd"},
		Addresses: []string{address.EncodeAddress()},
		Type:      "pubkeyhash",
	}
	scriptBytes, err := hex.DecodeString(outScript.Script.Hex)
	if err != nil {
		t.Fatalf("could not decode utxo for %v: %v", outScript, err)
	}
	prevHash, _ := chainhash.NewHashFromStr("a")
	sequence := uint32(898) // position in the block outputs
	receivedUtxo := wallet.Utxo{
		Op:           wire.OutPoint{*prevHash, sequence},
		AtHeight:     1,
		Value:        1.2345 * 1e8,
		ScriptPubkey: scriptBytes,
		WatchOnly:    false,
	}
	config.DB.Utxos().Put(receivedUtxo)

	// Ingest the initial stxo-containing txn
	txn := client.Transaction{
		Version:     1,
		BlockHeight: 5,
		Inputs: []client.Input{
			{
				Txid: prevHash.String(),
				Vout: int(sequence),
				Addr: address.EncodeAddress(),
			},
		},
		Outputs: []client.Output{
			{
				// Burn some money
				ScriptPubKey: client.OutScript{
					Script:    client.Script{Hex: "0000"},
					Addresses: []string{"0000"},
					Type:      "pubkeyhash",
				},
				Value: 1.1,
				N:     0,
			},
			{
				// Return the change
				ScriptPubKey: outScript,
				Value:        1.2345 - 1.1,
				N:            1,
			},
		},
	}
	if err := txStore.Ingest(txn, nil); err != nil {
		t.Fatal(err)
	}

	stxos, err := config.DB.Stxos().GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(stxos) != 1 {
		t.Fatalf("Expected 1 stxo, got: %v", stxos)
	}
	if stxos[0].SpendHeight != 5 {
		t.Errorf("Expected stxo height to be updated, got: %d", stxos[0].SpendHeight)
	}

	utxos, err := config.DB.Utxos().GetAll()
	if err != nil {
		t.Error(err)
	}
	for _, u := range utxos {
		if u.Op.String() == receivedUtxo.Op.String() {
			t.Errorf("Expected matching utxo to have been removed")
			break
		}
	}

	txns, err := config.DB.Txns().GetAll(true)
	if err != nil {
		t.Fatal(err)
	}
	if len(txns) != 1 {
		t.Fatalf("Expected 1 txn, got: %d", len(txns))
	}
	if txns[0].Value != -1.1*1e8 {
		t.Errorf("Expected txn value %d, got: %d", int64(-1.1*1e8), txns[0].Value)
	}
}

func TestTxStoreIngestUpdatesStxosHeight(t *testing.T) {
	config := testConfig(t)
	seed := b39.NewSeed(config.Mnemonic, "")
	mPrivKey, _ := hd.NewMaster(seed, config.Params)
	keyManager, err := keys.NewKeyManager(config.DB.Keys(), config.Params, mPrivKey, keys.Zcash)
	if err != nil {
		t.Fatal(err)
	}
	txStore, err := NewTxStore(config.Params, config.DB, keyManager)
	if err != nil {
		t.Fatal(err)
	}
	keys := keyManager.GetKeys()
	if len(keys) == 0 {
		t.Fatal(err)
	}
	address := keyToAddress(keys[0], config.Params)

	// Set up a previous txn where we received some utxos
	outScript := client.OutScript{
		Script:    client.Script{Hex: "abcd"},
		Addresses: []string{address.EncodeAddress()},
		Type:      "pubkeyhash",
	}
	scriptBytes, err := hex.DecodeString(outScript.Script.Hex)
	if err != nil {
		t.Fatalf("could not decode utxo for %v: %v", outScript, err)
	}
	prevHash, _ := chainhash.NewHashFromStr("a")
	sequence := uint32(898) // position in the block outputs
	existingStxo := wallet.Stxo{
		SpendHeight: 0,
		SpendTxid:   *prevHash,
		Utxo: wallet.Utxo{
			Op:           wire.OutPoint{*prevHash, sequence},
			AtHeight:     1,
			Value:        1.2345 * 1e8,
			ScriptPubkey: scriptBytes,
			WatchOnly:    false,
		},
	}
	if err := config.DB.Stxos().Put(existingStxo); err != nil {
		t.Fatal(err)
	}

	// Ingest the new stxo-containing txn
	txn := client.Transaction{
		Txid:        prevHash.String(),
		Version:     1,
		BlockHeight: 5,
		Inputs: []client.Input{
			{
				Txid: prevHash.String(),
				Vout: int(sequence),
				Addr: address.EncodeAddress(),
			},
		},
		Outputs: []client.Output{
			{
				// Burn some money
				ScriptPubKey: client.OutScript{
					Script:    client.Script{Hex: "0000"},
					Addresses: []string{"0000"},
					Type:      "pubkeyhash",
				},
				Value: 1.1,
				N:     0,
			},
			{
				// Return the change
				ScriptPubKey: outScript,
				Value:        1.2345 - 1.1,
				N:            1,
			},
		},
	}
	if err := txStore.Ingest(txn, nil); err != nil {
		t.Fatal(err)
	}

	stxos, err := config.DB.Stxos().GetAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(stxos) != 1 {
		t.Fatalf("Expected 1 stxo, got: %v", stxos)
	}
	if stxos[0].SpendHeight != 5 {
		t.Errorf("Expected stxo height to be updated, got: %d", stxos[0].SpendHeight)
	}
}
