package zcash

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func TestTransactionSign(t *testing.T) {
	w, _ := NewWallet(testConfig(t))
	address := w.NewAddress(wallet.EXTERNAL)
	script, err := w.AddressToScript(address)
	if err != nil {
		t.Fatal(err)
	}
	key, err := w.MasterPrivateKey().ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := w.DB.Keys().ImportKey(address.ScriptAddress(), key); err != nil {
		t.Fatal(err)
	}
	txHash, _ := chainhash.NewHashFromStr("a")
	txn := &Transaction{
		Version:   1,
		Timestamp: time.Now(),
		Inputs: []Input{
			{
				Txid: txHash.String(),
				Vout: 0,
				N:    0,
				ScriptSig: Script{
					Hex: hex.EncodeToString(script),
				},
			},
		},
	}
	additionalPrevScripts := map[string][]byte{txHash.String() + ":0": script}
	if err := txn.Sign(w.Params(), w.DB.Keys(), additionalPrevScripts, SigHashAll, uint32(0)); err != nil {
		t.Fatal(err)
	}

	// Check txn inputs are signed with our key
	if len(txn.Inputs) <= 0 {
		t.Fatalf("Txn had no inputs")
	}

	// Check the input signature
	signingKey, err := w.MasterPrivateKey().ECPubKey()
	if err != nil {
		t.Fatal(err)
	}
	pkData := signingKey.SerializeCompressed()
	scriptCode, err := hex.DecodeString(txn.Inputs[0].ScriptSig.Hex)
	if err != nil {
		t.Fatalf("error decoding signature hex: %v", err)
	}
	fmt.Printf("[DEBUG] Input hex: %v\n", txn.Inputs[0].ScriptSig.Hex)
	var sig *btcec.Signature
	var foundHashType SigHashType
	scriptCodeWithoutPKData := scriptCode[:len(scriptCode)-len(pkData)-1]
	for i := 0; i < len(scriptCodeWithoutPKData)-1; i++ {
		sig, err = btcec.ParseDERSignature(scriptCodeWithoutPKData[i:len(scriptCodeWithoutPKData)-i], btcec.S256())
		if err == nil {
			break
		}
		foundHashType = SigHashType(scriptCodeWithoutPKData[len(scriptCodeWithoutPKData)-i-1])
	}
	if sig == nil {
		t.Fatalf("Could not find signature in output scriptsig")
	}
	if foundHashType != SigHashAll {
		t.Fatalf("Expected sig hash type SigHashAll (%v), got: %v", SigHashAll, foundHashType)
	}
	hash, err := txn.InputSignatureHash(scriptCode, 0, SigHashAll, uint32(0))
	if err != nil {
		t.Fatalf("error hashing transaction: %v", err)
	}
	if !sig.Verify(hash, signingKey) {
		t.Errorf("Expected input signature did not verify")
	}
}
