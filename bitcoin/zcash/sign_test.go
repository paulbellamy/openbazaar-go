package zcash

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
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
	signed, err := w.Sign(txn, SigHashAll, uint32(0))
	if err != nil {
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
	if err := verifySignature(txn, signingKey, 0, signed.Inputs[0].ScriptSig.Hex); err != nil {
		t.Error(err)
	}
}

func verifySignature(txn *Transaction, signingKey *btcec.PublicKey, nIn int, sigHex string) error {
	scriptCode, err := hex.DecodeString(sigHex)
	if err != nil {
		return err
	}
	sig, hashType, pkData, err := disasmSignature(scriptCode)
	if err != nil {
		return err
	}
	if hashType != SigHashAll {
		return fmt.Errorf("Expected sig hash type SigHashAll (%v), got: %v", SigHashAll, hashType)
	}
	if hex.EncodeToString(pkData) != hex.EncodeToString(signingKey.SerializeCompressed()) {
		return fmt.Errorf("Expected pkData to be %v, got: %v", hex.EncodeToString(signingKey.SerializeCompressed()), hex.EncodeToString(pkData))
	}
	hash, err := txn.InputSignatureHash(scriptCode, nIn, SigHashAll, uint32(0))
	if err != nil {
		return fmt.Errorf("error hashing transaction: %v", err)
	}
	if !sig.Verify(hash, signingKey) {
		return fmt.Errorf("Expected input signature did not verify")
	}
	return nil
}

func disasmSignature(scriptCode []byte) (sig *btcec.Signature, hashType SigHashType, pkData []byte, err error) {
	disassembled, err := txscript.DisasmString(scriptCode)
	if err != nil {
		return nil, 0, nil, err
	}
	parts := strings.SplitN(disassembled, " ", 2)
	if len(parts) != 2 {
		return nil, 0, nil, fmt.Errorf("Found not enough parts to disassembled signature: %v", parts)
	}
	byteParts := make([][]byte, len(parts))
	for i, p := range parts {
		byteParts[i], err = hex.DecodeString(p)
		if err != nil {
			return nil, 0, nil, err
		}
	}
	sig, err = btcec.ParseDERSignature(byteParts[0][:len(byteParts[0])-1], btcec.S256())
	if err != nil {
		return nil, 0, nil, err
	}
	hashType = SigHashType(byteParts[0][len(byteParts[0])-1])
	pkData, err = hex.DecodeString(parts[1])
	if err != nil {
		return nil, 0, nil, err
	}
	return sig, hashType, pkData, nil
}
