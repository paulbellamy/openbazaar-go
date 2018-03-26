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
	btc "github.com/btcsuite/btcutil"
)

func TestTransactionSign(t *testing.T) {
	w, _ := NewWallet(testConfig(t))
	var addresses []btc.Address
	var keys []*btcec.PrivateKey
	for i := 0; i < 3; i++ {
		address := w.NewAddress(wallet.EXTERNAL)
		key, err := w.MasterPrivateKey().ECPrivKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := w.DB.Keys().ImportKey(address.ScriptAddress(), key); err != nil {
			t.Fatal(err)
		}
		addresses = append(addresses, address)
		keys = append(keys, key)
	}

	for _, tc := range []struct {
		name    string
		script  func() ([]byte, error)
		pending bool
	}{
		{
			name:   "pubkey",
			script: func() ([]byte, error) { return w.AddressToScript(addresses[0]) },
		},
		{name: "p2sh", pending: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pending {
				t.Fatal("pending")
			}

			script, err := tc.script()
			if err != nil {
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
		})
	}
}

func TestTransactionMultisign(t *testing.T) {
	w, _ := NewWallet(testConfig(t))
	var addresses []btc.Address
	var keys []*btcec.PrivateKey
	for i := 0; i < 3; i++ {
		address := w.NewAddress(wallet.EXTERNAL)
		key, err := w.MasterPrivateKey().ECPrivKey()
		if err != nil {
			t.Fatal(err)
		}
		if err := w.DB.Keys().ImportKey(address.ScriptAddress(), key); err != nil {
			t.Fatal(err)
		}
		addresses = append(addresses, address)
		keys = append(keys, key)
	}

	for _, tc := range []struct {
		name    string
		script  func() ([]byte, error)
		pending bool
	}{
		{
			name: "multisig 2 of 2",
			script: txscript.NewScriptBuilder().
				AddInt64(2).
				AddData(keys[0].PubKey().SerializeCompressed()).
				AddData(keys[1].PubKey().SerializeCompressed()).
				AddInt64(2).
				AddOp(txscript.OP_CHECKMULTISIG).
				Script,
		},
		{
			name: "multisig 1 of 2",
			script: txscript.NewScriptBuilder().
				AddInt64(1).
				AddData(keys[0].PubKey().SerializeCompressed()).
				AddData(keys[1].PubKey().SerializeCompressed()).
				AddInt64(2).
				AddOp(txscript.OP_CHECKMULTISIG).
				Script,
		},
		{
			name: "multisig 2 of 3",
			script: txscript.NewScriptBuilder().
				AddInt64(2).
				AddData(keys[0].PubKey().SerializeCompressed()).
				AddData(keys[1].PubKey().SerializeCompressed()).
				AddData(keys[2].PubKey().SerializeCompressed()).
				AddInt64(3).
				AddOp(txscript.OP_CHECKMULTISIG).
				Script,
		},
		{name: "multisig timeout", pending: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pending {
				t.Fatal("pending")
			}

			script, err := tc.script()
			if err != nil {
				t.Fatal(err)
			}
			txHash, _ := chainhash.NewHashFromStr("a")
			inputs := []wallet.TransactionInput{
				{
					OutpointHash:       txHash[:],
					OutpointIndex:      0,
					LinkedScriptPubKey: script,
					Value:              1234,
				},
			}
			outputs := []wallet.TransactionOutput{}
			redeemScript := []byte(nil) // TODO: Do we need this?
			feePerByte := uint64(0)
			sigs, err := w.CreateMultisigSignature(inputs, outputs, w.MasterPrivateKey(), redeemScript, feePerByte)
			if err != nil {
				t.Fatal(err)
			}
			// TODO: Do sigs1 and sigs2 need to be different?
			signedBytes, err := w.Multisign(inputs, outputs, sigs, sigs, redeemScript, feePerByte, true)
			if err != nil {
				t.Fatal(err)
			}

			var signed Transaction
			if err := signed.UnmarshalBinary(signedBytes); err != nil {
				t.Fatal(err)
			}

			// Check the input signature
			txn := &Transaction{
				Version:   1,
				Timestamp: time.Now(),
				Inputs: []Input{
					{
						Txid: txHash.String(),
						Vout: 0,
						ScriptSig: Script{
							Hex: hex.EncodeToString(script),
						},
					},
				},
			}
			signingKey, err := w.MasterPrivateKey().ECPubKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := verifySignature(txn, signingKey, 0, signed.Inputs[0].ScriptSig.Hex); err != nil {
				t.Error(err)
			}
		})
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
