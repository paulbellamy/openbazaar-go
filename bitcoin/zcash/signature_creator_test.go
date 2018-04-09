package zcash

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/OpenBazaar/openbazaar-go/bitcoin/zcash/testdata"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/conformal/btcec"
)

var (
	printSigHashJSON = flag.Bool("print-sighash-json", false, "Print sighash json from tests for debugging")
)

func randBool() bool {
	return 0 == rand.Intn(2)
}

func randHash(t *testing.T) (p [32]byte) {
	// TODO: We might need more realistic generation here
	if _, err := rand.Read(p[:]); err != nil {
		t.Fatal(err)
	}
	return p
}

func randProofInvalid(t *testing.T) (p [296]byte) {
	// TODO: We might need more realistic generation here
	if _, err := rand.Read(p[:]); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSigHashTest(t *testing.T) {
	if *printSigHashJSON {
		fmt.Printf("[\n")
		fmt.Printf("\t[\"raw_transaction, script, input_index, hashType, branchId, signature_hash (result)\"],\n")
	}
	nRandomTests := 50000

	if *printSigHashJSON {
		nRandomTests = 500
	}
	for i := 0; i < nRandomTests; i++ {
		nHashType := txscript.SigHashType(rand.Int())
		var consensusBranchID uint32
		if randBool() {
			consensusBranchID = SproutVersionGroupID
		} else {
			consensusBranchID = OverwinterVersionGroupID
		}
		txTo := RandomTransaction(t, (nHashType&0x1f) == txscript.SigHashSingle, consensusBranchID)
		scriptCode := RandomScript(t)
		nIn := rand.Intn(len(txTo.Inputs))

		sho, err := SignatureHashOld(scriptCode, txTo, nIn, nHashType)
		if err != nil {
			t.Error(err)
			continue
		}
		sh, err := SignatureHash(scriptCode, txTo, nIn, nHashType, consensusBranchID)
		if err != nil {
			t.Error(err)
			continue
		}
		if *printSigHashJSON {
			txBin, err := txTo.MarshalBinary()
			if err != nil {
				t.Error(err)
				continue
			}

			fmt.Printf("\t[")
			fmt.Printf("%q, %q, %d, %d, %d, ", hex.EncodeToString(txBin), hex.EncodeToString(scriptCode), nIn, nHashType, consensusBranchID)
			if txTo.IsOverwinter {
				fmt.Printf("%q]", hex.EncodeToString(sh))
			} else {
				fmt.Printf("%q]", hex.EncodeToString(sho))
			}
			if i+1 != nRandomTests {
				fmt.Printf(",")
			}
			fmt.Printf("\n")
		}
		if !txTo.IsOverwinter && string(sh) != string(sho) {
			t.Errorf("Signatures not equal:\n%q\n%q", hex.EncodeToString(sh), hex.EncodeToString(sho))
		}
	}

	if *printSigHashJSON {
		fmt.Printf("]\n")
	}
}

func randVersion(isOverwinter bool) uint32 {
	if isOverwinter {
		// There is only one valid overwinter version
		return OverwinterMinCurrentVersion
	}
	return rand.Uint32() &^ OverwinterFlagMask
}

func RandomTransaction(t *testing.T, fSingle bool, consensusBranchID uint32) *Transaction {
	tx := &Transaction{}
	tx.IsOverwinter = randBool()
	tx.Version = randVersion(tx.IsOverwinter)
	if tx.IsOverwinter {
		tx.VersionGroupID = OverwinterVersionGroupID
		if randBool() {
			tx.ExpiryHeight = rand.Uint32()
		}
	}
	if randBool() {
		tx.Timestamp = time.Unix(int64(rand.Uint32()), 0).UTC()
	}
	ins := rand.Intn(4) + 1
	outs := rand.Intn(4) + 1
	if fSingle {
		outs = ins
	}
	for in := 0; in < ins; in++ {
		input := Input{
			PreviousOutPoint: wire.OutPoint{Hash: randHash(t), Index: rand.Uint32() % 4},
			SignatureScript:  RandomScript(t),
			Sequence:         OverwinterFlagMask,
		}
		if randBool() {
			input.Sequence = rand.Uint32()
		}
		tx.Inputs = append(tx.Inputs, input)
	}
	for out := 0; out < outs; out++ {
		tx.Outputs = append(tx.Outputs, Output{
			Value:        rand.Int63n(100000000),
			ScriptPubKey: RandomScript(t),
		})
	}
	if tx.Version >= 2 {
		joinSplits := rand.Intn(4)
		for js := 0; js < joinSplits; js++ {
			jsdesc := JoinSplit{}
			if randBool() {
				jsdesc.VPubOld = rand.Uint64() % 100000000
			} else {
				jsdesc.VPubNew = rand.Uint64() % 100000000
			}
			jsdesc.Anchor = randHash(t)
			jsdesc.Nullifiers[0] = randHash(t)
			jsdesc.Nullifiers[1] = randHash(t)
			jsdesc.Commitments[0] = randHash(t)
			jsdesc.Commitments[1] = randHash(t)
			jsdesc.EphemeralKey = randHash(t)
			jsdesc.RandomSeed = randHash(t)
			for _, ciphertext := range jsdesc.Ciphertexts {
				if _, err := rand.Read(ciphertext[:]); err != nil {
					t.Fatal(err)
				}
			}
			jsdesc.Proof = randProofInvalid(t)
			jsdesc.Macs[0] = randHash(t)
			jsdesc.Macs[1] = randHash(t)
			tx.JoinSplits = append(tx.JoinSplits, jsdesc)
		}
		if joinSplits > 0 {
			// Generate a new keypair
			joinSplitPrivKey, err := btcec.NewPrivateKey(btcec.S256())
			if err != nil {
				t.Fatal(err)
			}
			copy(tx.JoinSplitPubKey[:], joinSplitPrivKey.PubKey().SerializeCompressed())

			// Empty output script.
			dataToBeSigned, err := SignatureHash(nil, tx, NotAnInput, txscript.SigHashAll, tx.VersionGroupID)
			if err != nil {
				t.Fatal(err)
			}
			signature, err := joinSplitPrivKey.Sign(dataToBeSigned)
			if err != nil {
				t.Fatal(err)
			}
			copy(tx.JoinSplitSignature[:], signature.Serialize())
		}
	}
	return tx
}

func RandomScript(t *testing.T) []byte {
	oplist := []byte{
		txscript.OP_FALSE,
		txscript.OP_1,
		txscript.OP_2,
		txscript.OP_3,
		txscript.OP_CHECKSIG,
		txscript.OP_IF,
		txscript.OP_VERIF,
		txscript.OP_RETURN,
	}
	builder := txscript.NewScriptBuilder()
	ops := rand.Intn(10)
	for i := 0; i < ops; i++ {
		builder = builder.AddOp(oplist[rand.Intn(len(oplist))])
	}
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	return script
}

func SignatureHashOld(scriptCode []byte, txTo *Transaction, nIn int, nHashType txscript.SigHashType) ([]byte, error) {
	one := "0000000000000000000000000000000000000000000000000000000000000001"
	if nIn >= len(txTo.Inputs) || nIn == NotAnInput {
		return hex.DecodeString(one)
	}
	txTmp := txTo.shallowCopy()

	// Blank out other inputs' signatures
	for i := 0; i < len(txTmp.Inputs); i++ {
		txTmp.Inputs[i].SignatureScript = nil
	}
	txTmp.Inputs[nIn].SignatureScript = scriptCode

	// Blank out some of the outputs
	if (nHashType & 0x1f) == txscript.SigHashNone {
		// Wildcard payee
		txTmp.Outputs = nil

		// Let the others update at will
		for i := 0; i < len(txTmp.Inputs); i++ {
			if i != nIn {
				txTmp.Inputs[i].Sequence = 0
			}
		}
	} else if (nHashType & 0x1f) == txscript.SigHashSingle {
		// Only lock-in the txout payee at same index as txin
		nOut := nIn
		if nOut >= len(txTmp.Outputs) {
			return hex.DecodeString(one)
		}
		txTmp.Outputs = txTmp.Outputs[:nOut+1]
		for i := 0; i < nOut; i++ {
			txTmp.Outputs[i] = Output{}
		}

		// Let the others update at will
		for i := 0; i < len(txTmp.Inputs); i++ {
			if i != nIn {
				txTmp.Inputs[i].Sequence = 0
			}
		}
	}

	// Blank out other inputs completely, not recommended for open transactions
	if nHashType&txscript.SigHashAnyOneCanPay > 0 {
		txTmp.Inputs = []Input{txTmp.Inputs[nIn]}
	}

	// Blank out the joinsplit signature.
	txTmp.JoinSplitSignature = [64]byte{}

	// Serialize and hash
	txBin, err := txTmp.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sha256.New().Sum(append(txBin, byte(nHashType))), nil
}

// Goal: check that SignatureHash generates correct hash
func TestSigHashFromData(t *testing.T) {
	for i, test := range testdata.SigHash {
		/*
			if i != 0 {
				continue
			}
		*/
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			//fmt.Printf("[DEBUG] Unmarshalling txn: %q\n", hex.EncodeToString(test.Raw(t)))
			var tx Transaction
			if err := tx.UnmarshalBinary(test.Raw(t)); err != nil {
				t.Fatal(err)
			}

			if err := validateTestData(tx); err != nil {
				t.Fatalf("Bad test, couldn't deserialize data: %v", err)
			}

			//fmt.Printf("[DEBUG] Unmarshalled txn: %#v\n", tx)
			sh, err := SignatureHash(test.Script(t), &tx, test.Index, test.HashType(), test.ConsensusBranchID())
			if err != nil {
				t.Error(err)
				return
			}
			if string(sh) != string(test.Result(t)) {
				t.Errorf("Signatures not equal:\n%q\n%q", hex.EncodeToString(sh), hex.EncodeToString(test.Result(t)))
			}
		})
	}
}

func validateTestData(tx Transaction) error {
	if tx.IsOverwinter {
		if tx.Version == 3 && tx.ExpiryHeight > TxExpiryHeightThreshold {
			// Transaction must be invalid
			if err := tx.Validate(); err == nil {
				return fmt.Errorf("Expected invalid overwinter transaction due to expiry height")
			}
		} else {
			return tx.Validate()
		}
	} else if tx.Version < OverwinterMinCurrentVersion {
		// Transaction must be invalid
		if err := tx.Validate(); err == nil {
			return fmt.Errorf("Expected invalid sprout transaction, due to Version(%d) < OverwinterMinCurrentVersion(%d)", tx.Version, OverwinterMinCurrentVersion)
		}
	} else if err := tx.Validate(); err != nil {
		return fmt.Errorf("Expected valid txn, got: %v", err)
	}
	return nil
}
