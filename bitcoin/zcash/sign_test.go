package zcash

import (
	"testing"
)

func TestWalletSign(t *testing.T) {
	w, _ := NewWallet(testConfig(t))
	txn := &Transaction{
		Inputs: []Input{{}},
	}
	if err := w.sign(txn); err != nil {
		t.Fatal(err)
	}

	// Check txn inputs are signed with our key
	if len(txn.Inputs) <= 0 {
		t.Errorf("Txn had no inputs")
	}
	for _, input := range txn.Inputs {
		if input.ScriptSig.Hex == "" {
			t.Errorf("Input was not signed: %v", input)
		}
	}
}
