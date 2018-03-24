package zcash

import (
	"testing"
)

func TestTransactionSign(t *testing.T) {
	t.Errorf("pending")
	w, _ := NewWallet(testConfig(t))
	txn := &Transaction{
		Inputs: []Input{{}},
	}
	additionalPrevScripts := make(map[string][]byte)
	if err := txn.Sign(w.Params(), w.DB.Keys(), additionalPrevScripts, SigHashAll, uint32(0)); err != nil {
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
