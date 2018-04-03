package zcash

import (
	"crypto/rand"
	"math"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func TestSerialization(t *testing.T) {
	now := time.Now().UTC().Truncate(1 * time.Second)
	hash, _ := chainhash.NewHashFromStr("a")
	var jsPubKey [32]byte
	if _, err := rand.Read(jsPubKey[:]); err != nil {
		t.Fatal(err)
	}
	var jsSignature [64]byte
	if _, err := rand.Read(jsSignature[:]); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		txn  Transaction
	}{
		{
			name: "empty v1",
			txn: Transaction{
				Version:   1,
				Timestamp: now,
				Inputs:    []Input{{}},
				Outputs:   []Output{},
			},
		},
		{
			name: "v1",
			txn: Transaction{
				Version:   1,
				Timestamp: now,
				Inputs: []Input{
					{PreviousOutPoint: wire.OutPoint{*hash, 1}, SignatureScript: []byte("signatureScript"), Sequence: 9},
				},
				Outputs: []Output{
					{Value: 1234, ScriptPubKey: []byte("scriptPubKey")},
				},
			},
		},
		{
			name: "v2",
			txn: Transaction{
				Version:            2,
				Timestamp:          now,
				Inputs:             []Input{},
				Outputs:            []Output{},
				JoinSplits:         []JoinSplit{{}},
				JoinSplitPubKey:    jsPubKey,
				JoinSplitSignature: jsSignature,
			},
		},
		{
			name: "overwinter",
			txn: Transaction{
				IsOverwinter:   true,
				Version:        3,
				VersionGroupID: OverwinterVersionGroupID,
				Timestamp:      now,
				Inputs: []Input{
					{PreviousOutPoint: wire.OutPoint{*hash, 1}, SignatureScript: []byte("signatureScript"), Sequence: 9},
				},
				Outputs: []Output{
					{Value: 1234, ScriptPubKey: []byte("scriptPubKey")},
				},
			},
		},
		{
			name: "overwinter with expiry",
			txn: Transaction{
				IsOverwinter:   true,
				Version:        3,
				VersionGroupID: OverwinterVersionGroupID,
				Timestamp:      now,
				ExpiryHeight:   99,
				Inputs: []Input{
					{PreviousOutPoint: wire.OutPoint{*hash, 1}, SignatureScript: []byte("signatureScript"), Sequence: 9},
				},
				Outputs: []Output{
					{Value: 1234, ScriptPubKey: []byte("scriptPubKey")},
				},
			},
		},
		// TODO: nJoinSplit handling
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.txn.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			var got Transaction
			if err := got.UnmarshalBinary(b); err != nil {
				t.Fatal(err)
			}
			if !got.IsEqual(&tc.txn) {
				t.Fatalf("\nExpected: %+v\n     Got: %+v", tc.txn, got)
			}
		})
	}
}

func TestTransactionValidate(t *testing.T) {
	for _, tc := range []struct {
		err string
		txn *Transaction
	}{
		{
			err: "transaction version must be greater than 0",
			txn: &Transaction{Version: 0, Inputs: []Input{{}}, Outputs: []Output{{}}},
		},
		{
			err: "transaction version must be less than 3",
			txn: &Transaction{Version: 3, Inputs: []Input{{}}, Outputs: []Output{{}}},
		},
		{
			err: "transaction has no inputs",
			txn: &Transaction{Version: 1, Outputs: []Output{{}}},
		},
		{
			err: "transaction has no outputs",
			txn: &Transaction{Version: 1, Inputs: []Input{{}}},
		},
		{
			err: "overwinter transaction version must be 3",
			txn: &Transaction{IsOverwinter: true, Version: 2, Inputs: []Input{{}}, Outputs: []Output{{}}},
		},
		{
			err: "transaction has unknown version group id",
			txn: &Transaction{IsOverwinter: true, Version: 3, VersionGroupID: 9999, Inputs: []Input{{}}, Outputs: []Output{{}}},
		},
		{
			err: "transaction with coinbase input must have no transparent outputs",
			txn: &Transaction{
				Version: 1,
				Inputs: []Input{
					{PreviousOutPoint: wire.OutPoint{Index: math.MaxUint32}, SignatureScript: []byte("signatureScript")},
				},
				Outputs: []Output{{}},
			},
		},
		// TODO: nJoinSplit handling
		// TODO: Other rules inherited from Bitcoin
	} {
		t.Run(tc.err, func(t *testing.T) {
			err := tc.txn.Validate()
			if err == nil {
				t.Errorf("Did not reject invalid txn")
			} else if err.Error() != tc.err {
				t.Errorf("Expected %q error, got: %q", tc.err, err.Error())
			}
		})
	}
}
