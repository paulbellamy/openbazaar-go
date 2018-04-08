package zcash

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"gx/ipfs/QmaPHkZLbQQbvcyavn8q1GFHg6o6yeceyHFSJ3Pjf3p3TQ/go-crypto/blake2b"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	btc "github.com/btcsuite/btcutil"
)

type SignatureCreator interface {
	CreateSig(address btc.Address, scriptCode []byte, consensusBranchId uint32) ([]byte, bool)
	txscript.KeyDB
	txscript.ScriptDB
}

func TransactionSignatureCreator(kdb txscript.KeyDB, sdb txscript.ScriptDB, tx *Transaction, idx int, hashType txscript.SigHashType) SignatureCreator {
	return &signatureCreator{
		KeyDB:    kdb,
		ScriptDB: sdb,
		tx:       tx,
		idx:      idx,
		hashType: hashType,
	}
}

type signatureCreator struct {
	txscript.KeyDB
	txscript.ScriptDB
	tx       *Transaction
	idx      int
	hashType txscript.SigHashType
}

func (s *signatureCreator) CreateSig(address btc.Address, scriptCode []byte, consensusBranchId uint32) ([]byte, bool) {
	key, _, err := s.GetKey(address)
	if err != nil {
		return nil, false
	}

	hash, err := SignatureHash(scriptCode, s.tx, s.idx, s.hashType, consensusBranchId)
	if err != nil {
		return nil, false
	}

	signature, err := key.Sign(hash)
	if err != nil {
		return nil, false
	}

	return append(signature.Serialize(), byte(s.hashType)), true
}

var (
	PrevoutsHashPersonalization   = []byte("ZcashPrevoutHash")
	SequenceHashPersonalization   = []byte("ZcashSequencHash")
	OutputsHashPersonalization    = []byte("ZcashOutputsHash")
	JoinSplitsHashPersonalization = []byte("ZcashJSplitsHash")
)

func SignatureHash(scriptCode []byte, tx *Transaction, idx int, hashType txscript.SigHashType, consensusBranchId uint32) ([]byte, error) {
	if idx >= len(tx.Inputs) && idx != NotAnInput {
		// index out of range
		return nil, fmt.Errorf("input index is out of range")
	}

	if tx.IsOverwinter {
		return overwinterSignatureHash(scriptCode, tx, idx, hashType, consensusBranchId)
	}
	return sproutSignatureHash(scriptCode, tx, idx, hashType)
}

func overwinterSignatureHash(scriptCode []byte, tx *Transaction, idx int, hashType txscript.SigHashType, consensusBranchId uint32) ([]byte, error) {
	/*
			BLAKE2b-256 hash of the serialization of:
		  1. header of the transaction (4-byte little endian)
		  2. nVersionGroupId of the transaction (4-byte little endian)
		  3. hashPrevouts (32-byte hash)
		  4. hashSequence (32-byte hash)
		  5. hashOutputs (32-byte hash)
		  6. hashJoinSplits (32-byte hash)
		  7. nLockTime of the transaction (4-byte little endian)
		  8. nExpiryHeight of the transaction (4-byte little endian)
		  9. sighash type of the signature (4-byte little endian)
		 10. If we are serializing an input (i.e. this is not a JoinSplit signature hash):
		     a. outpoint (32-byte hash + 4-byte little endian)
		     b. scriptCode of the input (serialized as scripts inside CTxOuts)
		     c. value of the output spent by this input (8-byte little endian)
		     d. nSequence of the input (4-byte little endian)
	*/

	// The default values are zeroes
	var hashPrevouts, hashSequence, hashOutputs, hashJoinSplits []byte

	if (hashType & txscript.SigHashAnyOneCanPay) == 0 {
		ss, err := blake2b.New256(PrevoutsHashPersonalization)
		if err != nil {
			return nil, err
		}
		for _, input := range tx.Inputs {
			if err := input.writeOutPoint(ss); err != nil {
				return nil, err
			}
		}
		hashPrevouts = ss.Sum(nil)
	}

	if (hashType&txscript.SigHashAnyOneCanPay == 0) && (hashType&0x1f) != txscript.SigHashSingle && (hashType&0x1f) != txscript.SigHashNone {
		ss, err := blake2b.New256(SequenceHashPersonalization)
		if err != nil {
			return nil, err
		}
		for _, input := range tx.Inputs {
			if err := writeField(input.Sequence)(ss); err != nil {
				return nil, err
			}
		}
		hashSequence = ss.Sum(nil)
	}

	if (hashType&0x1f) != txscript.SigHashSingle && (hashType&0x1f) != txscript.SigHashNone {
		ss, err := blake2b.New256(OutputsHashPersonalization)
		if err != nil {
			return nil, err
		}
		for _, output := range tx.Outputs {
			if _, err := output.WriteTo(ss); err != nil {
				return nil, err
			}
		}
		hashOutputs = ss.Sum(nil)
	} else if (hashType&0x1f) == txscript.SigHashSingle && idx < len(tx.Outputs) {
		ss, err := blake2b.New256(OutputsHashPersonalization)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Outputs[idx].WriteTo(ss); err != nil {
			return nil, err
		}
		hashOutputs = ss.Sum(nil)
	}

	if len(tx.JoinSplits) > 0 {
		ss, err := blake2b.New256(JoinSplitsHashPersonalization)
		if err != nil {
			return nil, err
		}
		for _, js := range tx.JoinSplits {
			if _, err := js.WriteTo(ss); err != nil {
				return nil, err
			}
		}
		if err := writeBytes(tx.JoinSplitPubKey[:])(ss); err != nil {
			return nil, err
		}
		hashJoinSplits = ss.Sum(nil)
	}

	personalization := bytes.NewBufferString("ZcashSigHash")
	if err := writeField(consensusBranchId)(personalization); err != nil {
		return nil, err
	}

	ss, err := blake2b.New256(personalization.Bytes())
	if err != nil {
		return nil, err
	}
	if err := writeAll(ss,
		// fOverwintered and nVersion
		tx.GetHeader(),
		// Version group ID
		tx.VersionGroupID,
		// Input prevouts/nSequence (none/all, depending on flags)
		hashPrevouts,
		hashSequence,
		// Outputs (none/one/all, depending on flags)
		hashOutputs,
		// JoinSplits
		hashJoinSplits,
		// Locktime
		uint32(tx.Timestamp.Unix()),
		// Expiry height
		tx.ExpiryHeight,
		// Sighash type
		hashType,
	); err != nil {
		return nil, err
	}

	if idx != NotAnInput {
		// The input being signed (replacing the scriptSig with scriptCode + amount)
		// The prevout may already be contained in hashPrevout, and the nSequence
		// may already be contained in hashSequence.
		var amountIn int64
		if idx < len(tx.Outputs) {
			amountIn = tx.Outputs[idx].Value
		}

		if err := tx.Inputs[idx].writeOutPoint(ss); err != nil {
			return nil, err
		}
		if err := writeAll(ss, scriptCode, amountIn, tx.Inputs[idx].Sequence); err != nil {
			return nil, err
		}
	}

	return ss.Sum(nil), nil
}

func sproutSignatureHash(scriptCode []byte, tx *Transaction, idx int, hashType txscript.SigHashType) ([]byte, error) {
	// Check for invalid use of SIGHASH_SINGLE
	if (hashType & 0x1f) == txscript.SigHashSingle {
		if idx >= len(tx.Outputs) {
			//  nOut out of range
			return nil, fmt.Errorf("no matching output for SIGHASH_SINGLE")
		}
	}

	var one chainhash.Hash
	one[0] = 0x01
	if idx >= len(tx.Inputs) || idx == NotAnInput {
		return one[:], nil
	}
	txTmp := tx.shallowCopy()

	// Blank out other inputs' signatures
	for i := 0; i < len(txTmp.Inputs); i++ {
		txTmp.Inputs[i].SignatureScript = nil
	}
	txTmp.Inputs[idx].SignatureScript = scriptCode

	// Blank out some of the outputs
	if (hashType & 0x1f) == txscript.SigHashNone {
		// Wildcard payee
		txTmp.Outputs = nil

		// Let the others update at will
		for i := 0; i < len(txTmp.Inputs); i++ {
			if i != idx {
				txTmp.Inputs[i].Sequence = 0
			}
		}
	} else if (hashType & 0x1f) == txscript.SigHashSingle {
		// Only lock-in the txout payee at same index as txin
		nOut := idx
		if nOut >= len(txTmp.Outputs) {
			return one[:], nil
		}
		txTmp.Outputs = txTmp.Outputs[:nOut+1]
		for i := 0; i < nOut; i++ {
			txTmp.Outputs[i] = Output{}
		}

		// Let the others update at will
		for i := 0; i < len(txTmp.Inputs); i++ {
			if i != idx {
				txTmp.Inputs[i].Sequence = 0
			}
		}
	}

	// Blank out other inputs completely, not recommended for open transactions
	if hashType&txscript.SigHashAnyOneCanPay > 0 {
		txTmp.Inputs = []Input{txTmp.Inputs[idx]}
	}

	// Blank out the joinsplit signature.
	txTmp.JoinSplitSignature = [64]byte{}

	// Serialize and hash
	txBin, err := txTmp.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return sha256.New().Sum(append(txBin, byte(hashType))), nil
}

// shallowCopy creates a shallow copy of the transaction for use when
// calculating the signature hash.  It is used over the Copy method on the
// transaction itself since that is a deep copy and therefore does more work and
// allocates much more space than needed.
func (tx Transaction) shallowCopy() Transaction {
	// As an additional memory optimization, use contiguous backing arrays
	// for the copied inputs and outputs and point the final slice of
	// pointers into the contiguous arrays.  This avoids a lot of small
	// allocations.
	txCopy := tx
	txCopy.Inputs = make([]Input, len(tx.Inputs))
	txCopy.Outputs = make([]Output, len(tx.Outputs))
	txCopy.JoinSplits = make([]JoinSplit, len(tx.JoinSplits))
	txCopy.JoinSplitPubKey = [32]byte{}
	txCopy.JoinSplitSignature = [64]byte{}

	for i := range tx.Inputs {
		txCopy.Inputs[i] = tx.Inputs[i]
	}
	for i := range tx.Outputs {
		txCopy.Outputs[i] = tx.Outputs[i]
	}
	for i := range tx.JoinSplits {
		txCopy.JoinSplits[i] = tx.JoinSplits[i]
	}
	copy(txCopy.JoinSplitPubKey[:], tx.JoinSplitPubKey[:])
	copy(txCopy.JoinSplitSignature[:], tx.JoinSplitSignature[:])
	return txCopy
}
