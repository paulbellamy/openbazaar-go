package zcash

import (
	"bytes"
	"fmt"
	"gx/ipfs/QmaPHkZLbQQbvcyavn8q1GFHg6o6yeceyHFSJ3Pjf3p3TQ/go-crypto/blake2b"

	"github.com/btcsuite/btcd/txscript"
	btc "github.com/btcsuite/btcutil"
)

type SignatureCreator interface {
	CreateSig(address btc.Address, scriptCode []byte, consensusBranchId uint32) ([]byte, bool)
}

func TransactionSignatureCreator(kdb txscript.KeyDB, tx *Transaction, idx int, amountIn int64, hashType txscript.SigHashType) SignatureCreator {
	return &signatureCreator{
		kdb:      kdb,
		tx:       tx,
		idx:      idx,
		amountIn: amountIn,
		hashType: hashType,
	}
}

type signatureCreator struct {
	kdb      txscript.KeyDB
	tx       *Transaction
	idx      int
	amountIn int64
	hashType txscript.SigHashType
}

func (s *signatureCreator) CreateSig(address btc.Address, scriptCode []byte, consensusBranchId uint32) ([]byte, bool) {
	key, _, err := s.kdb.GetKey(address)
	if err != nil {
		return nil, false
	}

	hash, err := SignatureHash(scriptCode, s.tx, s.idx, s.hashType, s.amountIn, consensusBranchId)
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

func SignatureHash(scriptCode []byte, tx *Transaction, idx int, hashType txscript.SigHashType, amountIn int64, consensusBranchId uint32) ([]byte, error) {
	if !tx.IsOverwinter {
		// TODO: Implement this for pre-overwinter txns
		return nil, fmt.Errorf("transaction signing for pre-overwinter txns not implemented")
	}

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

	var leConsensusBranchId uint32 = htole32(consensusBranchId)
	personalization := bytes.NewBufferString("ZcashSigHash")
	if err := writeField(leConsensusBranchId)(personalization); err != nil {
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

	if idx != NOT_AN_INPUT {
		// The input being signed (replacing the scriptSig with scriptCode + amount)
		// The prevout may already be contained in hashPrevout, and the nSequence
		// may already be contained in hashSequence.

		if err := tx.Inputs[idx].writeOutPoint(ss); err != nil {
			return nil, err
		}
		if err := writeAll(ss, scriptCode, amountIn, tx.Inputs[idx].Sequence); err != nil {
			return nil, err
		}
	}

	return ss.Sum(nil), nil
}
