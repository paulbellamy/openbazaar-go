package zcash

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	btc "github.com/btcsuite/btcutil"
)

func (w *Wallet) Sign(t *wire.MsgTx, hashType txscript.SigHashType, additionalPrevScripts map[wire.OutPoint][]byte, additionalKeysByAddress map[string]*btc.WIF) (*wire.MsgTx, error) {
	txCopy := shallowCopyTx(t)
	t = &txCopy
	for i, input := range t.TxIn {
		prevOutScript, ok := additionalPrevScripts[input.PreviousOutPoint]
		if !ok {
			return nil, fmt.Errorf("could not find script for tx input %d", i)
		}
		address, err := w.ScriptToAddress(prevOutScript)
		if err != nil {
			return nil, err
		}
		wif, ok := additionalKeysByAddress[address.EncodeAddress()]
		if !ok {
			return nil, fmt.Errorf("could not find key for tx: %v", address.EncodeAddress())
		}
		key := wif.PrivKey
		signature, err := inputSignature(t, i, prevOutScript, hashType, key)
		if err != nil {
			return nil, fmt.Errorf("failed to sign transaction: %v", err)
		}
		pk := (*btcec.PublicKey)(&key.PublicKey)
		// TODO: Check if we ever need to do the uncompressed...

		scriptSig, err := txscript.NewScriptBuilder().AddData(signature).AddData(pk.SerializeCompressed()).Script()
		if err != nil {
			return nil, err
		}

		t.TxIn[i].SignatureScript = scriptSig
	}
	return t, nil
}

func inputSignature(t *wire.MsgTx, nIn int, scriptCode []byte, hashType txscript.SigHashType, key *btcec.PrivateKey) ([]byte, error) {
	hash, err := inputSignatureHash(t, nIn, scriptCode, hashType)
	if err != nil {
		return nil, err
	}
	signature, err := key.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}
	return append(signature.Serialize(), byte(hashType)), nil
}

// TODO: Separate signing for joinsplits
// TODO: Separate signing for overwinter transactions
func inputSignatureHash(t *wire.MsgTx, nIn int, scriptCode []byte, hashType txscript.SigHashType) ([]byte, error) {
	if nIn >= len(t.TxIn) {
		//  nIn out of range
		return nil, fmt.Errorf("input index is out of range")
	}

	// The SigHashSingle signature type signs only the corresponding input
	// and output (the output with the same index number as the input).
	//
	// Since transactions can have more inputs than outputs, this means it
	// is improper to use SigHashSingle on input indices that don't have a
	// corresponding output.
	//
	// A bug in the original Satoshi client implementation means specifying
	// an index that is out of range results in a signature hash of 1 (as a
	// uint256 little endian).  The original intent appeared to be to
	// indicate failure, but unfortunately, it was never checked and thus is
	// treated as the actual signature hash.  This buggy behavior is now
	// part of the consensus and a hard fork would be required to fix it.
	//
	// Due to this, care must be taken by software that creates transactions
	// which make use of SigHashSingle because it can lead to an extremely
	// dangerous situation where the invalid inputs will end up signing a
	// hash of 1.  This in turn presents an opportunity for attackers to
	// cleverly construct transactions which can steal those coins provided
	// they can reuse signatures.
	if hashType&sigHashMask == txscript.SigHashSingle && nIn >= len(t.TxOut) {
		var hash chainhash.Hash
		hash[0] = 0x01
		return hash[:], nil
	}

	// Wrapper to serialize only the necessary parts of the transaction being signed
	txCopy := txTmp(t, scriptCode, nIn, hashType)

	// Serialize and hash
	wbuf := bytes.NewBuffer(make([]byte, 0, txCopy.SerializeSizeStripped()+4))
	if err := txCopy.SerializeNoWitness(wbuf); err != nil {
		return nil, err
	}
	if err := binary.Write(wbuf, binary.LittleEndian, hashType); err != nil {
		return nil, err
	}
	return chainhash.DoubleHashB(wbuf.Bytes()), nil
}

// sigHashMask defines the number of bits of the hash type which is used
// to identify which outputs are signed.
// It is from github.com/btcsuite/btcd/txscript/script.go
const sigHashMask = 0x1f

func txTmp(t *wire.MsgTx, scriptCode []byte, nIn int, hashType txscript.SigHashType) *wire.MsgTx {

	// Remove all instances of OP_CODESEPARATOR from the script.
	// TODO: See if we need to do this
	// script = removeOpcode(script, OP_CODESEPARATOR)

	txCopy := shallowCopyTx(t)
	// all inputs, with other signatures blanked
	for i := range t.TxIn {
		if i == nIn {
			txCopy.TxIn[i].SignatureScript = scriptCode
		} else {
			txCopy.TxIn[i].SignatureScript = nil
		}
	}

	switch hashType & sigHashMask {
	case txscript.SigHashNone:
		txCopy.TxOut = nil
		for i := range txCopy.TxIn {
			if i != nIn {
				txCopy.TxIn[i].Sequence = 0
			}
		}
	case txscript.SigHashSingle:
		txCopy.TxOut = txCopy.TxOut[nIn:1]
		// All but current output get zeroed out.
		for i := 0; i < nIn; i++ {
			txCopy.TxOut[i].Value = -1
			txCopy.TxOut[i].PkScript = nil
		}
		// Sequence on all other inputs is 0, too.
		for i := range txCopy.TxIn {
			if i != nIn {
				txCopy.TxIn[i].Sequence = 0
			}
		}
	default:
		// Consensus treats undefined hashtypes like normal SigHashAll
		// for purposes of hash generation.
		fallthrough
	case txscript.SigHashOld:
		fallthrough
	case txscript.SigHashAll:
		// Nothing special here.
	}
	if hashType&txscript.SigHashAnyOneCanPay != 0 {
		// Only selected input
		txCopy.TxIn = txCopy.TxIn[nIn : nIn+1]
	}

	// TODO: Joinsplits

	return &txCopy
}

// shallowCopyTx creates a shallow copy of the transaction for use when
// calculating the signature hash.  It is used over the Copy method on the
// transaction itself since that is a deep copy and therefore does more work and
// allocates much more space than needed.
func shallowCopyTx(tx *wire.MsgTx) wire.MsgTx {
	// As an additional memory optimization, use contiguous backing arrays
	// for the copied inputs and outputs and point the final slice of
	// pointers into the contiguous arrays.  This avoids a lot of small
	// allocations.
	txCopy := wire.MsgTx{
		Version:  tx.Version,
		TxIn:     make([]*wire.TxIn, len(tx.TxIn)),
		TxOut:    make([]*wire.TxOut, len(tx.TxOut)),
		LockTime: tx.LockTime,
	}
	txIns := make([]wire.TxIn, len(tx.TxIn))
	for i, oldTxIn := range tx.TxIn {
		txIns[i] = *oldTxIn
		txCopy.TxIn[i] = &txIns[i]
	}
	txOuts := make([]wire.TxOut, len(tx.TxOut))
	for i, oldTxOut := range tx.TxOut {
		txOuts[i] = *oldTxOut
		txCopy.TxOut[i] = &txOuts[i]
	}
	return txCopy
}
