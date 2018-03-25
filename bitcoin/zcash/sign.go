package zcash

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

func (w *Wallet) Sign(
	t *Transaction,
	hashType SigHashType,
	consensusBranchId uint32,
) (*Transaction, error) {
	t = t.shallowCopy()
	for i, input := range t.Inputs {
		prevOutScript, err := hex.DecodeString(input.ScriptSig.Hex)
		if err != nil {
			return nil, fmt.Errorf("could not decide previous script for %v", input.PreviousOutPoint())
		}
		address, err := w.ScriptToAddress(prevOutScript)
		if err != nil {
			return nil, err
		}
		key, err := w.DB.Keys().GetKey(address.ScriptAddress())
		if err != nil {
			return nil, fmt.Errorf("could not find key for tx: %v", err)
		}
		signature, err := t.InputSignature(prevOutScript, i, hashType, consensusBranchId, key)
		if err != nil {
			return nil, fmt.Errorf("failed to sign transaction: %v", err)
		}
		pk := (*btcec.PublicKey)(&key.PublicKey)
		// TODO: Check if we ever need to do the uncompressed...

		scriptSig, err := txscript.NewScriptBuilder().AddData(signature).AddData(pk.SerializeCompressed()).Script()
		if err != nil {
			return nil, err
		}

		t.Inputs[i].ScriptSig = Script{Hex: hex.EncodeToString(scriptSig)}
	}
	return t, nil
}

func (t *Transaction) InputSignature(
	scriptCode []byte,
	nIn int,
	hashType SigHashType,
	consensusBranchId uint32,
	key *btcec.PrivateKey,
) ([]byte, error) {
	hash, err := t.InputSignatureHash(scriptCode, nIn, hashType, consensusBranchId)
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
func (t *Transaction) InputSignatureHash(
	scriptCode []byte,
	nIn int,
	hashType SigHashType,
	consensusBranchId uint32,
) ([]byte, error) {
	if nIn >= len(t.Inputs) {
		//  nIn out of range
		return nil, fmt.Errorf("input index is out of range")
	}

	if hashType == SigHashSingle && nIn > len(t.Outputs) {
		return nil, fmt.Errorf("no matching output for SigHashSingle")
	}

	// Wrapper to serialize only the necessary parts of the transaction being signed
	txTmp := t.txTmp(scriptCode, nIn, hashType)

	// Serialize and hash
	buf := &bytes.Buffer{}
	if _, err := txTmp.WriteTo(buf); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, binary.LittleEndian, hashType); err != nil {
		return nil, err
	}
	return chainhash.DoubleHashB(buf.Bytes()), nil
}

func (t *Transaction) txTmp(scriptCode []byte, nIn int, hashType SigHashType) *Transaction {
	txCopy := t.shallowCopy()
	if hashType == SigHashAnyOneCanPay {
		// Only selected input
		txCopy.Inputs = txCopy.Inputs[nIn:1]
	} else {
		// all inputs, with other signatures blanked
		for i := range t.Inputs {
			if i != nIn {
				txCopy.Inputs[i].ScriptSig = Script{}
			}
		}
	}

	switch hashType {
	case SigHashNone:
		txCopy.Outputs = nil
	case SigHashSingle:
		txCopy.Outputs = txCopy.Outputs[nIn:1]
	}

	// TODO: Joinsplits

	return txCopy
}

func (t *Transaction) shallowCopy() *Transaction {
	txCopy := &Transaction{
		Version:   t.Version,
		Timestamp: t.Timestamp,
		Inputs:    make([]Input, len(t.Inputs)),
		Outputs:   make([]client.Output, len(t.Outputs)),
	}
	for i, input := range t.Inputs {
		txCopy.Inputs[i] = input
	}
	for i, output := range t.Outputs {
		txCopy.Outputs[i] = output
	}
	// TODO: Joinsplits
	return txCopy
}
