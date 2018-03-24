package zcash

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/OpenBazaar/openbazaar-go/bitcoin/zcashd"
	wallet "github.com/OpenBazaar/wallet-interface"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
)

func (t *Transaction) Sign(
	params *chaincfg.Params,
	keys wallet.Keys,
	additionalPrevScripts map[string][]byte,
	hashType SigHashType,
	consensusBranchId uint32,
) error {
	for i, input := range t.Inputs {
		prevOutScript := additionalPrevScripts[input.PreviousOutPoint()]
		address, err := zcashd.ExtractPkScriptAddrs(prevOutScript, params)
		if err != nil {
			return err
		}
		key, err := keys.GetKey(address.ScriptAddress())
		if err != nil {
			return fmt.Errorf("could not find key for tx: %v", err)
		}
		signature, err := t.InputSignature(prevOutScript, i, hashType, consensusBranchId, key)
		if err != nil {
			return fmt.Errorf("failed to sign transaction: %v", err)
		}
		pk := (*btcec.PublicKey)(&key.PublicKey)
		// TODO: Check if we ever need to do the uncompressed...
		scriptSig, err := txscript.NewScriptBuilder().AddData(signature).AddData(pk.SerializeCompressed()).Script()
		if err != nil {
			return err
		}

		t.Inputs[i].ScriptSig = Script{Hex: hex.EncodeToString(scriptSig)}
	}
	return nil
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
	txTmp, err := t.txTmp(scriptCode, nIn, hashType)
	if err != nil {
		return nil, err
	}

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

func (t *Transaction) txTmp(scriptCode []byte, nIn int, hashType SigHashType) (*Transaction, error) {
	txCopy := Transaction{
		Version:   t.Version,
		Timestamp: t.Timestamp,
	}
	if hashType == SigHashAnyOneCanPay {
		// Only selected input
		txCopy.Inputs = t.Inputs[nIn:1]
	} else {
		// all inputs, with other signatures blanked
		for i, input := range t.Inputs {
			if i != nIn {
				input.ScriptSig = Script{}
			}
			txCopy.Inputs = append(txCopy.Inputs, input)
		}
	}

	switch hashType {
	case SigHashNone:
		txCopy.Outputs = nil
	case SigHashSingle:
		txCopy.Outputs = t.Outputs[nIn:1]
	default:
		txCopy.Outputs = t.Outputs
	}

	// TODO: Joinsplits

	return &txCopy, nil
}
