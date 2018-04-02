package zcash

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

var (
	ErrTxVersionTooSmall = fmt.Errorf("transaction version must be greater than 0")
	ErrTxVersionTooLarge = fmt.Errorf("transaction version must be less than 3")
	ErrNoTxInputs        = fmt.Errorf("transaction has no inputs")
	ErrNoTxOutputs       = fmt.Errorf("transaction has no outputs")
	ErrDuplicateTxInputs = fmt.Errorf("transaction contains duplicate inputs")
	ErrBadTxInput        = fmt.Errorf("transaction input refers to previous output that is null")

	zeroHash chainhash.Hash
)

type Transaction struct {
	Version   uint32
	Inputs    []Input
	Outputs   []Output
	Timestamp time.Time
}

// TxHash generates the Hash for the transaction.
func (t *Transaction) TxHash() chainhash.Hash {
	// Encode the transaction and calculate double sha256 on the result.
	// Ignore the error returns since the only way the encode could fail
	// is being out of memory or due to nil pointers, both of which would
	// cause a run-time panic.
	b, _ := t.MarshalBinary()
	return chainhash.DoubleHashH(b)
}

func (t *Transaction) UnmarshalBinary(data []byte) error {
	_, err := t.ReadFrom(bytes.NewReader(data))
	return err
}

func (t *Transaction) ReadFrom(r io.Reader) (n int64, err error) {
	counter := &countingReader{Reader: r}
	for _, segment := range []func(io.Reader) error{
		t.readVersion,
		t.readInputs,
		t.readOutputs,
		t.readTimestamp,
		// TODO: read joinsplits
	} {
		if err := segment(counter); err != nil {
			return counter.N, err
		}
	}
	return counter.N, nil
}

func (t *Transaction) readVersion(r io.Reader) error {
	// TODO: Handle overwinter here
	// Check the version
	err := binary.Read(r, binary.LittleEndian, &t.Version)
	if err == nil && t.Version < 1 || 2 < t.Version {
		return fmt.Errorf("invalid txn version %v", t.Version)
	}
	return err
}

func (t *Transaction) readInputs(r io.Reader) error {
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	if t.Version == 1 && count <= 0 {
		return fmt.Errorf("txn must have transparent inputs")
	}
	for i := uint64(0); i < count; i++ {
		var input Input
		if _, err := input.ReadFrom(r); err != nil {
			return err
		}
		t.Inputs = append(t.Inputs, input)
	}
	return nil
}

func (t *Transaction) readOutputs(r io.Reader) error {
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	// TODO: Check if we have coinbase inputs, then we must have 0 transparent outputs
	for i := uint64(0); i < count; i++ {
		var output Output
		if _, err := output.ReadFrom(r); err != nil {
			return err
		}
		t.Outputs = append(t.Outputs, output)
	}
	return nil
}

// readScript reads a variable length byte array that represents a transaction
// script.  It is encoded as a varInt containing the length of the array
// followed by the bytes themselves.  An error is returned if the length is
// greater than the passed maxAllowed parameter which helps protect against
// memory exhuastion attacks and forced panics thorugh malformed messages.  The
// fieldName parameter is only used for the error message so it provides more
// context in the error.
func readScript(r io.Reader, fieldName string) ([]byte, error) {
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}

	// Prevent byte array larger than the max message size.  It would
	// be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > uint64(wire.MaxMessagePayload) {
		return nil, fmt.Errorf(
			"readScript: %s is larger than the max allowed size [count %d, max %d]",
			fieldName, count, wire.MaxMessagePayload,
		)
	}

	b := make([]byte, count)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func writeScript(w io.Writer, script []byte) error {
	return wire.WriteVarBytes(w, 0, script)
}

func (t *Transaction) readTimestamp(r io.Reader) error {
	var timestamp uint32
	if err := binary.Read(r, binary.LittleEndian, &timestamp); err != nil {
		return err
	}
	t.Timestamp = time.Unix(int64(timestamp), 0)
	return nil
}

func (t *Transaction) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}
	if _, err := t.WriteTo(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
	return buf.Bytes(), nil
}

func (t *Transaction) WriteTo(w io.Writer) (n int64, err error) {
	counter := &countingWriter{Writer: w}
	for _, segment := range []func(io.Writer) error{
		t.writeVersion,
		t.writeInputs,
		t.writeOutputs,
		t.writeTimestamp,
	} {
		if err := segment(counter); err != nil {
			return counter.N, err
		}
	}
	return counter.N, nil
}

func (t *Transaction) writeVersion(w io.Writer) error {
	// TODO: Handle joinsplits here
	// TODO: Handle overwinter here
	return binary.Write(w, binary.LittleEndian, uint32(1))
}

func (t *Transaction) writeInputs(w io.Writer) error {
	if err := wire.WriteVarInt(w, 0, uint64(len(t.Inputs))); err != nil {
		return err
	}
	for _, input := range t.Inputs {
		if _, err := input.WriteTo(w); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transaction) writeOutputs(w io.Writer) error {
	if err := wire.WriteVarInt(w, 0, uint64(len(t.Outputs))); err != nil {
		return err
	}
	for _, output := range t.Outputs {
		if _, err := output.WriteTo(w); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transaction) writeTimestamp(w io.Writer) error {
	return binary.Write(w, binary.LittleEndian, uint32(t.Timestamp.Unix()))
}

func (tx *Transaction) Validate() error {
	if tx.Version <= 0 {
		return ErrTxVersionTooSmall
	}
	if tx.Version >= 3 {
		return ErrTxVersionTooLarge
	}
	// A transaction must have at least one input.
	if len(tx.Inputs) == 0 {
		return ErrNoTxInputs
	}

	// A transaction must have at least one output.
	if len(tx.Outputs) == 0 {
		return ErrNoTxOutputs
	}

	// A transaction must not exceed the maximum allowed block payload when
	// serialized.
	serialized, err := tx.MarshalBinary()
	if err != nil {
		return err
	}
	serializedTxSize := len(serialized)
	// TODO: Figure out the max zcash block base size
	if serializedTxSize > blockchain.MaxBlockBaseSize {
		return fmt.Errorf("serialized transaction is too big - got %d, max %d", serializedTxSize, blockchain.MaxBlockBaseSize)
	}

	// Ensure the transaction amounts are in range.  Each transaction
	// output must not be negative or more than the max allowed per
	// transaction.  Also, the total of all outputs must abide by the same
	// restrictions.  All amounts in a transaction are in a unit value known
	// as a satoshi.  One bitcoin is a quantity of satoshi as defined by the
	// SatoshiPerBitcoin constant.
	var totalSatoshi int64
	for _, txOut := range tx.Outputs {
		satoshi := txOut.Value
		if satoshi < 0 {
			return fmt.Errorf("transaction output has negative value of %v", satoshi)
		}
		if satoshi > btcutil.MaxSatoshi {
			return fmt.Errorf("transaction output value of %v is higher than max allowed value of %v", satoshi, btcutil.MaxSatoshi)
		}

		// Two's complement int64 overflow guarantees that any overflow
		// is detected and reported.  This is impossible for Bitcoin, but
		// perhaps possible if an alt increases the total money supply.
		totalSatoshi += satoshi
		if totalSatoshi < 0 {
			return fmt.Errorf("total value of all transaction outputs exceeds max allowed value of %v", btcutil.MaxSatoshi)
		}
		if totalSatoshi > btcutil.MaxSatoshi {
			return fmt.Errorf("total value of all transaction outputs is %v which is higher than max allowed value of %v", totalSatoshi, btcutil.MaxSatoshi)
		}
	}

	// Check for duplicate transaction inputs.
	existingTxOut := make(map[wire.OutPoint]struct{})
	for _, txIn := range tx.Inputs {
		if _, exists := existingTxOut[txIn.PreviousOutPoint]; exists {
			return ErrDuplicateTxInputs
		}
		existingTxOut[txIn.PreviousOutPoint] = struct{}{}
	}

	// Coinbase script length must be between min and max length.
	if tx.IsCoinBase() {
		slen := len(tx.Inputs[0].SignatureScript)
		if slen < blockchain.MinCoinbaseScriptLen || slen > blockchain.MaxCoinbaseScriptLen {
			return fmt.Errorf("coinbase transaction script length of %d is out of range (min: %d, max: %d)", slen, blockchain.MinCoinbaseScriptLen, blockchain.MaxCoinbaseScriptLen)
		}
	} else {
		// Previous transaction outputs referenced by the inputs to this
		// transaction must not be null.
		for _, txIn := range tx.Inputs {
			prevOut := &txIn.PreviousOutPoint
			if isNullOutpoint(prevOut) {
				return ErrBadTxInput
			}
		}
	}

	return nil
}

// isNullOutpoint determines whether or not a previous transaction output point
// is set.
func isNullOutpoint(outpoint *wire.OutPoint) bool {
	if outpoint.Index == math.MaxUint32 && outpoint.Hash == zeroHash {
		return true
	}
	return false
}

// IsCoinBase determines whether or not a transaction is a coinbase.  A
// coinbase is a special transaction created by miners that has no inputs.
// This is represented in the block chain by a transaction with a single input
// that has a previous output transaction index set to the maximum value along
// with a zero hash.
func (t *Transaction) IsCoinBase() bool {
	// A coin base must only have one transaction input.
	if len(t.Inputs) != 1 {
		return false
	}

	// The previous output of a coin base must have a max value index and
	// a zero hash.
	prevOut := &t.Inputs[0].PreviousOutPoint
	if prevOut.Index != math.MaxUint32 || prevOut.Hash != zeroHash {
		return false
	}

	return true
}

type countingReader struct {
	io.Reader
	N int64
}

func (c *countingReader) Read(p []byte) (n int, err error) {
	n, err = c.Reader.Read(p)
	c.N += int64(n)
	return n, err
}

type countingWriter struct {
	io.Writer
	N int64
}

func (c *countingWriter) Write(p []byte) (n int, err error) {
	n, err = c.Writer.Write(p)
	c.N += int64(n)
	return n, err
}

type Input struct {
	PreviousOutPoint wire.OutPoint
	SignatureScript  []byte
	Sequence         uint32
}

func (i *Input) ReadFrom(r io.Reader) (int64, error) {
	counter := &countingReader{Reader: r}
	if err := i.readOutPoint(counter); err != nil {
		return counter.N, err
	}
	var err error
	i.SignatureScript, err = readScript(counter, "transaction input signature script")
	if err != nil {
		return counter.N, err
	}
	var sequence uint32
	if err := binary.Read(counter, binary.LittleEndian, &sequence); err != nil {
		return counter.N, err
	}
	i.Sequence = sequence
	return counter.N, nil
}

// readOutPoint reads the next sequence of bytes from r as an OutPoint.
func (i *Input) readOutPoint(r io.Reader) error {
	var txid chainhash.Hash
	if _, err := io.ReadFull(r, txid[:]); err != nil {
		return err
	}
	i.PreviousOutPoint.Hash = txid

	var index uint32
	if err := binary.Read(r, binary.LittleEndian, &index); err != nil {
		return err
	}
	i.PreviousOutPoint.Index = index
	return nil
}

func (i *Input) WriteTo(w io.Writer) (int64, error) {
	counter := &countingWriter{Writer: w}
	if err := i.writeOutPoint(counter); err != nil {
		return counter.N, err
	}
	if err := writeScript(counter, i.SignatureScript); err != nil {
		return counter.N, err
	}
	if err := binary.Write(counter, binary.LittleEndian, uint32(i.Sequence)); err != nil {
		return counter.N, err
	}
	return counter.N, nil
}

// writeOutPoint encodes op to the bitcoin/zcash protocol encoding for an OutPoint
// to w.
func (i *Input) writeOutPoint(w io.Writer) error {
	if _, err := w.Write(i.PreviousOutPoint.Hash[:]); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, i.PreviousOutPoint.Index)
}

type Output struct {
	Value        int64
	ScriptPubKey []byte
}

func (o *Output) ReadFrom(r io.Reader) (int64, error) {
	counter := &countingReader{Reader: r}
	if err := binary.Read(counter, binary.LittleEndian, &o.Value); err != nil {
		return counter.N, err
	}
	var err error
	o.ScriptPubKey, err = readScript(counter, "transaction output public key script")
	return counter.N, err
}

func (o *Output) WriteTo(w io.Writer) (int64, error) {
	counter := &countingWriter{Writer: w}
	if err := binary.Write(counter, binary.LittleEndian, uint64(o.Value)); err != nil {
		return counter.N, err
	}
	err := writeScript(counter, o.ScriptPubKey)
	return counter.N, err
}
