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
	ErrOverwinterTxVersionInvalid             = fmt.Errorf("overwinter transaction version must be 3")
	ErrOverwinterTxUnknownVersionGroupID      = fmt.Errorf("transaction has unknown version group id")
	ErrTxVersionTooSmall                      = fmt.Errorf("transaction version must be greater than 0")
	ErrTxVersionTooLarge                      = fmt.Errorf("transaction version must be less than 3")
	ErrNoTxInputs                             = fmt.Errorf("transaction has no inputs")
	ErrNoTxOutputs                            = fmt.Errorf("transaction has no outputs")
	ErrDuplicateTxInputs                      = fmt.Errorf("transaction contains duplicate inputs")
	ErrBadTxInput                             = fmt.Errorf("transaction input refers to previous output that is null")
	ErrCoinBaseTxMustHaveNoTransparentOutputs = fmt.Errorf("transaction with coinbase input must have no transparent outputs")

	zeroHash chainhash.Hash
)

const (
	NumJoinSplitInputs  = 2
	NumJoinSplitOutputs = 2

	OverwinterFlagMask       uint32 = 0x80000000
	OverwinterVersionMask           = 0x7FFFFFFF
	OverwinterVersionGroupID        = 0x03C48270
)

type Transaction struct {
	IsOverwinter       bool
	Version            uint32
	VersionGroupID     uint32
	Inputs             []Input
	Outputs            []Output
	Timestamp          time.Time
	ExpiryHeight       uint32
	JoinSplits         []JoinSplit
	JoinSplitPubKey    [32]byte
	JoinSplitSignature [64]byte
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

func (t *Transaction) IsEqual(other *Transaction) bool {
	switch {
	case t == nil && other == nil:
		return true
	case t == nil || other == nil:
		return false
	case t.IsOverwinter != other.IsOverwinter:
		return false
	case t.Version != other.Version:
		return false
	case t.VersionGroupID != other.VersionGroupID:
		return false
	case t.Timestamp != other.Timestamp:
		return false
	case t.ExpiryHeight != other.ExpiryHeight:
		return false
	case len(t.Inputs) != len(other.Inputs):
		return false
	case len(t.Outputs) != len(other.Outputs):
		return false
	}
	for i := range t.Inputs {
		if !t.Inputs[i].IsEqual(other.Inputs[i]) {
			return false
		}
	}
	for i := range t.Outputs {
		if !t.Outputs[i].IsEqual(other.Outputs[i]) {
			return false
		}
	}
	return true
}

func (t *Transaction) UnmarshalBinary(data []byte) error {
	_, err := t.ReadFrom(bytes.NewReader(data))
	return err
}

func (t *Transaction) ReadFrom(r io.Reader) (n int64, err error) {
	counter := &countingReader{Reader: r}
	for _, segment := range []func(io.Reader) error{
		t.readVersion,
		t.readVersionGroupID,
		t.readInputs,
		t.readOutputs,
		t.readTimestamp,
		t.readExpiryHeight,
		t.readJoinSplits,
		t.readJoinSplitPubKey,
		t.readJoinSplitSignature,
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
	if err != nil {
		return err
	}
	t.IsOverwinter = (t.Version & OverwinterFlagMask) > 0
	if t.IsOverwinter {
		t.Version = t.Version & OverwinterVersionMask
		if t.Version != 3 {
			return fmt.Errorf("invalid txn version %v", t.Version)
		}
	} else if t.Version < 1 || 2 < t.Version {
		return fmt.Errorf("invalid txn version %v", t.Version)
	}
	return err
}

func (t *Transaction) readVersionGroupID(r io.Reader) error {
	if !t.IsOverwinter {
		return nil
	}
	return binary.Read(r, binary.LittleEndian, &t.VersionGroupID)
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

func (t *Transaction) readTimestamp(r io.Reader) error {
	var timestamp uint32
	if err := binary.Read(r, binary.LittleEndian, &timestamp); err != nil {
		return err
	}
	t.Timestamp = time.Unix(int64(timestamp), 0).UTC()
	return nil
}

func (t *Transaction) readExpiryHeight(r io.Reader) error {
	if !t.IsOverwinter {
		return nil
	}
	return binary.Read(r, binary.LittleEndian, &t.ExpiryHeight)
}

func (t *Transaction) readJoinSplits(r io.Reader) error {
	if t.Version <= 1 {
		return nil
	}
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return err
	}
	for i := uint64(0); i < count; i++ {
		var js JoinSplit
		if _, err := js.ReadFrom(r); err != nil {
			return err
		}
		t.JoinSplits = append(t.JoinSplits, js)
	}
	return nil
}

func (t *Transaction) readJoinSplitPubKey(r io.Reader) error {
	if t.Version <= 1 {
		return nil
	}
	_, err := io.ReadFull(r, t.JoinSplitPubKey[:])
	return err
}

func (t *Transaction) readJoinSplitSignature(r io.Reader) error {
	if t.Version <= 1 {
		return nil
	}
	_, err := io.ReadFull(r, t.JoinSplitSignature[:])
	return err
}

func (t *Transaction) MarshalBinary() ([]byte, error) {
	buf := &bytes.Buffer{}
	if _, err := t.WriteTo(buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (t *Transaction) WriteTo(w io.Writer) (n int64, err error) {
	counter := &countingWriter{Writer: w}
	for _, segment := range []func(io.Writer) error{
		t.writeVersion,
		writeIf(t.IsOverwinter, writeField(t.VersionGroupID)),
		t.writeInputs,
		t.writeOutputs,
		writeField(uint32(t.Timestamp.Unix())),
		writeIf(t.IsOverwinter, writeField(t.ExpiryHeight)),
		t.writeJoinSplits,
		writeIf(t.Version >= 2, writeBytes(t.JoinSplitPubKey[:])),
		writeIf(t.Version >= 2, writeBytes(t.JoinSplitSignature[:])),
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
	var version uint32 = t.Version
	if t.IsOverwinter {
		version |= OverwinterFlagMask
	}
	return binary.Write(w, binary.LittleEndian, version)
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

func (t *Transaction) writeJoinSplits(w io.Writer) error {
	if t.Version <= 1 {
		return nil
	}
	if err := wire.WriteVarInt(w, 0, uint64(len(t.JoinSplits))); err != nil {
		return err
	}
	for _, js := range t.JoinSplits {
		if _, err := js.WriteTo(w); err != nil {
			return err
		}
	}
	return nil
}

func (tx *Transaction) Validate() error {
	if tx.IsOverwinter && tx.Version != 3 {
		return ErrOverwinterTxVersionInvalid
	} else if !tx.IsOverwinter && tx.Version <= 0 {
		return ErrTxVersionTooSmall
	} else if !tx.IsOverwinter && tx.Version >= 3 {
		return ErrTxVersionTooLarge
	}
	if tx.IsOverwinter && tx.VersionGroupID != OverwinterVersionGroupID {
		return ErrOverwinterTxUnknownVersionGroupID
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
		if len(tx.Outputs) > 0 {
			return ErrCoinBaseTxMustHaveNoTransparentOutputs
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

func (i Input) IsEqual(other Input) bool {
	if !outpointsEqual(i.PreviousOutPoint, other.PreviousOutPoint) {
		return false
	}
	if string(i.SignatureScript) != string(other.SignatureScript) {
		return false
	}
	if i.Sequence != other.Sequence {
		return false
	}
	return true
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
	if _, err := io.ReadFull(r, i.PreviousOutPoint.Hash[:]); err != nil {
		return err
	}

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
	if err := writeField(i.Sequence)(counter); err != nil {
		return counter.N, err
	}
	return counter.N, nil
}

func writeScript(w io.Writer, script []byte) error {
	return wire.WriteVarBytes(w, 0, script)
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

func (o Output) IsEqual(other Output) bool {
	if o.Value != other.Value {
		return false
	}
	if string(o.ScriptPubKey) != string(other.ScriptPubKey) {
		return false
	}
	return true
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
	if err := writeField(o.Value)(counter); err != nil {
		return counter.N, err
	}
	err := writeScript(counter, o.ScriptPubKey)
	return counter.N, err
}

type JoinSplit struct {
	// A value v_{pub}^{old} that the JoinSplit transfer removes from the
	// transparent value pool.
	VPubOld uint64

	// A value v_{pub}^{new} that the JoinSplit transfer inserts into the
	// transparent value pool.
	VPubNew uint64

	// A merkle root of the note commitment tree at some block height in the
	// past, or the merkle root produced by a previous JoinSplit transfer in this
	// transaction.
	//
	// JoinSplits are always anchored to a root in the note commitment tree at
	// some point in the blockchain history or in the history of the current
	// transaction.
	Anchor [32]byte

	// A sequence of nullifiers of the input notes $nf$_{1..N^{old}}^{old}
	//
	// Nullifiers are used to prevent double-spends. They are derived from the
	// secrets placed in the note and the secret spend-authority key known by the
	// spender.
	Nullifiers [NumJoinSplitInputs][32]byte

	// A sequence of note commitments for the output notes $cm$_{1..N^{new}}^{new}
	//
	// Note commitments are introduced into the commitment tree, blinding the
	// public about the values and destinations involved in the JoinSplit. The
	// presence of a commitment in the note commitment tree is required to spend
	// it.
	Commitments [NumJoinSplitOutputs][32]byte

	// A Curve25519 public key epk.
	EphemeralKey [32]byte

	// A 256-bit seed that must be chosen independently at random for each
	// JoinSplit description.
	RandomSeed [32]byte

	// A sequence of message authentication tags h_{1..N^{old}} that bind h^{Sig}
	// to each a_{sk} of the JoinSplit description.
	//
	// The verification of the JoinSplit requires these MACs to be provided as an
	// input.
	Macs [NumJoinSplitInputs][32]byte

	// An encoding of the zero-knowledge proof \pi_{ZKJoinSplit}
	//
	// This is a zk-SNARK which ensures that this JoinSplit is valid.
	Proof [296]byte

	// A sequence of ciphertext components for the encrypted output notes,
	// C_{1..N^{new}}^{enc}
	//
	// These contain trapdoors, values and other information that the recipient
	// needs, including a memo field. It is encrypted using the scheme
	// implemented in crypto/NoteEncryption.cpp
	Ciphertexts [NumJoinSplitOutputs][601]byte
}

func (js *JoinSplit) ReadFrom(r io.Reader) (int64, error) {
	counter := &countingReader{Reader: r}
	for _, segment := range []func(io.Reader) error{
		js.readVPubOld,
		js.readVPubNew,
		js.readAnchor,
		js.readNullifiers,
		js.readCommitments,
		js.readEphemeralKey,
		js.readRandomSeed,
		js.readMacs,
		js.readProof,
		js.readCiphertexts,
	} {
		if err := segment(counter); err != nil {
			return counter.N, err
		}
	}
	return counter.N, nil
}

func (js *JoinSplit) readVPubOld(r io.Reader) error {
	return binary.Read(r, binary.LittleEndian, &js.VPubOld)
}

func (js *JoinSplit) readVPubNew(r io.Reader) error {
	return binary.Read(r, binary.LittleEndian, &js.VPubNew)
}

func (js *JoinSplit) readAnchor(r io.Reader) error {
	_, err := io.ReadFull(r, js.Anchor[:])
	return err
}

func (js *JoinSplit) readNullifiers(r io.Reader) error {
	for _, x := range js.Nullifiers {
		if _, err := io.ReadFull(r, x[:]); err != nil {
			return err
		}
	}
	return nil
}

func (js *JoinSplit) readCommitments(r io.Reader) error {
	for _, x := range js.Commitments {
		if _, err := io.ReadFull(r, x[:]); err != nil {
			return err
		}
	}
	return nil
}

func (js *JoinSplit) readEphemeralKey(r io.Reader) error {
	_, err := io.ReadFull(r, js.Anchor[:])
	return err
}

func (js *JoinSplit) readRandomSeed(r io.Reader) error {
	_, err := io.ReadFull(r, js.Anchor[:])
	return err
}

func (js *JoinSplit) readMacs(r io.Reader) error {
	for _, x := range js.Macs {
		if _, err := io.ReadFull(r, x[:]); err != nil {
			return err
		}
	}
	return nil
}

func (js *JoinSplit) readProof(r io.Reader) error {
	_, err := io.ReadFull(r, js.Anchor[:])
	return err
}

func (js *JoinSplit) readCiphertexts(r io.Reader) error {
	for _, x := range js.Ciphertexts {
		if _, err := io.ReadFull(r, x[:]); err != nil {
			return err
		}
	}
	return nil
}

func (js *JoinSplit) WriteTo(w io.Writer) (n int64, err error) {
	counter := &countingWriter{Writer: w}
	for _, segment := range []func(io.Writer) error{
		writeField(js.VPubOld),
		writeField(js.VPubNew),
		writeBytes(js.Anchor[:]),
		writeByteArray32(js.Nullifiers[:]),
		writeByteArray32(js.Commitments[:]),
		writeBytes(js.EphemeralKey[:]),
		writeBytes(js.RandomSeed[:]),
		writeByteArray32(js.Macs[:]),
		writeBytes(js.Proof[:]),
		js.writeCiphertexts,
	} {
		if err := segment(counter); err != nil {
			return counter.N, err
		}
	}
	return counter.N, nil
}

// writeCiphertexts is needed because ciphertexts is an odd size (not 32
// bytes). We could probably eliminate this with some type inference magic,
// but...
func (js *JoinSplit) writeCiphertexts(w io.Writer) error {
	for _, x := range js.Ciphertexts {
		if _, err := w.Write(x[:]); err != nil {
			return err
		}
	}
	return nil
}

func writeIf(pred bool, f func(w io.Writer) error) func(w io.Writer) error {
	if pred {
		return f
	}
	return func(w io.Writer) error { return nil }
}

func writeField(v interface{}) func(w io.Writer) error {
	return func(w io.Writer) error {
		return binary.Write(w, binary.LittleEndian, v)
	}
}

func writeBytes(v []byte) func(w io.Writer) error {
	return func(w io.Writer) error {
		_, err := w.Write(v)
		return err
	}
}

func writeByteArray32(v [][32]byte) func(w io.Writer) error {
	return func(w io.Writer) error {
		for _, x := range v {
			_, err := w.Write(x[:])
			return err
		}
		return nil
	}
}
