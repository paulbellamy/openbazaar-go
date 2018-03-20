package zcash

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/OpenBazaar/multiwallet/client"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

type Transaction struct {
	Version   uint32
	Inputs    []Input
	Outputs   []client.Output
	Timestamp time.Time
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
		fmt.Printf("[DEBUG] Read input: %v\n", input)
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
		// TODO: Parse input
		txOut, err := readTxOut(r)
		if err != nil {
			return err
		}
		t.Outputs = append(t.Outputs, client.Output{
			Value: float64(txOut.Value) / 1e8, // TODO: STOP USING FLOATS. ARGH! Insight api is rife with this crap.
			ScriptPubKey: client.OutScript{
				Script: client.Script{
					Hex: hex.EncodeToString(txOut.PkScript),
				},
			},
		})
	}
	return nil
}

// readTxOut is based on wire.readTxOut
func readTxOut(r io.Reader) (txOut wire.TxOut, err error) {
	if err := binary.Read(r, binary.LittleEndian, &txOut.Value); err != nil {
		return txOut, err
	}

	txOut.PkScript, err = readScript(r, wire.MaxMessagePayload, "transaction output public key script")
	return txOut, err
}

// readScript reads a variable length byte array that represents a transaction
// script.  It is encoded as a varInt containing the length of the array
// followed by the bytes themselves.  An error is returned if the length is
// greater than the passed maxAllowed parameter which helps protect against
// memory exhuastion attacks and forced panics thorugh malformed messages.  The
// fieldName parameter is only used for the error message so it provides more
// context in the error.
func readScript(r io.Reader, maxAllowed uint32, fieldName string) ([]byte, error) {
	count, err := wire.ReadVarInt(r, 0)
	if err != nil {
		return nil, err
	}

	// Prevent byte array larger than the max message size.  It would
	// be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > uint64(maxAllowed) {
		return nil, fmt.Errorf(
			"readScript: %s is larger than the max allowed size [count %d, max %d]",
			fieldName, count, maxAllowed,
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
		script, err := hex.DecodeString(output.ScriptPubKey.Hex)
		if err != nil {
			return err
		}
		txout := &wire.TxOut{
			Value:    int64(output.Value * 1e8), // TODO: STOP USING FLOATS. ARGH! Insight api is rife with this crap.
			PkScript: script,                    // TODO: What do we put here?
		}
		if err := wire.WriteTxOut(w, 0, 0, txout); err != nil {
			return err
		}
	}
	return nil
}

func (t *Transaction) writeTimestamp(w io.Writer) error {
	return binary.Write(w, binary.LittleEndian, uint32(t.Timestamp.Unix()))
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
	Txid            string      `json:"txid"`
	Vout            int         `json:"vout"`
	Sequence        int         `json:"sequence"`
	N               int         `json:"n"`
	ScriptSig       Script      `json:"scriptSig"`
	Addr            string      `json:"addr"`
	Satoshis        int64       `json:"valueSat"`
	ValueIface      interface{} `json:"value"`
	Value           float64
	DoubleSpentTxid string `json:"doubleSpentTxID"`
}

func (i *Input) ReadFrom(r io.Reader) (int64, error) {
	counter := &countingReader{Reader: r}
	if err := i.readOutPoint(counter); err != nil {
		return counter.N, err
	}
	if _, err := i.ScriptSig.ReadFrom(counter); err != nil {
		return counter.N, err
	}
	var n uint32
	if err := binary.Read(counter, binary.LittleEndian, &n); err != nil {
		return counter.N, err
	}
	i.N = int(n)
	return counter.N, nil
}

// readOutPoint reads the next sequence of bytes from r as an OutPoint.
func (i *Input) readOutPoint(r io.Reader) error {
	var txid chainhash.Hash
	if _, err := io.ReadFull(r, txid[:]); err != nil {
		return err
	}
	i.Txid = txid.String()

	var vout uint32
	if err := binary.Read(r, binary.LittleEndian, &vout); err != nil {
		return err
	}
	i.Vout = int(vout)
	return nil
}

func (i *Input) WriteTo(w io.Writer) (int64, error) {
	counter := &countingWriter{Writer: w}
	if err := i.writeOutPoint(counter); err != nil {
		return counter.N, err
	}
	if _, err := i.ScriptSig.WriteTo(counter); err != nil {
		return counter.N, err
	}
	if err := binary.Write(counter, binary.LittleEndian, uint32(i.N)); err != nil {
		return counter.N, err
	}
	return counter.N, nil
}

// writeOutPoint encodes op to the bitcoin/zcash protocol encoding for an OutPoint
// to w.
func (i *Input) writeOutPoint(w io.Writer) error {
	hash, err := chainhash.NewHashFromStr(i.Txid)
	if err != nil {
		return err
	}
	if _, err := w.Write(hash[:]); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, uint32(i.Vout))
}

type Script struct {
	Hex string `json:"hex"`
	Asm string `json:"asm"`
}

func (s *Script) ReadFrom(r io.Reader) (n int64, err error) {
	counter := &countingReader{Reader: r}
	raw, err := readScript(counter, wire.MaxMessagePayload, "transaction input signature script")
	if err != nil {
		return counter.N, err
	}
	s.Hex = hex.EncodeToString(raw) // TODO: Is raw hex or asm???
	return counter.N, nil
}

func (s *Script) WriteTo(w io.Writer) (int64, error) {
	b, err := hex.DecodeString(s.Hex)
	if err != nil {
		return 0, err
	}
	counter := &countingWriter{Writer: w}
	if err := wire.WriteVarBytes(counter, 0, b); err != nil {
		return counter.N, err
	}
	return counter.N, err
}
