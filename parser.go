package btcbf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// BtcBlockIndexRecord contains index records parameters specitic to BTC
const (
	blockHaveData = 8  //!< full block available in blk*.dat
	blockHaveUndo = 16 //!< undo data available in rev*.dat

	txP2pkh    = 0x01
	txP2sh     = 0x02
	txP2pk     = 0x03
	txMultisig = 0x04
	txP2wpkh   = 0x05
	txP2wsh    = 0x06 // bench32

	txOpreturn = 0x10 // Should contain data and not public key
	txParseErr = 0xfe
	txUnknown  = 0xff

	op0  = 0x00
	op1  = 0x51 // 1 is pushed
	op16 = 0x60

	opDup       = 0x76
	opHash160   = 0xA9
	opChecksig  = 0xAC
	opPushdata1 = 0x4C // Next byte contains the number of bytes to be pushed onto the stack
	opPushdata2 = 0x4D // Next 2 bytes contain the number of bytes to be pushed (little endian)
	opPushdata4 = 0x4E // Next 4 bytes contain the number of bytes to be pushed (little endian)

	opEqual       = 0x87 // Returns 1 if the inputs are exactly equal, 0 otherwise
	opEqualverify = 0x88

	opReturn = 0x6A

	btcEckeyUncompressedLength = 65
	btcEckeyCompressedLength   = 33
	sha256DigestLength         = 32

	// BTC_ECKEY_PKEY_LENGTH = 32
	// BTC_HASH_LENGTH = 32
)

// Reader is an interface used to decode blocks and transactions
// it allows to apply the same functions to files and buffers
type Reader interface {
	Type() string
	Peek(int) ([]byte, error)
	Seek(int64, int) (int64, error)
	Reset()
	ReadByte() (byte, error)
	ReadBytes(uint64) []byte
	ReadUint32() uint32
	ReadUint64() uint64
	ReadInt32() int32
	ReadVarint() uint64
	ReadCompactSize() uint64

	ReadUint16() uint16
	Close()
}

// File allows to use the Reader interface when reading a file
type File struct {
	f     *os.File
	NFile uint32 // file number
}

// Buffer allows to use the Reader interface when storing data in memory
type Buffer struct {
	b   []byte
	pos uint64
}

// NewReader allows to declare a new Reader interface from a file or from raw data
func (db *database) NewReader(x interface{}) (Reader, error) {
	switch x := x.(type) {
	case []byte:
		return &Buffer{x, 0}, nil
	case uint32:
		filepath := fmt.Sprintf("%s/blocks/blk%05d.dat", db.dataDir, x)
		file, err := os.OpenFile(filepath, os.O_RDONLY, 0666)
		if err != nil {
			return nil, err
		}
		return &File{f: file, NFile: x}, nil
	default:
		return nil, fmt.Errorf("parser.New(): Unrecognized input type")
	}
}

// CompactSize convert an int to a series of 1 to 8 bytes
// Used for scriptLength, NVin, NVout, witnessCount
func CompactSize(n uint64) []byte {
	if n > 0xFFFFFFFE {
		val := make([]byte, 8)
		binary.LittleEndian.PutUint64(val, n)
		return append([]byte{0xFF}, val...)
	} else if n > 0xFFFE {
		val := make([]byte, 4)
		binary.LittleEndian.PutUint32(val, uint32(n))
		return append([]byte{0xFE}, val...)
	} else if n > 0xFC {
		val := make([]byte, 2)
		binary.LittleEndian.PutUint16(val, uint16(n))
		return append([]byte{0xFD}, val...)
	}
	return []byte{byte(n)}
}

// Type returns "file"
func (file *File) Type() string {
	return "file"
}

// Close file
func (file *File) Close() {
	file.f.Close()
}

// Reset sets cursor's position to 0
func (file *File) Reset() {
	// TODO: To implement
}

// Seek moves cursor's position to offset
func (file *File) Seek(offset int64, whence int) (int64, error) {
	return file.f.Seek(offset, whence)
}

// Size returns the size of a file
func (file *File) Size() (int64, error) {
	fInfo, err := file.f.Stat()
	if err != nil {
		return 0, err
	}
	return fInfo.Size(), err
}

// Peek read length bytes without moving cursor
func (file *File) Peek(length int) ([]byte, error) {
	pos, err := file.Seek(0, 1)
	if err != nil {
		return nil, err
	}
	val := make([]byte, length)
	file.f.Read(val)
	_, err = file.Seek(pos, 0)
	if err != nil {
		return nil, err
	}
	return val, nil
}

// ReadByte reads next one byte of data
func (file *File) ReadByte() (byte, error) {
	val := make([]byte, 1)
	file.f.Read(val)
	return val[0], nil
}

// ReadBytes reads next length bytes of data
func (file *File) ReadBytes(length uint64) []byte {
	val := make([]byte, length)
	file.f.Read(val)
	return val
}

// ReadUint16 reads next 4 bytes of data as uint16, LE
func (file *File) ReadUint16() uint16 {
	val := make([]byte, 2)
	file.f.Read(val)
	return binary.LittleEndian.Uint16(val)
}

// ReadInt32 reads next 8 bytes of data as int32, LE
func (file *File) ReadInt32() int32 {
	raw := make([]byte, 4)
	file.f.Read(raw)
	var val int32
	binary.Read(bytes.NewReader(raw), binary.LittleEndian, &val)
	return val
}

// ReadUint32 reads next 8 bytes of data as uint32, LE
func (file *File) ReadUint32() uint32 {
	val := make([]byte, 4)
	file.f.Read(val)
	return binary.LittleEndian.Uint32(val)
}

// ReadInt64 reads next 16 bytes of data as int64, LE
func (file *File) ReadInt64() int64 {
	raw := make([]byte, 8)
	file.f.Read(raw)
	var val int64
	binary.Read(bytes.NewReader(raw), binary.LittleEndian, &val)
	return val
}

// ReadUint64 reads next 16 bytes of data as uint64, LE
func (file *File) ReadUint64() uint64 {
	val := make([]byte, 8)
	file.f.Read(val)
	return binary.LittleEndian.Uint64(val)
}

// ReadCompactSize reads N byte of data as uint64, LE.
// N depends on the first byte
func (file *File) ReadCompactSize() uint64 {
	intType, _ := file.ReadByte() // TODO: Error handling
	if intType == 0xFF {
		return file.ReadUint64()
	} else if intType == 0xFE {
		return uint64(file.ReadUint32())
	} else if intType == 0xFD {
		return uint64(file.ReadUint16())
	}
	return uint64(intType)
}

// ReadVarint does not work for file
// TODO: Implement it
func (file *File) ReadVarint() uint64 {
	return 0xFFFFFF
}

// Type returns type of reader
func (buf *Buffer) Type() string {
	return "buffer"
}

// Reset cursor to position 0
func (buf *Buffer) Reset() {
	buf.pos = 0
}

// Close buffer
// TODO: Is it relevant for Buffer?
func (buf *Buffer) Close() {
}

// Peek up to length without moving cursor
func (buf *Buffer) Peek(length int) ([]byte, error) {
	return buf.b[buf.pos:(buf.pos + uint64(length))], nil
}

// Seek moves cursor tu position pos
func (buf *Buffer) Seek(pos int64, whence int) (int64, error) {
	switch whence {
	case 0:
		buf.pos = uint64(pos)
	case 1:
		buf.pos += uint64(pos)
		// TODO: case 2
	}
	return pos, nil
}

// ReadByte reads next one byte of data
func (buf *Buffer) ReadByte() (byte, error) {
	val := buf.b[buf.pos : buf.pos+1]
	buf.pos++
	return val[0], nil
}

// ReadBytes reads next length bytes of data
func (buf *Buffer) ReadBytes(length uint64) []byte {
	val := buf.b[buf.pos : buf.pos+length]
	buf.pos += length
	return val
}

// ReadUint16 reads next 4 bytes of data as uint16, LE
func (buf *Buffer) ReadUint16() uint16 {
	val := binary.LittleEndian.Uint16(buf.b[buf.pos : buf.pos+2])
	buf.pos += 2
	return val
}

// ReadInt32 reads next 8 bytes of data as int32, LE
func (buf *Buffer) ReadInt32() int32 {
	val := binary.LittleEndian.Uint32(buf.b[buf.pos : buf.pos+4])
	buf.pos += 4
	return int32(val)
}

// ReadUint32 reads next 8 bytes of data as uint32, LE
func (buf *Buffer) ReadUint32() uint32 {
	val := binary.LittleEndian.Uint32(buf.b[buf.pos : buf.pos+4])
	buf.pos += 4
	return val
}

// ReadInt64 reads next 16 bytes of data as int64, LE
func (buf *Buffer) ReadInt64() int64 {
	val := binary.LittleEndian.Uint64(buf.b[buf.pos : buf.pos+8])
	buf.pos += 8
	return int64(val)
}

// ReadUint64 reads next 16 bytes of data as uint64, LE
func (buf *Buffer) ReadUint64() uint64 {
	val := binary.LittleEndian.Uint64(buf.b[buf.pos : buf.pos+8])
	buf.pos += 8
	return val
}

// ReadCompactSize reads N byte of data as uint64, LE.
// N depends on the first byte
func (buf *Buffer) ReadCompactSize() uint64 {
	intType, _ := buf.ReadByte() // TODO: Error handling
	if intType == 0xFF {
		return buf.ReadUint64()
	} else if intType == 0xFE {
		return uint64(buf.ReadUint32())
	} else if intType == 0xFD {
		return uint64(buf.ReadUint16())
	}

	return uint64(intType)
}

// ReadVarint reads N byte of data as uint64, LE.
// N depends on the first byte
func (buf *Buffer) ReadVarint() uint64 {
	var n uint64
	for {
		b := buf.b[buf.pos : buf.pos+1][0]
		buf.pos++
		n = (n << uint64(7)) | uint64(b&uint8(0x7F))
		if b&uint8(0x80) > 0 {
			n++
		} else {
			return n
		}
	}
}

// TxInput holds tx inputs
type TxInput struct {
	Hash          Hash   `db:"hash"`     // Hash previous tx
	Index         uint32 `db:"index"`    // Output previous tx
	Script        []byte `db:"script"`   // Useless?
	Sequence      uint32 `db:"sequence"` // Always 0xFFFFFFFF
	ScriptWitness [][]byte
}

// TxOutput holds tx outputs
type TxOutput struct {
	Index  uint32 `db:"index"` // Output index
	Value  uint64 `db:"value"` // Satoshis
	Pkey   []byte `db:"addr"`
	Type   uint8
	Script []byte `db:"script"` // Where the magic happens
}

// Tx holds transaction
type Tx struct {
	NVersion int32  `db:"n_version"` // Always 1 or 2
	Hash     Hash   `db:"tx_hash"`   // Transaction hash (computed)
	NVin     uint32 `db:"n_vin"`     // Number of inputs
	NVout    uint32 `db:"n_vout"`    // Number of outputs
	Vin      []TxInput
	Vout     []TxOutput
	Locktime uint32 `db:"locktime"`
	Segwit   bool
}

type Hash []byte

func (h Hash) String() string {
	x, _ := chainhash.NewHash(h)
	return x.String()
}

// BlockHeader contains general index records parameters
// It defines the structure of the postgres table
type BlockHeader struct {
	NVersion       uint32 `db:"n_version"`        // Version
	NHeight        uint32 `db:"n_height"`         //
	NStatus        uint32 `db:"n_status"`         // ???
	NTx            uint32 `db:"n_tx"`             // Number of txs
	NFile          uint32 `db:"n_file"`           // File number
	NDataPos       uint32 `db:"n_data_pos"`       // (Index)
	NUndoPos       uint32 `db:"n_undo_pos"`       // (Index)
	Hash           Hash   `db:"hash_block"`       // current block hash (Added)
	HashPrev       Hash   `db:"hash_prev_block"`  // previous block hash (Index)
	HashMerkleRoot Hash   `db:"hash_merkle_root"` //
	NTime          uint32 `db:"n_time"`           // (Index)
	NBits          uint32 `db:"n_bits"`           // (Index)
	NNonce         uint32 `db:"n_nonce"`          // (Index)
	NSize          uint32 `db:"n_size"`           // Block size
}

// Block contains block infos
type Block struct {
	BlockHeader
	Txs []Tx
}
