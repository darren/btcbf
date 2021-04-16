package btcbf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
	"github.com/syndtr/goleveldb/leveldb/util"
	"golang.org/x/crypto/ripemd160"
)

type DB interface {
	LoadBlock(int64) (*Block, error)
	LoadBlockHash(Hash) (*Block, error)
	FindBlockRange(from, to int64) (int64, int64, error)
}

type database struct {
	idx     map[uint32]*BlockHeader
	dataDir string
}

// NewDB loads bitcoin database directory
// dataDir should contains blocks folder
// typically is under $HOME/.bitcoin
func NewDB(dataDir string) (DB, error) {
	db := &database{
		dataDir: dataDir,
	}

	err := db.LoadHeaderIndex(db.dataDir)
	return db, err
}

// LoadBlock loads block at specific height
func (db *database) LoadBlock(height int64) (*Block, error) {
	bh, ok := db.idx[uint32(height)]
	if !ok {
		return nil, fmt.Errorf("LoadBlock(): File for height %d does not exist", height)
	}

	if bh.NHeight != uint32(height) {
		return nil, fmt.Errorf("LoadBlock(): Loaded header has wrong height %d != %d", bh.NHeight, height)
	}

	file, err := db.NewReader(bh.NFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	file.Seek(int64(bh.NDataPos-8), 0)

	b, err := decodeBlock(file)
	if err != nil {
		return nil, fmt.Errorf("LoadBlock(): Height %d: %s", height, err.Error())
	}
	b.NHeight = uint32(height) // FIXME: DecodeBlock does not work for genesis block

	return b, nil
}

// LoadBlock loads block at specific block hash
func (db *database) LoadBlockHash(h Hash) (*Block, error) {
	for height, bhash := range db.idx {
		if bytes.Equal(h, bhash.Hash) {
			return db.LoadBlock(int64(height))
		}
	}

	return nil, fmt.Errorf("LoadBlockHash(): File for hash %s does not exist", h)
}

var ErrBlockRangeNotFound = errors.New("block not found")

// FindBlock loads block height whose blocktime between start and end
func (db *database) FindBlockRange(start, end int64) (int64, int64, error) {
	var err error
	hStart := int64(1 << 62)
	hEnd := int64(0)

	for height, header := range db.idx {
		h := int64(height)
		if header.NTime >= uint32(start) && header.NTime <= uint32(end) {
			if hStart > h {
				hStart = h
			}
			if hEnd < h {
				hEnd = h
			}
		}
	}
	if hEnd == 0 {
		return 0, 0, ErrBlockRangeNotFound
	}

	return hStart, hEnd, err
}

// decode block header from index files
func decodeBlockHeaderIdx(br Reader) *BlockHeader {
	bh := new(BlockHeader)

	br.ReadVarint() // SerGetHash = 1 << 2 (client version)

	bh.NHeight = uint32(br.ReadVarint())
	bh.NStatus = uint32(br.ReadVarint())
	bh.NTx = uint32(br.ReadVarint())
	if bh.NStatus&(blockHaveData|blockHaveUndo) == 0 {
		return nil
	}
	bh.NFile = uint32(br.ReadVarint())
	if bh.NStatus&blockHaveData > 0 {
		bh.NDataPos = uint32(br.ReadVarint())
	}
	if bh.NStatus&blockHaveUndo > 0 {
		bh.NUndoPos = uint32(br.ReadVarint())
	}

	decodeBlockHeader(bh, br)
	return bh
}

// LoadHeaderIndex constructs a map of the form map[BlockHeight] = BlockHeader.
// In particular, BlockHeader contains DataPos and FileNum
func (db *database) LoadHeaderIndex(dir string) (err error) {
	ldb, err := leveldb.OpenFile(dir+"/blocks/index", &opt.Options{
		ReadOnly: true,
	})
	if err != nil {
		return err
	}

	defer ldb.Close()
	iter := ldb.NewIterator(util.BytesPrefix([]byte("b")), nil)
	defer iter.Release()

	db.idx = make(map[uint32]*BlockHeader)
	for iter.Next() {
		blockHash := iter.Key()[1:]
		data := iter.Value()
		buf, err := db.NewReader(data)
		if err != nil {
			return err
		}
		tmp := decodeBlockHeaderIdx(buf)
		if tmp == nil {
			continue
		}
		if !bytes.Equal(blockHash, tmp.Hash) {
			return fmt.Errorf("LoadHeaderIndex: %x != %x (h: %d, len: %d %d)",
				tmp.Hash, blockHash,
				tmp.NHeight,
				len(tmp.Hash), len(blockHash))
		}
		v, exist := db.idx[tmp.NHeight]
		/*
			if exist {
				fmt.Printf("Height %d: Header Index already exists %b vs %b (%x, %x)\n", tmp.NHeight, v.NStatus, tmp.NStatus, v.Hash, tmp.Hash)
			}
		*/
		if !exist || tmp.NStatus > v.NStatus {
			db.idx[tmp.NHeight] = tmp
		}
	}

	return nil
}

const (
	blockMagicID = 0xd9b4bef9
	serGetHash   = 1 << 2
)

func putBlockHash(b *BlockHeader) {
	bin := make([]byte, 0) // TODO: Optimize. 4 + 4 + 4 + 8 + 4 + 4

	value := make([]byte, 4)
	binary.LittleEndian.PutUint32(value, b.NVersion) // 4
	bin = append(bin, value...)

	bin = append(bin, b.HashPrev...)       // ?
	bin = append(bin, b.HashMerkleRoot...) // ?

	binary.LittleEndian.PutUint32(value, b.NTime) // 4
	bin = append(bin, value...)

	binary.LittleEndian.PutUint32(value, b.NBits) // 4
	bin = append(bin, value...)

	binary.LittleEndian.PutUint32(value, b.NNonce) // 4
	bin = append(bin, value...)

	b.Hash = DoubleSha256(bin)
}

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// DoubleSha256 applies Sha256 twice
func DoubleSha256(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), sha256.New())
}

// Hash160 calculates the hash ripemd160(sha256(b)).
func Hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

// Hash160ToAddress p2pkh
func Hash160ToAddress(hash160 []byte, prefix []byte) string {
	b := append(prefix, hash160...)
	chksum := DoubleSha256(b)[:4]
	b = append(b, chksum...)

	return EncodeBase58(b)
}

var b58 = [256]byte{
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 0, 1, 2, 3, 4, 5, 6,
	7, 8, 255, 255, 255, 255, 255, 255,
	255, 9, 10, 11, 12, 13, 14, 15,
	16, 255, 17, 18, 19, 20, 21, 255,
	22, 23, 24, 25, 26, 27, 28, 29,
	30, 31, 32, 255, 255, 255, 255, 255,
	255, 33, 34, 35, 36, 37, 38, 39,
	40, 41, 42, 43, 255, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54,
	55, 56, 57, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
	255, 255, 255, 255, 255, 255, 255, 255,
}

var bigRadix = big.NewInt(58)
var bigZero = big.NewInt(0)

// DecodeBase58 decodes a modified base58 string to a byte slice.
func DecodeBase58(b string) []byte {
	answer := big.NewInt(0)
	j := big.NewInt(1)

	scratch := new(big.Int)
	for i := len(b) - 1; i >= 0; i-- {
		tmp := b58[b[i]]
		if tmp == 255 {
			return []byte("")
		}
		scratch.SetInt64(int64(tmp))
		scratch.Mul(j, scratch)
		answer.Add(answer, scratch)
		j.Mul(j, bigRadix)
	}

	tmpval := answer.Bytes()

	var numZeros int
	for numZeros = 0; numZeros < len(b); numZeros++ {
		if b[numZeros] != alphabetIdx0 {
			break
		}
	}
	flen := numZeros + len(tmpval)
	val := make([]byte, flen)
	copy(val[numZeros:], tmpval)

	return val
}

const (
	alphabet     = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	alphabetIdx0 = '1'
)

// EncodeBase58 encodes a byte slice to a modified base58 string.
func EncodeBase58(b []byte) string {
	x := new(big.Int)
	x.SetBytes(b)

	answer := make([]byte, 0, len(b)*136/100)
	for x.Cmp(bigZero) > 0 {
		mod := new(big.Int)
		x.DivMod(x, bigRadix, mod)
		answer = append(answer, alphabet[mod.Int64()])
	}

	// leading zero bytes
	for _, i := range b {
		if i != 0 {
			break
		}
		answer = append(answer, alphabetIdx0)
	}

	// reverse
	alen := len(answer)
	for i := 0; i < alen/2; i++ {
		answer[i], answer[alen-1-i] = answer[alen-1-i], answer[i]
	}

	return string(answer)
}

// p2psh p2wpkh

// TODO: Currently won't return any error
func decodeBlockHeader(bh *BlockHeader, br Reader) {
	bh.NVersion = br.ReadUint32()
	bh.HashPrev = br.ReadBytes(32) // FIXME: Slice out of bound (in production)
	bh.HashMerkleRoot = br.ReadBytes(32)
	bh.NTime = br.ReadUint32()
	bh.NBits = br.ReadUint32() // TODO: Parse this as mantissa?
	bh.NNonce = br.ReadUint32()
	putBlockHash(bh)
}

func decodeBlockTxs(b *Block, br Reader) error {
	b.Txs = nil

	b.NTx = uint32(br.ReadCompactSize()) // TODO: Move outside of blockHeader?
	b.Txs = make([]Tx, b.NTx)
	for t := uint32(0); t < b.NTx; t++ {
		tx, err := DecodeTx(br)
		if err != nil {
			return err
		}
		tx.NVout = uint32(len(tx.Vout))
		b.Txs[t] = *tx
	}
	return nil
}

// decodeBlock decodes a block
func decodeBlock(br Reader) (b *Block, err error) {
	b = &Block{}
	if br.Type() == "file" {
		magicID := uint32(br.ReadUint32())
		if magicID == 0 {
			return nil, fmt.Errorf("DecodeBlock: EOF")
		} else if magicID != blockMagicID {
			// blockFile.Seek(curPos, 0) // Restore pos before the error
			return nil, fmt.Errorf("invalid block header: Can't find Magic ID")
		}
		b.NSize = br.ReadUint32() // Only for block files
	}

	decodeBlockHeader(&b.BlockHeader, br)
	decodeBlockTxs(b, br)

	if b.NHeight == 0 && len(b.Txs[0].Vin[0].Script) > 4 {
		cbase := b.Txs[0].Vin[0].Script[0:5]
		if cbase[0] == 3 {
			cbase[4] = 0
		}
		b.NHeight = binary.LittleEndian.Uint32(cbase[1:])
	}
	return b, err
}

// Witness : https://github.com/bitcoin/bitcoin/blob/master/src/primitives/transaction.h
// const serializeTransactionNoWitness = 0x40000000;

// DecodeTx decodes a transaction
func DecodeTx(br Reader) (*Tx, error) {
	var txFlag byte // Check for extended transaction serialization format
	emptyByte := make([]byte, 32)
	allowWitness := true // TODO: Port code - !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);
	tx := &Tx{}

	tx.NVersion = br.ReadInt32()
	tx.NVin = uint32(br.ReadCompactSize())
	if tx.NVin == 0 { // We are dealing with extended transaction (witness format)
		txFlag, _ = br.ReadByte() // TODO: Error handling
		if txFlag != 0x01 {       // Must be 1, other flags may be supported in the future
			return nil, fmt.Errorf("witness tx but flag is %x != 0x01", txFlag)
		}
		tx.NVin = uint32(br.ReadCompactSize())
	}

	tx.Vin = make([]TxInput, tx.NVin)
	for i := uint32(0); i < tx.NVin; i++ {
		input := TxInput{}
		input.Hash = br.ReadBytes(32)                                         // Transaction hash in a prev transaction
		input.Index = br.ReadUint32()                                         // Transaction index in a prev tx TODO: Not sure if correctly read
		if input.Index == 0xFFFFFFFF && !bytes.Equal(input.Hash, emptyByte) { // block-reward case
			return nil, fmt.Errorf("if Index is 0xFFFFFFFF, then Hash should be nil. Input: %d, Hash: %x", input.Index, input.Hash)
		}
		scriptLength := br.ReadCompactSize()
		input.Script = br.ReadBytes(scriptLength)
		input.Sequence = br.ReadUint32()
		tx.Vin[i] = input
	}

	tx.NVout = uint32(br.ReadCompactSize())
	tx.Vout = make([]TxOutput, tx.NVout)
	for i := uint32(0); i < tx.NVout; i++ {
		output := TxOutput{}
		output.Index = i
		output.Value = br.ReadUint64()
		scriptLength := br.ReadCompactSize()
		output.Script = br.ReadBytes(scriptLength)
		output.Type, output.Pkey = getPkeyFromScript(output.Script)
		tx.Vout[i] = output
	}

	if (txFlag&1) == 1 && allowWitness {
		// txFlag ^= 1 // Not sure what this is for
		tx.Segwit = true
		for i := uint32(0); i < tx.NVin; i++ {
			witnessCount := br.ReadCompactSize()
			tx.Vin[i].ScriptWitness = make([][]byte, witnessCount)
			for j := uint64(0); j < witnessCount; j++ {
				length := br.ReadCompactSize()
				tx.Vin[i].ScriptWitness[j] = br.ReadBytes(length)
			}
		}
	} // TODO: Missing 0 field?

	tx.Locktime = br.ReadUint32()
	putTxHash(tx)
	return tx, nil
}

func getInputBinary(in TxInput) []byte {
	bin := make([]byte, 0)
	bin = append(bin, in.Hash...)

	index := make([]byte, 4)
	binary.LittleEndian.PutUint32(index, uint32(in.Index))
	bin = append(bin, index...)

	scriptLength := CompactSize(uint64(len(in.Script)))
	bin = append(bin, scriptLength...)

	bin = append(bin, in.Script...)

	sequence := make([]byte, 4)
	binary.LittleEndian.PutUint32(sequence, uint32(in.Sequence))
	bin = append(bin, sequence...)

	return bin
}

func getOutputBinary(out TxOutput) []byte {
	bin := make([]byte, 0)

	value := make([]byte, 8)
	binary.LittleEndian.PutUint64(value, uint64(out.Value))
	bin = append(bin, value...)

	scriptLength := CompactSize(uint64(len(out.Script)))
	bin = append(bin, scriptLength...)

	bin = append(bin, out.Script...)

	return bin
}

// 0100000001e507cb947464fc74540a9c197f815aa283ba9db74185ac08449c38491a8c34ac00000000
// Compute transaction hash ( [nVersion][Inputs][Outputs][nLockTime] )
func putTxHash(tx *Tx) {
	bin := make([]byte, 0)
	version := make([]byte, 4)
	binary.LittleEndian.PutUint32(version, uint32(tx.NVersion))
	bin = append(bin, version...)

	vinLength := CompactSize(uint64(tx.NVin))
	bin = append(bin, vinLength...)
	for _, in := range tx.Vin {
		bin = append(bin, getInputBinary(in)...)
	}

	voutLength := CompactSize(uint64(tx.NVout))
	bin = append(bin, voutLength...)
	for _, out := range tx.Vout {
		bin = append(bin, getOutputBinary(out)...)
	}

	locktime := make([]byte, 4)
	binary.LittleEndian.PutUint32(locktime, tx.Locktime)
	bin = append(bin, locktime...)

	tx.Hash = DoubleSha256(bin)
}

// Check if OP is a PubkeyHash (length == 20)
func isOpPubkeyhash(op []byte) bool {
	// TODO: OP_PUSHDATA4
	return len(op) == 20
}

func isOpPubkey(op []byte) bool {
	// TODO: OP_PUSHDATA4
	dataLength := len(op)
	if dataLength != btcEckeyCompressedLength && dataLength != btcEckeyUncompressedLength {
		return false
	}
	return true
}

// P2PKH
func scriptIsPubkeyHash(ops [][]byte) []byte {
	if len(ops) == 5 {
		if ops[0][0] == opDup &&
			ops[1][0] == opHash160 &&
			isOpPubkeyhash(ops[2]) &&
			ops[3][0] == opEqualverify &&
			ops[4][0] == opChecksig {
			return ops[2]
		}
	}
	return nil
}

// P2SH
func scriptIsScriptHash(ops [][]byte) []byte {
	if len(ops) == 3 {
		if ops[0][0] == opHash160 &&
			isOpPubkeyhash(ops[1]) &&
			ops[2][0] == opEqual {
			return ops[1]
		}
	}
	return nil
}

// P2PK
func scriptIsPubkey(ops [][]byte) []byte {
	if len(ops) == 2 {
		if ops[1][0] == opChecksig && isOpPubkey(ops[0]) {
			return Hash160(ops[0])
		}
	}
	return nil
}

func scriptIsMultiSig(ops [][]byte) []byte {
	opLength := len(ops)
	if opLength < 3 || opLength > (16+3) {
		return nil
	}
	return nil
}

func scriptIsOpReturn(ops [][]byte) []byte {
	if len(ops) == 2 && ops[0][0] == opReturn && len(ops[1]) <= 20 {
		return ops[1]
	}
	return nil
}

// TODO: Improve
// A witness program is any valid script that consists of a 1-byte push opcode
// followed by a data push between 2 and 40 bytes
func scriptIsWitnessProgram(ops [][]byte) bool {
	if len(ops) != 2 {
		return false
	}
	if ops[0][0] != op0 && (ops[0][0] < op1 || ops[0][0] > op16) {
		return false
	}
	return true
}

// segwitAddrDecode decodes hrp(human-readable part) Segwit Address(string), returns version(int) and data(bytes array) / or error
func segwitAddrDecode(hrp, addr string) (byte, []byte, error) {
	dechrp, data, err := bech32.Decode(addr)
	if err != nil {
		return 0, nil, err
	}
	if dechrp != hrp {
		return 0, nil, fmt.Errorf("invalid human-readable part : %s != %s", hrp, dechrp)
	}
	if len(data) < 1 {
		return 0, nil, fmt.Errorf("invalid decode data length : %d", len(data))
	}
	if data[0] > 16 {
		return 0, nil, fmt.Errorf("invalid witness version : %d", data[0])
	}
	pkey, err := bech32.ConvertBits(data[1:], 5, 8, false)
	if err != nil {
		return 0, nil, err
	}
	if len(pkey) < 2 || len(pkey) > 40 {
		return 0, nil, fmt.Errorf("invalid convertbits length : %d", len(pkey))
	}
	if data[0] == 0 && len(pkey) != 20 && len(pkey) != 32 {
		return 0, nil, fmt.Errorf("invalid program length for witness version 0 (per BIP141) : %d", len(pkey))
	}
	return data[0], pkey, nil
}

// segwitAddrEncode encodes hrp(human-readable part), version and data(bytes array), returns Segwit Address / or error
func segwitAddrEncode(hrp string, version byte, pkey []byte) (string, error) {
	if version > 16 {
		return "", fmt.Errorf("invalid witness version : %d", version)
	}
	if len(pkey) < 2 || len(pkey) > 40 {
		return "", fmt.Errorf("invalid pkey length : %d", len(pkey))
	}
	if version == 0 && len(pkey) != 20 && len(pkey) != 32 {
		return "", fmt.Errorf("invalid pkey length for witness version 0 (per BIP141) : %d", len(pkey))
	}
	data, err := bech32.ConvertBits(pkey, 8, 5, true)
	if err != nil {
		return "", err
	}
	addr, err := bech32.Encode(hrp, append([]byte{version}, data...))
	if err != nil {
		return "", err
	}
	return addr, nil
}

// AddrEncode encodes address from pkey
func AddrEncode(txType uint8, pkey []byte) (string, error) {
	var addr string
	switch txType {
	case txP2pkh:
		addr = Hash160ToAddress(pkey, []byte{0x00})
	case txP2sh:
		addr = Hash160ToAddress(pkey, []byte{0x05})
	case txP2pk:
		addr = Hash160ToAddress(pkey, []byte{0x00})
	case txMultisig:
		return "", fmt.Errorf("script: Multisig, %d", len(pkey))
	case txP2wpkh:
		addr, _ = segwitAddrEncode("bc", 0x00, pkey)
	case txP2wsh:
		addr, _ = segwitAddrEncode("bc", 0x00, pkey)
	case txOpreturn:
		addr = fmt.Sprintf("%x", pkey)
	case txParseErr:
		addr = ""
	case txUnknown:
		addr = ""
	default:
		return "", fmt.Errorf("EncodeAddr: Unable to encode addr from pkeyscript")
	}
	return addr, nil
}

// AddrDecode accepts an encoded address (P2PKH or P2SH, human readable)
// returns its public key
func AddrDecode(addr string) ([]byte, error) {
	switch {
	case addr[0] == '1':
		data := DecodeBase58(addr)
		if data[0] != 0x00 {
			return nil, fmt.Errorf("address must start with byte 0x00")
		}
		return data[1:21], nil
	case addr[0] == '3':
		data := DecodeBase58(addr)
		if data[0] != 0x05 {
			return nil, fmt.Errorf("address must start with byte 0x05")
		}
		return data[1:21], nil
	case addr[0] == 'b' && addr[1] == 'c':
		_, data, err := segwitAddrDecode("bc", addr)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return nil, fmt.Errorf("EncodeAddr: Unable to decode pkey from addr")
	// TODO: Check DoubleSha256(data[:21])[:4] == data[-4:]
}

func getPkeyFromOps(ops [][]byte) (txType uint8, pkey []byte) {
	if pkey = scriptIsPubkeyHash(ops); pkey != nil {
		txType = txP2pkh
	} else if pkey = scriptIsScriptHash(ops); pkey != nil {
		txType = txP2sh
	} else if pkey = scriptIsPubkey(ops); pkey != nil {
		txType = txP2pk
	} else if pkey = scriptIsMultiSig(ops); pkey != nil {
		txType = txMultisig // TODO: MULTISIG
	} else if scriptIsWitnessProgram(ops) {
		pkey = ops[1]
		if len(pkey) == 20 { // TODO: Improve
			txType = txP2wpkh
		} else if len(pkey) == 32 {
			txType = txP2wsh
		} else {
			pkey = nil
			txType = txUnknown
		}
	} else if pkey = scriptIsOpReturn(ops); pkey != nil {
		txType = txOpreturn
	} else {
		pkey = nil
		txType = txUnknown
	}
	return txType, pkey
}

/*
* script:
* version:
* Return hash and hash type (P2PKH,P2SH...) from output script
 */
func getPkeyFromScript(script []byte) (txType uint8, hash []byte) {
	ops, err := getOps(script)
	if err != nil {
		return txParseErr, nil
	}
	return getPkeyFromOps(ops)
}

func getNextOp(script []byte) ([]byte, []byte) {
	dataLength := uint32(0)
	switch {
	case script[0] < opPushdata1 && script[0] > op0:
		dataLength = uint32(script[0])
	case script[0] == opPushdata1 && len(script) > 1:
		dataLength = uint32(script[1])
	case script[0] == opPushdata2 && len(script) > 2:
		dataLength = binary.LittleEndian.Uint32(append([]byte{0, 0}, script[1:3]...))
	case script[0] == opPushdata4 && len(script) > 4:
		dataLength = binary.LittleEndian.Uint32(script[1:5])
	default:
		return script[:1], script[1:]
	}
	if dataLength >= uint32(len(script)) {
		return script[1:], nil
	}
	return script[1 : 1+dataLength], script[1+dataLength:]
}

// Get Ops from Script
func getOps(raw []byte) (ops [][]byte, err error) {
	script := make([]byte, len(raw))
	copy(script, raw)
	var op []byte
	for len(script) > 0 {
		if op, script = getNextOp(script); script == nil {
			return ops, fmt.Errorf("Overflow")
		}
		ops = append(ops, op)
	}
	return ops, nil
}
