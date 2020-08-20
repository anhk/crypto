package sm4

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

type Block [4]uint32

func newBlock(data []byte) (*Block, error) {
	if len(data) != BlockSize {
		return nil, errors.New("invalid size of data, must be 16 bytes")
	}
	b := &Block{}
	b[0] = binary.BigEndian.Uint32(data[0:4])
	b[1] = binary.BigEndian.Uint32(data[4:8])
	b[2] = binary.BigEndian.Uint32(data[8:12])
	b[3] = binary.BigEndian.Uint32(data[12:16])
	return b, nil
}

func (b *Block) AddFk() {
	for i := 0; i < 4; i++ {
		b[i] ^= FK[i]
	}
}

func (b *Block) LeftShift() {
	b[0], b[1], b[2], b[3] = b[1], b[2], b[3], b[0]
}

func (b *Block) Rotate() {
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
}

func (b *Block) Write(out []byte) {
	binary.BigEndian.PutUint32(out[0:4], b[0])
	binary.BigEndian.PutUint32(out[4:8], b[1])
	binary.BigEndian.PutUint32(out[8:12], b[2])
	binary.BigEndian.PutUint32(out[12:16], b[3])
}

func tau(b uint32) uint32 {
	return uint32(SBox[b&0xFF]) | uint32(SBox[(b>>8)&0xFF])<<8 | uint32(SBox[(b>>16)&0xFF])<<16 | uint32(SBox[(b>>24)&0xFF])<<24
}

func lAp(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 13) ^ bits.RotateLeft32(b, 23)
}

func tAp(b uint32) uint32 {
	return lAp(tau(b))
}

func l(b uint32) uint32 {
	return b ^ bits.RotateLeft32(b, 2) ^ bits.RotateLeft32(b, 10) ^
		bits.RotateLeft32(b, 18) ^ bits.RotateLeft32(b, 24)
}

func t(b uint32) uint32 {
	return l(tau(b))
}
