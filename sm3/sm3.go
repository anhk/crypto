package sm3

import (
	"encoding/binary"
)

const (
	BlockSize = 64
	Size      = 32
)

type SM3 struct {
	digest      [8]uint32
	length      uint64
	unhandleMsg []byte
}

func New() *SM3 {
	sm3 := &SM3{}
	sm3.Reset()
	return sm3
}

func (sm3 *SM3) Size() int {
	return Size
}

func (sm3 *SM3) BlockSize() int {
	return BlockSize
}

func (sm3 *SM3) Reset() {
	for i := 0; i < 8; i++ {
		sm3.digest[i] = InitVec[i]
	}
	sm3.unhandleMsg = []byte{}
	sm3.length = 0
}

func (sm3 *SM3) Write(data []byte) (n int, err error) {
	sm3.length += uint64(len(data))
	msg := append(sm3.unhandleMsg, data...)
	nblocks := len(msg) / BlockSize
	sm3.update(msg, nblocks)
	sm3.unhandleMsg = msg[nblocks*BlockSize:]
	return len(data), nil
}

func (sm3 *SM3) Sum(in []byte) []byte {
	sm3New := *sm3
	sm3New.pad()
	sm3New.Write(nil)
	out := make([]byte, Size)
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:(i+1)*4], sm3New.digest[i])
	}
	return append(in, out...)
}

func (sm3 *SM3) updateBlock(data []byte) { // 64 bytes
	var w [68]uint32
	var w1 [64]uint32

	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(data[i*4 : (i+1)*4])
	}

	for i := 16; i < 68; i++ {
		w[i] = p1(w[i-16]^w[i-9]^leftRotate(w[i-3], 15)) ^ leftRotate(w[i-13], 7) ^ w[i-6]
	}

	for i := 0; i < 64; i++ {
		w1[i] = w[i] ^ w[i+4]
	}
	a, b, c, d, e, f, g, h := sm3.digest[0], sm3.digest[1], sm3.digest[2], sm3.digest[3],
		sm3.digest[4], sm3.digest[5], sm3.digest[6], sm3.digest[7]
	for i := 0; i < 16; i++ {
		ss1 := leftRotate(leftRotate(a, 12)+e+leftRotate(0x79cc4519, uint32(i)), 7)
		ss2 := ss1 ^ leftRotate(a, 12)
		tt1 := ff0(a, b, c) + d + ss2 + w1[i]
		tt2 := gg0(e, f, g) + h + ss1 + w[i]
		d, c, b, a = c, leftRotate(b, 9), a, tt1
		h, g, f, e = g, leftRotate(f, 19), e, p0(tt2)
	}

	for i := 16; i < 64; i++ {
		ss1 := leftRotate(leftRotate(a, 12)+e+leftRotate(0x7a879d8a, uint32(i)), 7)
		ss2 := ss1 ^ leftRotate(a, 12)
		tt1 := ff1(a, b, c) + d + ss2 + w1[i]
		tt2 := gg1(e, f, g) + h + ss1 + w[i]
		d, c, b, a = c, leftRotate(b, 9), a, tt1
		h, g, f, e = g, leftRotate(f, 19), e, p0(tt2)
	}
	sm3.digest[0] ^= a
	sm3.digest[1] ^= b
	sm3.digest[2] ^= c
	sm3.digest[3] ^= d
	sm3.digest[4] ^= e
	sm3.digest[5] ^= f
	sm3.digest[6] ^= g
	sm3.digest[7] ^= h
}

func (sm3 *SM3) update(data []byte, nblocks int) {
	for i := 0; i < nblocks; i++ {
		sm3.updateBlock(data[i*BlockSize : (i+1)*BlockSize])
	}
}

func (sm3 *SM3) pad() {
	sm3.unhandleMsg = append(sm3.unhandleMsg, 0x80) // append '1'

	sm3.length <<= 3

	if len(sm3.unhandleMsg)%BlockSize < 56 {
		sm3.unhandleMsg = append(sm3.unhandleMsg, make([]byte, BlockSize-len(sm3.unhandleMsg)%BlockSize)...)
	} else {
		sm3.unhandleMsg = append(sm3.unhandleMsg, make([]byte, BlockSize*2-len(sm3.unhandleMsg)%BlockSize)...)
	}
	binary.BigEndian.PutUint64(sm3.unhandleMsg[len(sm3.unhandleMsg)-8:], sm3.length)
}

func leftRotate(x uint32, i uint32) uint32 { return (x<<(i%32) | x>>(32-i%32)) }
func ff0(x, y, z uint32) uint32            { return x ^ y ^ z }
func ff1(x, y, z uint32) uint32            { return (x & y) | (x & z) | (y & z) }
func gg0(x, y, z uint32) uint32            { return x ^ y ^ z }
func gg1(x, y, z uint32) uint32            { return (x & y) | (^x & z) }
func p0(x uint32) uint32                   { return x ^ leftRotate(x, 9) ^ leftRotate(x, 17) }
func p1(x uint32) uint32                   { return x ^ leftRotate(x, 15) ^ leftRotate(x, 23) }

func Sm3Sum(data []byte) []byte {
	sm3 := New()
	sm3.Write(data)
	return sm3.Sum(nil)
}
