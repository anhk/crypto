package sm3

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	DigestLength = 32
	BlockSize    = 16
)

var gT = []uint32{
	0x79CC4519, 0xF3988A32, 0xE7311465, 0xCE6228CB, 0x9CC45197, 0x3988A32F, 0x7311465E, 0xE6228CBC,
	0xCC451979, 0x988A32F3, 0x311465E7, 0x6228CBCE, 0xC451979C, 0x88A32F39, 0x11465E73, 0x228CBCE6,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5,
	0x7A879D8A, 0xF50F3B14, 0xEA1E7629, 0xD43CEC53, 0xA879D8A7, 0x50F3B14F, 0xA1E7629E, 0x43CEC53D,
	0x879D8A7A, 0x0F3B14F5, 0x1E7629EA, 0x3CEC53D4, 0x79D8A7A8, 0xF3B14F50, 0xE7629EA1, 0xCEC53D43,
	0x9D8A7A87, 0x3B14F50F, 0x7629EA1E, 0xEC53D43C, 0xD8A7A879, 0xB14F50F3, 0x629EA1E7, 0xC53D43CE,
	0x8A7A879D, 0x14F50F3B, 0x29EA1E76, 0x53D43CEC, 0xA7A879D8, 0x4F50F3B1, 0x9EA1E762, 0x3D43CEC5}

type SM3 struct {
	v         [DigestLength / 4]uint32
	inWords   [BlockSize]uint32
	xOff      int32
	w         [68]uint32
	xBuf      [4]byte
	xBufOff   int32
	byteCount int64
}

func New() hash.Hash {
	sm3 := new(SM3)
	sm3.Reset()
	return sm3
}

func (sm3 *SM3) Sum(b []byte) []byte {
	d1 := sm3
	h := d1.checkSum()
	return append(b, h[:]...)
}

// Size returns the number of bytes Sum will return.
func (sm3 *SM3) Size() int {
	return DigestLength
}

// BlockSize returns the hash's underlying block size.
// The Write method must be able to accept any amount
// of data, but it may operate more efficiently if all writes
// are a multiple of the block size.
func (sm3 *SM3) BlockSize() int {
	return BlockSize
}

func (sm3 *SM3) Reset() {
	sm3.byteCount = 0

	sm3.xBufOff = 0
	for i := 0; i < len(sm3.xBuf); i++ {
		sm3.xBuf[i] = 0
	}

	for i := 0; i < len(sm3.inWords); i++ {
		sm3.inWords[i] = 0
	}

	for i := 0; i < len(sm3.w); i++ {
		sm3.w[i] = 0
	}

	sm3.v[0] = 0x7380166F
	sm3.v[1] = 0x4914B2B9
	sm3.v[2] = 0x172442D7
	sm3.v[3] = 0xDA8A0600
	sm3.v[4] = 0xA96F30BC
	sm3.v[5] = 0x163138AA
	sm3.v[6] = 0xE38DEE4D
	sm3.v[7] = 0xB0FB0E4E

	sm3.xOff = 0
}

func (sm3 *SM3) Write(p []byte) (n int, err error) {
	//_ = p[0]
	inLen := len(p)

	i := 0
	if sm3.xBufOff != 0 {
		for i < inLen {
			sm3.xBuf[sm3.xBufOff] = p[i]
			sm3.xBufOff++
			i++
			if sm3.xBufOff == 4 {
				sm3.processWord(sm3.xBuf[:], 0)
				sm3.xBufOff = 0
				break
			}
		}
	}

	limit := ((inLen - i) & ^3) + i
	for ; i < limit; i += 4 {
		sm3.processWord(p, int32(i))
	}

	for i < inLen {
		sm3.xBuf[sm3.xBufOff] = p[i]
		sm3.xBufOff++
		i++
	}

	sm3.byteCount += int64(inLen)

	n = inLen
	return
}

func (sm3 *SM3) finish() {
	bitLength := sm3.byteCount << 3

	sm3.Write([]byte{128})

	for sm3.xBufOff != 0 {
		sm3.Write([]byte{0})
	}

	sm3.processLength(bitLength)

	sm3.processBlock()
}

func (sm3 *SM3) checkSum() [DigestLength]byte {
	sm3.finish()
	vlen := len(sm3.v)
	var out [DigestLength]byte
	for i := 0; i < vlen; i++ {
		binary.BigEndian.PutUint32(out[i*4:(i+1)*4], sm3.v[i])
	}
	return out
}

func (sm3 *SM3) processBlock() {
	for j := 0; j < 16; j++ {
		sm3.w[j] = sm3.inWords[j]
	}
	for j := 16; j < 68; j++ {
		wj3 := sm3.w[j-3]
		r15 := (wj3 << 15) | (wj3 >> (32 - 15))
		wj13 := sm3.w[j-13]
		r7 := (wj13 << 7) | (wj13 >> (32 - 7))
		sm3.w[j] = p1(sm3.w[j-16]^sm3.w[j-9]^r15) ^ r7 ^ sm3.w[j-6]
	}

	A := sm3.v[0]
	B := sm3.v[1]
	C := sm3.v[2]
	D := sm3.v[3]
	E := sm3.v[4]
	F := sm3.v[5]
	G := sm3.v[6]
	H := sm3.v[7]

	for j := 0; j < 16; j++ {
		a12 := (A << 12) | (A >> (32 - 12))
		s1 := a12 + E + gT[j]
		SS1 := (s1 << 7) | (s1 >> (32 - 7))
		SS2 := SS1 ^ a12
		Wj := sm3.w[j]
		W1j := Wj ^ sm3.w[j+4]
		TT1 := ff0(A, B, C) + D + SS2 + W1j
		TT2 := gg0(E, F, G) + H + SS1 + Wj
		D = C
		C = (B << 9) | (B >> (32 - 9))
		B = A
		A = TT1
		H = G
		G = (F << 19) | (F >> (32 - 19))
		F = E
		E = p0(TT2)
	}

	for j := 16; j < 64; j++ {
		a12 := (A << 12) | (A >> (32 - 12))
		s1 := a12 + E + gT[j]
		SS1 := (s1 << 7) | (s1 >> (32 - 7))
		SS2 := SS1 ^ a12
		Wj := sm3.w[j]
		W1j := Wj ^ sm3.w[j+4]
		TT1 := ff1(A, B, C) + D + SS2 + W1j
		TT2 := gg1(E, F, G) + H + SS1 + Wj
		D = C
		C = (B << 9) | (B >> (32 - 9))
		B = A
		A = TT1
		H = G
		G = (F << 19) | (F >> (32 - 19))
		F = E
		E = p0(TT2)
	}

	sm3.v[0] ^= A
	sm3.v[1] ^= B
	sm3.v[2] ^= C
	sm3.v[3] ^= D
	sm3.v[4] ^= E
	sm3.v[5] ^= F
	sm3.v[6] ^= G
	sm3.v[7] ^= H

	sm3.xOff = 0
}

func (sm3 *SM3) processWord(in []byte, inOff int32) {
	n := binary.BigEndian.Uint32(in[inOff : inOff+4])

	sm3.inWords[sm3.xOff] = n
	sm3.xOff++

	if sm3.xOff >= 16 {
		sm3.processBlock()
	}
}

func (sm3 *SM3) processLength(bitLength int64) {
	if sm3.xOff > (BlockSize - 2) {
		sm3.inWords[sm3.xOff] = 0
		sm3.xOff++

		sm3.processBlock()
	}

	for ; sm3.xOff < (BlockSize - 2); sm3.xOff++ {
		sm3.inWords[sm3.xOff] = 0
	}

	sm3.inWords[sm3.xOff] = uint32(bitLength >> 32)
	sm3.xOff++
	sm3.inWords[sm3.xOff] = uint32(bitLength)
	sm3.xOff++
}

func p0(x uint32) uint32 {
	r9 := bits.RotateLeft32(x, 9)
	r17 := bits.RotateLeft32(x, 17)
	return x ^ r9 ^ r17
}

func p1(x uint32) uint32 {
	r15 := bits.RotateLeft32(x, 15)
	r23 := bits.RotateLeft32(x, 23)
	return x ^ r15 ^ r23
}

func ff0(x uint32, y uint32, z uint32) uint32 {
	return x ^ y ^ z
}

func ff1(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | (x & z) | (y & z)
}

func gg0(x uint32, y uint32, z uint32) uint32 {
	return x ^ y ^ z
}

func gg1(x uint32, y uint32, z uint32) uint32 {
	return (x & y) | ((^x) & z)
}

func Sm3Sum(data []byte) [DigestLength]byte {
	var d SM3
	d.Reset()
	d.Write(data)
	return d.checkSum()
}
