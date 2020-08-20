package sm4

import (
	"errors"
)

const (
	BlockSize = 16
	KeySize   = 16
)

type SM4 struct {
	subKeys [32]uint32
}

func NewCipher(key []byte) (*SM4, error) {
	if len(key) != KeySize {
		return nil, errors.New("invalid size of key, only support 16 bytes.")
	}
	sm4 := &SM4{}
	sm4.keyExpansion(key)
	return sm4, nil
}

func (sm4 *SM4) keyExpansion(key []byte) {
	b, _ := newBlock(key)
	b.AddFk()
	for i := 0; i < 32; i++ {
		sm4.subKeys[i] = b[0] ^ tAp(b[1]^b[2]^b[3]^CK[i])
		b[0] = sm4.subKeys[i]
		b.LeftShift()
	}
}

func (sm4 *SM4) Encrypt(dst, src []byte) {
	b, _ := newBlock(src)
	for i := 0; i < 32; i++ {
		b[0] = b[0] ^ t(b[1]^b[2]^b[3]^sm4.subKeys[i])
		b.LeftShift()
	}
	b.Rotate()
	b.Write(dst)
}

func (sm4 *SM4) Decrypt(dst, src []byte) {
	b, _ := newBlock(src)
	for i := 32; i > 0; i-- {
		b[0] = b[0] ^ t(b[1]^b[2]^b[3]^sm4.subKeys[i-1])
		b.LeftShift()
	}
	b.Rotate()
	b.Write(dst)
}

func (sm4 *SM4) BlockSize() int {
	return BlockSize
}
