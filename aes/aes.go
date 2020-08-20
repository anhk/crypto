package aes

import (
	"errors"
)

const (
	BlockSize = 16

	nb = 4 // Number of blocks (AES 规范只允许 128bits的输入
)

//AES -
type AES struct {
	/** Number of round(nr)，加密运算执行回合数 **/
	nr int

	/**
	 * Number of block of key, 轮密钥（每block-32bits）的block数量
	 * AES-128: 4 blocks, AES-192: 6 blocks, AES-256: 8 blocks
	 */
	nbk int

	/**
	 * 轮密钥Array: w0(index 0 ~ 3) w1(index 4 ~ 7)....
	 * - AES-128: 44 words = 176 bytes
	 * - AES-256: 60 words = 240 bytes
	 */
	roundKey [240]byte

	/**
	 * 密钥，AES-128: 16 bytes, AES-256: 32 bytes
	 */
	//	Key []byte
}

//NewCipher -
func NewCipher(key []byte) (*AES, error) {
	aes := &AES{}
	switch l := len(key); l {
	case 16:
		aes.nbk, aes.nr = 4, 10
	case 24:
		aes.nbk, aes.nr = 6, 12
	case 32:
		aes.nbk, aes.nr = 8, 14
	default:
		return nil, errors.New("Invalid size of key")
	}
	aes.keyExpansion(key)
	return aes, nil
}

/**
 * 密钥扩展： 扩充轮密钥
 */
func (aes *AES) keyExpansion(key []byte) {

	/**
	 * 第一回合轮密钥
	 * - AES-128, nbk = 4, 4 blocks W0 ~ W3
	 * - AES-256, nbk = 8, 8 blocks W0 ~ W7
	 */
	for i := 0; i < aes.nbk; i++ {
		copy(aes.roundKey[i*4:(i+1)*4], key[i*4:(i+1)*4])
	}

	/**
	 * 之后的轮密钥
	 * - AES-128: i= 4 ~ 43, 共1+10个blocks
	 * - AES-256: i= 8 ~ 59, 共1+14个blocks
	 */
	for i := aes.nbk; i < (nb * (aes.nr + 1)); i++ {
		tempBytes := make([]byte, 4)
		copy(tempBytes, aes.roundKey[(i-1)*4:i*4])
		if i%aes.nbk == 0 {
			// RotWord, [a0,a1,a2,a3] left circular shift -> [a1, a2, a3, a0]
			tempBytes[0], tempBytes[1], tempBytes[2], tempBytes[3] = tempBytes[1], tempBytes[2], tempBytes[3], tempBytes[0]

			// SubWord (SBox substitution)
			aes.SubBytes(tempBytes)

			// XOR Rcon, Only left byte are changed
			tempBytes[0] = tempBytes[0] ^ Rcon[i/aes.nbk]
		} else if aes.nbk == 8 && i%aes.nbk == 4 {
			// Only AES-256 used: SubWord (SBox substitution)
			aes.SubBytes(tempBytes)
		}

		/** Wn = Wn-1 XOR Wk */
		aes.AddRoundKey(aes.roundKey[(i-aes.nbk)*4:(i-aes.nbk+1)*4], tempBytes)
		copy(aes.roundKey[i*4:(i+1)*4], tempBytes)
	}
}

//AddRoundKey - 轮密钥XOR
func (aes *AES) AddRoundKey(roundKey, block []byte) {
	for i := range block {
		block[i] = roundKey[i] ^ block[i]
	}
}

//SubBytes - TODO: BIJECTION.
func (aes *AES) SubBytes(block []byte) {
	for i := range block {
		block[i] = SBox[block[i]]
	}
}

//UnSubBytes - TODO: BIJECTION.
func (aes *AES) UnSubBytes(block []byte) {
	for i := range block {
		block[i] = InvSBox[block[i]]
	}
}

//ShiftRows -
func (aes *AES) ShiftRows(block []byte) {
	copy(block, []byte{
		block[0], block[5], block[10], block[15],
		block[4], block[9], block[14], block[3],
		block[8], block[13], block[2], block[7],
		block[12], block[1], block[6], block[11],
	})
}

//UnShiftRows -
func (aes *AES) UnShiftRows(block []byte) {
	copy(block, []byte{
		block[0], block[13], block[10], block[7],
		block[4], block[1], block[14], block[11],
		block[8], block[5], block[2], block[15],
		block[12], block[9], block[6], block[3],
	})
}

/**
 * MixColumn
 *    c0      | 2 3 1 1 |    |b0|
 *    c1   =  | 1 2 3 1 | *  |b1|
 *    c2      | 1 1 2 3 |    |b2|
 *    c3      | 3 1 1 2 |    |b3|
 */
func (aes *AES) mixColumn(a, b []byte) []byte {
	out := make([]byte, 4)

	out[0] = gmult(a[0], b[0]) ^ gmult(a[3], b[1]) ^ gmult(a[2], b[2]) ^ gmult(a[1], b[3])
	out[1] = gmult(a[1], b[0]) ^ gmult(a[0], b[1]) ^ gmult(a[3], b[2]) ^ gmult(a[2], b[3])
	out[2] = gmult(a[2], b[0]) ^ gmult(a[1], b[1]) ^ gmult(a[0], b[2]) ^ gmult(a[3], b[3])
	out[3] = gmult(a[3], b[0]) ^ gmult(a[2], b[1]) ^ gmult(a[1], b[2]) ^ gmult(a[0], b[3])
	return out
}

//MixColumns -
func (aes *AES) MixColumns(block []byte) {
	a := []byte{0x02, 0x01, 0x01, 0x03}
	for i := 0; i < len(block); i += 4 {
		tmp := aes.mixColumn(a, block[i:i+4])
		copy(block[i:i+4], tmp)
	}
}

//UnMixColumns -
func (aes *AES) UnMixColumns(block []byte) {
	a := []byte{0x0e, 0x09, 0x0d, 0x0b}
	for i := 0; i < len(block); i += 4 {
		tmp := aes.mixColumn(a, block[i:i+4])
		copy(block[i:i+4], tmp)
	}
}

func gmult(a, b byte) byte {
	p := byte(0)
	for i := 0; i < 8; i++ {
		if (b & 1) != 0 {
			p ^= a
		}
		hbs := a & 0x80

		a <<= 1
		if hbs != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

//Encrypt -
func (aes *AES) Encrypt(dst, src []byte) {
	copy(dst, src)
	aes.AddRoundKey(aes.roundKey[:16], dst)
	for i := 1; i < aes.nr; i++ {
		aes.SubBytes(dst)
		aes.ShiftRows(dst)
		aes.MixColumns(dst)
		aes.AddRoundKey(aes.roundKey[i*16:(i+1)*16], dst)
	}
	aes.SubBytes(dst)
	aes.ShiftRows(dst)
	aes.AddRoundKey(aes.roundKey[aes.nr*16:], dst)
}

//Decrypt -
func (aes *AES) Decrypt(dst, src []byte) {
	copy(dst, src)
	aes.AddRoundKey(aes.roundKey[aes.nr*16:], dst)
	aes.UnShiftRows(dst)
	aes.UnSubBytes(dst)
	for i := aes.nr - 1; i >= 1; i-- {
		aes.AddRoundKey(aes.roundKey[i*16:(i+1)*16], dst)
		aes.UnMixColumns(dst)
		aes.UnShiftRows(dst)
		aes.UnSubBytes(dst)
	}
	aes.AddRoundKey(aes.roundKey[:16], dst)
}

func (aes *AES) BlockSize() int {
	return BlockSize
}
