package sm4

import (
	"bytes"
	"testing"
)

var key = [16]byte{
	0x66, 0x0D, 0x16, 0xF4, 0xCC, 0x9E, 0x1E, 0xC5, 0x4F, 0xB1, 0x66, 0x0A, 0xBB, 0x97, 0xE6, 0x4E,
}

var data = []byte{
	0xE2, 0xF6, 0xB9, 0xF2, 0x44, 0x75, 0xE6, 0xEC, 0x7A, 0x6F, 0x2F, 0xDB, 0xF5, 0xE9, 0x4C, 0x6E,
}

var encData = []byte{
	0x70, 0xAE, 0xBC, 0x66, 0xE3, 0x86, 0xD0, 0xDF, 0x5D, 0xD6, 0x6C, 0x75, 0xAD, 0xC8, 0x60, 0xC0,
}

var decData = []byte{
	0xA9, 0x1A, 0x6E, 0xD1, 0x49, 0xE8, 0x3E, 0x5A, 0x9D, 0x8B, 0x81, 0x88, 0x05, 0xC8, 0x1A, 0xF9,
}

var iv = []byte{
	0x56, 0xB6, 0x8B, 0x04, 0x19, 0xD3, 0xD8, 0x42, 0xCF, 0x1E, 0x4D, 0x70, 0x71, 0x1A, 0xA6, 0x67,
}

var roundKey = []uint32{
	584842451, 641576065, 1985738851, 105099466, 3051158793, 1539834001, 1423045271, 4012128966, 1952847767, 894142582, 1255191338, 2212120743,
	940735457, 1708858160, 3215567312, 703622591, 80474254, 704202401, 1392251231, 1599941582, 857960926, 2515454310, 2403071519, 2218236885,
	1288133630, 3121992281, 1516397203, 2363740549, 2173319383, 3013317934, 926979705, 3562538709,
}

func TestNewCipher(t *testing.T) {
	sm4, _ := NewCipher(key[:])
	for i := 0; i < len(sm4.subKeys); i++ {
		if sm4.subKeys[i] != roundKey[i] {
			t.Fatal("invalid roundKey.")
		}
	}
}

/**
 */
func TestSM4_Encrypt(t *testing.T) {
	sm4, _ := NewCipher(key[:])
	sm4.Encrypt(data, data)
	if !bytes.Equal(data, encData) {
		t.Fatal("invalid encrypt")
	}
}

/*
[169 26 110 209 73 232 62 90 157 139 129 136 5 200 26 249]
*/
func TestSM4_Decrypt(t *testing.T) {
	sm4, _ := NewCipher(key[:])
	sm4.Decrypt(data, data)
	if !bytes.Equal(data, decData) {
		t.Fatal("invalid decrypt")
	}
}
