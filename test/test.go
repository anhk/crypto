package main

import (
	"crypto/cipher"
	"fmt"
	"github.com/anhk/crypto/aes"
	"github.com/anhk/crypto/sm3"
	"github.com/anhk/crypto/sm4"
)

var (
	key = []byte{0x66, 0x0D, 0x16, 0xF4, 0xCC, 0x9E, 0x1E, 0xC5, 0x4F, 0xB1, 0x66, 0x0A, 0xBB, 0x97, 0xE6, 0x4E}
	iv  = []byte{0x56, 0xB6, 0x8B, 0x04, 0x19, 0xD3, 0xD8, 0x42, 0xCF, 0x1E, 0x4D, 0x70, 0x71, 0x1A, 0xA6, 0x67}
)

func TestAES() {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	data := []byte("1234567890123456123456789012345612345678901234561234567890123456")
	modeEnc := cipher.NewCBCEncrypter(block, iv)
	modeEnc.CryptBlocks(data, data)
	fmt.Printf("%2X\n", data)

	modeDec := cipher.NewCBCDecrypter(block, iv)
	modeDec.CryptBlocks(data, data)
	fmt.Println(string(data))
}

func TestSM4() {
	block, err := sm4.NewCipher(key)
	if err != nil {
		panic(err)
	}

	data := []byte("1234567890123456123456789012345612345678901234561234567890123456")
	modeEnc := cipher.NewCBCEncrypter(block, iv)
	modeEnc.CryptBlocks(data, data)
	fmt.Printf("%2X\n", data)

	modeDec := cipher.NewCBCDecrypter(block, iv)
	modeDec.CryptBlocks(data, data)
	fmt.Println(string(data))
}

func TestSM3() {
	fmt.Printf("%2X\n", sm3.Sm3Sum([]byte("hello world.")))
}

func main() {
	TestAES()
	TestSM4()
	TestSM3()
}
