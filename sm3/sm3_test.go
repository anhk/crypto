package sm3

import (
	"fmt"
	"strings"
	"testing"
)

func TestNew(t *testing.T) {
	sm3 := New()
	fmt.Println(sm3)

	sm3.Reset()
	fmt.Println(sm3)
}

func TestSM3_BlockSize(t *testing.T) {
	sm3 := New()
	if sm3.BlockSize() != 16 {
		t.Fatal("invalid blocksize")
	}
	if sm3.Size() != 32 {
		t.Fatal("invalid size")
	}
}

//[179 238 212 91 22 172 230 200 241 5 236 95 2 118 62 180 108 14 202 17 39 119 34 222 26 94 42 149 41 236 244 73]
func TestSm3Sum(t *testing.T) {
	result := "B3EED45B16ACE6C8F105EC5F02763EB46C0ECA11277722DE1A5E2A9529ECF449"
	if !strings.EqualFold(result, fmt.Sprintf("%2X", Sm3Sum([]byte("Hello World.")))) {
		t.Fatal("invalid sm3 ")
	}
}

func TestSm3Sum2(t *testing.T) {
	result := "F63E7B627F946C8655F5096A1EFE83C02F871441EBF1C54E0396C1828F76D4F1"
	data := []byte(` 01 61 F4 DD CF 43 D0 B4 B5 71 87 F4 F6 80 71 1D	.a...C...q....q.
 84 3F C0 CE 45 A3 22 BA FA 3A 5C EF C5 7F 14 F0	.?..E."..:\...
 F6 30 13 4E 6B C2 19 B4 8B B4 1A 3A 6F 89 AD 2C	.0.Nk......:o..,
 47 9E 7F 4E CF 1B 53 AB C4 2F 28 AA A3 74 0B 24	GN..S../(..t.$
 DC F9 88 63 1C 9B C9 49 D0 DA 2B 69 58 F3 B2 F8	...c...I..+iX...
 8E 05 E1 88 CC 2C 6D E3 2D 7B 98 64 17 79 1A AF	.....,m.-{.d.y..
 FA CF 48 3C F0 3C 5B FD 13 28 A0 AF 1F 0B 8E B9	..H<.<[..(......
 D6 C1 61                                       	..a
`)
	if !strings.EqualFold(result, fmt.Sprintf("%2X", Sm3Sum(data))) {
		t.Fatal("invalid sm3")
	}
}
