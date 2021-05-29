package cbccts_test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/mixcode/golib/cbccts"
)

func TestCTS(t *testing.T) {

	var err error

	// prepare a key and an iv
	key := make([]byte, 0x20) // aes-256 key
	for i := 0; i < 0x20; i++ {
		key[i] = byte(i)
	}
	iv := make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		iv[i] = byte(i * 2)
	}

	// prepare aligned data
	hexstr := "0123456789abcdef"
	dataAligned := make([]byte, 4*aes.BlockSize)
	for i, j := 0, 0; i < len(dataAligned); i++ {
		dataAligned[i] = hexstr[j]
		j = (j + 1) % len(hexstr)
	}
	// prepare unaligned data
	dataUnaligned := make([]byte, 4*aes.BlockSize+3)
	for i, j := 0, 0; i < len(dataUnaligned); i++ {
		dataUnaligned[i] = hexstr[j]
		j = (j + 1) % len(hexstr)
	}

	ac, err := aes.NewCipher(key)

	type testParam struct {
		enc, dec cbccts.Format
		data     []byte
		ok       bool
	}
	testCase := []testParam{
		// enc/dec must succeed in same type cases
		{cbccts.CS1, cbccts.CS1, dataAligned, true},
		{cbccts.CS2, cbccts.CS2, dataAligned, true},
		{cbccts.CS3, cbccts.CS3, dataAligned, true},
		{cbccts.CS1, cbccts.CS1, dataUnaligned, true},
		{cbccts.CS2, cbccts.CS2, dataUnaligned, true},
		{cbccts.CS3, cbccts.CS3, dataUnaligned, true},

		// cbccts.CS1/cbccts.CS2 is compatible on aligned data
		{cbccts.CS1, cbccts.CS2, dataAligned, true},
		{cbccts.CS2, cbccts.CS1, dataAligned, true},
		{cbccts.CS1, cbccts.CS2, dataUnaligned, false},
		{cbccts.CS2, cbccts.CS1, dataUnaligned, false},

		// cbccts.CS2/cbccts.CS3 is compatible on unaligned data
		{cbccts.CS2, cbccts.CS3, dataUnaligned, true},
		{cbccts.CS3, cbccts.CS2, dataUnaligned, true},
		{cbccts.CS2, cbccts.CS3, dataAligned, false},
		{cbccts.CS3, cbccts.CS2, dataAligned, false},

		// cbccts.CS1 and cbccts.CS3 is incompatible on all cases
		{cbccts.CS1, cbccts.CS3, dataAligned, false},
		{cbccts.CS3, cbccts.CS1, dataAligned, false},
		{cbccts.CS1, cbccts.CS3, dataUnaligned, false},
		{cbccts.CS3, cbccts.CS1, dataUnaligned, false},

		// Raw CBC is compaible with cbccts.CS1 and cbccts.CS2
		// (note: raw CBC can't do unaligned data)
		{0, cbccts.CS1, dataAligned, true},
		{0, cbccts.CS2, dataAligned, true},
		{0, cbccts.CS3, dataAligned, false},

		{cbccts.CS1, 0, dataAligned, true},
		{cbccts.CS2, 0, dataAligned, true},
		{cbccts.CS3, 0, dataAligned, false},
	}

	for i, c := range testCase {

		// prepare encoder/decoder
		var enc, dec cipher.BlockMode
		if c.enc == 0 {
			enc = cipher.NewCBCEncrypter(ac, iv)
		} else {
			enc = cbccts.NewCBCCTSEncrypter(ac, iv, c.enc)
		}
		if c.dec == 0 {
			dec = cipher.NewCBCDecrypter(ac, iv)
		} else {
			dec = cbccts.NewCBCCTSDecrypter(ac, iv, c.dec)
		}
		encBuf := make([]byte, len(c.data))
		decBuf := make([]byte, len(c.data))

		enc.CryptBlocks(encBuf, c.data) // encode
		dec.CryptBlocks(decBuf, encBuf) // decode

		if c.ok != bytes.Equal(c.data, decBuf) {
			t.Errorf("compare failed: case %d, encoder %d, decoder %d", i, c.enc, c.dec)
		}

	}

	if err != nil {
		t.Error(err)
	}
}
