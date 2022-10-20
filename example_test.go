package cbccts_test

import (
	"bytes"
	"crypto/aes"
	"fmt"

	"github.com/mixcode/golib-cbccts"
)

var (
	key, iv, data []byte
)

func Example() {
	// Prepare a block-mode cipher.
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	// Create an CBC CTS encrypter
	modeEnc := cbccts.NewCBCCTSEncrypter(block, iv, cbccts.CS3)
	encoded := make([]byte, len(data))
	// run the encrypter
	modeEnc.CryptBlocks(encoded, data)

	// create an CBC CTS decrypter
	modeDec := cbccts.NewCBCCTSDecrypter(block, iv, cbccts.CS3)
	decoded := make([]byte, len(data))
	// run the decrypter
	modeDec.CryptBlocks(decoded, encoded)

	// compare results
	fmt.Println(bytes.Equal(data, decoded))

	// Output:
	// true
}

func init() {
	key = make([]byte, 0x20) // AES-256
	for i := 0; i < len(key); i++ {
		key[i] = byte(i)
	}

	iv = make([]byte, aes.BlockSize)
	for i := 0; i < len(iv); i++ {
		iv[i] = byte(i * 2)
	}

	data = make([]byte, 0x54) // random size
	for i := 0; i < len(data); i++ {
		data[i] = byte(i * 7)
	}
}
