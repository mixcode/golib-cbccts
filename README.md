# cbccts : A CBC encrypter/decrypter in CTS mode

Go Package cbccts is a block cipher CBC encrypter/decrypter in Ciphertext stealing (CTS) mode.
CTS is a mode to handle arbitrary-length data. In other words, CTS can handle data not aligned to a block boundary.

The encoder/decoder is compatible with Go standard cipher package's cipher.BlockMode interface.

See https://en.wikipedia.org/wiki/Ciphertext_stealing for info.


## Example

```Go

import (
    "crypto/aes"
    "github.com/mixcode/golib-cbccts"
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
}

```

