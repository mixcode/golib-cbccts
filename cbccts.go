/*
	cbccts.go
	2021-05, github.com/mixcode
*/

/*
	Package cbccts is a block cipher CBC encrypter/decrypter in Ciphertext stealing (CTS) mode.
	CTS is a mode to handle arbitrary-length data. In other words, CTS can handle data not aligned to a block boundary.

	The encoder/decoder is compatible with Go standard cipher package's cipher.BlockMode interface.

	See https://en.wikipedia.org/wiki/Ciphertext_stealing for info.
*/
package cbccts

import (
	"crypto/cipher"
	"fmt"
)

// Data transmission format of CTS ciphertext.
type Format int

const (
	CS1 Format = 1 // A partial block precedes a full block. compatible with non-CTS encoding.
	CS2 Format = 2 // If the data is aligned at block size, then use CS1, otherwise use CS3.
	CS3 Format = 3 // A full block precedes a partial block.
)

// CBC-CTS-Decrypter is a cipher.BlockMode interface which decrypts ciphers in CBC-CTS mode.
// CTS means "Ciphertext Stealing", an encoding scheme for data not aligned for block boundaries; i.e. arbitrary length data.
type cbccts struct {
	encoder bool // if true, use
	block   cipher.Block
	codec   cipher.BlockMode
	mode    Format
}

func (cd *cbccts) BlockSize() int {
	return cd.codec.BlockSize()
}

// NewCBCCTSEncrypter creates a new CBC-CTS encrypter, compatible with cipher.BlockMode.
func NewCBCCTSEncrypter(b cipher.Block, iv []byte, mode Format) cipher.BlockMode {
	if mode < CS1 || mode > CS3 {
		panic(fmt.Errorf("invalid mode"))
	}
	return &cbccts{
		encoder: true,
		block:   b,
		codec:   cipher.NewCBCEncrypter(b, iv),
		mode:    mode,
	}
}

// NewCBCCTSDecrypter creates a new CBC-CTS decrypter, compatible with cipher.BlockMode
func NewCBCCTSDecrypter(b cipher.Block, iv []byte, mode Format) cipher.BlockMode {
	if mode < CS1 || mode > CS3 {
		panic(fmt.Errorf("invalid mode"))
	}
	return &cbccts{
		encoder: false,
		block:   b,
		codec:   cipher.NewCBCDecrypter(b, iv),
		mode:    mode,
	}
}

// Execute the cipher work
func (cd *cbccts) CryptBlocks(dst, src []byte) {
	if cd.encoder {
		cd.encode(dst, src)
	} else {
		cd.decode(dst, src)
	}
}

// decrypt text in CBC-CTS mode
func (cd *cbccts) encode(dst, src []byte) {
	blocksz := cd.codec.BlockSize()
	textlen := len(src)
	leftover := textlen % blocksz

	if leftover == 0 { // text aligned at block size
		cd.codec.CryptBlocks(dst, src)

		switch cd.mode {

		case CS1, CS2:
			// No final block swapping
			return

		case CS3:
			// mode CS3: Swap the last two blocks
			py, pz := textlen-2*blocksz, textlen-blocksz
			tmp := make([]byte, blocksz)
			copy(tmp, dst[py:pz])
			copy(dst[py:pz], dst[pz:])
			copy(dst[pz:], tmp)
			return

		default:
			panic(fmt.Errorf("invalid mode"))
		}
	}

	padding := blocksz - leftover
	buflen := textlen + padding
	py, pz := buflen-2*blocksz, buflen-blocksz

	if py < 0 {
		// data smaller than a block
		panic(fmt.Errorf("data size too small; must be larger than one block"))
	}

	// encrypt aligned blocks
	cd.codec.CryptBlocks(dst[:py], src[:py])

	// process last two blocks
	tmp := make([]byte, 2*blocksz)
	copy(tmp[:blocksz+leftover], src[py:])
	cd.codec.CryptBlocks(tmp, tmp)

	switch cd.mode {
	case CS1:
		// retain the block order: partial blck precedes full block
		copy(dst[py:py+leftover], tmp[:leftover]) // copy partial block
		copy(dst[py+leftover:], tmp[blocksz:])    // copy full block
	case CS2, CS3:
		// swap last two blocks and make the full block precedes the partial block
		copy(dst[py:pz], tmp[blocksz:]) // copy the last full block
		copy(dst[pz:], tmp[:leftover])  // copy partial block
	}
}

// decrypt text in CBC-CTS mode
func (cd *cbccts) decode(dst, src []byte) {

	blocksz := cd.codec.BlockSize()
	textlen := len(src)

	leftover := textlen % blocksz
	if leftover == 0 { // src aligned at block boundary
		switch cd.mode {

		case CS1, CS2:
			// No final block swapping
			cd.codec.CryptBlocks(dst, src)
			return

		case CS3:
			// mode CS3: Swap the last two blocks
			py, pz := textlen-2*blocksz, textlen-blocksz
			copy(dst[:py], src[:py])
			copy(dst[py:pz], src[pz:])
			copy(dst[pz:], src[py:pz])
			cd.codec.CryptBlocks(dst, dst)
			return

		default:
			panic(fmt.Errorf("invalid mode"))
		}
	}

	padding := blocksz - leftover
	buflen := textlen + padding
	py, pz := buflen-2*blocksz, buflen-blocksz

	if py < 0 { // data smaller than a block
		panic(fmt.Errorf("data size too small; must be larger than one block"))
	}

	// encrypt aligned blocks
	cd.codec.CryptBlocks(dst[:py], src[:py])

	tmp := make([]byte, 2*blocksz)

	switch cd.mode {
	case CS1:
		// in mode CS1, the partial block precedes a full block
		copy(tmp[:leftover], src[py:py+leftover])
		// there are paddings between the partial block and the last full block
		copy(tmp[blocksz:], src[py+leftover:])
	case CS2, CS3:
		// in mode CS2(not aligned in block) and CS3, a full block procedes the partial block
		copy(tmp[:leftover], src[pz:])  // move the partial block to [last-1] block
		copy(tmp[blocksz:], src[py:pz]) // move the full block to the last
	default:
		panic(fmt.Errorf("invalid mode"))
	}

	// decrypt the last full block, in ECB mode
	D := make([]byte, blocksz)
	cd.block.Decrypt(D, tmp[blocksz:])

	// Overlay the decrypted portion with the partial block
	for i := leftover; i < blocksz; i++ {
		tmp[i] = D[i]
	}

	// run the decrypter
	cd.codec.CryptBlocks(tmp, tmp)
	copy(dst[py:], tmp)
}
