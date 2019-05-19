package set3

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

func aesCTR(key []byte, input []byte) string {
	block, _ := aes.NewCipher(key)
	keystream := genKeystream(block, len(input))

	result := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		result[i] = keystream[i] ^ input[i]
	}

	return string(result)
}

func genKeystream(block cipher.Block, inputLen int) []byte {
	bs := block.BlockSize()

	extraBlock := 0 // even if our input isn't perfectly divisible by blockLen, we need a full final block
	if (inputLen/bs)%bs != 0 {
		extraBlock = bs
	}

	keystream := make([]byte, ((inputLen/bs)*bs)+extraBlock)
	ctrB := make([]byte, block.BlockSize())      // ctr as a LitteEndian []byte
	ctrI := binary.LittleEndian.Uint16(ctrB[8:]) // ctr as a LitteEndian uint16

	for i := 0; i < len(keystream); i += bs {
		block.Encrypt(keystream[i:i+block.BlockSize()], ctrB)
		ctrI++
		binary.LittleEndian.PutUint16(ctrB[8:], ctrI)
	}

	return keystream
}
