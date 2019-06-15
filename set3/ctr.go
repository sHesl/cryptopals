package set3

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
)

func AESCTR(key []byte, input []byte) string {
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

	inputLen += bs - (inputLen % bs) // Ensure we've got a full block

	keystream := make([]byte, inputLen)
	ctrB := make([]byte, block.BlockSize())      // ctr as a LitteEndian []byte
	ctrI := binary.LittleEndian.Uint16(ctrB[8:]) // ctr as a LitteEndian uint16

	for i := 0; i < len(keystream); i += bs {
		block.Encrypt(keystream[i:i+block.BlockSize()], ctrB)
		ctrI++
		binary.LittleEndian.PutUint16(ctrB[8:], ctrI)
	}

	return keystream
}
