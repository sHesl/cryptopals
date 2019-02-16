package set1

import "crypto/aes"

// aesECBDecrypt splits the input into individual blocks of 128 bits and decrypts those blocks one at a time
// using the cryptographically broken Electronic Codebook Cipher.
func aesECBDecrypt(c, k []byte) []byte {
	blockLen := len(k)
	bc, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(c); i += blockLen {
		bc.Decrypt(c[i:i+blockLen], c[i:i+blockLen])
	}

	return c
}
