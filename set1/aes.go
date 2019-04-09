package set1

import "crypto/aes"

// AESECBDecrypt splits the input into individual blocks of 128 bits and decrypts those blocks one at a time
// using the cryptographically broken Electronic Codebook Cipher.
func AESECBDecrypt(c, k []byte) []byte {
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

func AESECBEncrypt(p, k []byte) []byte {
	blockLen := len(k)
	bc, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}

	for i := 0; i < len(p); i += blockLen {
		bc.Encrypt(p[i:i+blockLen], p[i:i+blockLen])
	}

	return p
}
