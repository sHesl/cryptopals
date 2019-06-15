package set4

import (
	"github.com/sHesl/cryptopals/set3"
)

func aesCTREdit(key, ciphertext []byte, offset int, newValue []byte) []byte {
	plaintext := []byte(set3.AESCTR(key, ciphertext))
	updatedPlaintext := append(plaintext[:offset], newValue...)

	newCiphertext := set3.AESCTR(key, updatedPlaintext)

	return []byte(newCiphertext)
}
