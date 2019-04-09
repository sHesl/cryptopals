package set2

import (
	"crypto/rand"
	"encoding/base64"
	mrand "math/rand"

	"github.com/sHesl/cryptopals/set1"
)

type ecbAppendEncrypter struct {
	key []byte
}

func newECBAppendEncrypter() *ecbAppendEncrypter {
	k := make([]byte, 32)
	rand.Read(k)

	return &ecbAppendEncrypter{key: k}
}

// encryptionOracle encrypts the given plaintext, but only *after* prependeding a secret b64 string
// It uses the same key for every operation, allowing for byte-at-a-time decryption.
func (e *ecbAppendEncrypter) encryptionOracle(p []byte) []byte {
	toAppendB64 := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`

	toAppend, _ := base64.StdEncoding.DecodeString(toAppendB64)

	p = append(p, toAppend...)

	p = pkcs7(p, len(e.key))

	return set1.AESECBEncrypt(p, e.key)
}

// encryptionOracleRandomised encrypts the given plaintext, but only *after* appending a secret b64 string
// It uses the same key for every operation, allowing for byte-at-a-time decryption.
func (e *ecbAppendEncrypter) encryptionOracleRandomised(p []byte) []byte {
	// Add between 0 and 20 bytes of random noise
	randI := int(mrand.Float32() * 20)
	randomPrefix := make([]byte, randI)
	rand.Read(randomPrefix)

	toAppendB64 := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`

	toAppend, _ := base64.StdEncoding.DecodeString(toAppendB64)

	p = append(randomPrefix, p...)
	p = append(p, toAppend...)

	p = pkcs7(p, len(e.key))

	return set1.AESECBEncrypt(p, e.key)
}
