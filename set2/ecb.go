package set2

import (
	"crypto/rand"
	"encoding/base64"
	mrand "math/rand"

	"github.com/sHesl/cryptopals/set1"
)

type ecbAppendEncrypter struct {
	key          []byte
	randomPrefix []byte
}

func newECBAppendEncrypter() *ecbAppendEncrypter {
	k := make([]byte, 32)
	rand.Read(k)

	randI := int(mrand.Float32()*30) + 1
	prefix := make([]byte, randI)
	rand.Read(prefix)

	return &ecbAppendEncrypter{key: k, randomPrefix: prefix}
}

// encryptionOracle encrypts the given plaintext, but only *after* prependeding a secret b64 string
// It uses the same key for every operation, allowing for byte-at-a-time decryption.
func (e *ecbAppendEncrypter) encryptionOracle(p []byte) []byte {
	toAppendB64 := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`

	toAppend, _ := base64.StdEncoding.DecodeString(toAppendB64)

	p = append(p, toAppend...)

	p = PKCS7(p, len(e.key))

	return set1.AESECBEncrypt(p, e.key)
}

// encryptionOracleRandomised encrypts the given plaintext, but only *after* appending the secret b64 prefix
// It uses the same key *and prefix* for every operation, allowing for byte-at-a-time decryption.
func (e *ecbAppendEncrypter) encryptionOracleRandomised(p []byte) []byte {
	p = append(e.randomPrefix, p...)

	toAppendB64 := `Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK`
	toAppend, _ := base64.StdEncoding.DecodeString(toAppendB64)

	p = append(p, toAppend...)

	p = PKCS7(p, len(e.key))

	return set1.AESECBEncrypt(p, e.key)
}
