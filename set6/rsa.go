package set6

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"

	"github.com/sHesl/cryptopals/set5"
)

// pkcs1v15.go contains precomuted ANS1 digests for numerous hashes, I've copied the SHA256 one
var sha256ANS1 = []byte{
	0x30, 0x31, 0x30, 0x0d, 0x06,
	0x09, 0x60, 0x86, 0x48, 0x01,
	0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x20,
}

func RSASignSHA256(privKey *rsa.PrivateKey, m []byte) []byte {
	// 00 01 | 0xff... | 00  | ANSI | HASH
	// 0  1  | 2-203   | 204 | 205  | 225
	sig := make([]byte, privKey.Size())
	sig[0] = 0x00
	sig[1] = 0x01

	ffPos := 2
	ffLen := privKey.Size() - 32 - len(sha256ANS1) - 3 // privKey size - digest len - ANS1 len - (1 - ffPos)
	copy(sig[ffPos:ffPos+ffLen], bytes.Repeat([]byte{0xff}, ffLen))

	ansiPos := ffLen + ffPos + 1
	ansiLen := len(sha256ANS1)
	sig[ansiPos-1] = 0x00 // we need a zero byte before our ansi digest
	copy(sig[ansiPos:ansiPos+ansiLen], sha256ANS1)

	hashPos := privKey.Size() - 32 // privKey size - sha256 digest len
	hash := sha256.Sum256(m)
	copy(sig[hashPos:], hash[:])

	return set5.RSADecrypt(*privKey, sig)
}

// DodgeyRSAVerifySHA256 performs a signature validation on m, using the known RSA verification vulnerability
// of skipping to the 00 byte prefixing the hash type, as well as not actually checking the final bytes of the
// signature, and instead stops after the hash func digest len.
// This allows a signature of '00 01 00 ANSI HASH GARBAGE' to pass verification!
func DodgeyRSAVerifySHA256(pubKey *rsa.PublicKey, m, sig []byte) bool {
	encrypted := set5.RSAEncrypt(*pubKey, sig)
	encrypted = append([]byte{0x00}, encrypted...)

	hashIndex := bytes.Index(encrypted, sha256ANS1) + len(sha256ANS1)
	if hashIndex == -1 {
		return false
	}

	// 32 = len of sha256 digest
	if hashIndex+32 > len(encrypted)+1 {
		return false
	}

	// Here, we're skipping straight to the hash, and ignoring any bytes after the hash.
	// A secure implementation would verify EVERY BYTE of the signature!
	sigHash := encrypted[hashIndex : hashIndex+32]
	expHash := sha256.Sum256(m)

	return bytes.Equal(sigHash, expHash[:])
}
