package set2

import (
	"crypto/aes"
	"crypto/rand"
	mathrand "math/rand"
	"time"

	"github.com/sHesl/cryptopals/set1"
)

func aesCBCEncrypt(p, k, iv []byte) []byte {
	blockLen := len(k)
	bc, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}

	p = pkcs7(p, blockLen)

	for i := 0; i < len(p); i += blockLen {
		var prevBlock []byte
		if i == 0 {
			prevBlock = iv
		} else {
			prevBlock = p[i-blockLen : i]
		}

		curBlockStart := i
		curBlockEnd := i + blockLen
		xordBlock := set1.XOR(prevBlock, p[curBlockStart:curBlockEnd])

		for ii, b := range xordBlock {
			p[ii+curBlockStart] = b
		}

		bc.Encrypt(p[curBlockStart:curBlockEnd], p[curBlockStart:curBlockEnd])
	}

	return p
}

func aesCBCDecrypt(p, k, iv []byte) []byte {
	blockLen := len(k)
	bc, err := aes.NewCipher(k)
	if err != nil {
		panic(err)
	}

	for i := len(p); i >= blockLen; i -= blockLen {
		curBlockStart := i - blockLen
		curBlockEnd := i

		bc.Decrypt(p[curBlockStart:curBlockEnd], p[curBlockStart:curBlockEnd])

		var prevBlock []byte
		if i == blockLen {
			prevBlock = iv
		} else {
			prevBlock = p[curBlockStart-blockLen : curBlockStart]
		}

		xordBlock := set1.XOR(prevBlock, p[curBlockStart:curBlockEnd])

		for ii, b := range xordBlock {
			p[curBlockStart+ii] = b
		}
	}

	return p
}

func aesCBCOrECBEncrypt(p []byte) []byte {
	k := make([]byte, 16)
	rand.Read(k)

	padN := mathrand.Intn(5) + 5
	pad := make([]byte, padN)
	rand.Read(pad)
	p = append(pad, p...) // chuck in some random padding to the start of our plaintext...
	p = append(p, pad...) // and some to the end of our ciphertext

	mathrand.Seed(time.Now().UnixNano())
	n := mathrand.Intn(2)
	if n == 0 {
		iv := make([]byte, 16)
		rand.Read(iv)

		return aesCBCEncrypt(p, k, iv)
	}

	return set1.AESECBEncrypt(p, k)
}
