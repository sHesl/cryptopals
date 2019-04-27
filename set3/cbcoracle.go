package set3

import (
	"crypto/rand"
	"encoding/base64"
	mrand "math/rand"
	"time"

	"github.com/sHesl/cryptopals/set2"
)

func encryptRandomString(blockLen int) (ciphertext, key, iv []byte) {
	randomStrings := []string{
		"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
		"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
		"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
		"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
		"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
		"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
		"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
		"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
		"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
		"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
	}

	key, iv = make([]byte, blockLen), make([]byte, blockLen)
	rand.Read(key)
	rand.Read(iv)

	// Pick one of our random strings, pad it with PKCS7, then encrypt it
	mrand.Seed(time.Now().UnixNano())
	randomInputB64 := randomStrings[mrand.Intn(9)]
	randomInput, _ := base64.StdEncoding.DecodeString(randomInputB64)

	ciphertext = set2.AESCBCEncrypt(randomInput, key, iv)

	return ciphertext, key, iv
}
