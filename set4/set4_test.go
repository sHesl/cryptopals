package set4

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/sHesl/cryptopals/set1"
	"github.com/sHesl/cryptopals/set3"
)

func Test_Challenge25_CTRRandomReadWriteAccess(t *testing.T) {
	ecbCiphertext := set1.ReadBase64File("./data/25.txt")
	plaintext := set1.AESECBDecrypt(ecbCiphertext, []byte("YELLOW SUBMARINE"))
	key := make([]byte, 32)
	rand.Read(key)

	ciphertext := set3.AESCTR(key, plaintext)

	// Using the same logic as the CBC Bitflipping attack, we're going to flip the final byte from 0-255 until
	// we produce a ciphertext identical to our input ciphertext. If they match, the value we placed at the
	// final position XOR'd with the keystream byte produces our ciphertext byte (aka b ^ X = result where we
	// have b and X).

	knownBytes := make([]byte, len(ciphertext))
	numCrackedBytes := 0
	for i := len(ciphertext) - 1; i >= 0; i-- {
		crackedBytes := knownBytes[len(ciphertext)-numCrackedBytes:]

		for b := byte(0); b < byte(255); b++ {
			output := aesCTREdit(key, []byte(ciphertext), i, append([]byte{b}, crackedBytes...))

			if string(output) == ciphertext {
				knownBytes[i] = b
				numCrackedBytes++
				break
			}
		}
	}

	if bytes.Equal(plaintext, knownBytes) {
		fmt.Printf("Challenge 25: Cracked 'random access/edit' CTR!\n")
	}
}
