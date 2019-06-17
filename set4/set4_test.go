package set4

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/sHesl/cryptopals/set1"
	"github.com/sHesl/cryptopals/set2"
	"github.com/sHesl/cryptopals/set3"
)

func Test_Challenge25_CTRRandomReadWriteAccess(t *testing.T) {
	ecbCiphertext := set1.ReadBase64File("./data/25.txt")
	plaintext := set1.AESECBDecrypt(ecbCiphertext, []byte("YELLOW SUBMARINE"))
	key := make([]byte, 32)
	rand.Read(key)

	ciphertext := set3.AESCTR(key, plaintext)

	// Using the same logic as the CBC padding oracle attack, we're going to flip the final byte from 0-255
	// until we produce a ciphertext identical to our input ciphertext. If they match, the value we selected as
	// our plaintext byte is the actual plaintext byte. Continue doing that backwards through the ciphertext
	// until we've cracked the entire input. If you want the keystream after that, just need to use the XOR
	// trick from the same challenge to reveal the keystream byte for the given plaintext/ciphertext byte combo

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

func Test_Challenge26_CTRBitFlipping(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encrypted := set3.AESCTR(key, []byte("blahblah;admin=0;blahblahblah;"))

	flipped := []byte(encrypted)
	flipped[15] = (encrypted[15] ^ '0') ^ '1'

	decrypted := set3.AESCTR(key, flipped)

	fmt.Printf("Challenge 26: Bit flipped CTR to get '%s'\n", decrypted)
}

func Test_Challenge27_CBCKeyAsIV(t *testing.T) {
	keyAndIV := make([]byte, 32)
	rand.Read(keyAndIV)

	// Here, we need 3 blocks of input (P_1 through 3), and the ability to reorder/change the ciphertext blocks
	// prior to decryption.

	// AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
	// C_1, C_2, C_3 -> C_1, 0, C_1
	// P'_1 XOR P'_3

	// The first step in CBC decryption is the first block (C_1) is decrypted, then XOR'd with the second block
	// of ciphertext (which we set to be all zeros). The final step of CBC decryption is to decrypt the final
	// block (which we also set to be C_1), then XOR it with the IV (which is actually just the key).
	// P'_1 = C_1 XOR 0
	// P'_3 = C_1 XOR KEY
	// The C_1 cancels out, and the 0 has no influence, so P'_1 XOR P'_3 only returns the key!

	input := []byte("this is our super secret input pretend we don't know it but we'll use it to get the key!")
	encrypted := set2.AESCBCEncrypt(input, keyAndIV, keyAndIV)

	// The exercise assumes an oracle that only returns the decrypted plaintext during an error, but to save
	// time I'm just going to print out only the first block of decrypted plaintext (that is all we will need).
	poisonedInput := append(encrypted[:32], append(bytes.Repeat([]byte{0}, 32), encrypted[:32]...)...)
	decrypted := set2.AESCBCDecrypt(poisonedInput, keyAndIV, keyAndIV)

	result := set1.XOR(decrypted[:32], decrypted[64:]) // imagine this was raised from an error

	if bytes.Equal(result, keyAndIV) {
		fmt.Printf("Challenge 27: Key recovered due to use as IV!\n")
	}

	// The actual exercise attempts to use the real world scenario of erroring on decryption failures, but the
	// fundamental lesson is this: if you use the key as the IV as well, an attacker with access to plaintext
	// material and ciphertext material can uncover the value of the first block (the IV aka the key).
}
