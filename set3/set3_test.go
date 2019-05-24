package set3

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/sHesl/cryptopals/cryptocrack"
	"github.com/sHesl/cryptopals/set1"
	"github.com/sHesl/cryptopals/set2"
)

// Pick, at random, a string from the set provided, encrypt it with a random AES key/IV and then prove you can
// decrypt it via a CBC padding oracle attack.
func Test_Challenge17_CBCPaddingOracle(t *testing.T) {
	blockLen := 16

	ciphertext, key, iv := encryptRandomString(16) // Encrypt a random string under a random key/iv
	plaintext := make([]byte, len(ciphertext))     // We'll populate this with the bytes we've cracked as we go

	// Now we want to try and crack the contents of ciphertext, using only a padding oracle.
	// Let's define our padding oracle here (this should be the last place we 'know' the key!)
	paddingOracle := func(c, iv []byte) bool {
		result := set2.ASCBCDecrypt(c, key, iv)
		valid := set2.PKCS7Validate(result, blockLen)
		return valid
	}

	// First, we want to understand how many bytes of padding are already applied to our plaintext. This gives
	// us our starting state we need to know so we can successfully 'repad' our plaintext.
	padLen, padByte := cryptocrack.PKCS7PaddingLength(blockLen, func(c []byte) bool {
		return paddingOracle(c, iv)
	}, ciphertext)

	for i := len(plaintext) - padLen; i < len(plaintext); i++ {
		plaintext[i] = padByte
	}

	plaintextByte := len(plaintext) - padLen - 1

	// Now we are ready to being!
	//
	// For each block (going backwards, starting from the final block)...
	for blockIndex := len(plaintext) / blockLen; blockIndex > 0; blockIndex-- {
		// ...consider only our current block, and the preceding block
		blockToCrack, _ := cryptocrack.NthBlock(ciphertext, blockLen, blockIndex)

		// ... if we run out of preceding blocks, use the IV instead (as it is functionally the same as block 0)
		var blockToPoison []byte
		if blockIndex-1 > 0 {
			blockToPoison, _ = cryptocrack.NthBlock(ciphertext, blockLen, blockIndex-1)
		} else {
			blockToPoison = iv
		}

		blocksDone := (len(plaintext) / blockLen) - blockIndex

		// ... for each byte in those blocks
		for byteIndex := blockLen - padLen - 1; byteIndex >= 0; byteIndex-- {
			// ... 'repad' our plaintext by flipping bits in our poisoned block (this requires knowledge of the
			// corresponding plaintext bytes we've already cracked!). e.g xxx55555 becomes xxx66666
			blockToRepad := make([]byte, len(blockToPoison))
			copy(blockToRepad, blockToPoison)

			for rePad := blockLen - padLen; rePad < blockLen; rePad++ {
				plaintextI := (len(plaintext) - ((blocksDone)+1)*blockLen) + rePad
				intermediary := blockToRepad[rePad] ^ plaintext[plaintextI]
				intermediaryMask := intermediary ^ (padByte + 1)
				blockToRepad[rePad] = intermediaryMask
			}

			// ... now we can begin iterating over our unknown byte until we produce valid padding
			cracked := false
			for b := byte(0); b < byte(255); b++ {
				blockToCrackCopy, blockToPoisonCopy := make([]byte, blockLen), make([]byte, blockLen)
				copy(blockToCrackCopy, blockToCrack)
				copy(blockToPoisonCopy, blockToRepad)

				blockToPoisonCopy[byteIndex] = b

				// We provide our poisoned block as our IV (block 0), and only a single block of ciphertext (block 1)
				// to our padding oracle. If the value we poisoned in block 0 decrypts to produce valid padding in our
				// ciphertext block, we can calculate the intermediary byte (and thus this byte of plaintext!)
				valid := paddingOracle(blockToCrackCopy, blockToPoisonCopy)

				if valid {
					cracked = true
					// If we have valid padding, that means we know what value our intermediate byte is.
					// XOR this to our original (unpoisoned) ciphertext byte to reveal our plaintext byte
					intermediateByte := b ^ (padByte + 1)
					plaintext[plaintextByte] = intermediateByte ^ blockToPoison[byteIndex]
					break
				}
			}

			if !cracked {
				// Sometimes, we just don't get valid padding. I should really try and figure our why that is...
				// Just use the poisoned block, this allows us to keep going (though we will lose this block)
				plaintext[plaintextByte] = blockToPoison[byteIndex]
			}

			plaintextByte--
			padLen++
			padByte++
		}

		// We've finished this block, reset our padding length and byte back to zero
		padLen = 0
		padByte = byte(0)
	}

	plaintext = bytes.ReplaceAll(plaintext, []byte{11}, []byte{}) // Don't print newline padding

	fmt.Printf("Challenge 17: Cracked via padding oracle - %s\n", plaintext)
}

// Decrypt the given string, encrypted under the key 'YELLOW SUBMARINE' via AES CTR
func Test_Challenge18_CTRDecrypt(t *testing.T) {
	ciphertextB64 := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	ciphertext, _ := base64.StdEncoding.DecodeString(ciphertextB64)

	plaintext := aesCTR([]byte("YELLOW SUBMARINE"), ciphertext)

	fmt.Printf("Challenge 18: Plaintext - %s\n", plaintext)
}

// 19 was supposed to show us the weakness of using a fixed nonce in CTR mode (i.e always starting at zero),
// but it is hard to look past the small scale leakage of plaintext material via substitution when nonce reuse
// can be catastrophically broken by encrypting a 'zerod' string and XORing the results
func Test_Challenge19_CTRFixedNonce1(t *testing.T) {
	p, _ := base64.StdEncoding.DecodeString("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==")
	k := make([]byte, 32)
	rand.Read(k)

	c1 := aesCTR(k, p)

	zeros := bytes.Repeat([]byte("0"), len(p))
	c2 := aesCTR(k, zeros)

	xord := set1.XOR([]byte(c2), []byte(c1))
	result := set1.XOR(xord, zeros)

	fmt.Printf("Challenge 19: Cracked via exploiting fixed nonce - %s\n", result)
}

// 20 is easily solved using the solution to 19 as well...
func Test_Challenge20_CTRFixedNonce2(t *testing.T) {
	p, _ := base64.StdEncoding.DecodeString("QW5kIGNvdW50IG91ciBtb25leSAvIFlvLCB3ZWxsIGNoZWNrIHRoaXMgb3V0LCB5byBFbGk=")
	k := make([]byte, 32)
	rand.Read(k)

	c1 := aesCTR(k, p)

	zeros := bytes.Repeat([]byte("0"), len(p))
	c2 := aesCTR(k, zeros)

	xord := set1.XOR([]byte(c2), []byte(c1))
	result := set1.XOR(xord, zeros)

	fmt.Printf("Challenge 20: Cracked via exploiting fixed nonce - %s\n", result)
}
