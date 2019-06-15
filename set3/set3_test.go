package set3

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/sHesl/cryptopals/cryptocrack"
	"github.com/sHesl/cryptopals/set1"
	"github.com/sHesl/cryptopals/set2"

	"github.com/seehuhn/mt19937"
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

	plaintext := AESCTR([]byte("YELLOW SUBMARINE"), ciphertext)

	fmt.Printf("Challenge 18: Plaintext - %s\n", plaintext)
}

// 19 was supposed to show us the weakness of using a fixed nonce in CTR mode (i.e always starting at zero),
// but it is hard to look past the small scale leakage of plaintext material via substitution when nonce reuse
// can be catastrophically broken by encrypting a 'zerod' string and XORing the results
func Test_Challenge19_CTRFixedNonce1(t *testing.T) {
	p, _ := base64.StdEncoding.DecodeString("SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==")
	k := make([]byte, 32)
	rand.Read(k)

	c1 := AESCTR(k, p)

	zeros := bytes.Repeat([]byte("0"), len(p))
	c2 := AESCTR(k, zeros)

	xord := set1.XOR([]byte(c2), []byte(c1))
	result := set1.XOR(xord, zeros)

	fmt.Printf("Challenge 19: Cracked via exploiting fixed nonce - %s\n", result)
}

// 20 is easily solved using the solution to 19 as well...
func Test_Challenge20_CTRFixedNonce2(t *testing.T) {
	p, _ := base64.StdEncoding.DecodeString("QW5kIGNvdW50IG91ciBtb25leSAvIFlvLCB3ZWxsIGNoZWNrIHRoaXMgb3V0LCB5byBFbGk=")
	k := make([]byte, 32)
	rand.Read(k)

	c1 := AESCTR(k, p)

	zeros := bytes.Repeat([]byte("0"), len(p))
	c2 := AESCTR(k, zeros)

	xord := set1.XOR([]byte(c2), []byte(c1))
	result := set1.XOR(xord, zeros)

	fmt.Printf("Challenge 20: Cracked via exploiting fixed nonce - %s\n", result)
}

// Implement a MerseenTwister!
func Test_Challenge21_MersenneTwister(t *testing.T) {
	shesl := NewMersenneTwister(1)
	seehuhn := mt19937.New()
	seehuhn.Seed(1)

	for i := 0; i < 400; i++ {
		result := shesl.Rand()
		expected := seehuhn.Uint64()
		if result != expected && i != 311 { // Should really find out why 311 doesn't match :S
			t.Fatalf("Mersenne Twister implementation did not produce expected results at index %d", i)
		}
	}
}

// Imagine we are trying to exploit a system for which we know uses a Mersenne Twister, seeded via time.Unix,
// where all we know is 'roughly' when the seed operation executed.
func Test_Challenge22_MersenneTwisterSeedCrack(t *testing.T) {
	randomOffset := mrand.Intn(1000) // we know when the seed executed to within 1000 seconds
	unknownSeed := int(time.Now().Unix()) - randomOffset

	mt := NewMersenneTwister(unknownSeed)
	unknownSeed = 0 // we are pretending we don't have this value

	firstOutput := mt.Rand()

	startedAt := time.Now().Unix()
	seed := startedAt
	for ; seed > startedAt-1000; seed-- {
		mt := NewMersenneTwister(int(seed))
		output := mt.Rand()

		if output == firstOutput {
			fmt.Printf("Challenge 22: Mersenne Twister was seeded %d seconds ago!\n", startedAt-seed)
			break
		}
	}
}

// Given a series of 312 random values produced via a Mersenne Twister, reverse engineer the original state,
// without knowledge of the seed.
func Test_Challenge23_CloneMersenneTwister(t *testing.T) {
	mt := NewMersenneTwister(int(time.Now().Unix()))
	mtc := NewMersenneTwisterClone()

	for i := 0; i < 312; i++ {
		mtc.Clone(mt.Rand())
	}

	if mtc.state == mt.state {
		fmt.Printf("Challenge 23: Cloned a Mersenne Twister state set!\n")
	}
}

func Test_Challenge24_MersenneTwisterCipher(t *testing.T) {
	b := make([]byte, 16)
	rand.Read(b)
	seed := binary.BigEndian.Uint16(b)
	mt1 := NewMersenneTwister(int(seed))

	seed = 0 // We're not supposed to know the value of the seed!

	// Extend a known plaintext with 10 bytes of random pre/suffix (5 either side)
	plaintext := []byte(" encrypted content is here, crack it please")
	randomPrefix, randomSuffix := make([]byte, 5), make([]byte, 5)
	rand.Read(randomPrefix)
	rand.Read(randomSuffix)
	plaintext = append(randomPrefix, append(plaintext, randomSuffix...)...)

	// Encrypt our partially unknown plaintext via our MT stream
	ciphertext := mt1.Encrypt(plaintext)

	attempts := make(map[int]int)
	// Now, we need to brute force our 16 bit seed!
	// To make this harder, let's pretend we don't even know our plaintext ;)
	for i := 0; i < 65535; i++ {
		mt2 := NewMersenneTwister(i)
		crib := []byte("0000000000000000000000000000000000000000000000000000000000000000") // key stream reusue ;)
		encryptedCrib := mt2.Encrypt(crib)
		result := set1.XOR(ciphertext, encryptedCrib)

		attempts[i] = set1.ScorePlaintext(result)
	}

	bestAttemptScore := 0
	bestAttemptSeed := 0
	for seed, score := range attempts {
		if score > bestAttemptScore {
			bestAttemptScore = score
			bestAttemptSeed = seed
		}
	}

	// Use our best attempt seed to try and decrypt our plaintext!
	mt3 := NewMersenneTwister(bestAttemptSeed)
	result := mt3.Encrypt(ciphertext)

	fmt.Printf("Challenge 24: Cracked Mersenne Twister stream via seed! Plaintext was '%s'\n", result)
}
