package set1

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
)

// Convert the given hex string into base64
func Test_Challenge1_HexToBase64(t *testing.T) {
	h := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	b, _ := hex.DecodeString(h)

	result := base64.StdEncoding.EncodeToString(b)

	fmt.Printf("Challenge 1: Base64 = %s\n", result)

	expected := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
	if result != expected {
		t.Fatalf("Challenge 1: Did not receive expected output. Expected %s. Got %s", expected, result)
	}
}

// Write a function that takes two equal-length buffers and produces their XOR combination.
func Test_Challenge2_FixedXOR(t *testing.T) {
	b1, _ := hex.DecodeString("1c0111001f010100061a024b53535009181c")
	b2, _ := hex.DecodeString("686974207468652062756c6c277320657965")

	result := XOR(b1, b2)
	resultHex := hex.EncodeToString(result)

	fmt.Printf("Challenge 2: Hex = %s\n", resultHex)

	expected := "746865206b696420646f6e277420706c6179"
	if resultHex != expected {
		t.Fatalf("Challenge 2: Did not receive expected output. Expected %s. Got %s", expected, resultHex)
	}
}

// This hex encoded string has been XOR'd against a single character.
// Find the key, decrypt the message.
func Test_Challenge3_SingleByteXOR(t *testing.T) {
	b, _ := hex.DecodeString("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	plaintext, mostLikelyRune := singleByteXORDecipher(b)

	fmt.Printf("Challenge 3: Plaintext = '%s', Rune = %q\n", plaintext, mostLikelyRune)
}

// One of the 60-character strings in this file has been encrypted by single-character XOR.
// Find it.
func Test_Challenge4_DetectSingleByteXOR(t *testing.T) {
	f, err := os.OpenFile("./data/4.txt", os.O_RDONLY, os.ModePerm)
	defer f.Close()

	if err != nil {
		panic(err)
	}

	plaintext := ""
	mostLikelyRune := rune('a')
	highestScore := -100

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		b, err := hex.DecodeString(scanner.Text())
		if err != nil {
			continue
		}

		potentialPlaintext, potentialRune := singleByteXORDecipher(b)
		lineScore := scorePlaintext([]byte(potentialPlaintext))

		if lineScore > highestScore {
			highestScore = lineScore
			mostLikelyRune = potentialRune
			plaintext = string(potentialPlaintext)
		}
	}

	fmt.Printf("Challenge 4: Plaintext = '%s', Rune = %q\n", strings.Replace(plaintext, "\n", "", -1), mostLikelyRune)
}

// Here is the opening stanza of an important work of the English language...
// Encrypt it, under the key "ICE", using repeating-key XOR.
func Test_Challenge5_RepeatedKeyXOR(t *testing.T) {
	result := repeatingKeyXOR("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal", "ICE")
	resultHex := hex.EncodeToString([]byte(result))

	fmt.Printf("Challenge 5: Ciphertext = '%s'\n", resultHex)

	expected := "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20690a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

	if resultHex != expected {
		t.Fatalf("Challenge 5: Did not receive expected output. Expected:\n%s\n. Got:\n%s\n", expected, resultHex)
	}
}

// There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
// Decrypt it.
func Test_Challenge6_CrackRepeatedKeyXOR(t *testing.T) {
	b := readBase64File("./data/6.txt")

	// Attempt to determine our key length by finding the minimum hamming distances for different block lengths.
	// Shortest average distance suggests the likely block length.
	keyLen := hammingBlock(b, 15)

	// Split our input into blocks for the given position in the block (i.e first block is comprised from
	// the first character of every block, second block is second character of every block etc)
	blocks := make([][]byte, keyLen)
	for i, r := range b {
		blocks[i%keyLen] = append(blocks[i%keyLen], r)
	}

	// Now we have split our inputs into blocks by character position, we attempt to crack each position
	// individually using our single-byte XOR cracker
	letters := make([]string, 0, keyLen)
	for _, block := range blocks {
		_, l := singleByteXORDecipher(block)
		letters = append(letters, string(l))
	}

	// Combine each of our cracked single-byte XOR characters into a single key, ready to cracking our ciphertext
	key := strings.Join(letters, "")

	plaintext := repeatingKeyXOR(string(b), key)

	fmt.Printf("Challenge 6: Key = '%s' Plaintext = '%s...'\n", key, plaintext[:111])
}

func Test_Challenge7_AESECBDecrypt(t *testing.T) {
	b := readBase64File("./data/7.txt")

	plaintext := AESECBDecrypt(b, []byte("YELLOW\x20SUBMARINE"))

	fmt.Printf("Challenge 7: Plaintext ='%s...'\n", plaintext[:111])
}

func Test_Challenge8_DetectAESECB(t *testing.T) {
	f, err := os.Open("./data/8.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	l := 1
	found := false
	for scanner.Scan() {
		b, _ := hex.DecodeString(scanner.Text())
		for i := 0; i < len(b); i += 16 {
			bl := b[i : i+16]

			if bytes.Count(b, bl) > 1 {
				// duplicate 16 byte block! Suggests the plaintext has duplicate blocks
				found = true
				break
			}
		}

		if found {
			break
		}

		l++
	}

	fmt.Printf("Challenge 8: Line = %d\n", l)
}
