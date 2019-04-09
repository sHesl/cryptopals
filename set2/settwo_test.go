package set2

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
)

// Implement PKCS#7 padding
func Test_Challenge9_PKCS7(t *testing.T) {
	input := []byte("YELLOW SUBMARINE")

	result := pkcs7(input, 20)

	fmt.Printf("Challenge 1: Padded = '%q'\n", result)

	expected := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(result) != expected {
		t.Fatalf("Challenge 9: Did not receive expected output. Expected %s. Got %s", expected, result)
	}
}

// Implement CBC mode by hand
func Test_Challenge10_AESCBCEncrypt(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := []byte("0000000000000000")

	encryptResult := aesCBCEncrypt([]byte("YELLOW SUBMARINEYELLOW SUBMARIN"), key, iv)
	bl, _ := aes.NewCipher(key)
	ecr := cipher.NewCBCEncrypter(bl, iv)
	expectedEncryptResult := make([]byte, len(encryptResult))
	ecr.CryptBlocks(expectedEncryptResult, pkcs7([]byte("YELLOW SUBMARINEYELLOW SUBMARIN"), len(key)))

	if !bytes.Equal(encryptResult, expectedEncryptResult) {
		t.Fatalf("Challenge 1: AES CBC ciphertext did not match Go implementation. Expected %s. Got %s",
			expectedEncryptResult, encryptResult)
	}

	expectedDecryptResult := []byte("YELLOW SUBMARINEYELLOW SUBMARIN\x01")
	decryptResult := aesCBCDecrypt(encryptResult, key, iv)

	if !bytes.Equal(decryptResult, expectedDecryptResult) {
		t.Fatalf("Challenge 1: AES CBC plaintext did not match original input. Expected %s. Got %s",
			expectedDecryptResult, decryptResult)
	}

	fmt.Printf("Challenge 10: AES CBC roundtrip successful!\n")
}

func Test_Challenge11_EncryptionOracle(t *testing.T) {
	p := []byte("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE")

	c := aesCBCOrECBEncrypt(p)

	blocks := make([][]byte, len(c)-16)
	for i := 0; i < len(c)-16; i++ {
		blocks[i] = c[i : i+16]
	}

	mode := "CBC"
	isECB := false
	for _, block := range blocks {
		isECB = bytes.Count(c, block) > 1

		if isECB {
			mode = "ECB"
			break
		}
	}

	fmt.Printf("Challenge 11: Plaintext was encrypted by %s\n", mode)
}

func Test_Challenge12_EBCDecryptByteAtATime(t *testing.T) {
	ee := newECBAppendEncrypter()

	// We want to know the length of our secret, so that we can create an input of the same length to decrypt
	secretLen := len(ee.encryptionOracle([]byte{}))

	// Make a string of 'A's of the same length of our secret, minus one. The one 'missing' byte means
	// the oracle will 'push' the first byte of our secret into this block
	curByte := secretLen - 1
	aaaas := make([]byte, curByte)
	for i := range aaaas {
		aaaas[i] = byte('A')
	}

	knownBytes := make([]byte, 0)

	for curByte > 20 {
		// Encrypt our string of A's
		curProgress := ee.encryptionOracle(aaaas)

		// Create a new crib of equal length to the number of bytes we still need to crack
		crib := make([]byte, secretLen)

		// Start by filling the crib with our A's
		copy(crib, aaaas)

		// Next, need to copy all the bytes we've successfully decrypted and add them to our 'A's at their
		// respective positions. This means if we know the first 3 bytes are D,O,G, we want our 'A's to look
		// like 'AAAAADOG_' where _ is the byte we are iterating and the length of 'A's is equal to the
		// number of bytes we still have to decrypt.
		kbi := 0
		for i := curByte; kbi < len(knownBytes); i++ {
			crib[i] = knownBytes[kbi]
			kbi++
		}

		// For the unknown byte, iterate up from 0 to 255 to find whichever one matches curProgress
		for b := byte(0); b <= byte(255); b++ {
			crib[secretLen-1] = b

			if bytes.Equal(curProgress[:secretLen], ee.encryptionOracle(crib)[:secretLen]) {
				curByte--
				aaaas = aaaas[1:] // Shorten our 'A's by one so another byte of the secret is included
				knownBytes = append(knownBytes, b)
				break
			}
		}
	}

	fmt.Printf("Challenge 12: Secret value is %s\n", string(knownBytes))
}

func Test_Challenge13_EBCCopyPasteAttack(t *testing.T) {
	e := newUserECBEncrypter()

	// First, generate a ciphertext of the actual user account we want to escalate privileges for.
	// We want the first block to consist of 'email=%s&uid=10&role=', where the word 'user' falls into the
	// second block. 'email=' + '&uid=10&role=' is 19 bytes. This means our email must be blocklen-19 (13 bytes)
	acc := e.encrypt("thirt@een.com")

	// Now, we want to find the ciphertext for just the string 'admin' that appears at the start of the block.
	// This means our email needs to contain the string 'admin', and 'admin' has to appear as the first 5 bytes
	// of the block. We can't just put this at the start of our block because 'email=' is appended.
	admin := []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxadmin")

	// We need to fix up the padding. If our second block should consist of just the word 'admin', then we should
	// add padding equal to blocklen-len("admin"). That is 27 bytes of '27'.
	for i := 0; i < 27; i++ {
		admin = append(admin, byte(27))
	}

	// The contents of the third block are irrelevant, but I've tried to mask it so that we have valid looking
	// email address for this chosen plaintext.
	admin = append(admin, []byte("@test.com")...)

	adminStr := e.encrypt(string(admin))

	// We now have two ciphertexts constructed from the following. Block end denoted via '|' and padding via '_'
	// email=thirt@een.com&uid=10&role=|user_____________
	// email=xxxxxxxxxxxxxxxxxxxxxxxxxx|admin____________|@test.com&uid=10&role=user
	// We can now cut the second block of the second ciphertext into the second block of the first ciphertext!
	spliced := acc[:32]
	spliced = append(spliced, adminStr[32:64]...)

	fmt.Printf("Challenge 13: Here is your admin account! %s\na", e.decrypt(spliced))
}

func Test_Challenge14_EBCDecryptByteAtATime(t *testing.T) {
	// I figure the nature of this challenge is to prove that if the first block contains random content,
	// and we are using ECB (where blocks are independent), we can just skip the entire first block rather
	// than try and decrypt the random content. But if we are using padding, and we can't tell how much padding
	// was applied (that would involve decrypting with the key...), how can I know how many bytes to make my
	// plaintext to ensure the first block is factored out?

	// :(

	fmt.Printf("Challenge 14: TBC\n")
}

func Test_Challenge15_PKCS7PaddingValidation(t *testing.T) {
	fmt.Printf("Challenge 15: PKCS7 Validation\n")

	input1 := []byte("ICE ICE BABY\x04\x04\x04\x04")
	fmt.Printf("%v is valid ? %v\n", input1, pkcs7Validate(input1, 16))

	input2 := []byte("ICE ICE BABY\x05\x05\x05\x05")
	fmt.Printf("%v is valid ? %v\n", input2, pkcs7Validate(input2, 16))

	input3 := []byte("ICE ICE BABY\x03\x03\x03\x03")
	fmt.Printf("%v is valid ? %v\n", input3, pkcs7Validate(input3, 16))

	input4 := []byte("ICE ICE BABY\x01\x02\x03\x04")
	fmt.Printf("%v is valid ? %v\n", input4, pkcs7Validate(input4, 16))
}

func Test_Challenge16_CBCBitflipping(t *testing.T) {
	blockLen := 16

	randomAESKey := make([]byte, blockLen)
	rand.Read(randomAESKey)

	randomIV := make([]byte, blockLen)
	rand.Read(randomIV)

	// We specifically construct a plaintext that we can flip the bytes of the preceding block to replace the
	// 0's with reserved characters. This means our poisoned block must be preceeded by a block we can destroy.
	// The reason we use 0's is because they are represented as 00000000 in binary, and therefore are easy to
	// work with when bitflipping.
	chosenPlaintext := "a block of data stuff0user0admin"
	ciphertext := cbcEncryptUserData(chosenPlaintext, randomAESKey, randomIV)

	// We need to know the location for the §'s we need to flip
	// There are 2 blocks prefixed during encryption
	// We provide 2 blocks (we need one before our user=admin block to poison)
	// Therefore, the location we need to poison is the third block
	// Since our index returns a value in the second block, add anther blockLen to it
	iFirst := strings.Index(chosenPlaintext, "0user") + blockLen
	iSecond := strings.Index(chosenPlaintext, "0admin") + blockLen

	// We also need to know which character to XOR with
	semiColonXorByte := byte('0') ^ byte(';')
	equalsXorByte := byte('0') ^ byte('=')

	// Flip the bits of our preceding block so their values XOR to produce our reserved characters
	ciphertext[iFirst] ^= semiColonXorByte
	ciphertext[iSecond] ^= equalsXorByte

	plaintext := aesCBCDecrypt(ciphertext, randomAESKey, randomIV)

	fmt.Printf("Challenge 16: Bit flipped admin! %s\n", plaintext)
}
