package set7

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/sHesl/cryptopals/cryptocrack"
	"github.com/sHesl/cryptopals/set1"
)

func Test_Challenge49_CBCMACForgery(t *testing.T) {
	key, iv := make([]byte, 32), make([]byte, 16)

	rand.Read(key)
	rand.Read(iv)

	pad := func(p []byte) []byte {
		lenToPad := 16 - len(p)%16
		if lenToPad == 16 {
			return p
		}

		for i := 0; i < lenToPad; i++ {
			p = append(p, uint8(lenToPad))
		}
		return p
	}

	client := func(msg, iv []byte) []byte {
		block, _ := aes.NewCipher(key)
		cbc := cipher.NewCBCEncrypter(block, iv)
		msg = pad(msg)
		cbc.CryptBlocks(msg, msg)

		return cryptocrack.LastBlock(msg, block.BlockSize())
	}

	srv := func(msg, iv, mac []byte) bool {
		block, _ := aes.NewCipher(key)
		cbc := cipher.NewCBCEncrypter(block, iv)
		msg = pad(msg)
		cbc.CryptBlocks(msg, msg)

		return bytes.Equal(mac, cryptocrack.LastBlock(msg, block.BlockSize()))
	}

	testCiphertext := []byte(`just checking client-server interaction works`)
	mac := client(testCiphertext, iv)
	if !srv(testCiphertext, iv, mac) {
		t.Fatalf("basic client-server CBC MAC verification implemented incorrectly")
	}

	// Ok, so we are in complete control of the IV, our goal is to 'zero out' the first block of our message,
	// aka the 'from' component. If we zero this block out, the resulting message will always be the same,
	// regardless of the account we specified in the 'from' section.

	// message format is `from=#{from_id}&to=#{to_id}&amount=#{amount}`

	// fromBlock must be exactly 1 block long, and represents an account we don't control
	fromBlock := []byte(`from=moneybagzzz`)

	// If we encrypt this block with a zero IV, it becomes simply enc(msg) rather than (enc(msg) XOR IV)
	// This gives us a block of 'pure' ciphertext, before the XOR.
	zeroIV := make([]byte, 16)
	fromBlockEncrypted := client(fromBlock, zeroIV)

	// `from=.......&to=....&amount=.......`
	// | 1st block | rest of the blocks |... (we only need to poison the first block since that is the 'from')
	freeMoneyReq := append(fromBlock, []byte(`&to=shesl&amount=1000000`)...)

	// Now, when we sign this message, our first block is going to be zerod out entirely, the signature is only
	// going to verify the 2nd block onwards! We could prove this by repeating the process for another 'from'.
	forgedMAC := client(freeMoneyReq, fromBlockEncrypted)

	differentFromBlock := []byte(`from=ezzzzzzzzzz`)
	differentFromBlockEncrypted := client(differentFromBlock, zeroIV)
	freeMoneyReq2 := append(differentFromBlock, []byte(`&to=shesl&amount=1000000`)...)
	forgedMAC2 := client(freeMoneyReq2, differentFromBlockEncrypted)

	// Assert the signatures are identical despite two different 'from' values.
	if !bytes.Equal(forgedMAC, forgedMAC2) {
		t.Fatalf("changes in 'from' account produce different signatures!")
	}

	// new message format: from=#{from_id}&tx_list=#{transactions}
	// For this part of the exercise, the IV is fixed; it starts at zero and increments each operation. If we
	// only do 1 operation though, then we have a predicable (and therefore reuseable!) IV.
	genuineMessage := []byte(`from=acct1&tx_list=acct2:10;acct3:100;acct4:121;`)
	genuineMAC := client(genuineMessage, zeroIV) // we intercept this operation

	extension := []byte(`shesl:1000000;`)
	extension = pad(extension)

	// Our genuine MAC represents the state of the encryption cipher after encrypting the original message. If
	// the message was longer, this output would be XOR'd with the next block, and then encrypted to produce the
	// next block (in our case, this will be the final block, aka the signature!).
	xord := set1.XOR(genuineMAC, extension)

	// this is where the attacks falls down, we'd need the victim to sign our extension, which isn't particuarly
	// likely imo...
	xordMAC := client(xord, zeroIV)

	fakeMessage := []byte(`from=acct1&tx_list=acct2:10;acct3:100;acct4:121;shesl:1000000;`)
	fakeMessage = pad(fakeMessage)

	valid := srv(fakeMessage, zeroIV, xordMAC)

	if !valid {
		t.Fatalf("expected forged MAC to be valid")
	}

	fmt.Printf("Challenge 49: Forged CBC MAC signature via length extension!\n")
}
