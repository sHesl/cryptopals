package set7

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"sync"
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

	// this is where the attacks falls down, we'd need the victim to sign our extension, which isn't
	// particularly likely imo...
	xordMAC := client(xord, zeroIV)

	fakeMessage := []byte(`from=acct1&tx_list=acct2:10;acct3:100;acct4:121;shesl:1000000;`)
	fakeMessage = pad(fakeMessage)

	valid := srv(fakeMessage, zeroIV, xordMAC)

	if !valid {
		t.Fatalf("expected forged MAC to be valid")
	}

	fmt.Printf("Challenge 49: Forged CBC MAC signature via length extension!\n")
}

func Test_Challenge50_CBCMACHashForgery(t *testing.T) {
	// So, we're trying to forge a message with a certain hash. Since the hash is just the final block of
	// encrypted plaintext, we need to include our desired alert, then some arbitrary final block, so that the
	// final block encrypts to produce the desired hash. Since we have already encrypted our target block, we
	// know the input that will be XOR'd with the mystery plaintext during the final block encryption.
	// Our goal is to find z where 'enc(alertCiphertext XOR z) = target hash'

	// To do this, we need to start from our final output, and determine the intermediate value that was passed
	// in before the XOR operation. This will simply be decryptCBC(ciphertext, key)
	cbcYellowSubDecrypt := func(ciphertext []byte) []byte {
		block, _ := aes.NewCipher([]byte(`YELLOW SUBMARINE`))
		result := make([]byte, len(ciphertext))
		block.Decrypt(result, ciphertext)

		return result
	}

	// We then determine the expected hash for the 'good' input...
	cbcMACYellowSub := func(msg []byte) []byte {
		block, _ := aes.NewCipher([]byte(`YELLOW SUBMARINE`))
		cbc := cipher.NewCBCEncrypter(block, make([]byte, 16))
		cbc.CryptBlocks(msg, msg)

		return cryptocrack.LastBlock(msg, block.BlockSize())
	}

	originalAlert := []byte("alert('MZA who was that?');;;;;;")
	originalHash := cbcMACYellowSub(originalAlert)

	// ...as well as reversing our final hash to produce the intermediate value for our last block
	intermediateValue := cbcYellowSubDecrypt(originalHash)

	// Next, we need to know our preceding blocks output; this is the value that will be XOR'd with our mystery
	// plaintext to produce the expected hash.
	encryptedTarget := cbcMACYellowSub([]byte("alert('Ayo, the Wu is back!');;;"))

	// To calculate our mystery value, we need to XOR our encrypted output, and our intermediate value
	poisonedBlock := set1.XOR(encryptedTarget, intermediateValue)

	collision := append([]byte("alert('Ayo, the Wu is back!');;;"), poisonedBlock...)

	result := cbcMACYellowSub(collision)

	if bytes.Equal(result, originalHash) {
		fmt.Printf("Challenge 50: Forced a CBC MAC collision via ciphertext manipulation!\n")
	}
}

func Test_Challenge51_CompressionRatioSideChannelAttack(t *testing.T) {
	reqB := []byte(`POST / HTTP/1.1
Host: cryptopals.com
Cookie: sessionid=XXXXX
Content-Length: 86
this is the body of the request, contents don't matter, but being longer makes this easier
because the chance of false positives from equivalent compression lengths decreases`)
	placeholderCookie := []byte("XXXXX")

	formatReq := func(cookie []byte) []byte {
		return bytes.Replace(reqB, placeholderCookie, cookie, 1)
	}

	compress := func(req []byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write(req)
		zw.Close()

		return buf.Bytes()
	}

	encryptAES := func(b []byte) []byte {
		key, iv := make([]byte, 32), make([]byte, 16)
		rand.Read(key)
		rand.Read(iv)

		cc, _ := aes.NewCipher(key)
		stream := cipher.NewCTR(cc, iv)
		stream.XORKeyStream(b, b)

		return b
	}

	compressionOracle := func(cookie []byte) int {
		return len(encryptAES(compress(formatReq(cookie))))
	}

	// This takes quite a while lol, trimming the size of the cookie and the charset so the test can complete.
	// Less chars means waaaayy more collisions, but this at least demonstrates the point.
	cookie := []byte("aecaga")
	charset := []byte("abcdefgh")
	targetLen := compressionOracle(cookie)

	// We're going to get a lot of false positives/negatives, keep a track of any options that compress
	allOptions := make(map[string]interface{})

	// If the cookie we try compresses to the same length, it _could_ be valid
	matchFn := func(b []byte) bool { return compressionOracle(b) == targetLen }

	var wg sync.WaitGroup
	var mut sync.Mutex

	wg.Add(len(charset))

	for _, char := range charset {
		go func(c byte) {
			n := cryptocrack.CartesianEnumerator(charset, c, len(cookie))

			for {
				if option := n(); matchFn(option) {
					mut.Lock()
					allOptions[string(option)] = struct{}{}
					mut.Unlock()
				} else if len(option) == 0 || option[0] != c {
					wg.Done()
					break
				}
			}
		}(char)
	}

	wg.Wait()

	if _, ok := allOptions[string(cookie)]; ok {
		fmt.Printf("Challenge 51: Determined valid session cookie via compression oracle!\n")
	}
}
