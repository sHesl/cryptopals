package set6

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"

	"github.com/sHesl/cryptopals/set5"
)

func Test_Challenge41_RSAUnpaddedMessageRecovery(t *testing.T) {
	privKey, _ := rsa.GenerateKey(rand.Reader, 1024)

	// DecryptOracle pretends to be a server that RSA decrypts the incoming ciphertext. Imagine it defends
	// against message replay via a hash of the ciphertext. The only way to get it to decrypt the message is if
	// is the first time we've seen that message.
	decryptOracle := func(c []byte) []byte {
		return set5.RSADecrypt(*privKey, c)
	}

	// Imagine we've captured this ciphertext in transit, but the server has already decrypted it. If we want it
	// to decrypt it once more, we need to change the ciphertext.
	ciphertext := set5.RSAEncrypt(privKey.PublicKey, []byte(`recover me!!!!`))

	// In this scenario, we can 're-encrypt' the ciphertext using the public key
	pubKey := privKey.PublicKey
	c1 := new(big.Int).SetBytes(ciphertext)

	// se = S**E mod N
	// C2 = (se * C1) mod N
	s := big.NewInt(25) // s can be anything > 1 mod N
	se := new(big.Int).Exp(s, big.NewInt(int64(pubKey.E)), pubKey.N)

	c2 := new(big.Int)
	c2.Mul(se, c1)
	c2.Mod(c2, pubKey.N)

	p2 := new(big.Int).SetBytes(decryptOracle(c2.Bytes()))

	// P1 = P2/S mod N
	p1 := new(big.Int).Mul(p2, new(big.Int).ModInverse(s, pubKey.N))
	p1.Mod(p1, pubKey.N).Bytes()

	if bytes.Equal(p1.Bytes(), []byte(`recover me!!!!`)) {
		fmt.Printf("Challenge 41: Recovered plaintext by re-encrypting RSA ciphertext + decrypt oracle\n")
	}
}

func Test_Challenge42_BleichenbacherE3Attack(t *testing.T) {
	weakKey := set5.RSAKeyGen() // We need a key with e=3
	message := []byte(`this is the message we are forging the signature for`)

	validSig := RSASignSHA256(&weakKey, message)

	hm := sha256.Sum256(message)
	goImplSig, _ := rsa.SignPKCS1v15(rand.Reader, &weakKey, crypto.SHA256, hm[:])

	if !bytes.Equal(validSig, goImplSig) {
		t.Fatalf("Your RSA PKCS1v15 signing implemention is not correct!")
	}

	if err := rsa.VerifyPKCS1v15(&weakKey.PublicKey, crypto.SHA256, hm[:], validSig); err != nil {
		t.Fatalf("Your RSA signature was not verified by official go implemention")
	}

	if !DodgeyRSAVerifySHA256(&weakKey.PublicKey, message, validSig) {
		t.Fatalf("Your DodgeyRSAVerifySHA256 did not respect a valid sig")
	}

	if DodgeyRSAVerifySHA256(&weakKey.PublicKey, message, validSig[1:]) {
		t.Fatalf("Your DodgeyRSAVerifySHA256 did not reject an invalid sig")
	}

	fakeSig := []byte{0x00, 0x01, 0x00}
	fakeSig = append(fakeSig, sha256ANS1...)
	fakeSig = append(fakeSig, hm[:]...)

	// fill the block with 0xffs. It must be the highest byte to ensure the cube root value is sufficiently
	// large enough for all of the corruption (aka the bytes of discrepency between the valid sig and our fake)
	// occur AFTER the message hash, which a bad implementation will not verify!
	padLen := weakKey.Size() - len(fakeSig)
	fakeSig = append(fakeSig, bytes.Repeat([]byte{0xff}, padLen)...)

	// Instead of doing RSAEncrypt on our signature, we just cube root it. This value will be much larger than
	// the valid signature, but as the verifier is not checking the contents beyond the hash, they will not
	// realise this!
	root := CubeRoot(new(big.Int).SetBytes(fakeSig))

	// VALID:   00 01 | 0xff... | ANSI | HASH
	// INVALID: 00 01 01 | ANSI | HASH | 0xff...
	// CHECK:  |_______________________|         // a bad implementation only checks up to hash, and not beyond

	if DodgeyRSAVerifySHA256(&weakKey.PublicKey, message, root.Bytes()) {
		fmt.Printf("Challenge 42: Forged an RSA signature via Bleichenbacher e=3 attack!\n")
	}
}

func Test_Challenge43_DSAKeyRecoveryFromNonce(t *testing.T) {
	key := NewDSAKey()
	m := []byte(`testing DSA signing and verifying works`)
	r, sig := key.Sign(m)

	if !key.Verify(m, r, sig) {
		t.Fatal("DSA signing and verification not implemented correctly")
	}

	if key.Verify(m[1:], r, sig) {
		t.Fatal("DSA signing and verification not implemented correctly")
	}

	// Now we've verified our DSA is implemented correctly, let's try and crack a weak K
	y, _ := new(big.Int).SetString("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", 16)
	r, _ = new(big.Int).SetString("548099063082341131477253921760299949438196259240", 10)
	s, _ := new(big.Int).SetString("857042759984254168557880549501802188789837994940", 10)

	m = []byte(`For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
`)

	x := BruteForceViaWeakK(m, r, s, y)
	xHex := fmt.Sprintf("%x", x)
	xDigest := fmt.Sprintf("%x", sha1.Sum([]byte(xHex)))

	if xDigest == "0954edd5e0afe5542a4adf012611a91912a3ec16" {
		fmt.Printf("Challenge 43: Cracked a DSA private component via weak K! x = %X\n", x.Bytes())
	}
}

func Test_Challenge44_DSANonceReuse(t *testing.T) {
	type signedMessage struct {
		msg []byte
		r   string
		s   string
		m   []byte
	}

	messages := []signedMessage{
		{
			msg: []byte("Listen for me, you better listen for me now. "),
			s:   "1267396447369736888040262262183731677867615804316",
			r:   "1105520928110492191417703162650245113664610474875",
			m:   []byte("a4db3de27e2db3e5ef085ced2bced91b82e0df19"),
		}, {
			msg: []byte("Listen for me, you better listen for me now. "),
			s:   "29097472083055673620219739525237952924429516683",
			r:   "51241962016175933742870323080382366896234169532",
			m:   []byte("a4db3de27e2db3e5ef085ced2bced91b82e0df19"),
		}, {
			msg: []byte("When me rockin' the microphone me rock on steady, "),
			s:   "277954141006005142760672187124679727147013405915",
			r:   "228998983350752111397582948403934722619745721541",
			m:   []byte("21194f72fe39a80c9c20689b8cf6ce9b0e7e52d4"),
		}, {
			msg: []byte("Yes a Daddy me Snow me are de article dan. "),
			s:   "1013310051748123261520038320957902085950122277350",
			r:   "1099349585689717635654222811555852075108857446485",
			m:   []byte("1d7aaaa05d2dee2f7dabdc6fa70b6ddab9c051c5"),
		}, {
			msg: []byte("But in a in an' a out de dance em "),
			s:   "203941148183364719753516612269608665183595279549",
			r:   "425320991325990345751346113277224109611205133736",
			m:   []byte("6bc188db6e9e6c7d796f7fdd7fa411776d7a9ff"),
		}, {
			msg: []byte("Aye say where you come from a, "),
			s:   "502033987625712840101435170279955665681605114553",
			r:   "486260321619055468276539425880393574698069264007",
			m:   []byte("5ff4d4e8be2f8aae8a5bfaabf7408bd7628f43c9"),
		}, {
			msg: []byte("People em say ya come from Jamaica, "),
			s:   "1133410958677785175751131958546453870649059955513",
			r:   "537050122560927032962561247064393639163940220795",
			m:   []byte("7d9abd18bbecdaa93650ecc4da1b9fcae911412"),
		}, {
			msg: []byte("But me born an' raised in the ghetto that I want yas to know, "),
			s:   "559339368782867010304266546527989050544914568162",
			r:   "826843595826780327326695197394862356805575316699",
			m:   []byte("88b9e184393408b133efef59fcef85576d69e249"),
		}, {
			msg: []byte("Pure black people mon is all I mon know. "),
			s:   "1021643638653719618255840562522049391608552714967",
			r:   "1105520928110492191417703162650245113664610474875",
			m:   []byte("d22804c4899b522b23eda34d2137cd8cc22b9ce8"),
		}, {
			msg: []byte("Yeah me shoes a an tear up an' now me toes is a show a "),
			s:   "506591325247687166499867321330657300306462367256",
			r:   "51241962016175933742870323080382366896234169532",
			m:   []byte("bc7ec371d951977cba10381da08fe934dea80314"),
		}, {
			msg: []byte("Where me a born in are de one Toronto, so "),
			s:   "458429062067186207052865988429747640462282138703",
			r:   "228998983350752111397582948403934722619745721541",
			m:   []byte("d6340bfcda59b6b75b59ca634813d572de800e8f"),
		},
	}

	y := new(big.Int)
	y.SetString("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", 16)

	for i, msg1 := range messages {
		for ii, msg2 := range messages {
			if i == ii {
				continue
			}

			// r = (g^^k mod p) mod q
			// so if k (the nonce) is reused across two messages, r will also be the same!
			if msg1.r == msg2.r {
				s1, s2 := new(big.Int), new(big.Int)
				s1.SetString(msg1.s, 10)
				s2.SetString(msg2.s, 10)

				r := new(big.Int)
				r.SetString(msg1.r, 10)
				// s = (k^^-1 * (H(m)+xr)) mod q
				// So in the nonce reuse scenarios, x,r,k and q are all identical between signings. If we have the
				// original message as well, we can compute H(m), so we have every element except x. We just need to
				// factor out these values (and calculate the distance between the two hashes) to reveal x.
				x := CrackPrivKeyFromReusedK(msg1.msg, msg2.msg, s1, s2, r)

				xHex := fmt.Sprintf("%x", x)
				xDigest := fmt.Sprintf("%x", sha1.Sum([]byte(xHex)))

				if xDigest == "ca8f6f7c66fa362d40760d135b763eb8527d3d52" {
					fmt.Printf("Challenge 44: Cracked a DSA private component via reused K! x = %X\n", x.Bytes())
					return
				}
			}
		}
	}
}

func Test_Challenge45_DSADodgeyParams(t *testing.T) {
	key := NewDSAKey()

	r, s := key.SignWithCustomParams([]byte(`uh oh, g is zero!`), dsaP, dsaQ, bigZero) // r == 0

	anyMessageValidates := key.VerifyWithCustomParams([]byte(`message has changed!`), r, s, dsaP, dsaQ, bigZero)

	if !anyMessageValidates {
		t.Fatalf("when g=0, all signatures should pass validation")
	}

	msg := []byte(`this message can be verified without x because of magic g!`)

	r, s = key.MagicSignature()

	magicG := new(big.Int).Add(dsaP, bigOne) // this is the magic number that enables magic signatures!
	magicSignatureVerified := key.VerifyWithCustomParams(msg, r, s, dsaP, dsaQ, magicG)

	if magicSignatureVerified {
		fmt.Printf("Challenge 45: Used magic G to DSA sign message without x!\n")
	}
}

func Test_Challenge46_RSAParityOracle(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 1024)

	oddOracle := func(x *big.Int) bool {
		plaintext := set5.RSADecrypt(*priv, x.Bytes())
		y := new(big.Int)
		y.SetBytes(plaintext)

		mod2 := y.Mod(y, big.NewInt(2))

		return mod2.Cmp(bigZero) != 0
	}

	secretB64 := "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
	secret, _ := base64.StdEncoding.DecodeString(secretB64)
	s := set5.RSAEncrypt(priv.PublicKey, secret)
	c := new(big.Int).SetBytes(s)

	e := big.NewInt(int64(priv.PublicKey.E))
	factor := big.NewInt(2) // start from 2, but we will x2 this every round

	// our plaintext exists somewhere within the bound [0, N]
	upperBound := priv.N
	lowerBound := big.NewInt(0)

	bitLen := len(c.Bytes()) * 8 // We need to do this once per bit of the message

	for i := 0; i < bitLen; i++ {
		// N is a prime (and therefore odd), so we have to multiply our ciphertext by a multiple of 2, otherwise
		// it would always be false! Since our parity oracle decrypts the contents, we can't just do ciphertext*f,
		// we need to do c * enc(f). We can use the public key to encrypt the factor.
		enc2 := new(big.Int).Exp(factor, e, priv.PublicKey.N)
		cf := new(big.Int).Mul(c, enc2) // original ciphertext * our factor

		// Each round, we learn whether our cf/n wraps the modulus (even), or doesn't (odd).
		// If it does wrap the modulus, the real plaintext lies below that value.
		// If it doesn't, the real plaintext lies above that value.
		// We can then narrow our total range down by either raising the lower bound (odd case)
		// Or lowering the upper bound (even case).
		newBound := new(big.Int).Add(upperBound, lowerBound)
		newBound.Div(newBound, bigTwo)

		if odd := oddOracle(cf); odd {
			lowerBound = newBound
		} else {
			upperBound = newBound
		}

		// As we narrow our bounds, we need to increase the amount of time we multiply our ciphertext to force the
		// ciphertext to fold over N more and more times (for example, folding over 3 times = odd, folding over 8
		// times = even).
		factor.Mul(factor, bigTwo)
	}

	fmt.Printf("Challenge 46: Cracked RSA encrypted ciphertext via parity oracle. \n\t"+
		"Message: '%s'\n", lowerBound.Bytes())
}
