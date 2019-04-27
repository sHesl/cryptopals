package cryptocrack

import (
	"bytes"
)

func PKCS7(b []byte, blockLen int) []byte {
	if b == nil {
		return b
	}

	if blockLen < 1 {
		return b
	}

	toPad := blockLen - (len(b) % blockLen)
	padding := bytes.Repeat([]byte{byte(toPad)}, toPad)

	return append(b, padding...)
}

func PKCS7Validate(p []byte, blockLen int) bool {
	if len(p)%blockLen != 0 {
		return false
	}

	lastByte := p[len(p)-1]
	paddingBytes := 1

	for i := paddingBytes; i < len(p)-1; i++ {
		if p[len(p)-i] == lastByte {
			continue
		}

		paddingBytes = i - 1
		break
	}

	x := int(lastByte) == paddingBytes

	return x
}

// PKCS7PaddingLength manipulates a given ciphertext to determine the length of the PKCS7 padding bytes
// that were added to fill the block. It uses a padding oracle to achieve this, by checking which is the
// byte of last byte of the ciphertext that we need to flip before we produce valid padding.
// e.g (for an eight byte block)
//   1, Flip 7: a b c d e f 0 2 - (1 bytes of 2's for padding) - INVALID
//   2, Flip 6: a b c d e 0 2 2 - (2 bytes of 2's for padding) - VALID
//
//   The first valid flip we performed was on our second iteration. This we know there was 2 bytes of
//   padding on the plaintext
//
// This will only work on unauthenticated ciphers (e.g CBC), as flipping these pre-padding bytes will
// invalidate any hashes/MACs/signatures of the plaintext.
func PKCS7PaddingLength(blockLen int, paddingOracle func(c []byte) bool, ciphertext []byte) (int, byte) {
	if len(ciphertext)%blockLen != 0 {
		return 0, byte(0) // If our ciphertext is not a complete block, assume no padding was added
	}

	padLen := 0
	for i := len(ciphertext) - 2; i > 0; i-- {
		padLen++

		// Keep a copy of the expected value of the byte we are flipping so we can reset it after this operation
		tmp := ciphertext[i]

		// Copy our ciphertext to ensure the paddingOracle does not manipulate the bytes therein
		tmpB := make([]byte, len(ciphertext))
		copy(tmpB, ciphertext)

		// We are byte-flipping to ensure the integrity of our final block
		// This means we need to poison the preceding block
		slbi := i - blockLen
		if slbi < 0 {
			return 0, byte(0) // We've ran out of slice to check, assume there was zero padding
		}

		// We poison the value of our preceding block with the value of our final block
		tmpB[slbi] = 255

		if validPadding := paddingOracle(tmpB); validPadding {
			return padLen, byte(padLen)
		}

		// Return our flipped value back to it's expected value to preserve the integrity of the block for future
		// operations. It is important the only byte that changes is the one we are using to check the padding!
		tmpB[i] = tmp
	}

	return 0, byte(0)
}
