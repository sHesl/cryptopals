package set1

func xor(b1, b2 []byte) []byte {
	for i, b := range b1 {
		b2[i] = b ^ b2[i]
	}

	return b2
}

func singleCharacterXOR(b []byte, char rune) []byte {
	result := make([]byte, len(b))
	for i, r := range b {
		result[i] = r ^ byte(char)
	}

	return result
}

func singleByteXORDecipher(b []byte) (string, rune) {
	plaintext := ""
	mostLikelyRune := rune('a')
	highestScore := -100

	for r := '\x00'; r < '\xff'; r++ {
		pt := singleCharacterXOR(b, r)
		score := scorePlaintext(pt)

		if score > highestScore {
			highestScore = score
			mostLikelyRune = r
			plaintext = string(pt)
		}
	}

	return plaintext, mostLikelyRune
}

func repeatingKeyXOR(plaintext, key string) string {
	output := make([]byte, len(plaintext))

	for i := 0; i < len(plaintext); {
		for _, r := range key {
			output[i] = plaintext[i] ^ byte(r)
			i++

			if i >= len(plaintext) {
				break
			}
		}
		if i >= len(plaintext) {
			break
		}
	}

	return string(output)
}
