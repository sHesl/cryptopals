package set1

import (
	"bytes"
	"unicode"
)

var linotypeRanges = [][]byte{linotypeE, linotypeD, linotypeC, linotypeB, linotypeA}
var linotypeA = []byte("etaoinETAOIN")
var linotypeB = []byte("shrdluSHRDLU")
var linotypeC = []byte("cmfwypCMFWYP")
var linotypeD = []byte("vbgkjqVBGKJQ")
var linotypeE = []byte("xzXZ")

// scoreRune is a very crude frequency analysis check that highly weights spaces and characters
// deemed most frequent by linotype machine letter placements. Punctuation symbols are also considered
// resonably sensible and are weighted according to my own guestimations of frequency.
func scoreRune(r rune) int {
	if unicode.In(r, unicode.Latin) {
		for i := 0; i < len(linotypeRanges); i++ {
			if bytes.IndexRune(linotypeRanges[i], r) > -1 {
				return i + 2
			}
		}
	}

	if unicode.In(r, unicode.Space) {
		return 4
	}

	if unicode.In(r, unicode.Symbol) {
		if r == '.' || r == ',' || r == '"' || r == '\'' {
			return 2
		}

		if r == '!' || r == '?' || r == '(' || r == ')' {
			return 1
		}

		return 0
	}

	return -1
}

func ScorePlaintext(b []byte) int {
	score := 0

	for _, r := range b {
		score += scoreRune(rune(r))
	}

	splt := bytes.Split(b, []byte(" "))
	for _, s := range splt {
		if looksLikeWord(s) {
			score += 5
		}
	}

	return score
}

// looksLikeWord tries to determine if the 'middle' of a word is all characters (not just letters + symbols)
func looksLikeWord(b []byte) bool {
	isA := len(b) == 1 && b[0] == 'a'
	if isA {
		return true
	} else if len(b) == 1 {
		// If it is one character long but not an 'a', it ain't a word
		return false
	}

	// Check if the 'middle' of the word is entirely latin characters
	// we ignore the first and last characters because they very well may be symbols
	if len(b) < 3 {
		for _, r := range b {
			if !unicode.In(rune(r), unicode.Latin) {
				return false
			}
		}
	} else {
		for _, r := range b[1 : len(b)-1] {
			if !unicode.In(rune(r), unicode.Latin) {
				return false
			}
		}
	}

	return true
}
