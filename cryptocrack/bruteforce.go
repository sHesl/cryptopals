package cryptocrack

import (
	"bytes"
)

func BruteForce(alphabet []byte, l int, pred func([]byte) bool, matches int) chan []byte {
	c := make(chan []byte)

	for _, char := range alphabet {
		go BruteForceLoopWithPrefix(c, alphabet, []byte{char}, l, pred)
	}

	out := make(chan []byte)
	go func() {
		found := 0
		finished := 0

		for result := range c {
			if result == nil {
				finished++
				if finished == len(alphabet) {
					out <- nil
					close(out)
					return
				}
				continue
			}

			out <- result
			found++

			if found == matches {
				close(out)
				return
			}
		}
	}()

	return out
}

func BruteForceLoopWithPrefix(c chan []byte, alphabet []byte, prefix []byte, l int, pred func([]byte) bool) {
	alphabetLen := len(alphabet)
	b := bytes.Repeat(alphabet[:1], l-len(prefix))
	b = append(prefix, b...)
	hit := make([]byte, l)

	prog := make([]int, l) // prog tracks the _numeric_ progress e.g [0,0,0], [0,0,1] ... [0,1,0], [0,1,1]

	for pos := l - 1; pos > len(prefix); pos-- {
		for charInc := 0; charInc <= alphabetLen-1; charInc++ {
			if pos != l-1 {
				pos++ // not currently operating on the least significant digit, shift right towards LSD
				charInc--
				continue
			}

			b[pos] = alphabet[charInc]
			if pred(b) {
				copy(hit, b)
				c <- hit
			}
			prog[pos]++
		}

		// Consult our progress array to determine our next MSD to inc and which lower digits to reset
	stateUpdate:
		for iii := l - 1; iii >= 0; iii-- {
			switch {
			case prog[iii] >= alphabetLen-1: // This digit is done, reset this digit...
				if iii == len(prefix) {
					c <- nil
					return
				}
				prog[iii] = 0
				b[iii] = alphabet[0]
			default: // We've reset all lower digits that we've scanned through, now we can increment
				prog[iii]++
				b[iii] = alphabet[prog[iii]]
				break stateUpdate
			}
		}
	}
}
