package cryptocrack

func CartesianEnumerator(alphabet []byte, start byte, l int) func() []byte {
	attempt := make([]byte, l)
	attempt[0] = start
	prog := make([]int, l)

	return func() []byte {
		p := attempt[:l]
		for i, xi := range prog {
			p[i] = alphabet[xi]
		}

		for i := len(prog) - 1; i >= 0; i-- {
			prog[i]++
			if prog[i] < len(alphabet) {
				break
			}

			prog[i] = 0
			if i <= 0 {
				prog = prog[0:0]
				break
			}
		}

		return p
	}
}

func Cartesian(alphabet []byte, l int, pred func([]byte) bool) chan []byte {
	c := make(chan []byte)
	prog := make([]int, l)

	go func() {
		defer close(c)
		iter(c, alphabet, prog, l, pred)
	}()

	return c
}

func iter(c chan []byte, alphabet []byte, prog []int, l int, pred func([]byte) bool) {
	attempt := make([]byte, l)
	for i, xi := range prog {
		attempt[i] = alphabet[xi]
	}

	for i := len(prog) - 1; i >= 0; i-- {
		prog[i]++
		if prog[i] < len(alphabet) {
			break
		}
		prog[i] = 0
		if i <= 0 {
			prog = prog[0:0]
			if pred(attempt) {
				c <- attempt
			}
			return
		}
	}

	if pred(attempt) {
		c <- attempt
	}

	iter(c, alphabet, prog, l, pred)
}
