package cryptocrack

import "math/bits"

// BitArray turns a unit64 into a slice of bits (0 or 1), revealing which bits (at which positions) are set
func BitArray(i int) []int {
	result := make([]int, bits.Len(uint(i)))
	mask := 1

	for ii := len(result) - 1; ii >= 0; ii-- {
		if i&mask == mask {
			result[ii] = 1
		}
		mask *= 2
	}

	return result
}
