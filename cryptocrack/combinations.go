package cryptocrack

// CombinationsFromSets produces every possible ordered combination from the two given sets
func CombinationsFromSets(setA, setB [][]byte) [][]byte {
	superset := make([][][]byte, 2)
	superset[0] = make([][]byte, len(setA))
	superset[1] = make([][]byte, len(setB))

	for a := range setA {
		superset[0][a] = setA[a]
	}

	for b := range setB {
		superset[1][b] = setB[b]
	}

	result := make([][]byte, len(setA)*len(setB))
	for i := 0; i < len(result)-1; i++ {
		result[i] = make([]byte, 0)
		ba := BitArray(i)
		selections := make([]int, len(setA)-len(ba))
		selections = append(selections, ba...)

		for ii, s := range selections {
			result[i] = append(result[i], superset[s][ii]...)
		}
	}

	return result
}
