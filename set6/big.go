package set6

import "math/big"

func CubeRoot(i *big.Int) *big.Int {
	// Shameless copy-paste from https://github.com/FiloSottile/mostly-harmless/blob/master/cryptopals/set5.go
	// This is just a cube-root implementation for big nums.
	result := new(big.Int).Rsh(i, uint(i.BitLen())/3*2)

	for {
		d := new(big.Int).Exp(result, big.NewInt(3), nil)
		d.Sub(d, i)
		d.Div(d, big.NewInt(3))
		d.Div(d, result)
		d.Div(d, result)
		if d.Sign() == 0 {
			break
		}
		result.Sub(result, d)
	}

	for new(big.Int).Exp(result, big.NewInt(3), nil).Cmp(i) < 0 {
		result.Add(result, big.NewInt(1))
	}
	for new(big.Int).Exp(result, big.NewInt(3), nil).Cmp(i) > 0 {
		result.Sub(result, big.NewInt(1))
	}

	return result
}
