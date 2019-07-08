package set5

import "math/big"

// CRT3 performs the Chinese Remainder Theorem for the 3 given remainders (r's) and their moduli (m's)
func CRT3(r1, r2, r3, m1, m2, m3 *big.Int) *big.Int {
	// Calculate the product of all our moduli...
	N := new(big.Int)
	N.Mul(m1, m2)
	N.Mul(N, m3)

	// ...our n's...
	n1 := new(big.Int).Div(N, m1)
	n2 := new(big.Int).Div(N, m2)
	n3 := new(big.Int).Div(N, m3)

	// ...and our x's...
	x1 := new(big.Int).ModInverse(n1, m1)
	x2 := new(big.Int).ModInverse(n2, m2)
	x3 := new(big.Int).ModInverse(n3, m3)

	// ...then calculate the product of all of these seperate elements (individually first)...
	rnx1, rnx2, rnx3 := new(big.Int), new(big.Int), new(big.Int)
	rnx1.Mul(new(big.Int).Mul(r1, n1), x1) // r1*n1*x1
	rnx2.Mul(new(big.Int).Mul(r2, n2), x2) // r2*n2*x2
	rnx3.Mul(new(big.Int).Mul(r3, n3), x3) // r3*n3*x3

	// ...then sum all those products together...
	X := new(big.Int).Add(new(big.Int).Add(rnx1, rnx2), rnx3)

	// ...finally, we can do X mod N!
	return new(big.Int).Mod(X, N)
}
