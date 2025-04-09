package main

import (
	"fmt"
	"math/big"
)

func babyStepGiantStep(g, h, p *big.Int) *big.Int {
	one := big.NewInt(1)
	m := new(big.Int).Sqrt(p)
	m.Add(m, one) // m = sqrt(p) + 1

	// Baby steps
	babySteps := make(map[string]*big.Int)
	current := big.NewInt(1)

	for j := int64(0); j < m.Int64(); j++ {
		babySteps[current.String()] = big.NewInt(j)
		current.Mul(current, g).Mod(current, p)
	}

	// g^-m mod p
	gm := new(big.Int).Exp(g, m, p)
	gm.ModInverse(gm, p)
	if gm == nil {
		fmt.Println("Modular inverse failed. g might not be invertible mod p.")
		return nil
	}

	// Giant steps
	y := new(big.Int).Set(h)
	for i := int64(0); i < m.Int64(); i++ {
		if j, ok := babySteps[y.String()]; ok {
			ix := new(big.Int).Mul(big.NewInt(i), m)
			return ix.Add(ix, j)
		}
		y.Mul(y, gm).Mod(y, p)
	}

	return nil // No solution found
}

func main() {
	// You can change these inputs as needed
	gStr := "12"
	hStr := "155"
	pStr := "227"

	// Parse big integers
	g := new(big.Int)
	h := new(big.Int)
	p := new(big.Int)
	g.SetString(gStr, 10)
	h.SetString(hStr, 10)
	p.SetString(pStr, 10)

	// Run BSGS
	x := babyStepGiantStep(g, h, p)
	if x != nil {
		fmt.Printf("Solution: x = %s\n", x.String())
	} else {
		fmt.Println("No solution found.")
	}
}
