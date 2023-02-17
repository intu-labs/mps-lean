package polynomial_test

import (
	"testing"

	"github.com/cronokirby/saferith"
	"github.com/stretchr/testify/assert"
	"github.com/w3-key/mps-lean/pkg/math/curve"
	"github.com/w3-key/mps-lean/pkg/math/polynomial"
	"github.com/w3-key/mps-lean/pkg/test"
)

func TestLagrange(t *testing.T) {
	group := curve.Secp256k1{}

	N := 10
	allIDs := test.PartyIDs(N)
	coefsEven := polynomial.Lagrange(group, allIDs)
	coefsOdd := polynomial.Lagrange(group, allIDs[:N-1])
	sumEven := group.NewScalar()
	sumOdd := group.NewScalar()
	one := group.NewScalar().SetNat(new(saferith.Nat).SetUint64(1))
	for _, c := range coefsEven {
		sumEven.Add(c)
	}
	for _, c := range coefsOdd {
		sumOdd.Add(c)
	}
	assert.True(t, sumEven.Equal(one))
	assert.True(t, sumOdd.Equal(one))
}
