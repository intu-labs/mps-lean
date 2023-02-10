package ecdsa

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/w3-key/mps-lean/pkg/math/curve"
)

type Signature struct {
	R curve.Point
	S curve.Scalar
}

// EmptySignature returns a new signature with a given curve, ready to be unmarshalled.
func EmptySignature(group curve.Curve) Signature {
	return Signature{R: group.NewPoint(), S: group.NewScalar()}
}

// Marshal marshals a signature to a byte slice.
func (sig Signature) ToEthBytes() ([]byte, error) {
	rb, err := sig.R.MarshalBinary()

	if err != nil {
		return nil, err
	}

	sb, err := sig.S.MarshalBinary()

	if err != nil {
		return nil, err
	}

	recoverId := sig.GetRecoverIdIntu()

	sigbytes := append(rb[1:], sb...)
	sigbytes = append(sigbytes, recoverId)
	return sigbytes, nil
}

func (sig Signature) GetRecoverIdIntu() byte {
	toECDSA := sig.R.ToECDSA()
	stringY := fmt.Sprint(toECDSA.Y)
	a := strings.Split(stringY, "")
	s := a[len(a)-1]
	i, _ := strconv.Atoi(s)
	finalV := i % 2
	return byte(finalV)
}

// Verify is a custom signature format using curve data.
func (sig Signature) Verify(X curve.Point, hash []byte) bool {
	group := X.Curve()
	m := curve.FromHash(group, hash)
	sInv := group.NewScalar().Set(sig.S).Invert()
	mG := m.ActOnBase()
	r := sig.R.XScalar()
	rX := r.Act(X)
	R2 := mG.Add(rX)
	R2 = sInv.Act(R2)
	return R2.Equal(sig.R)
}
