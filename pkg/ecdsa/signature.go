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

func (sig Signature) RecoveryId() byte {
	r := sig.R.(*curve.Secp256k1Point)
	s := sig.S.(*curve.Secp256k1Scalar)

	var recid byte = 0

	if !r.HasEvenY() {
		recid = 1;
	}

	if s.Value().IsOverHalfOrder() {
		recid ^= 1
	}

	//fmt.Println("Recid")
	//fmt.Println(recid)
	//fmt.Println("Recid")

	return recid
}

func (sig Signature) SigEthereum() ([]byte, error) {
	IsOverHalfOrder := sig.S.IsOverHalfOrder() // s-values greater than secp256k1n/2 are considered invalid

	if IsOverHalfOrder {
		sig.S.Negate()
	}

	r, err := sig.R.MarshalBinary()
	if err != nil {
		return nil, err
	}
	s, err := sig.S.MarshalBinary()
	if err != nil {
		return nil, err
	}

	rs := make([]byte, 0, 65)
	rs = append(rs, r...)
	rs = append(rs, s...)

	if IsOverHalfOrder {
		v := rs[0] - 2 // Convert to Ethereum signature format with 'recovery id' v at the end.
		copy(rs, rs[1:])
		rs[64] = v ^ 1
	} else {
		v := rs[0] - 2
		copy(rs, rs[1:])
		rs[64] = v
	}

	r[0] = rs[64] + 2
	if err := sig.R.UnmarshalBinary(r); err != nil {
		return nil, err
	}

	return rs, nil
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
