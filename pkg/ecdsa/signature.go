package ecdsa

import (
	dcrm256k1 "github.com/anyswap/FastMulThreshold-DSA/crypto/secp256k1"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
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

	toECDSA := sig.R.ToECDSA()
	recoverId := byte(dcrm256k1.Get_ecdsa_sign_v(toECDSA.X, toECDSA.Y))

	sigbytes := append(rb[1:], sb...)
	sigbytes = append(sigbytes, recoverId)
	return sigbytes, nil
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
