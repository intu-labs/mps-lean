package zkdec

import (
	"crypto/rand"

	"github.com/cronokirby/saferith"
	"github.com/w3-key/mps-lean/pkg/hash"
	"github.com/w3-key/mps-lean/pkg/math/arith"
	"github.com/w3-key/mps-lean/pkg/math/curve"
	"github.com/w3-key/mps-lean/pkg/math/sample"
	"github.com/w3-key/mps-lean/pkg/paillier"
	"github.com/w3-key/mps-lean/pkg/pedersen"
)

type Public struct {
	// C = Enc₀(y;ρ)
	C *paillier.Ciphertext

	// X = y (mod q)
	X curve.Scalar

	// Prover = N₀
	Prover *paillier.PublicKey
	Aux    *pedersen.Parameters
}

type Private struct {
	// Y = y
	Y *saferith.Int

	// Rho = ρ
	Rho *saferith.Nat
}

type Commitment struct {
	// S = sʸ tᵘ
	S *saferith.Nat
	// T = sᵃ tᵛ
	T *saferith.Nat
	// A = Enc₀(α; r)
	A *paillier.Ciphertext
	// Gamma = α (mod q)
	Gamma curve.Scalar
}

type Proof struct {
	group curve.Curve
	*Commitment
	// Z1 = α + e•y
	Z1 *saferith.Int
	// Z2 = ν + e•μ
	Z2 *saferith.Int
	// W  = r ρ ᵉ (mod N₀)
	W *saferith.Nat
}

func (p *Proof) IsValid(public Public) bool {
	if p == nil {
		return false
	}
	if p.Gamma == nil || p.Gamma.IsZero() {
		return false
	}
	if !public.Prover.ValidateCiphertexts(p.A) {
		return false
	}
	if !arith.IsValidNatModN(public.Prover.N(), p.W) {
		return false
	}
	return true
}

func NewProof(group curve.Curve, hash *hash.Hash, public Public, private Private) *Proof {
	N := public.Prover.N()
	NModulus := public.Prover.Modulus()
	alpha := sample.IntervalLEps(rand.Reader)

	mu := sample.IntervalLN(rand.Reader)
	nu := sample.IntervalLEpsN(rand.Reader)
	r := sample.UnitModN(rand.Reader, N)

	gamma := group.NewScalar().SetNat(alpha.Mod(group.Order()))

	commitment := &Commitment{
		S:     public.Aux.Commit(private.Y, mu),
		T:     public.Aux.Commit(alpha, nu),
		A:     public.Prover.EncWithNonce(alpha, r),
		Gamma: gamma,
	}

	e, _ := challenge(hash, group, public, commitment)

	// z₁ = e•y+α
	z1 := new(saferith.Int).SetInt(private.Y)
	z1.Mul(e, z1, -1)
	z1.Add(z1, alpha, -1)
	// z₂ = e•μ + ν
	z2 := new(saferith.Int).Mul(e, mu, -1)
	z2.Add(z2, nu, -1)
	// w = ρ^e•r mod N₀
	w := NModulus.ExpI(private.Rho, e)
	w.ModMul(w, r, N)

	return &Proof{
		group:      group,
		Commitment: commitment,
		Z1:         z1,
		Z2:         z2,
		W:          w,
	}
}

func (p *Proof) Verify(hash *hash.Hash, public Public) bool {
	if !p.IsValid(public) {
		return false
	}

	e, err := challenge(hash, p.group, public, p.Commitment)
	if err != nil {
		return false
	}

	if !public.Aux.Verify(p.Z1, p.Z2, e, p.T, p.S) {
		return false
	}

	{
		// lhs = Enc₀(z₁;w)
		lhs := public.Prover.EncWithNonce(p.Z1, p.W)

		// rhs = (e ⊙ C) ⊕ A
		rhs := public.C.Clone().Mul(public.Prover, e).Add(public.Prover, p.A)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	{
		// lhs = z₁ mod q
		lhs := p.group.NewScalar().SetNat(p.Z1.Mod(p.group.Order()))

		// rhs = e•x + γ
		rhs := p.group.NewScalar().SetNat(e.Mod(p.group.Order())).Mul(public.X).Add(p.Gamma)
		if !lhs.Equal(rhs) {
			return false
		}
	}

	return true
}

func challenge(hash *hash.Hash, group curve.Curve, public Public, commitment *Commitment) (e *saferith.Int, err error) {
	err = hash.WriteAny(public.Aux, public.Prover,
		public.C, public.X,
		commitment.S, commitment.T, commitment.A, commitment.Gamma)
	e = sample.IntervalScalar(hash.Digest(), group)
	return
}

func Empty(group curve.Curve) *Proof {
	return &Proof{group: group, Commitment: &Commitment{Gamma: group.NewScalar()}}
}
