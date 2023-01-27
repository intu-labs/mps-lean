package sign

import (
	"errors"
	"fmt"

	"github.com/davecgh/go-spew/spew"
	"github.com/w3-key/mps-lean/pkg/ecdsa"
	"github.com/w3-key/mps-lean/pkg/math/curve"
	"github.com/w3-key/mps-lean/pkg/party"
	"github.com/w3-key/mps-lean/pkg/round"
)

var _ round.Round = (*round5)(nil)

type round5 struct {
	*round4

	// SigmaShares[j] = σⱼ = m⋅kⱼ + χⱼ⋅R|ₓ
	SigmaShares map[party.ID]curve.Scalar

	// Delta = δ = ∑ⱼ δⱼ
	// computed from received shares
	Delta curve.Scalar

	// BigDelta = Δ = ∑ⱼ Δⱼ
	BigDelta curve.Point

	// R = [δ⁻¹] Γ
	BigR curve.Point

	// R = R|ₓ
	R curve.Scalar

	ChiShare curve.Scalar

	KSHare curve.Scalar
}

type broadcast5 struct {
	round.NormalBroadcastContent
	SigmaShare curve.Scalar
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - save σⱼ
func (r *round5) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast5)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	if body.SigmaShare.IsZero() {
		return round.ErrNilFields
	}

	r.SigmaShares[msg.From] = body.SigmaShare
	return nil
}

// VerifyMessage implements round.Round.
func (round5) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round5) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - compute σ = ∑ⱼ σⱼ
// - verify signature.
func (r *round5) Finalize(chan<- *round.Message) (round.Session, error) {
	// compute σ = ∑ⱼ σⱼ
	Sigma := r.Group().NewScalar()

	//printer, err := GetOutputPrinter(r.round1.PublicKey.ToAddress())
	//if err != nil {
	//	return r, err
	//}
	//defer printer.Close()

	for _, j := range r.PartyIDs() {
		Sigma.Add(r.SigmaShares[j])

		//b, _ := r.SigmaShares[j].MarshalBinary()
		//if r.SelfID() == "a" {
		//	printer.Write([]byte(fmt.Sprintf("Merge signature data, from node %s, result %s \n", j, ethereumhexutil.Encode(b))))
		//}
	}
	fmt.Println("round5")
	spew.Dump(r.Delta)

	signature := &ecdsa.Signature{
		R: r.BigR,
		S: Sigma,
	}

	//b, _ := Sigma.MarshalBinary()

	//if r.SelfID() == "a" {
	//	printer.Write([]byte(fmt.Sprintf("Sign success %s \nMerged result: %s\n", ethereumhexutil.Encode(r.Message), ethereumhexutil.Encode(b))))
	//}


	if !signature.Verify(r.PublicKey, r.Message) {
		return r.AbortRound(errors.New("failed to validate signature")), nil
	}
//	return r.ResultRound(signature, r.Delta, r.BigDelta, r.KShare, r.BigR, r.ChiShare,), nil

	return r.ResultRound(signature,), nil
}

// MessageContent implements round.Round.
func (r *round5) MessageContent() round.Content { return nil }

// RoundNumber implements round.Content.
func (broadcast5) RoundNumber() round.Number { return 5 }

// BroadcastContent implements round.BroadcastRound.
func (r *round5) BroadcastContent() round.BroadcastContent {
	return &broadcast5{
		SigmaShare: r.Group().NewScalar(),
	}
}

// Number implements round.Round.
func (round5) Number() round.Number { return 5 }
