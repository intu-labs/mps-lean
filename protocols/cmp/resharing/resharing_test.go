package resharing

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/w3-key/mps-lean/pkg/math/curve"
	"github.com/w3-key/mps-lean/pkg/pool"
	"github.com/w3-key/mps-lean/pkg/round"
	"github.com/w3-key/mps-lean/pkg/test"
)

var group = curve.Secp256k1{}

func TestReshare(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 2
	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "cmp/keygen-test",
			FinalRoundNumber: Rounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        N - 1,
			Group:            group,
		}
		r, err := Start(info, pl, nil)(nil) // QFS how does the code knows from where the start function comes?
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	fmt.Print("rounds : ", rounds)
}
