package main

import (
	cryptoecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"
	"sync"

	ethereumhexutil "github.com/ethereum/go-ethereum/common/hexutil"
	ethereumcrypto "github.com/ethereum/go-ethereum/crypto"
	ethereumsecp256k1 "github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/w3-key/mps-lean/pkg/ecdsa"
	"github.com/w3-key/mps-lean/pkg/math/curve"
	"github.com/w3-key/mps-lean/pkg/party"
	"github.com/w3-key/mps-lean/pkg/pool"
	"github.com/w3-key/mps-lean/pkg/protocol"
	"github.com/w3-key/mps-lean/pkg/test"
	"github.com/w3-key/mps-lean/protocols/cmp"
	"github.com/w3-key/mps-lean/protocols/example"
)

type signatureParts struct {
	GroupDelta curve.Scalar
	GroupBigDelta curve.Point
	GroupKShare curve.Scalar
	GroupBigR curve.Point
	GroupChiShare curve.Scalar
	}

func XOR(id party.ID, ids party.IDSlice, n *test.Network) error {
	h, err := protocol.NewMultiHandler(example.StartXOR(id, ids), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(id, h, n)
	_, err = h.Result()
	if err != nil {
		return err
	}
	return nil
}

func CMPKeygen(id party.ID, ids party.IDSlice, threshold int, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}

	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	config := r.(*cmp.Config)

	return config, nil
}

func CMPRefresh(c *cmp.Config, n *test.Network, pl *pool.Pool) (*cmp.Config, error) {
	hRefresh, err := protocol.NewMultiHandler(cmp.Refresh(c, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(c.ID, hRefresh, n)

	r, err := hRefresh.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPSignGetExtraInfo(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool, forkeys bool) (signatureParts, error) {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl, forkeys), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}
	signature := signResult.(*ecdsa.Signature)

	if err != nil {
		return nil, err
	}

	sig, err := ethereumhexutil.Decode("0xd8d963bf1fd8e09cc7a55d1f5f39c762036017d662b87e58403752078952be5e34a5dbe67b18b2a9fd46c96866a3c0118d092df8219d0f69034dd8949ed8c34a1c")

	if err != nil {
		return nil, err
	}
	// println(len(rb), len(sb), len(sig), len(m), recoverId, "rb len")

	m = []byte("0xc019d8a5f1cbf05267e281484f3ddc2394a6b5eacc14e9d210039cf34d8391fc")
	sig[64] = sig[64] - 27

	// println(hex.EncodeToString(sig), "sign")
	if ss, err := ethereumsecp256k1.RecoverPubkey(m, sig); err != nil {
		return err
	} else {
		// bs, _ := c.PublicPoint().MarshalBinary()
		x, y := elliptic.Unmarshal(ethereumsecp256k1.S256(), ss)
		pk := cryptoecdsa.PublicKey{Curve: ethereumsecp256k1.S256(), X: x, Y: y}

		pk2 := c.PublicPoint().ToAddress().Hex()
		println(ethereumcrypto.PubkeyToAddress(pk).Hex(), "public key", pk2)
	}

	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}

	signatureParts := signatureParts{
		signResult.Delta,
		signResult.BigDelta,
		signResult.KShare,
		signResult.BigR,
		signResult.ChiShare,
	}

	fmt.Println(signatureParts)
	return signatureParts
}

func CMPSign(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool, forkeys string) error {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)

	if err != nil {
		return err
	}

	sig, err := ethereumhexutil.Decode("0xd8d963bf1fd8e09cc7a55d1f5f39c762036017d662b87e58403752078952be5e34a5dbe67b18b2a9fd46c96866a3c0118d092df8219d0f69034dd8949ed8c34a1c")

	if err != nil {
		return err
	}
	// println(len(rb), len(sb), len(sig), len(m), recoverId, "rb len")

	m = []byte("0xc019d8a5f1cbf05267e281484f3ddc2394a6b5eacc14e9d210039cf34d8391fc")
	sig[64] = sig[64] - 27

	// println(hex.EncodeToString(sig), "sign")
	if ss, err := ethereumsecp256k1.RecoverPubkey(m, sig); err != nil {
		return err
	} else {
		// bs, _ := c.PublicPoint().MarshalBinary()
		x, y := elliptic.Unmarshal(ethereumsecp256k1.S256(), ss)
		pk := cryptoecdsa.PublicKey{Curve: ethereumsecp256k1.S256(), X: x, Y: y}

		pk2 := c.PublicPoint().ToAddress().Hex()
		println(ethereumcrypto.PubkeyToAddress(pk).Hex(), "public key", pk2)
	}

	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}


func All(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()

	// XOR
	err := XOR(id, ids, n)
	if err != nil {
		return err
	}

	// CMP KEYGEN
	keygenConfig, err := CMPKeygen(id, ids, threshold, n, pl)
	if err != nil {
		return err
	}

	// CMP REFRESH
	refreshConfig, err := CMPRefresh(keygenConfig, n, pl)


	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

		// CMP SIGN
		result, err = CMPSignGetExtraInfo(refreshConfig, message, signers, n, pl, true)
		if err != nil {
			return err
		}

		fmt.Println(result)

	// CMP SIGN
	//err = CmpSign(refreshConfig, message, signers, n, pl)
	//if err != nil {
	//	return err
	//}

	return nil
}

func main() {
	ids := party.IDSlice{"a", "b"}
	threshold := 1
	messageToSign := ethereumcrypto.Keccak256([]byte("hellohellohello1hellohellohello1"))
	net := test.NewNetwork(ids)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(10)
			defer pl.TearDown()
			if err := All(id, ids, threshold, messageToSign, net, &wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}
