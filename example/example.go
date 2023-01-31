package main

import (
	"fmt"
	"sync"

	"github.com/davecgh/go-spew/spew"
	ethereumcommon "github.com/ethereum/go-ethereum/common"
	ethereumhexutil "github.com/ethereum/go-ethereum/common/hexutil"
	ethereumcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/fxamacker/cbor/v2"
	"github.com/klaytn/klaytn/common"
	"github.com/storyicon/sigverify"
	"github.com/w3-key/mps-lean/pkg/ecdsa"
	"github.com/w3-key/mps-lean/pkg/math/curve"
	"github.com/w3-key/mps-lean/pkg/party"
	"github.com/w3-key/mps-lean/pkg/pool"
	"github.com/w3-key/mps-lean/pkg/protocol"
	"github.com/w3-key/mps-lean/pkg/test"
	"github.com/w3-key/mps-lean/protocols/cmp"
	"github.com/w3-key/mps-lean/protocols/cmp/sign"
	"github.com/w3-key/mps-lean/protocols/example"
)

var signaturePartsArray = []sign.SignatureParts{}
var signaturesArray = []curve.Scalar{}
var masterPublicAddress ethereumcommon.Address

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

func SingleSign(specialConfig sign.SignatureParts, message []byte) (signresult curve.Scalar) {
	group := specialConfig.Group
	KShare := specialConfig.GroupKShare
	BigR := specialConfig.GroupBigR // R = [δ⁻¹] Γ
	R := BigR.XScalar()             // r = R|ₓ
	km := curve.FromHash(group, message)
	km.Mul(KShare)
	SigmaShare := group.NewScalar().Set(R).Mul(specialConfig.GroupChiShare).Add(km)
	return SigmaShare
}

func CombineSignatures(SigmaShares []curve.Scalar, specialConfig []sign.SignatureParts) (signature ecdsa.Signature) {
	var Sigma curve.Scalar
	var BigR curve.Point

	for id, config := range specialConfig {
		fmt.Println(id)
		Sigma = config.Group.NewScalar()
		BigR = config.GetBigR()
		//maybe also try the GetBigR function
	}
	fmt.Println(Sigma)
	for id, SS := range SigmaShares {
		fmt.Println(id)
		Sigma.Add(SS)
	}
	combinedSig := ecdsa.Signature{
		R: BigR,
		S: Sigma,
	}
	return combinedSig
}

func CMPSignGetExtraInfo(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool, justinfo bool) (sign.SignatureParts, error) {
	h, _ := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl, justinfo), nil)
	test.HandlerLoop(c.ID, h, n)
	signResult, _ := h.Result()
	sigparts := signResult.(sign.SignatureParts)
	return sigparts, nil
}

func CMPSign(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool, justinfo bool) error {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl, justinfo), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	fmt.Println(signature)
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

	return nil
}

func All(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	defer wg.Done()
	err := XOR(id, ids, n)
	if err != nil {
		return err
	}
	keygenConfig, err := CMPKeygen(id, ids, threshold, n, pl)
	if err != nil {
		return err
	}
	fmt.Println(keygenConfig.PublicPoint().ToAddress())
	masterPublicAddress = keygenConfig.PublicPoint().ToAddress()
	refreshConfig, err := CMPRefresh(keygenConfig, n, pl)
	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	var unmarshalledSigData *sign.SignatureParts
	unmarshalledConfig := unmarshalledSigData.EmptyConfig()

	sigparts, _ := CMPSignGetExtraInfo(refreshConfig, message, signers, n, pl, true)
	signaturePartsArray = append(signaturePartsArray, sigparts)
	marshalledConfig, err := cbor.Marshal(sigparts)
	if err != nil {
		fmt.Println(err)
	}
	//store marshalledconfigs
	err = cbor.Unmarshal(marshalledConfig, &unmarshalledConfig)
	if err != nil {
		fmt.Println(err)
	}
	//this will be done before signing ^
	blehsign := SingleSign(unmarshalledConfig, message)
	//store result of singlesign, marshalled or base64?
	signaturesArray = append(signaturesArray, blehsign)

	//spew.Dump(sig)
	//recovered, err := crypto.SigToPub(message, sig)
	//if err != nil {
	//	fmt.Println("ERROR: ", err)
	//}
	//fmt.Println(recovered)

	//publicPoint := sigparts.GetGroupPublicPoint()
	//spew.Dump(publicPoint)
	//fmt.Println(combined.Verify(publicPoint, message))

	//marshalSignData, _ := cbor.Marshal(result)
	//spew.Dump(marshalSignData)
	return nil
}

func main() {
	ids := party.IDSlice{"a", "b"}
	threshold := 1
	messageToSign := ethereumcrypto.Keccak256([]byte("Hi"))
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
	spew.Dump(len(signaturePartsArray))
	combined := CombineSignatures(signaturesArray, signaturePartsArray)

	sigForVerification, _ := combined.ToEthBytes()
	sig := "0x" + common.Bytes2Hex(sigForVerification)

	valid, err := sigverify.VerifyEllipticCurveHexSignatureEx(
		masterPublicAddress,
		messageToSign,
		sig,
	)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(valid)
	wg.Wait()
}
