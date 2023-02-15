package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"
	"time"

	ethereumcrypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/crypto/sha3"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/fxamacker/cbor/v2"
	"github.com/klaytn/klaytn/common/hexutil"
	"github.com/klaytn/klaytn/rlp"

	"github.com/w3-key/mps-lean/pkg/ecdsa"
	"github.com/w3-key/mps-lean/pkg/math/curve"
	"github.com/w3-key/mps-lean/pkg/paillier"
	"github.com/w3-key/mps-lean/pkg/party"
	"github.com/w3-key/mps-lean/pkg/pool"
	"github.com/w3-key/mps-lean/pkg/protocol"
	"github.com/w3-key/mps-lean/pkg/test"
	"github.com/w3-key/mps-lean/protocols/cmp"
	"github.com/w3-key/mps-lean/protocols/cmp/sign"
	"github.com/w3-key/mps-lean/protocols/example"
)

//var signatureConfigArray []sign.SignatureParts
//var signaturesArray curve.Scalar
var signatureConfigArray = []sign.SignatureParts{}
var signaturesArray = []curve.Scalar{}
var masterPublicAddress common.Address
var finalDataToSign []byte
var finalEmptyTx *types.Transaction

//var endpoint string = "https://goerli.infura.io/v3/f0b33e4b953e4306b6d5e8b9f9d51567"
//var endpoint string = "https://sepolia.infura.io/v3/f0b33e4b953e4306b6d5e8b9f9d51567"
var endpoint string = "https://rpc.sepolia.org/"

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
	//existing function, keygen
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
	//existing function, confirms the keygen works
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
	//this signs a message for a single participant using their signatureparts
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
	//this combines signatures from vault participants
	var Sigma curve.Scalar
	var BigR curve.Point

	for _, config := range specialConfig {
		Sigma = config.Group.NewScalar()
		BigR = config.GroupBigR
		//maybe also try the GetBigR function
	}
	for _, SS := range SigmaShares {
		Sigma.Add(SS)
	}

	combinedSig := ecdsa.Signature{
		R: BigR,
		S: Sigma,
	}

	return combinedSig
}

func CMPSignGetExtraInfo(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool, justinfo bool) (sign.SignatureParts, error) {
	//this is my special function to get the users Groupsignature parts
	h, _ := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl, justinfo), nil)
	test.HandlerLoop(c.ID, h, n)
	signResult, _ := h.Result()
	sigparts := signResult.(sign.SignatureParts)
	return sigparts, nil
}

func FundEOA(client1 *ethclient.Client, eoa common.Address) error {
	//this is a dummy function I have in place to fund the EOA
	var privateKey, _ = crypto.HexToECDSA("c99a62c5540f68590fff30338e730fc1bea3f3c6fd4bb964e3618c6519a027eb")
	var data []byte
	var chainID, _ = client1.NetworkID(context.Background())
	var fundvalue = big.NewInt(1000000000000000)
	var fromAddress2 = common.HexToAddress("0x94fD43dE0095165eE054554E1A84ccEfa8fdA47F")
	var nonce2, _ = client1.PendingNonceAt(context.Background(), fromAddress2)
	var gas, _ = hexutil.DecodeUint64("0x5208")
	var gasPrice, _ = client1.SuggestGasPrice(context.Background())
	manualCreatedTx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce2,
		GasPrice: gasPrice,
		Gas:      gas,
		To:       &eoa,
		Value:    fundvalue,
		Data:     data,
	})
	signedFUNDTx, _ := types.SignTx(manualCreatedTx, types.LatestSignerForChainID(chainID), privateKey)
	client1.SendTransaction(context.Background(), signedFUNDTx)
	//this works fine
	return nil
}

func FormTransaction(client1 *ethclient.Client) ([]byte, error) {
	//this will be used when the transaction submission is made by a vault participant, it will not show up in the signing/combining/sending process
	var nonce1, _ = client1.PendingNonceAt(context.Background(), masterPublicAddress)
	var value1 = big.NewInt(10000000000000)
	var gasLimit1 = uint64(21000)
	var tip1 = big.NewInt(2000000000)
	var feeCap1 = big.NewInt(20000000000)
	var data1 []byte
	var chainID1, _ = client1.NetworkID(context.Background())
	var toAddress1 = common.HexToAddress("0x94fD43dE0095165eE054554E1A84ccEfa8fdA47F")

	emptyNewTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:    chainID1,
		Nonce:      nonce1,
		GasTipCap:  tip1,
		GasFeeCap:  feeCap1,
		Gas:        gasLimit1,
		To:         &toAddress1,
		Value:      value1,
		Data:       data1,
		AccessList: nil,
	})

	finalEmptyTx = emptyNewTx

	blah := []interface{}{
		chainID1,
		emptyNewTx.Nonce(),
		emptyNewTx.GasTipCap(),
		emptyNewTx.GasFeeCap(),
		emptyNewTx.Gas(),
		emptyNewTx.To(),
		emptyNewTx.Value(),
		emptyNewTx.Data(),
		emptyNewTx.AccessList(),
	}

	hashtoSign := prefixedRlpHash(emptyNewTx.Type(), blah)
	hashBytes := hashtoSign.Bytes()
	finalDataToSign = hashBytes
	fmt.Println("DATATOSIGN")
	fmt.Println(finalDataToSign)
	return hashBytes, nil
}

func SendTransaction(SigmaShares []curve.Scalar, specialConfig []sign.SignatureParts) error {
	var client1, _ = ethclient.Dial(endpoint)
	var chainID1, _ = client1.NetworkID(context.Background())

	signature := CombineSignatures(signaturesArray, signatureConfigArray)

	//IMPORTANT CALLOUT HERE, I CHANGED THE the function below to use GetRecoverId instead of GetEthRecoverId. This allowed the rest of this stuff to verify.
	sigForVerification, _ := signature.ToEthBytes()

	sig := hexutil.MustDecode("0x" + common.Bytes2Hex(sigForVerification))

	//Comemnting this out, it continually resolves to the EOA ADDRESS / masterpublickey, keeping it here in case we need to test it again.
	//recovered, err := crypto.SigToPub(finalDataToSign, sig)
	//if err != nil {
	//	fmt.Println("ERROR: ", err)
	//}
	//recoveredAddr := crypto.PubkeyToAddress(*recovered)
	//fmt.Println("recoveredaddr", recoveredAddr)

	//var toAddress1 = common.HexToAddress("0x94fD43dE0095165eE054554E1A84ccEfa8fdA47F")

	//fmt.Println("TIMESTARTWAITFORFUNDING")
	time.Sleep(15 * time.Second)
	//fmt.Println("TIMEENDWAITFORFUNDING")
	//balance, _ := client1.BalanceAt(context.Background(), masterPublicAddress, nil)
	//fmt.Println("BALANCEOFEOASTART")
	//fmt.Println(balance)
	//fmt.Println("BALANCEOFEOAEND")
	emptyNewTxSigned, _ := finalEmptyTx.WithSignature(types.LatestSignerForChainID(chainID1), sig)

	//fmt.Println("TIMESTARTTRANSACTIONSENT")
	//time.Sleep(20 * time.Second)
	//fmt.Println("TIMESTARTTRANSACTIONEND")
	fmt.Println(emptyNewTxSigned)
	meh := client1.SendTransaction(context.Background(), emptyNewTxSigned)
	fmt.Println("SIGNED WITH WITHSIGNATURE")
	spew.Dump(meh)
	ParseTransactionBaseInfo(emptyNewTxSigned)
	return nil
}

func ParseTransactionBaseInfo(tx *types.Transaction) {
	spew.Dump(tx)
	txV, txR, txS := tx.RawSignatureValues()
	fmt.Printf("PARSE TX BASE INFO\n")
	fmt.Printf("Hash: %s\n", tx.Hash().Hex())
	fmt.Printf("ChainId: %d\n", tx.ChainId())
	fmt.Printf("Value: %s\n", tx.Value().String())
	fmt.Printf("EOA from Manually formed TX: %s\n", GetTransactionMessage(tx).From().Hex()) // from field is not inside of transation
	fmt.Printf("To: %s\n", tx.To().Hex())
	fmt.Printf("Gas: %d\n", tx.Gas())
	fmt.Printf("Gas Price: %d\n", tx.GasPrice().Uint64())
	fmt.Printf("Nonce: %d\n", tx.Nonce())
	fmt.Printf("R: %d\nS: %d\nV: %d", txR, txS, txV)
	//fmt.Print("\n")
}

func GetTransactionMessage(tx *types.Transaction) types.Message {
	msg, _ := tx.AsMessage(types.LatestSignerForChainID(tx.ChainId()), nil)
	return msg
}

var hasherPool = sync.Pool{
	New: func() interface{} { return sha3.NewLegacyKeccak256() },
}

func prefixedRlpHash(prefix byte, x interface{}) (h common.Hash) {
	sha := hasherPool.Get().(crypto.KeccakState)
	defer hasherPool.Put(sha)
	sha.Reset()
	sha.Write([]byte{prefix})
	rlp.Encode(sha, x)
	sha.Read(h[:])
	return h
}

func All(id party.ID, ids party.IDSlice, threshold int, message []byte, n *test.Network, wg *sync.WaitGroup, pl *pool.Pool) error {
	var client1, _ = ethclient.Dial(endpoint)
	defer wg.Done()
	err := XOR(id, ids, n)
	if err != nil {
		return err
	}
	keygenConfig, err := CMPKeygen(id, ids, threshold, n, pl)
	if err != nil {
		return err
	}
	if id == "a" {
		fmt.Println("EOA ADDRESS: ", keygenConfig.PublicPoint().ToAddress())
		masterPublicAddress = keygenConfig.PublicPoint().ToAddress()
	}

	refreshConfig, err := CMPRefresh(keygenConfig, n, pl)
	refreshConfig = ChangeConfig(refreshConfig, id, 5, 3, shares)
	signers := ids[:threshold+1]
	if !signers.Contains(id) {
		n.Quit(id)
		return nil
	}

	for i := 1; i < 10; i++ {

		if id == "a" {
			FundEOA(client1, masterPublicAddress)
			FormTransaction(client1)
		}
		fmt.Println("HERRE")

		var unmarshalledSigData *sign.SignatureParts
		unmarshalledConfig := unmarshalledSigData.EmptyConfig()

		sigparts, _ := CMPSignGetExtraInfo(refreshConfig, message, signers, n, pl, true)
		signatureConfigArray = append(signatureConfigArray, sigparts)
		marshalledConfig, err := cbor.Marshal(sigparts)
		if err != nil {
			fmt.Println(err)
		}
		//store marshalledconfigs
		err = cbor.Unmarshal(marshalledConfig, &unmarshalledConfig)
		if err != nil {
			fmt.Println(err)
		}

		if id == "a" {
			share := SingleSign(signatureConfigArray[0], finalDataToSign)
			signaturesArray = append(signaturesArray, share)
			fmt.Println(id)
			fmt.Println(signaturesArray)

			/*sigForVerification, _ := signature.ToEthBytes()
			sig := hexutil.MustDecode("0x" + common.Bytes2Hex(sigForVerification))
			emptyNewTxSigned, _ := finalEmptyTx.WithSignature(types.LatestSignerForChainID(chainID1), sig)
			fmt.Println(emptyNewTxSigned)
			meh := client1.SendTransaction(context.Background(), emptyNewTxSigned)
			fmt.Println("SIGNED WITH WITHSIGNATURE")
			spew.Dump(meh)
			ParseTransactionBaseInfo(emptyNewTxSigned)*/
		}

		if id == "b" {
			share := SingleSign(signatureConfigArray[1], finalDataToSign)
			signaturesArray = append(signaturesArray, share)
			fmt.Println(id)
			fmt.Println(signaturesArray)
		}

		if id == "c" {
			share := SingleSign(signatureConfigArray[2], finalDataToSign)
			signaturesArray = append(signaturesArray, share)
			fmt.Println(id)
			fmt.Println(signaturesArray)
		}

		if id == "c" || id == "d" || id == "e" || id == "" {
			SendTransaction(signaturesArray, signatureConfigArray)
		}
	}

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

	wg.Wait()
}

func hexDecode(s string) []byte {
	decoded, _ := hex.DecodeString(s)
	return decoded
}

func ChangeConfig(Paillier *paillier.SecretKey, id party.ID, ids party.IDSlice, n int, t int, shares map[party.ID]*curve.Scalar, c *cmp.Config) (*cmp.Config, error) {

	//shares := [c6f41b6941ba2e10560bae52d5c16a215ce9ce8c2dd0bccb846ad6996c4f2190, 851c366b5b17c267ad3fe27301324b387659ab2c3c20a4eab90c5ee6da01b48d, d0fed3d9463bd8cb21c0905030d3a2473c5355e2baa7c7bd770d9ffdff0dba85, cacdf8283da71a30b3611d99565e66491a7902fa4ac5c7ecd800ed2e15619802, 92bba7cd7bda2f8e61f4effd638b8e38371bc3a43d22e85db54af8532721f2cf]

	Newshares := [][]byte{
		hexDecode("c6f41b6941ba2e10560bae52d5c16a215ce9ce8c2dd0bccb846ad6996c4f2190"),
		hexDecode("851c366b5b17c267ad3fe27301324b387659ab2c3c20a4eab90c5ee6da01b48d"),
		hexDecode("d0fed3d9463bd8cb21c0905030d3a2473c5355e2baa7c7bd770d9ffdff0dba85"),
		hexDecode("cacdf8283da71a30b3611d99565e66491a7902fa4ac5c7ecd800ed2e15619802"),
		hexDecode("92bba7cd7bda2f8e61f4effd638b8e38371bc3a43d22e85db54af8532721f2cf"),
	}

	c.Threshold = t
	c.ECDSA = Newshares[2].encoding.BinaryUnmarshaler
	//c.ECDSA = *shares[id]
	c.ID = id
	c.Paillier = Paillier

	return c, nil
}
