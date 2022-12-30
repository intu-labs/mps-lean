package main

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"
	"unsafe"

	"github.com/klaytn/klaytn/common/hexutil"
	"github.com/klaytn/klaytn/rlp"

	"github.com/davecgh/go-spew/spew"
	_ "github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/w3-key/mps-lean/pkg/ecdsa"
	"github.com/w3-key/mps-lean/pkg/math/curve"
	"github.com/w3-key/mps-lean/pkg/party"
	"github.com/w3-key/mps-lean/pkg/pool"
	"github.com/w3-key/mps-lean/pkg/protocol"
	"github.com/w3-key/mps-lean/pkg/test"
	"github.com/w3-key/mps-lean/protocols/cmp"
	"github.com/w3-key/mps-lean/protocols/example"
	"golang.org/x/crypto/sha3"
)

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

func CMPSign(c *cmp.Config, m []byte, signers party.IDSlice, n *test.Network, pl *pool.Pool) error {
	//c.PublicPoint()
	fmt.Println("EARLY ADDRESS")
	fmt.Println(c.PublicPoint().ToAddress())

	var client1, _ = ethclient.Dial("https://rpc.ankr.com/eth_goerli")
	var signfromAddress1 = c.PublicPoint().ToAddress()
	var nonce1, _ = client1.PendingNonceAt(context.Background(), signfromAddress1)
	var value1 = big.NewInt(1000000000000000)
	var gasLimit1 = uint64(21000)              
	var tip1 = big.NewInt(2000000000)          
	var feeCap1 = big.NewInt(20000000000)      
	var fundtoAddress1 = c.PublicPoint().ToAddress()
	var data1 []byte
	var chainID1, _ = client1.NetworkID(context.Background())
	var toAddress1 = common.HexToAddress("0x94fD43dE0095165eE054554E1A84ccEfa8fdA47F")

	emptyNewTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID1,
		Nonce:     nonce1,
		GasTipCap: tip1,
		GasFeeCap: feeCap1,
		Gas:       gasLimit1,
		To:        &toAddress1,
		Value:     value1,
		Data:      data1,
		AccessList: nil,
	})

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
	//fmt.Println("HAILMARY")
	//fmt.Println(hashtoSign)
	hashBytes := hashtoSign.Bytes()
	//fmt.Println(hashBytes)
	//fmt.Println(common.BytesToHash(hashBytes))
	//fmt.Println("HAILMARY")

	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, hashBytes, pl), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)
	signResult, err := h.Result()
	if err != nil {
		return err
	}
	signature := signResult.(*ecdsa.Signature)
	sigForVerification, _ := signature.ToEthBytes()
	sig := hexutil.MustDecode("0x" + common.Bytes2Hex(sigForVerification))
	//rb, _ := signature.R.MarshalBinary()
	//sb, _ := signature.S.MarshalBinary()
	//toECDSA := signature.R.ToECDSA()
	//recoverid := byte(dcrm256k1.Get_ecdsa_sign_v(toECDSA.X, toECDSA.Y))
	//vbyte := IntToByteArray(int64(recoverid))
	//eR := common.Bytes2Hex(sig[:32])
	//eS := common.Bytes2Hex(sig[32:64])
	//eV := sig[64] + 27
	recovered, err := crypto.SigToPub(hashBytes, sig)
	if err != nil {
		fmt.Println("ERROR: ", err)
	}
	recoveredAddr := crypto.PubkeyToAddress(*recovered)
	var privateKey, _ = crypto.HexToECDSA("4d834712dd37232a3d1670f97656a12d411f0b42328ac429d2fd2924fdd4883a")
	//var fromAddress = common.HexToAddress("0x34A44Fac0CF62EE4e2d0Ce708eA057eeD8f2CD17")
	var data []byte
	var chainID, _ = client1.NetworkID(context.Background())

	//fmt.Println("MESSAGE")
	//fmt.Println(m)
	//fmt.Println(common.Bytes2Hex(m))
	//fmt.Println()
//
//
	//fmt.Println("MarshalBinary RSV")
	////sigbytes := append(rb[:1], sb...)
	////sigbytes = append(sigbytes, recoverid)
	//fmt.Println("R: ", common.Bytes2Hex(rb[1:]))
	//fmt.Println("S: ", common.Bytes2Hex(sb))
	//fmt.Println("V: ", common.Bytes2Hex(vbyte[:1]))
	//fmt.Println("MarshalBinary bytes")
	//fmt.Println(rb)
	//fmt.Println(sb)
	//fmt.Println(recoverid)
	//fmt.Println()
	//fmt.Println("ToEthBytes bytes")
	//fmt.Println(sigForVerification)
	//fmt.Println("ToEthBytes bytes")
	//fmt.Println("R: ", eR)
	//fmt.Println("S: ", eS)
	//fmt.Println("V: ", eV)
	//fmt.Println()
	var fundvalue = big.NewInt(10000000000000000)

	var fromAddress2 = common.HexToAddress("0x34A44Fac0CF62EE4e2d0Ce708eA057eeD8f2CD17")
	var nonce2, _ = client1.PendingNonceAt(context.Background(), fromAddress2)
	fmt.Println("'recovered' Address from initial EOA creation: ", recoveredAddr)
	fmt.Println((&fundtoAddress1))
	var gas, _ = hexutil.DecodeUint64("0x5208")
	var gasPrice, _ = client1.SuggestGasPrice(context.Background())
	manualCreatedTx := types.NewTx(&types.LegacyTx{
		Nonce:    nonce2,
		GasPrice: gasPrice,
		Gas:      gas,
		To:       &fundtoAddress1,
		Value:    fundvalue,
		Data:     data,
	})
	signedFUNDTx, _ := types.SignTx(manualCreatedTx, types.NewLondonSigner(chainID), privateKey)
	meh1 := client1.SendTransaction(context.Background(), signedFUNDTx)
	fmt.Println("FUNDING TX BELOW")
	spew.Dump(meh1)
	var BLAHADDRESS = common.HexToAddress("0x52C27B705210c6F776Ac1bd65B3225cc2E5447F9")
	balance, err := client1.BalanceAt(context.Background(), BLAHADDRESS, nil)
	fmt.Println("BALANCE")
	fmt.Println(balance)
	fmt.Println("BALANCE")

	//signedEmptyTx, _ := types.SignTx(emptyNewTx, types.NewLondonSigner(chainID), privateKey)
	//signedRawTx, _ := signedEmptyTx.MarshalBinary()
	//fmt.Println("SIGNEDRAWTX")
	//fmt.Println(signedRawTx)
	//finaltx_string := common.Bytes2Hex(signedRawTx)
	//fmt.Println(finaltx_string)
	
	
	
	fmt.Println(chainID)
	emptyNewTxSigned, _ := emptyNewTx.WithSignature(types.NewLondonSigner(chainID), sig)
	
	fmt.Println("TIMESTART")
	time.Sleep(30 * time.Second)
	fmt.Println("TIMEEND")	
	
	meh := client1.SendTransaction(context.Background(), emptyNewTxSigned)
	fmt.Println("SIGNED WITH WITHSIGNATURE")
	spew.Dump(meh)
	ParseTransactionBaseInfo(emptyNewTxSigned)
	return nil
}

func ParseTransactionBaseInfo(tx *types.Transaction) {
	txV, txR, txS := tx.RawSignatureValues()
	fmt.Printf("PARSE TX BASE INFO")
	fmt.Printf("Hash: %s\n", tx.Hash().Hex())
	fmt.Printf("ChainId: %d\n", tx.ChainId())
	//fmt.Printf("Value: %s\n", tx.Value().String())
	fmt.Printf("EOA from Manually formed TX: %s\n", GetTransactionMessage(tx).From().Hex()) // from field is not inside of transation
	//fmt.Printf("To: %s\n", tx.To().Hex())
	//fmt.Printf("Gas: %d\n", tx.Gas())
	//fmt.Printf("Gas Price: %d\n", tx.GasPrice().Uint64())
	fmt.Printf("Nonce: %d\n", tx.Nonce())
	fmt.Printf("R: %d\nS: %d\nV: %d", txR, txS, txV)
	//fmt.Print("\n")
}

func GetTransactionMessage(tx *types.Transaction) types.Message {
	msg, _ := tx.AsMessage(types.LatestSignerForChainID(tx.ChainId()), nil)
	return msg
}

func IntToByteArray(num int64) []byte {
	size := int(unsafe.Sizeof(num))
	arr := make([]byte, size)
	for i := 0 ; i < size ; i++ {
			byt := *(*uint8)(unsafe.Pointer(uintptr(unsafe.Pointer(&num)) + uintptr(i)))
			arr[i] = byt
	}
	return arr
}

//func CMPPreSign(c *cmp.Config, signers party.IDSlice, n *test.Network, pl *pool.Pool) (*ecdsa.PreSignature, error) {
//	h, err := protocol.NewMultiHandler(cmp.Presign(c, signers, pl), nil)
//	if err != nil {
//		return nil, err
//	}
//
//	test.HandlerLoop(c.ID, h, n)
//
//	signResult, err := h.Result()
//	if err != nil {
//		return nil, err
//	}
//
//	preSignature := signResult.(*ecdsa.PreSignature)
//	if err = preSignature.Validate(); err != nil {
//		return nil, errors.New("failed to verify cmp presignature")
//	}
//	return preSignature, nil
//}
//
//func CMPPreSignOnline(c *cmp.Config, preSignature *ecdsa.PreSignature, m []byte, n *test.Network, pl *pool.Pool) error {
//	h, err := protocol.NewMultiHandler(cmp.PresignOnline(c, preSignature, m, pl), nil)
//	if err != nil {
//		return err
//	}
//	test.HandlerLoop(c.ID, h, n)
//
//	signResult, err := h.Result()
//	if err != nil {
//		return err
//	}
//	signature := signResult.(*ecdsa.Signature)
//	if !signature.Verify(c.PublicPoint(), m) {
//		return errors.New("failed to verify cmp signature")
//	}
//	return nil
//}


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
	err = CMPSign(refreshConfig, message, signers, n, pl)
	if err != nil {
		return err
	}

	// CMP PRESIGN
	//preSignature, err := CMPPreSign(refreshConfig, signers, n, pl)
	//if err != nil {
	//	return err
	//}
//
	//// CMP PRESIGN ONLINE
	//err = CMPPreSignOnline(refreshConfig, preSignature, message, n, pl)
	//if err != nil {
	//	return err
	//}

	return nil
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

func main() {
	ids := party.IDSlice{"a", "b"}
	threshold := 1
	var client, _ = ethclient.Dial("https://rpc.ankr.com/eth_goerli")
	//var fromAddress = common.HexToAddress("0x34A44Fac0CF62EE4e2d0Ce708eA057eeD8f2CD17")
	//var nonce, _ = client.PendingNonceAt(context.Background(), fromAddress)
	var value = big.NewInt(1000000000000000)
	var gasLimit = uint64(21000)              
	var tip = big.NewInt(2000000000)          
	var feeCap = big.NewInt(20000000000)      
	var toAddress = common.HexToAddress("0x8362668f0a0C4006687C84BB9902429718091B01")
	var data []byte
	var chainID, _ = client.NetworkID(context.Background())
	emptyNewTx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		GasTipCap: tip,
		GasFeeCap: feeCap,
		Gas:       gasLimit,
		To:        &toAddress,
		Value:     value,
		Data:      data,
		AccessList: nil,
	})

	//rawtx, _ := emptyNewTx.MarshalBinary()
	//messageToSign := crypto.Keccak256(rawtx)
	//fmt.Println(messageToSign)
	//newSigner := types.NewLondonSigner(chainID)

	blah := []interface{}{
		chainID,
		emptyNewTx.Nonce(),
		emptyNewTx.GasTipCap(),
		emptyNewTx.GasFeeCap(),
		emptyNewTx.Gas(),
		emptyNewTx.To(),
		emptyNewTx.Value(),
		emptyNewTx.Data(),
		emptyNewTx.AccessList(),
	}
	hashtoSignDONTUSE := prefixedRlpHash(emptyNewTx.Type(), blah)
	//fmt.Println("HAILMARY")
	//fmt.Println(hashtoSignDONTUSE)
	hashBytesDONTUSE := hashtoSignDONTUSE.Bytes()
	//fmt.Println(hashBytesDONTUSE)
	//fmt.Println(common.BytesToHash(hashBytesDONTUSE))
	//fmt.Println("HAILMARY")

	net := test.NewNetwork(ids)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		go func(id party.ID) {
			pl := pool.NewPool(-1)
			defer pl.TearDown()
			if err := All(id, ids, threshold, hashBytesDONTUSE, net, &wg, pl); err != nil {
				fmt.Println(err)
			}
		}(id)
	}
	wg.Wait()
}
