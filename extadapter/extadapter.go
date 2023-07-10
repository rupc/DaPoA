// Package main provides
package extadapter

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/extadapter/exttype"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
)

var (
	Urls = [...]string{"http://141.223.121.54:8080"}
	// Urls                      = [...]string{"http://141.223.121.45:40001"}
	proposalMethodName string = "auditchain_proposal"
)

const (
	ExtraAuditorSignature = crypto.SignatureLength
	ExtraAuditorStartPos  = 120
	PaddingBitsLength     = 4

	TestKeyStore   = `{"address":"9f0ee8037891ad91c99104ba03edeb193ef182d8","crypto":{"cipher":"aes-128-ctr","ciphertext":"da115b7bf2e3dc247ddc12152304d41424d67189fae44c03dd4300b53091366a","cipherparams":{"iv":"4124b45f57fcfbd15706aef3c94be174"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"a94152c57962054f562714e59c018fbc18f4e84fc81bfe57abf3f15a5883eb40"},"mac":"9ad00d41a090cc9d942d3927e4629ecfd56e8975777a1cf3926b68863a468c07"},"id":"7794cce0-1862-4ed6-899c-cba0cc2aed74","version":3}`
	TestPassword   = "sslab423"
	TestPrivateKey = ""
	TestPublicKey  = ""
)

func extractSigAndVerify(extra, body, sig []byte) bool {
	signature := extra[len(extra)-ExtraAuditorStartPos:]
	digest := accounts.TextHash(body)

	// Recover the public key and the Ethereum address
	pubkey, err := crypto.Ecrecover(digest, signature)
	if err != nil {
		return false
	}
	_ = pubkey
	return true
	// var signer common.Address
	// copy(signer[:], crypto.Keccak256(pubkey[1:])[12:])
}

func getTestAuditorSignature(body []byte) []byte {
	file, err := ioutil.TempFile("tmp", "eth_keystore")
	if err != nil {
		panic(err)
	}
	defer os.Remove(file.Name())

	ks := keystore.NewKeyStore(file.Name(), keystore.StandardScryptN, keystore.StandardScryptP)

	jsonBytes := []byte(TestKeyStore)
	account, err := ks.Import(jsonBytes, TestPassword, TestPassword)
	if err != nil {
		panic(err)
	}
	wallet := ks.Wallets()[0]
	sighash, err := wallet.SignText(account, body)
	if err != nil {
		panic(err)
	}

	// sighash, err := signFn(accounts.Account{Address: signer}, accounts.MimetypeClique, CliqueRLP(header))
	// SignData(account Account, mimeType string, data []byte) ([]byte, error)

	fmt.Println("Test user account>")
	fmt.Println(account.Address.Hex())

	fmt.Println("Signed on BlockBody>")
	fmt.Println(sighash)

	return sighash
}

func BroadcastBlockAndRebuildHeader(block *types.Block) (rebuildHeader *types.Header) {
	rebuildHeader = block.Header()

	blockBytes, err := rlp.EncodeToBytes(block)
	if err != nil {
		panic("Failed on RLP encoding on the block")
	}

	headerBytes, err := rlp.EncodeToBytes(block.Header())
	if err != nil {
		panic("Failed on RLP encoding on the block header")
	}

	sendMsg := &exttype.SendMsg{
		EthereumBlock: blockBytes,
		Header:        headerBytes,
	}

	sendMsgBytes, err := json.Marshal(sendMsg)
	if err != nil {
		errmsg := fmt.Sprintf("json marshal failed on sendMsg")
		panic(errmsg)
	}

	log.Info("BroadcastBlockAndHeader", "blockSize", len(blockBytes), "headerSize", len(headerBytes), "jsonTotal", len(sendMsgBytes))

	rmsgs := []*exttype.RecvMsg{}
	l := sync.Mutex{}
	wg := sync.WaitGroup{}

	// simFlag (== true) means it uses simulation audit chain network
	simFlag := true

	for _, url := range Urls {
		wg.Add(1)
		go func(endpoint string) {
			wg.Done()
			var result interface{}
			log.Info("Sending to Auditor", "endpoint", endpoint)

			err = InvokeRPC_AuditChain(simFlag, rebuildHeader, url, result, proposalMethodName, sendMsgBytes)
			if err != nil {
				log.Error(err.Error())
			}

			res := (result.(*exttype.RecvMsg))
			log.Info("Result", "number", res.Header.Number)

			l.Lock()
			rmsgs = append(rmsgs, (result.(*exttype.RecvMsg)))
			l.Unlock()
		}(url)
	}
	wg.Wait()

	// assumes only 1 auditor.. so simply pick the first element among RecvMsgs.
	finalMsg := rmsgs[0]
	_ = finalMsg
	rebuildHeader = block.Header()
	rebuildHeader.Extra = EncodeExtraWithPaddings(rebuildHeader.Extra, finalMsg)

	return
}

func EncodeExtraWithPaddings(extra []byte, recvMsg *exttype.RecvMsg) []byte {
	if len(extra) >= ExtraAuditorStartPos {
		panic("WTF? It's already exceed allowance in Extra field")
	}

	paddingSize := uint32(ExtraAuditorStartPos - len(extra))

	// Append paddings
	bs := make([]byte, PaddingBitsLength)
	binary.LittleEndian.PutUint32(bs, paddingSize)
	extra = append(extra, make([]byte, paddingSize)...)

	// Append padding size
	extra = append(extra, bs...)

	// Append Signatures
	for _, sig := range recvMsg.Header.AuditorSignatures {
		extra = append(extra, sig...)
	}
	return extra
	// return nil
}

func GetOriginalExtra(extra []byte) []byte {
	if len(extra) < ExtraAuditorStartPos {
		panic("Size of Extra is lesser than the original extra bytes, which is impossible")
	}

	paddingBytes := extra[ExtraAuditorStartPos : ExtraAuditorStartPos+4]
	paddingSize := binary.LittleEndian.Uint32(paddingBytes)
	return extra[:ExtraAuditorStartPos-paddingSize]
}

func GetAuditorSignatures(extra []byte) [][]byte {
	startPos := ExtraAuditorStartPos + PaddingBitsLength
	numSigs := (len(extra) - ExtraAuditorStartPos) / ExtraAuditorSignature
	sigs := make([][]byte, numSigs)

	for i := 0; i < numSigs; i++ {
		sigs[i] = extra[startPos+i*ExtraAuditorSignature : startPos+((i+1)*ExtraAuditorSignature+ExtraAuditorSignature)]
	}
	return sigs
}

func invokeRPC_AuditChain_Sim(header *types.Header, result interface{}, methodName string, args ...interface{}) error {
	numAuditor := 1

	fakeAuditChainBlock := make([]byte, 10)
	fakeSignatures := make([][]byte, 1)
	fakePubKeys := make([][]byte, 1)
	fakeParentHash := header.ParentHash.Bytes()
	// fakeParentHash := make([]byte, 32)
	fakeNumber := header.Number.Uint64()

	sig := crypto.Sign()
	crypto.VerifySignature()

	fakeAuditChainHeader := &exttype.AuditChainHeader{
		AuditorSignatures: fakeSignatures,
		PubKeys:           fakePubKeys,
		ParentHash:        fakeParentHash,
		Number:            fakeNumber,
	}

	fakeRecvMsg := &exttype.RecvMsg{
		AuditChainBlock: fakeAuditChainBlock,
		Header:          fakeAuditChainHeader,
	}

	result = fakeRecvMsg

	return nil
}

func InvokeRPC_AuditChain(sim bool, header *types.Header, url string, result interface{}, methodName string, args ...interface{}) error {
	if sim {
		return invokeRPC_AuditChain_Sim(header, result, methodName, args...)
	}

	client, err := rpc.DialContext(context.Background(), url)
	if err != nil {
		return fmt.Errorf("Connection to AuditChain failed! err[%s]", err.Error())
	}

	err = client.CallContext(context.Background(), &result, methodName, args...)
	if err != nil {
		return fmt.Errorf("Send Block Proposal to AuditChain failed ! err[%s]", err.Error())
	}

	return nil
}
