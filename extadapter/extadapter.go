// Package main provides
package extadapter

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/extadapter/exttype"
	pb "github.com/ethereum/go-ethereum/extadapter/proto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

const (
	ExtraAuditorSignature = crypto.SignatureLength
	ExtraAuditorStartPos  = 120
	PaddingBitsLength     = 4

	TestKeyStore   = `{"address":"9f0ee8037891ad91c99104ba03edeb193ef182d8","crypto":{"cipher":"aes-128-ctr","ciphertext":"da115b7bf2e3dc247ddc12152304d41424d67189fae44c03dd4300b53091366a","cipherparams":{"iv":"4124b45f57fcfbd15706aef3c94be174"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"a94152c57962054f562714e59c018fbc18f4e84fc81bfe57abf3f15a5883eb40"},"mac":"9ad00d41a090cc9d942d3927e4629ecfd56e8975777a1cf3926b68863a468c07"},"id":"7794cce0-1862-4ed6-899c-cba0cc2aed74","version":3}`
	TestPassword   = "sslab423"
	TestPrivateKey = ""
	TestPublicKey  = ""
	GatewayUrl     = "http://141.223.121.31:50051"
	// Urls = [...]string{"http://141.223.121.54:8080"}
	// Urls                      = [...]string{"http://141.223.121.45:40001"}
	proposalMethodName string = "auditchain_proposal"
)

type NarwhalAdapter struct {
	// Listen address for the server specified as hostname:port
	hostAddress string

	gatewayAddress string
	// GRPC server
	server *grpc.Server

	gatewayConn   *grpc.ClientConn
	gatewayClient pb.NarwhalGatewayClient

	outc chan *NarwhalOutput

	committedSeqs map[uint64]bool
}

type NarwhalOutput struct {
	Headers []*types.Header
	Evt     *pb.NarwhalCommitEvent
}

func GetNarwhalAdapter(hostAddr, gatewayAddr string) *NarwhalAdapter {
	// address := fmt.Sprintf("%s:%s", addr, port)
	// gatewayAddr := "0.0.0.0:50051"

	lis, err := net.Listen("tcp", hostAddr)
	if err != nil {
		panic("failed to listen:" + err.Error())
	}
	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	na := &NarwhalAdapter{
		hostAddress:    hostAddr,
		gatewayAddress: gatewayAddr,
		server:         grpcServer,
		outc:           make(chan *NarwhalOutput, 100),
		committedSeqs:  make(map[uint64]bool),
	}

	pb.RegisterCommitNotifierServer(grpcServer, na)
	go grpcServer.Serve(lis)

	return na
}

func (na *NarwhalAdapter) CheckConnection() bool {
	if na.gatewayConn == nil {
		return false
	}

	healthClient := healthpb.NewHealthClient(na.gatewayConn)
	response, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})

	if err != nil {
		log.Error("Failed to check the connection to Narwhal Gateway")
		return false
	}

	if response.GetStatus() != healthpb.HealthCheckResponse_SERVING {
		log.Error("Narwhal Gateway is not serving")
		return false
	}

	state := na.gatewayConn.GetState()
	switch state {
	case connectivity.Idle:
	case connectivity.Shutdown:
	case connectivity.TransientFailure:
		return false
	}
	return true
}

// Broadcast invokes SubmitTransaction to NarwhalGateway
func (na *NarwhalAdapter) encodeBlock(block *types.Block) ([]byte, []byte) {
	blockBytes, err := rlp.EncodeToBytes(block)
	if err != nil {
		panic("Failed on RLP encoding on the block")
	}

	headerBytes, err := rlp.EncodeToBytes(block.Header())
	if err != nil {
		panic("Failed on RLP encoding on the block header")
	}

	return blockBytes, headerBytes
}

func (na *NarwhalAdapter) getGatewayClient() error {
	log.Info("Trying to dial to narwhal gateway")
	// conn, err := grpc.Dial(na.gatewayAddress, grpc.WithInsecure(), grpc.WithBlock())
	conn, err := grpc.Dial(na.gatewayAddress, grpc.WithInsecure())
	if err != nil {
		return fmt.Errorf("Did not connect Narwhal Gateway, plz check the gateway server is running on %s!, err[%s]", na.gatewayAddress, err.Error())
	}
	na.gatewayConn = conn

	na.gatewayClient = pb.NewNarwhalGatewayClient(na.gatewayConn)
	return nil
}

func (na *NarwhalAdapter) Broadcast(block *types.Block) error {
	var err error
	if na.gatewayConn == nil {
		err = na.getGatewayClient()
		if err != nil {
			log.Error(err.Error())
			return err
		}
	}

	if !na.CheckConnection() {
		return fmt.Errorf("gateway connection lost!")
	}

	blockBytes, headerBytes := na.encodeBlock(block)
	proposal := &pb.Proposal{
		EthereumBlock:  blockBytes,
		EthereumHeader: headerBytes,
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	// hexHeader for debugging header's byte layout
	// hexHeaders := fmt.Sprintf("%x", proposal.EthereumHeader)
	log.Info("Start to submit Tx: ", "proposal.header", block.Number())
	propresp, err := na.gatewayClient.SubmitTransaction(ctx, proposal)
	if err != nil {
		log.Error("could not request: %v", err)
		return err
	}

	if propresp.SuccessOrFail == "fail" {
		return fmt.Errorf("Failed to Submit Tx to narwhal gateway!")
	}

	return nil
}

func (na *NarwhalAdapter) RebuildHeaderWithNarwhalSig(block *types.Block, co *NarwhalOutput) (*types.Block, error) {
	rebuildHeader := block.Header()
	ethNumber := block.Header().Number
	narwhalNumbers := make([]*big.Int, 0, len(co.Headers))

	for _, header := range co.Headers {
		narwhalNumbers = append(narwhalNumbers, header.Number)

		log.Info("Compare header numbers", "eth", ethNumber, "eth-in-narwhal", header.Number)
		if ethNumber.Cmp(header.Number) == 0 {
			log.Info("Found matching block number, safe to execute", "number", ethNumber)
			return block.WithSeal(rebuildHeader), nil
		}
	}
	// rebuildHeader.Extra = EncodeExtraFieldwithNewSigs(rebuildHeader.Extra, recvMsg)
	return nil, fmt.Errorf("no matching eth block number[%d] in narwhal[%+v]", ethNumber, narwhalNumbers)
}

func (na *NarwhalAdapter) WaitForCommit() *NarwhalOutput {
	evt := <-na.outc

	return evt
}

func (na *NarwhalAdapter) Notify(ctx context.Context, req *pb.NarwhalCommitEvent) (*pb.NotifyResp, error) {
	// hexHeader for debugging header's byte layout
	// hexHeaders := fmt.Sprintf("%x", req.EthBlockDigest)
	log.Info("Received Endorsed Commits from Narwhal", "narwhal-number", req.NarwhalSequenceNumber)
	resp := &pb.NotifyResp{
		Resp: "thanks",
	}

	// Detect duplicated messages. Uncomment this if a quorum-based processing is needed)
	if _, ok := na.committedSeqs[req.NarwhalSequenceNumber]; ok {
		resp := &pb.NotifyResp{
			Resp: "already got it, but thanks tho",
		}
		return resp, nil
	}
	na.committedSeqs[req.NarwhalSequenceNumber] = true
	log.Info("Add and be ready to process a new NarwhalCommitEvent", "narwhal-number", req.NarwhalSequenceNumber)

	var headers []*types.Header
	for _, headerBytes := range req.EthBlockDigest {
		h := &types.Header{}
		err := rlp.DecodeBytes(headerBytes, h)
		if err != nil {
			errmsg := fmt.Sprintf("err[%s], headerBytes:%x", err.Error(), headerBytes)
			panic(errmsg)
		}

		log.Info("narwhal commit: ", "eth-number", h.Number, "narwhal-number", req.NarwhalSequenceNumber)
		headers = append(headers, h)

	}

	narwhalOut := &NarwhalOutput{
		Headers: headers,
		Evt:     req,
	}

	na.outc <- narwhalOut

	return resp, nil
}

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

func broadcastBlock(sendMsgBytes []byte, url string) error {
	var err error
	log.Info("Sending to Auditor Narwhal Network", "endpoint", url)

	err = InvokeSubmitTransactionViaGRPC(url, sendMsgBytes)
	if err != nil {
		return err
	}

	log.Info("Successfully sends EthereumBlock to NarwhalGateway", "gateway.endpoint", url)
	return nil
}

func BroadcastBlock(block *types.Block) error {
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

	return broadcastBlock(sendMsgBytes, GatewayUrl)
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

// func invokeRPC_AuditChain_Sim(header *types.Header, result interface{}, methodName string, args ...interface{}) error {
//     numAuditor := 1

//     fakeAuditChainBlock := make([]byte, 10)
//     fakeSignatures := make([][]byte, 1)
//     fakePubKeys := make([][]byte, 1)
//     fakeParentHash := header.ParentHash.Bytes()
//     // fakeParentHash := make([]byte, 32)
//     fakeNumber := header.Number.Uint64()

//     sig := crypto.Sign()
//     crypto.VerifySignature()

//     fakeAuditChainHeader := &exttype.AuditChainHeader{
//         AuditorSignatures: fakeSignatures,
//         PubKeys:           fakePubKeys,
//         ParentHash:        fakeParentHash,
//         Number:            fakeNumber,
//     }

//     fakeRecvMsg := &exttype.RecvMsg{
//         AuditChainBlock: fakeAuditChainBlock,
//         Header:          fakeAuditChainHeader,
//     }

//     result = fakeRecvMsg

//     return nil
// }

func InvokeRPC_AuditChain(sim bool, header *types.Header, url string, result interface{}, methodName string, args ...interface{}) error {
	// if sim {
	//     return invokeRPC_AuditChain_Sim(header, result, methodName, args...)
	// }

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

// InvokeSubmitTransactionViaGRPC submits Tx to NarwhalGateway
func InvokeSubmitTransactionViaGRPC(url string, data []byte) error {
	fmt.Println("dial to gateway")
	conn, err := grpc.Dial(url, grpc.WithInsecure(), grpc.WithBlock())
	defer conn.Close()

	fmt.Println("connected to gateway")
	if err != nil {
		log.Error("Did not connect to Narwhal Gateway, plz check the gateway server is running on", "url", url, "err", err.Error())
		return err
	}

	client := pb.NewNarwhalGatewayClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	proposal := &pb.Proposal{
		EthereumBlock: data,
	}

	fmt.Println("Start to submit Tx")
	propresp, err := client.SubmitTransaction(ctx, proposal)
	if err != nil {
		log.Error("could not request: err", err.Error())
		return err
	}

	if propresp.SuccessOrFail == "fail" {
		return fmt.Errorf("Failed to Submit Tx to narwhal gateway!")
	}

	return nil
}

func CheckSignerFlag() bool {
	return os.Getenv("SIGNER") == "true"
}
