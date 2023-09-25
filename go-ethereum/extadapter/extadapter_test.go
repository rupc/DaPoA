package extadapter

import (
	"context"
	"fmt"
	"sync"
	"testing"

	pb "github.com/ethereum/go-ethereum/extadapter/proto"
	"google.golang.org/grpc"
)

// func TestAdapter(t *testing.T) {
// url := "http://141.223.181.54:8080/api"
// testMethodName := "message"
// var result interface{}
// params := []interface{}{1, "abcdefg"}

// fmt.Println(params)
// err := SendToAuditor(url, &result, testMethodName, params...)
// if err != nil {
// fmt.Println(err.Error())
// t.Fatal(err.Error())
// }
// log.Println("result", result)
// }

// func TestInvokeSubmitTransactionViaGRPC(t *testing.T) {
//     url := "0.0.0.0:50051"
//     // url := "http://[::1]:50051"
//     // url := "localhost:50051"
//     // url := "http://141.223.121.31:50051"
//     data := []byte("HelloTestGateway")
//     fmt.Println("Test SubmitTransaction to NarwahlGateway")
//     err := InvokeSubmitTransactionViaGRPC(url, data)
//     fmt.Println("Success on SubmitTransaction to NarwhalGateway")
//     if err != nil {
//         t.Fatal(err.Error())
//     }
// }

func TestNarwhalAdapter(t *testing.T) {
	server := GetNarwhalAdapter("0.0.0.0", "60000")
	wg := sync.WaitGroup{}

	wg.Add(1)
	go func() {
		evt := server.WaitForCommit()
		fmt.Printf("Received ConsensusOutput %+v", evt)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		conn, err := grpc.Dial("0.0.0.0:60000", grpc.WithInsecure(), grpc.WithBlock())
		if err != nil {
			panic(err)
		}

		client := pb.NewCommitNotifierClient(conn)
		evt := &pb.NarwhalCommitEvent{
			NarwhalSequenceNumber: 0,
			EthSequenceNumbers:    []uint64{1, 2, 3},
		}

		resp, err := client.Notify(context.Background(), evt)
		if err != nil {
			panic(resp)
		}

		fmt.Printf("sent consensusoutput to server with resp[%+v]\n", resp)
		wg.Done()
	}()

	wg.Wait()
	fmt.Println("grpc test success")
}
