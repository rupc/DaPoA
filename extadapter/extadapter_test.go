package extadapter

import (
	"fmt"
	"log"
	"testing"
)

func TestAdapter(t *testing.T) {
	url := "http://141.223.181.54:8080/api"
	testMethodName := "message"
	var result interface{}
	params := []interface{}{1, "abcdefg"}

	// fmt.Println(params)
	err := SendToAuditor(url, &result, testMethodName, params...)
	if err != nil {
		fmt.Println(err.Error())
		t.Fatal(err.Error())
	}
	log.Println("result", result)
}
