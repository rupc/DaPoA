package exttype

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"

	blst "github.com/supranational/blst/bindings/go"
	"github.com/tidwall/gjson"
)

func TestBlsSignature1(t *testing.T) {
	var ikm [32]byte
	_, _ = rand.Read(ikm[:])
	sk := blst.KeyGen(ikm[:])
	pk := new(PublicKey).From(sk)

	// pk := (PublicKey{}).From(sk)
	// pk := new(PublicKey).From(sk)

	msg := []byte("hello foo")
	sig := new(Signature).Sign(sk, msg, dst)

	if !sig.Verify(true, pk, true, msg, dst) {
		fmt.Println("ERROR: Invalidshit!")
	} else {
		fmt.Println("heh Valid!")
		fmt.Println("Size(PubKey)", len(pk.Serialize()))
		// compressed := pk.Compress()
		fmt.Println("Size(Sig)", len(sig.Serialize()))
		fmt.Println()
		fmt.Println("Size(CompressedPubKey)", len(pk.Compress()))
		fmt.Println("Size(CompressedSig)", len(sig.Compress()))
		fmt.Println()
	}
}

func TestJsonDeserialization(t *testing.T) {
	// fmt.Println(committedsubdagjson)
	pubkey := gjson.Get(committedsubdagjson, "leader.header.author")
	aggreated_signature := gjson.Get(committedsubdagjson, "leader.aggregated_signature")
	signature := gjson.Get(committedsubdagjson, "leader.header.signature")
	// seq := gjson.Get(committedsubdagjson, "sub_dag_index")

	sigBytes, _ := base64.StdEncoding.DecodeString(signature.String())
	pubkeyBytes, _ := base64.StdEncoding.DecodeString(pubkey.String())
	aggBytes, err := base64.StdEncoding.DecodeString(aggreated_signature.String())
	if err != nil {
		fmt.Println("error", err)
	}

	fmt.Println("pubkey\t", pubkey.String(), "len", len(pubkeyBytes))
	fmt.Println("agg_sig\t", aggreated_signature.String(), "len", len(aggBytes))
	fmt.Println("sig\t", signature.String(), "len", len(sigBytes))
	// fmt.Println("seq", seq.String())
}
