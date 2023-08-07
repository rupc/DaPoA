package exttype

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/RoaringBitmap/roaring"
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

	var pubkeys []string
	var G2_pubkeys []*blst.P2Affine

	// Retrieve public keys
	gjson.Get(committeejson, "authorities").ForEach(func(key, _ gjson.Result) bool {
		pubkeys = append(pubkeys, key.String())

		pubkeyBytes, _ := base64.StdEncoding.DecodeString(key.String())
		// fmt.Println("pubkey", key.String(), len(pubkeyBytes))

		bls_pubkeyFromBytes := new(blst.P2Affine).Uncompress(pubkeyBytes)
		// bls_pubkeyFromBytes := new(blst.P2Affine).Deserialize(pubkeyBytes)

		if bls_pubkeyFromBytes == nil {
			fmt.Println("Failed to deserialize public key")
		}

		G2_pubkeys = append(G2_pubkeys, bls_pubkeyFromBytes)

		fmt.Println("pubkey", key.String()[:10], len(bls_pubkeyFromBytes.Serialize()), len(bls_pubkeyFromBytes.Compress()))
		return true // keep iterating
	})
	// fmt.Println("pubkeys", pubkeys)
	aggregatedPk := new(blst.P2Aggregate)
	aggregatedPk.Aggregate(G2_pubkeys, false)
	aggregatedPkAffine := aggregatedPk.ToAffine()

	// 집계된 공개 키를 출력합니다.
	fmt.Printf("Aggregated public key: %d\n", len(aggregatedPkAffine.Serialize()))

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

	var bytes []byte

	signed_authorities := gjson.Get(committedsubdagjson, "leader.signed_authorities").String()
	err = json.Unmarshal([]byte(signed_authorities), &bytes)
	if err != nil {
		fmt.Println("Failed to unmarshal byte string:", err)
		return
	}
	fmt.Println(bytes)

	// byte slice를 RoaringBitmap으로 디코딩
	bitmap := roaring.NewBitmap()
	_, err = bitmap.FromBuffer(bytes)

	if err != nil {
		fmt.Println("Failed to deserialize bitmap:", err)
		return
	}

	iter := bitmap.Iterator()
	var signed_authorities_idx []uint32

	for iter.HasNext() {
		signed_authorities_idx = append(signed_authorities_idx, iter.Next())
	}

	fmt.Println("Deserialized bitmap:", signed_authorities_idx)

	var signed_public_keys []*blst.P2Affine

	for _, idx := range signed_authorities_idx {
		key := G2_pubkeys[idx]
		signed_public_keys = append(signed_public_keys, key)
	}

	aggregatedFinalPk := new(blst.P2Aggregate)
	aggregatedFinalPk.Aggregate(signed_public_keys, false)
	aggregatedFinalPkAffine := aggregatedFinalPk.ToAffine()

	aggregatedFinalSig := new(blst.P1Affine)
	aggregatedFinalSig.Deserialize(aggBytes)
	fmt.Println("aggregatedFinalPk", len(aggregatedFinalPkAffine.Serialize()))
	fmt.Println("aggregatedFinalSig", len(aggregatedFinalSig.Serialize()))

	// for i, v := range

	// bls_sig := new(blst.P1Aggregate).FromBytes(sigBytes)
	// bls_pubkey := new(blst.P2Affine).FromBytes(pubKeyBytes)

	// bls_pubkey.VerifyCompressed(sigBytes, true, msg, dst)
}

// func (dummy *P2Affine) VerifyCompressed(sig []byte, sigGroupcheck bool,
//     valid := blst.Verify(bls_pubkey, bls_sig)
//     // sig := new(P1Aggregat).Deserialize(aggBytes)
//     // fmt.Println("seq", seq.String())
// }
