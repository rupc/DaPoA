package exttype

import (
	blst "github.com/supranational/blst/bindings/go"
)

type SendMsg struct {
	EthereumBlock []byte `json:"ethereum_block"`
	Header        []byte `json:"header"`
}

type RecvMsg struct {
	AuditChainBlock []byte            `json:"audit_chain_block"`
	Header          *AuditChainHeader `json:"header"`
}

type AuditChainHeader struct {
	AuditorSignatures [][]byte `json:"auditor_signatures"`
	PubKeys           [][]byte `json:"pub_keys"`
	ParentHash        []byte   `json:"parent"`
	Number            uint64   `json:"number"`
}

type PublicKey = blst.P2Affine
type Signature = blst.P1Affine

type AggregatePublicKey = blst.P2Aggregate
type AggregateSignature = blst.P1Aggregate

const (
	BLSSignatureSize = 96
)

var dst = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_")

type BlsSignature struct {
	Signature Signature
}

func (sig *BlsSignature) VerifySignature(pubkey *PublicKey, msg []byte) bool {
	return sig.Signature.Verify(true, pubkey, true, msg, []byte(dst))
}
