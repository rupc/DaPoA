package exttype

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
