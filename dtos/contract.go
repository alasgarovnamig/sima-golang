package dtos

type Contract struct {
	Header            Header            `json:"Header"`
	SignableContainer SignableContainer `json:"SignableContainer"`
}

type Header struct {
	AlgorithmName string `json:"AlgName"`
	Signature     []byte `json:"Signature"`
}

type SignableContainer struct {
	ProtoInfo     ProtoInfo     `json:"ProtoInfo"`
	OperationInfo OperationInfo `json:"OperationInfo"`
	ClientInfo    ClientInfo    `json:"ClientInfo"`
	DataInfo      DataInfo      `json:"DataInfo"`
}

type ClientInfo struct {
	ClientId    int      `json:"ClientId"`
	ClientName  string   `json:"ClientName"`
	IconURI     string   `json:"IconURI"`
	Callback    string   `json:"Callback"`
	HostName    []string `json:"HostName"`
	RedirectURI string   `json:"RedirectURI"`
}

type DataInfo struct {
	DataURI     string `json:"DataURI"`
	AlgName     string `json:"AlgName"`
	FingerPrint string `json:"FingerPrint"`
}

type OperationInfo struct {
	Type        string   `json:"Type"`
	OperationId string   `json:"OperationId"`
	NbfUTC      int64    `json:"NbfUTC"`
	ExpUTC      int64    `json:"ExpUTC"`
	Assignee    []string `json:"Assignee"`
}

type ProtoInfo struct {
	Name    string `json:"Name"`
	Version string `json:"Version"`
}
