package dtos

type CallbackRequestDto struct {
	Type           string `json:"Type"`
	OperationId    string `json:"OperationId"`
	DataSignature  string `json:"DataSignature"`
	SignedDataHash string `json:"SignedDataHash"`
	AlgName        string `json:"AlgName"`
}
