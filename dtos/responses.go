package dtos

type GetDataResponseDto struct {
	FileName string `json:"fileName"`
	Data     string `json:"data"`
}

type GetDataErrorResponseDto struct {
	ErrorMessage string `json:"errorMessage"`
}

type CallbackResponseDto struct {
	Status string `json:"status"`
}
