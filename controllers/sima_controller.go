package controllers

import (
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"net/http"
	"sima-golang/services"
	"sima-golang/utils"
)

type ISimaController interface {
	GetData(context *gin.Context)
	Callback(context *gin.Context)
	GetAppURI(context *gin.Context)
	GetQR(context *gin.Context)
}

type SimaController struct {
	simaService services.ISimaService
}

func NewSimaController(simaService services.ISimaService) ISimaController {
	return &SimaController{
		simaService: simaService,
	}
}

func (s SimaController) GetData(context *gin.Context) {
	data, err := s.simaService.GetData(context)
	if err != nil {
		context.AbortWithStatusJSON(http.StatusBadRequest, data)
		return
	}
	context.AbortWithStatusJSON(http.StatusOK, data)
	return
}

func (s SimaController) Callback(context *gin.Context) {
	data, err := s.simaService.Callback(context)
	if err != nil {
		context.AbortWithStatusJSON(http.StatusBadRequest, data)
		return
	}
	context.AbortWithStatusJSON(http.StatusOK, data)
	return
}

func (s SimaController) GetAppURI(context *gin.Context) {
	data, err := s.simaService.GetAppURI()
	if err != nil {
		context.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"ErrorMessage": "This request has not been addressed by the Sima application"})
		return
	}
	context.AbortWithStatusJSON(http.StatusOK, data)
	return
}
func (s SimaController) GetQR(context *gin.Context) {
	url, err := s.simaService.GetQrURI()
	if err != nil {
		context.HTML(500, "error.html", gin.H{})
		return
	}
	byteQR, err := utils.GenerateQRCode(string(url), 350, 350)
	if err != nil {
		context.HTML(500, "error.html", gin.H{})
		return
	}
	qrBase64 := base64.StdEncoding.EncodeToString(byteQR)
	context.HTML(200, "qr.html", gin.H{
		"images": qrBase64,
	})
}
