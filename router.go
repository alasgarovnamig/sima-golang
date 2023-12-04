package main

import (
	"github.com/gin-gonic/gin"
	"sima-golang/controllers"
)

type Routing struct {
	SimaController controllers.ISimaController
}

func NewRouting(
	simaController controllers.ISimaController,
) *Routing {
	return &Routing{
		SimaController: simaController,
	}
}
func (rt *Routing) RoutStart() {
	r := gin.Default()
	r.LoadHTMLGlob("templates/*.html")
	simaRoutes := r.Group("sima")
	{
		simaRoutes.GET("/getfile", rt.SimaController.GetData)
		simaRoutes.POST("/callback", rt.SimaController.Callback)
		simaRoutes.GET("/appURI", rt.SimaController.GetAppURI)
		simaRoutes.GET("/getQR", rt.SimaController.GetQR)
	}

	r.Run(":8080")
}
