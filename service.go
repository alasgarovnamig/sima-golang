package main

import (
	"sima-golang/controllers"
	"sima-golang/services"
)

type service struct {
}

func (s *service) Start() {

	simaService := services.NewSimaService()
	simaController := controllers.NewSimaController(simaService)
	r := NewRouting(simaController)
	r.RoutStart()

}
