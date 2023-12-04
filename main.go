package main

import (
	"flag"
	"github.com/mosteknoloji/glog"
	"runtime"
	"sima-golang/config"
)

func main() {
	_ = flag.CommandLine.Parse([]string{})
	config.LoadStaticData()
	glog.Info("[INFO] -  Go Runtime is  " + runtime.Version())
	s := new(service)
	s.Start()
}
