package main

import (
	"net"
	"net/http"
)

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:8081")
	if err != nil {
		panic(err)
	}
	router := Router{}
	err = router.Init()
	if err != nil {
		panic(err)
	}
	http.Handle("/", &router)
	panic(http.Serve(listener, nil))
}
