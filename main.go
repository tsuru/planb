package main

import (
	"net"
	"net/http"
	"os"
	"os/signal"
)

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:8080")
	if err != nil {
		panic(err)
	}
	router := Router{
		RedisHost: "127.0.0.1",
		RedisPort: 6379,
		LogPath:   "./access.log",
	}
	err = router.Init()
	if err != nil {
		panic(err)
	}
	sigChan := make(chan os.Signal, 1)
	go func() {
		if _, ok := <-sigChan; ok {
			router.Stop()
		}
	}()
	signal.Notify(sigChan, os.Interrupt, os.Kill)
	panic(http.Serve(listener, &router))
}
