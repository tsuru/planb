package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
)

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:8989")
	if err != nil {
		panic(err)
	}
	router := Router{
		ReadRedisHost:  "127.0.0.1",
		ReadRedisPort:  6379,
		WriteRedisHost: "127.0.0.1",
		WriteRedisPort: 6379,
		LogPath:        "./access.log",
	}
	err = router.Init()
	if err != nil {
		panic(err)
	}
	sigChan := make(chan os.Signal, 1)
	go func() {
		if _, ok := <-sigChan; ok {
			router.Stop()
			os.Exit(0)
		}
	}()
	signal.Notify(sigChan, os.Interrupt, os.Kill)
	fmt.Printf("Listening on %v...\n", listener.Addr())
	panic(http.Serve(listener, &router))
}
