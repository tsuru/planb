package main

import (
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"runtime/pprof"
	"syscall"
	"time"
)

func main() {
	listener, err := net.Listen("tcp", "0.0.0.0:8989")
	if err != nil {
		log.Fatal(err)
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
		log.Fatal(err)
	}
	sigChan := make(chan os.Signal, 3)
	go func() {
		for sig := range sigChan {
			if sig == os.Interrupt || sig == os.Kill {
				router.Stop()
				os.Exit(0)
			}
			if sig == syscall.SIGUSR1 {
				var buf []byte
				var written int
				currLen := 1024
				for written == len(buf) {
					buf = make([]byte, currLen)
					written = runtime.Stack(buf, true)
					currLen *= 2
				}
				log.Print(string(buf[:written]))
			}
			if sig == syscall.SIGUSR2 {
				go func() {
					cpufile, _ := os.OpenFile("./gohipache_cpu.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
					memfile, _ := os.OpenFile("./gohipache_mem.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
					log.Println("enabling profile...")
					pprof.WriteHeapProfile(memfile)
					memfile.Close()
					pprof.StartCPUProfile(cpufile)
					time.Sleep(60 * time.Second)
					pprof.StopCPUProfile()
					cpufile.Close()
					log.Println("profiling done")
				}()
			}
		}
	}()
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGUSR1, syscall.SIGUSR2)
	log.Printf("Listening on %v...\n", listener.Addr())
	panic(http.Serve(listener, &router))
}
