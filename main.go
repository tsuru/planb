// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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

	"github.com/codegangsta/cli"
)

func handleSignals(router *Router) {
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
}

func runServer(c *cli.Context) {
	listener, err := net.Listen("tcp", c.String("listen"))
	if err != nil {
		log.Fatal(err)
	}
	router := Router{
		ReadRedisHost:  c.String("read-redis-host"),
		ReadRedisPort:  c.Int("read-redis-port"),
		WriteRedisHost: c.String("write-redis-host"),
		WriteRedisPort: c.Int("write-redis-port"),
		LogPath:        c.String("access-log"),
		RequestTimeout: time.Duration(c.Int("request-timeout")) * time.Second,
		DialTimeout:    time.Duration(c.Int("dial-timeout")) * time.Second,
	}
	err = router.Init()
	if err != nil {
		log.Fatal(err)
	}
	handleSignals(&router)
	log.Printf("Listening on %v...\n", listener.Addr())
	log.Fatal(http.Serve(listener, &router))
}

func main() {
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "listen, l",
			Value: "0.0.0.0:8989",
			Usage: "Address to listen",
		},
		cli.StringFlag{
			Name:  "read-redis-host",
			Value: "127.0.0.1",
		},
		cli.IntFlag{
			Name:  "read-redis-port",
			Value: 6379,
		},
		cli.StringFlag{
			Name:  "write-redis-host",
			Value: "127.0.0.1",
		},
		cli.IntFlag{
			Name:  "write-redis-port",
			Value: 6379,
		},
		cli.StringFlag{
			Name:  "access-log",
			Value: "./access.log",
			Usage: "File path where access log will be written. If value is `syslog` log will be sent to local syslog.",
		},
		cli.IntFlag{
			Name:  "request-timeout",
			Value: 30,
			Usage: "Total backend request timeout in seconds",
		},
		cli.IntFlag{
			Name:  "dial-timeout",
			Value: 10,
			Usage: "Dial backend request timeout in seconds",
		},
	}
	app.Version = "0.1.0"
	app.Name = "gohipache"
	app.Usage = "http and websockets reverse proxy"
	app.Action = runServer
	app.Author = "tsuru team"
	app.Email = "https://github.com/tsuru/gohipache"
	app.Run(os.Args)
}
