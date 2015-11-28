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
	"strings"
	"syscall"
	"time"

	"github.com/braintree/manners"
	"github.com/codegangsta/cli"
)

func handleSignals(server *manners.GracefulServer) {
	sigChan := make(chan os.Signal, 3)
	go func() {
		for sig := range sigChan {
			if sig == os.Interrupt || sig == os.Kill {
				server.Close()
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
					cpufile, _ := os.OpenFile("./planb_cpu.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
					memfile, _ := os.OpenFile("./planb_mem.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
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
		DeadBackendTTL: c.Int("dead-backend-time"),
		FlushInterval:  time.Duration(c.Int("flush-interval")) * time.Millisecond,
	}
	err = router.Init()
	if err != nil {
		log.Fatal(err)
	}
	s := manners.NewWithServer(&http.Server{Handler: &router})
	handleSignals(s)
	log.Printf("Listening on %v...\n", listener.Addr())
	err = s.Serve(listener)
	router.Stop()
	if err != nil {
		log.Fatal(err)
	}
}

func fixUsage(s string) string {
	parts := strings.Split(s, " ")
	currLen := 0
	lastPart := 0
	var lines []string
	for i := range parts {
		if currLen+len(parts[i])+1 > 55 {
			lines = append(lines, strings.Join(parts[lastPart:i], " "))
			currLen = 0
			lastPart = i
		}
		currLen += len(parts[i]) + 1
	}
	lines = append(lines, strings.Join(parts[lastPart:], " "))
	return strings.Join(lines, "\n\t")
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
			Usage: fixUsage("File path where access log will be written. If value equals `syslog` log will be sent to local syslog."),
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
		cli.IntFlag{
			Name:  "dead-backend-time",
			Value: 30,
			Usage: fixUsage("Time in seconds a backend will remain disabled after a network failure."),
		},
		cli.IntFlag{
			Name:  "flush-interval",
			Value: 10,
			Usage: fixUsage("Time in milliseconds to flush the proxied request."),
		},
	}
	app.Version = "0.1.3"
	app.Name = "planb"
	app.Usage = "http and websockets reverse proxy"
	app.Action = runServer
	app.Author = "tsuru team"
	app.Email = "https://github.com/tsuru/planb"
	app.Run(os.Args)
}
