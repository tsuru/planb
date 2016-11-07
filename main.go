// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/codegangsta/cli"
	"github.com/tsuru/planb/backend"
	"github.com/tsuru/planb/reverseproxy"
	"github.com/tsuru/planb/router"
)

func handleSignals(server interface {
	Stop()
}) {
	sigChan := make(chan os.Signal, 3)
	go func() {
		for sig := range sigChan {
			if sig == os.Interrupt || sig == os.Kill {
				server.Stop()
			}
			if sig == syscall.SIGUSR1 {
				pprof.Lookup("goroutine").WriteTo(os.Stdout, 2)
			}
			if sig == syscall.SIGUSR2 {
				go startProfiling()
			}
		}
	}()
	signal.Notify(sigChan, os.Interrupt, os.Kill, syscall.SIGUSR1, syscall.SIGUSR2)
}

func startProfiling() {
	cpufile, _ := os.OpenFile("./planb_cpu.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
	memfile, _ := os.OpenFile("./planb_mem.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
	lockfile, _ := os.OpenFile("./planb_lock.pprof", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
	log.Println("enabling profile...")
	runtime.GC()
	pprof.WriteHeapProfile(memfile)
	memfile.Close()
	runtime.SetBlockProfileRate(1)
	time.Sleep(30 * time.Second)
	pprof.Lookup("block").WriteTo(lockfile, 0)
	runtime.SetBlockProfileRate(0)
	lockfile.Close()
	pprof.StartCPUProfile(cpufile)
	time.Sleep(30 * time.Second)
	pprof.StopCPUProfile()
	cpufile.Close()
	log.Println("profiling done")
}

func runServer(c *cli.Context) {
	var rp reverseproxy.ReverseProxy
	switch c.String("engine") {
	case "native":
		rp = &reverseproxy.NativeReverseProxy{}
	case "fasthttp":
		rp = &reverseproxy.FastReverseProxy{}
	default:
		log.Fatal(errors.New("invalid engine"))
	}
	readOpts := backend.RedisOptions{
		Host:          c.String("read-redis-host"),
		Port:          c.Int("read-redis-port"),
		SentinelAddrs: c.String("read-redis-sentinel-addrs"),
		SentinelName:  c.String("read-redis-sentinel-name"),
		Password:      c.String("read-redis-password"),
		DB:            c.Int("read-redis-db"),
	}
	writeOpts := backend.RedisOptions{
		Host:          c.String("write-redis-host"),
		Port:          c.Int("write-redis-port"),
		SentinelAddrs: c.String("write-redis-sentinel-addrs"),
		SentinelName:  c.String("write-redis-sentinel-name"),
		Password:      c.String("write-redis-password"),
		DB:            c.Int("write-redis-db"),
	}
	routesBE, err := backend.NewRedisBackend(readOpts, writeOpts)
	if err != nil {
		log.Fatal(err)
	}
	if c.Bool("active-healthcheck") {
		err = routesBE.StartMonitor()
		if err != nil {
			log.Fatal(err)
		}
	}
	r := router.Router{
		Backend:        routesBE,
		LogPath:        c.String("access-log"),
		DeadBackendTTL: c.Int("dead-backend-time"),
		CacheEnabled:   c.Bool("backend-cache"),
	}
	err = r.Init()
	if err != nil {
		log.Fatal(err)
	}
	err = rp.Initialize(reverseproxy.ReverseProxyConfig{
		Router:          &r,
		RequestIDHeader: c.String("request-id-header"),
		FlushInterval:   time.Duration(c.Int("flush-interval")) * time.Millisecond,
		DialTimeout:     time.Duration(c.Int("dial-timeout")) * time.Second,
		RequestTimeout:  time.Duration(c.Int("request-timeout")) * time.Second,
	})
	if err != nil {
		log.Fatal(err)
	}
	handleSignals(rp)
	listener, err := net.Listen("tcp", c.String("listen"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Listening on %s...\n", listener.Addr().String())
	rp.Listen(listener)
	r.Stop()
	routesBE.StopMonitor()
}

func fixUsage(s string) string {
	linebreakRegexp := regexp.MustCompile(`\n{1}[\t ]*`)
	s = linebreakRegexp.ReplaceAllString(s, " ")
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
			Name:  "read-redis-sentinel-addrs",
			Usage: "Comma separated list of redis addresses",
		},
		cli.StringFlag{
			Name: "read-redis-sentinel-name",
		},
		cli.StringFlag{
			Name: "read-redis-password",
		},
		cli.IntFlag{
			Name: "read-redis-db",
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
			Name:  "write-redis-sentinel-addrs",
			Usage: "Comma separated list of redis addresses",
		},
		cli.StringFlag{
			Name: "write-redis-sentinel-name",
		},
		cli.StringFlag{
			Name: "write-redis-password",
		},
		cli.IntFlag{
			Name: "write-redis-db",
		},
		cli.StringFlag{
			Name:  "access-log",
			Value: "./access.log",
			Usage: fixUsage(`File path where access log will be written.
If value equals 'syslog' log will be sent to local syslog.
The value 'none' can be used to disable access logs.`),
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
			Usage: fixUsage("Time in seconds a backend will remain disabled after a network failure"),
		},
		cli.IntFlag{
			Name:  "flush-interval",
			Value: 10,
			Usage: fixUsage("Time in milliseconds to flush the proxied request"),
		},
		cli.StringFlag{
			Name:  "request-id-header",
			Usage: "Header to enable message tracking",
		},
		cli.BoolFlag{
			Name: "active-healthcheck",
		},
		cli.StringFlag{
			Name:  "engine",
			Value: "native",
			Usage: fixUsage("Reverse proxy engine, options are 'native' and 'fasthttp'"),
		},
		cli.BoolFlag{
			Name:  "backend-cache",
			Usage: "Enable caching backend results for 2 seconds. This may cause temporary inconsistencies.",
		},
	}
	app.Version = "0.1.8"
	app.Name = "planb"
	app.Usage = "http and websockets reverse proxy"
	app.Action = runServer
	app.Author = "tsuru team"
	app.Email = "https://github.com/tsuru/planb"
	app.Run(os.Args)
}
