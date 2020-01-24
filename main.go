// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"

	"github.com/codegangsta/cli"
	"github.com/google/gops/agent"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/edukorg/planb/backend"
	"github.com/edukorg/planb/reverseproxy"
	"github.com/edukorg/planb/router"
	"github.com/edukorg/planb/tls"
)

func handleSignals(server interface {
	Stop()
}) {
	sigChan := make(chan os.Signal, 3)
	go func() {
		for sig := range sigChan {
			if sig == os.Interrupt || sig == os.Kill {
				server.Stop()
				agent.Close()
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
	err := agent.Listen(agent.Options{})
	if err != nil {
		log.Printf("Unable to start gops agent: %v", err)
	}

	var rp reverseproxy.ReverseProxy
	switch c.String("engine") {
    case "native":
        rp = &reverseproxy.NativeReverseProxy{}
	default:
		log.Fatal(errors.New("invalid engine"))
	}
	log.Printf("Using %T engine\n", rp)
	readOpts := backend.RedisOptions{
		Network:       c.String("read-redis-network"),
		Host:          c.String("read-redis-host"),
		Port:          c.Int("read-redis-port"),
		SentinelAddrs: c.String("read-redis-sentinel-addrs"),
		SentinelName:  c.String("read-redis-sentinel-name"),
		Password:      c.String("read-redis-password"),
		DB:            c.Int("read-redis-db"),
	}
	writeOpts := backend.RedisOptions{
		Network:       c.String("write-redis-network"),
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
		Router:            &r,
		RequestIDHeader:   http.CanonicalHeaderKey(c.String("request-id-header")),
		FlushInterval:     time.Duration(c.Int("flush-interval")) * time.Millisecond,
		DialTimeout:       time.Duration(c.Int("dial-timeout")) * time.Second,
		RequestTimeout:    time.Duration(c.Int("request-timeout")) * time.Second,
		ReadTimeout:       c.Duration("client-read-timeout"),
		ReadHeaderTimeout: c.Duration("client-read-header-timeout"),
		WriteTimeout:      c.Duration("client-write-timeout"),
		IdleTimeout:       c.Duration("client-idle-timeout"),
	})
	if err != nil {
		log.Fatal(err)
	}

	listener := &router.RouterListener{
		ReverseProxy: rp,
		Listen:       c.String("listen"),
		TLSListen:    c.String("tls-listen"),
		TLSPreset:    c.String("tls-preset"),
		CertLoader:   getCertificateLoader(c, readOpts),
	}

	if addr := c.String("metrics-address"); addr != "" {
		handler := http.NewServeMux()
		handler.Handle("/metrics", promhttp.Handler())
		go func() {
			log.Fatal(http.ListenAndServe(addr, handler))
		}()
	}

	handleSignals(listener)
	listener.Serve()

	r.Stop()
	routesBE.StopMonitor()
}

func getCertificateLoader(c *cli.Context, readOpts backend.RedisOptions) tls.CertificateLoader {
	if c.String("tls-listen") == "" {
		return nil
	}

	from := c.String("load-certificates-from")
	switch from {
	case "redis":
		client, err := readOpts.Client()
		if err != nil {
			log.Fatal(err)
		}

		return tls.NewRedisCertificateLoader(client)
	default:
		return tls.NewFSCertificateLoader(from)
	}
}

func fixUsage(s string) string {
	linebreakRegexp := regexp.MustCompile(`\n{1}[\t ]*`)
	s = linebreakRegexp.ReplaceAllString(s, " ")
	parts := strings.Split(s, " ")
	currLen := 0
	lastPart := 0
	var lines []string
	for i := range parts {
		if currLen+len(parts[i])+1 > 65 {
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
	oldStringer := cli.FlagStringer
	cli.FlagStringer = func(flag cli.Flag) string {
		usage := oldStringer(flag)
		usageIdx := strings.LastIndex(usage, "\t")
		if usageIdx != -1 {
			usage = usage[:usageIdx] + "\t" + fixUsage(usage[usageIdx+1:])
		}
		return usage
	}
	app := cli.NewApp()
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "listen, l",
			Value: "0.0.0.0:8989",
			Usage: "Address to listen",
		},
		cli.StringFlag{
			Name:  "tls-listen",
			Usage: "Address to listen with tls",
		},
		cli.StringFlag{
			Name: "tls-preset",
			Usage: fmt.Sprintf(`Preset containing supported TLS versions and cyphers, according to https://wiki.mozilla.org/Security/Server_Side_TLS.
Possible values are [%s, %s, %s]`, router.TLS_PRESET_MODERN, router.TLS_PRESET_INTERMEDIATE, router.TLS_PRESET_OLD),
			Value: router.TLS_PRESET_MODERN,
		},
		cli.StringFlag{
			Name:  "metrics-address",
			Usage: "Address to expose prometheus /metrics",
		},
		cli.StringFlag{
			Name:  "load-certificates-from",
			Value: "redis",
			Usage: `Path where certificate will found.
If value equals 'redis' certificate will be loaded from redis service.`,
		},
		cli.StringFlag{
			Name:  "read-redis-network",
			Value: "tcp",
			Usage: "Redis address network, possible values are \"tcp\" for tcp connection and \"unix\" for connecting using unix sockets",
		},
		cli.StringFlag{
			Name:  "read-redis-host",
			Value: "127.0.0.1",
			Usage: "Redis host address for tcp connections or socket path for unix sockets",
		},
		cli.IntFlag{
			Name:  "read-redis-port",
			Value: 6379,
			Usage: "Redis port",
		},
		cli.StringFlag{
			Name:  "read-redis-sentinel-addrs",
			Usage: "Comma separated list of redis sentinel addresses",
		},
		cli.StringFlag{
			Name:  "read-redis-sentinel-name",
			Usage: "Redis sentinel name",
		},
		cli.StringFlag{
			Name:  "read-redis-password",
			Usage: "Redis password",
		},
		cli.IntFlag{
			Name:  "read-redis-db",
			Usage: "Redis database number",
		},
		cli.StringFlag{
			Name:  "write-redis-network",
			Value: "tcp",
			Usage: "Redis address network, possible values are \"tcp\" for tcp connection and \"unix\" for connecting using unix sockets",
		},
		cli.StringFlag{
			Name:  "write-redis-host",
			Value: "127.0.0.1",
			Usage: "Redis host address for tcp connections or socket path for unix sockets",
		},
		cli.IntFlag{
			Name:  "write-redis-port",
			Value: 6379,
			Usage: "Redis port",
		},
		cli.StringFlag{
			Name:  "write-redis-sentinel-addrs",
			Usage: "Comma separated list of redis sentinel addresses",
		},
		cli.StringFlag{
			Name:  "write-redis-sentinel-name",
			Usage: "Redis sentinel name",
		},
		cli.StringFlag{
			Name:  "write-redis-password",
			Usage: "Redis password",
		},
		cli.IntFlag{
			Name:  "write-redis-db",
			Usage: "Redis database number",
		},
		cli.StringFlag{
			Name:  "access-log",
			Value: "./access.log",
			Usage: `File path where access log will be written.
If value equals 'syslog' log will be sent to local syslog.
The value 'none' can be used to disable access logs.`,
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
		cli.DurationFlag{
			Name:  "client-read-timeout",
			Value: 0,
			Usage: "Maximum duration for reading the entire request, including the body",
		},
		cli.DurationFlag{
			Name:  "client-read-header-timeout",
			Value: 0,
			Usage: "Amount of time allowed to read request headers",
		},
		cli.DurationFlag{
			Name:  "client-write-timeout",
			Value: 0,
			Usage: "Maximum duration before timing out writes of the response",
		},
		cli.DurationFlag{
			Name:  "client-idle-timeout",
			Value: 0,
			Usage: "Maximum amount of time to wait for the next request when keep-alives are enabled",
		},
		cli.IntFlag{
			Name:  "dead-backend-time",
			Value: 30,
			Usage: "Time in seconds a backend will remain disabled after a network failure",
		},
		cli.IntFlag{
			Name:  "flush-interval",
			Value: 10,
			Usage: "Time in milliseconds to flush the proxied request",
		},
		cli.StringFlag{
			Name:  "request-id-header",
			Usage: "Header to enable message tracking",
		},
		cli.BoolFlag{
			Name:  "active-healthcheck",
			Usage: "Enable active healthcheck on dead backends once they are marked as dead. Enabling this flag will result in dead backends only being enabled again once the active healthcheck routine is able to reach them.",
		},
		cli.StringFlag{
			Name:  "engine",
			Value: "native",
			Usage: "Reverse proxy engine. Option is only 'native'.",
		},
		cli.BoolFlag{
			Name:  "backend-cache",
			Usage: "Enable caching backend results for 2 seconds. This may cause temporary inconsistencies.",
		},
	}
	app.Version = "0.1.15"
	app.Name = "planb"
	app.Usage = "http and websockets reverse proxy"
	app.Action = runServer
	app.Author = "tsuru team"
	app.Email = "https://github.com/edukorg/planb"
	app.Run(os.Args)
}
