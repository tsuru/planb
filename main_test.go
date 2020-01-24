// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"runtime/pprof"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis"
	"github.com/edukorg/planb/backend"
	"github.com/edukorg/planb/reverseproxy"
	"github.com/edukorg/planb/router"
	"gopkg.in/check.v1"
)

type S struct {
	redis *redis.Client
}

var _ = check.Suite(&S{})

var redisDB int = 2

func Test(t *testing.T) {
	check.TestingT(t)
}

func clearKeys(r *redis.Client) error {
	val := r.Keys("frontend:*").Val()
	val = append(val, r.Keys("dead:*").Val()...)
	if len(val) > 0 {
		return r.Del(val...).Err()
	}
	return nil
}

func redisConn() (*redis.Client, error) {
	return redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379", DB: redisDB}), nil
}

func (s *S) SetUpTest(c *check.C) {
	var err error
	s.redis, err = redisConn()
	c.Assert(err, check.IsNil)
	err = clearKeys(s.redis)
	c.Assert(err, check.IsNil)
}

func (s *S) TearDownTest(c *check.C) {
	s.redis.Close()
}

func (s *S) TestServeHTTPStressAllLeakDetector(c *check.C) {
	if testing.Short() {
		c.Skip("this test takes a long time, specially with -race")
	}
	checkLeaksEnabled := os.Getenv("PLANB_CHECK_LEAKS") != ""
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)
	nFrontends := 50
	nServers := nFrontends * 4
	servers := make([]*httptest.Server, nServers)
	allNamesMap := map[string]struct{}{}
	for i := range servers {
		msg := fmt.Sprintf("server-%d", i)
		allNamesMap[msg] = struct{}{}
		srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.Write([]byte(msg))
		}))
		defer srv.Close()
		servers[i] = srv
	}
	frontends := make([]string, nFrontends)
	for i := range frontends {
		frontend := fmt.Sprintf("stressfront%0d.com", i)
		frontends[i] = frontend
		err := s.redis.RPush("frontend:"+frontend, frontend).Err()
		c.Assert(err, check.IsNil)
		ratio := nServers / nFrontends
		for j := 0; j < ratio; j++ {
			err := s.redis.RPush("frontend:"+frontend, servers[(i*ratio)+j].URL).Err()
			c.Assert(err, check.IsNil)
		}
		if i > nFrontends/2 {
			// Add invalid backends forcing errors on half of the frontends
			err := s.redis.RPush("frontend:"+frontend, "http://127.0.0.1:32412", "http://127.0.0.1:32413").Err()
			c.Assert(err, check.IsNil)
		}
	}
	nProffs := 4
	files := make([]*os.File, nProffs)
	if checkLeaksEnabled {
		for i := range files {
			files[i], _ = os.OpenFile(fmt.Sprintf("./planb_stress_%d_mem.pprof", i), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
		}
	}
	opts := backend.RedisOptions{
		Host: "localhost",
		Port: 6379,
		DB:   int(redisDB),
	}
	routesBE, err := backend.NewRedisBackend(opts, opts)
	c.Assert(err, check.IsNil)
	r := router.Router{Backend: routesBE}
	err = r.Init()
	c.Assert(err, check.IsNil)
	var nativeRP reverseproxy.ReverseProxy = &reverseproxy.NativeReverseProxy{}
	err = nativeRP.Initialize(reverseproxy.ReverseProxyConfig{
		Router:      &r,
		DialTimeout: time.Second,
	})
	c.Assert(err, check.IsNil)
	listener, err := net.Listen("tcp", ":0")
	c.Assert(err, check.IsNil)
	addr := listener.Addr().String()
	go nativeRP.Listen(listener, nil)
	defer nativeRP.Stop()
	defer listener.Close()
	nClients := 4
	rec := make(chan string, 1000)
	wg := sync.WaitGroup{}
	accessedBackends := map[string]struct{}{}
	mtx := sync.Mutex{}
	for i := 0; i < nClients; i++ {
		go func() {
			for host := range rec {
				req, inErr := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
				c.Assert(inErr, check.IsNil)
				req.Host = host
				rsp, inErr := http.DefaultClient.Do(req)
				c.Assert(inErr, check.IsNil)
				srvName, _ := ioutil.ReadAll(rsp.Body)
				rsp.Body.Close()
				if len(srvName) != 0 {
					mtx.Lock()
					accessedBackends[string(srvName)] = struct{}{}
					mtx.Unlock()
				}
				wg.Done()
			}
		}()
	}
	N := 20000
	for _, f := range files {
		for i := 0; i < N; i++ {
			wg.Add(1)
			rec <- frontends[i%len(frontends)]
		}
		wg.Wait()
		c.Assert(accessedBackends, check.DeepEquals, allNamesMap)
		if checkLeaksEnabled {
			runtime.GC()
			pprof.WriteHeapProfile(f)
		}
	}
	if checkLeaksEnabled {
		for _, f := range files {
			f.Close()
		}
	}
}
