// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/garyburd/redigo/redis"
	"golang.org/x/net/websocket"
	"gopkg.in/check.v1"
)

type S struct {
	redis redis.Conn
}

var _ = check.Suite(&S{})

func Test(t *testing.T) {
	check.TestingT(t)
}

func clearKeys(r redis.Conn) error {
	keys, err := redis.Values(r.Do("KEYS", "frontend:*"))
	if err != nil {
		return err
	}
	keys2, err := redis.Values(r.Do("KEYS", "dead:*"))
	if err != nil {
		return err
	}
	for _, k := range append(keys, keys2...) {
		_, err = r.Do("DEL", k)
		if err != nil {
			return err
		}
	}
	return nil
}

func redisConn() (redis.Conn, error) {
	return redis.Dial("tcp", "127.0.0.1:6379")
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

func (s *S) TestInit(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	c.Assert(router.roundRobin, check.DeepEquals, map[string]*uint64{})
	type requestCanceler interface {
		CancelRequest(*http.Request)
	}
	var canceler requestCanceler
	c.Assert(&router, check.Implements, &canceler)
	c.Assert(router.rp.Transport, check.Equals, &router)
	c.Assert(router.readRedisPool, check.NotNil)
	c.Assert(router.writeRedisPool, check.NotNil)
	c.Assert(router.logger, check.NotNil)
	c.Assert(router.cache, check.NotNil)
}

type BufferCloser struct {
	bytes.Buffer
}

func (b *BufferCloser) Close() error {
	return nil
}

func (s *S) TestRoundTrip(c *check.C) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := Router{}
	buf := &BufferCloser{}
	router.logger = NewWriterLogger(buf)
	err := router.Init()
	c.Assert(err, check.IsNil)
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/", ts.URL), nil)
	c.Assert(err, check.IsNil)
	rsp := router.RoundTripWithData(request, &requestData{})
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	router.logger.Stop()
	msgs := strings.Split(buf.String(), "\n")
	c.Assert(msgs, check.HasLen, 2)
	c.Assert(msgs[0], check.Matches, ".*?GET / HTTP/1.1.*?")
	c.Assert(msgs[1], check.Equals, "")
}

func (s *S) TestRoundTripDebugHeaders(c *check.C) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/", ts.URL), nil)
	c.Assert(err, check.IsNil)
	rsp := router.RoundTripWithData(request, &requestData{
		debug:      true,
		backend:    "backend",
		backendIdx: 1,
		host:       "a.b.c",
	})
	c.Assert(rsp.Header.Get("X-Debug-Backend-Url"), check.Equals, "backend")
	c.Assert(rsp.Header.Get("X-Debug-Backend-Id"), check.Equals, "1")
	c.Assert(rsp.Header.Get("X-Debug-Frontend-Key"), check.Equals, "a.b.c")
}

func (s *S) TestRoundTripDebugHeadersNoXDebug(c *check.C) {
	var sentReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		sentReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/", ts.URL), nil)
	c.Assert(err, check.IsNil)
	request.Header.Set("X-Debug-A", "a")
	request.Header.Set("X-Debug-B", "b")
	rsp := router.RoundTripWithData(request, &requestData{})
	c.Assert(rsp.Header.Get("X-Debug-A"), check.Equals, "")
	c.Assert(rsp.Header.Get("X-Debug-B"), check.Equals, "")
	c.Assert(sentReq.Header.Get("X-Debug-A"), check.Equals, "a")
	c.Assert(sentReq.Header.Get("X-Debug-B"), check.Equals, "b")
}

func (s *S) TestRoundTripNoRoute(c *check.C) {
	router := Router{}
	buf := &BufferCloser{}
	router.logger = NewWriterLogger(buf)
	err := router.Init()
	c.Assert(err, check.IsNil)
	request, err := http.NewRequest("GET", "", nil)
	c.Assert(err, check.IsNil)
	rsp := router.RoundTripWithData(request, &requestData{})
	c.Assert(rsp.StatusCode, check.Equals, http.StatusBadRequest)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(data, check.DeepEquals, noRouteResponseBody.value)
}

func (s *S) TestServeHTTPStress(c *check.C) {
	var logOutput bytes.Buffer
	log.SetOutput(&logOutput)
	defer log.SetOutput(os.Stderr)
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	wg := sync.WaitGroup{}
	nConnections := 50
	recorders := make([]*httptest.ResponseRecorder, nConnections)
	for i := 0; i < nConnections; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			url := fmt.Sprintf("http://a%d.com", i)
			recorder := httptest.NewRecorder()
			request, err := http.NewRequest("GET", url, nil)
			c.Assert(err, check.IsNil)
			router.ServeHTTP(recorder, request)
			recorders[i] = recorder
		}(i)
	}
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Minute):
		c.Fatal("timeout out after 1 minute")
	}
	logParts := strings.Split(logOutput.String(), "\n")
	c.Assert(logParts, check.HasLen, nConnections+1)
	for _, part := range logParts[:nConnections] {
		c.Assert(part, check.Matches, ".*no backends available$")
	}
	for _, recorder := range recorders {
		c.Assert(recorder.Body.String(), check.Equals, "no such route")
		c.Assert(recorder.Code, check.Equals, http.StatusBadRequest)
	}
}

func (s *S) TestServeHTTPStressWithTimeoutBackend(c *check.C) {
	_, err := s.redis.Do("RPUSH", "frontend:badfrontend.com", "badfrontend", "127.0.0.1:23771")
	c.Assert(err, check.IsNil)
	var logOutput bytes.Buffer
	log.SetOutput(&logOutput)
	defer log.SetOutput(os.Stderr)
	router := Router{
		DialTimeout:     time.Second,
		markingDisabled: true,
	}
	err = router.Init()
	c.Assert(err, check.IsNil)
	wg := sync.WaitGroup{}
	nConnections := 50
	recorders := make([]*httptest.ResponseRecorder, nConnections)
	for i := 0; i < nConnections; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			url := fmt.Sprintf("http://badfrontend.com/%d", i)
			recorder := httptest.NewRecorder()
			request, err := http.NewRequest("GET", url, nil)
			c.Assert(err, check.IsNil)
			router.ServeHTTP(recorder, request)
			recorders[i] = recorder
		}(i)
	}
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Minute):
		c.Fatal("timeout out after 1 minute")
	}
	logParts := strings.Split(logOutput.String(), "\n")
	c.Assert(logParts, check.HasLen, nConnections+1)
	for _, part := range logParts[:nConnections] {
		c.Assert(part, check.Matches, ".*error in backend request: dial tcp 127.0.0.1:23771.*")
	}
	for _, recorder := range recorders {
		c.Assert(recorder.Body.String(), check.Equals, "")
		c.Assert(recorder.Code, check.Equals, http.StatusServiceUnavailable)
	}
}

func (s *S) TestServeHTTPRoundRobin(c *check.C) {
	var servers []*httptest.Server
	for i := 0; i < 4; i++ {
		msg := fmt.Sprintf("server-%d", i)
		srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.Write([]byte(msg + req.URL.Path))
		}))
		defer srv.Close()
		servers = append(servers, srv)
	}
	var err error
	_, err = s.redis.Do("RPUSH", "frontend:myfrontend.com", "myfrontend", servers[0].URL, servers[1].URL)
	c.Assert(err, check.IsNil)
	_, err = s.redis.Do("RPUSH", "frontend:otherfrontend.com", "otherfrontend", servers[2].URL, servers[3].URL)
	c.Assert(err, check.IsNil)
	router := Router{}
	err = router.Init()
	c.Assert(err, check.IsNil)
	checkReq := func(url, expected string) {
		request, err := http.NewRequest("GET", url, nil)
		c.Assert(err, check.IsNil)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		c.Assert(recorder.Code, check.Equals, http.StatusOK)
		c.Assert(recorder.Body.String(), check.Equals, expected)
	}
	checkReq("http://myfrontend.com/somewhere", "server-0/somewhere")
	checkReq("http://otherfrontend.com/somewhere", "server-2/somewhere")
	checkReq("http://myfrontend.com/somewhere", "server-1/somewhere")
	checkReq("http://myfrontend.com/somewhere", "server-0/somewhere")
	checkReq("http://otherfrontend.com/somewhere", "server-3/somewhere")
}

func (s *S) TestServeHTTPRoundRobinMarksDead(c *check.C) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("hit"))
	}))
	defer srv.Close()
	_, err := s.redis.Do("RPUSH", "frontend:mixfrontend.com", "mixfrontend", srv.URL, "http://127.0.0.1:34291")
	c.Assert(err, check.IsNil)
	router := Router{
		DialTimeout: time.Second,
	}
	err = router.Init()
	c.Assert(err, check.IsNil)
	checkReq := func(url string, code int, expected string) {
		request, err := http.NewRequest("GET", url, nil)
		c.Assert(err, check.IsNil)
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, request)
		c.Assert(recorder.Code, check.Equals, code)
		c.Assert(recorder.Body.String(), check.Equals, expected)
		router.cache.Purge()
	}
	checkReq("http://mixfrontend.com/somewhere", http.StatusOK, "hit")
	checkReq("http://mixfrontend.com/somewhere", http.StatusServiceUnavailable, "")
	checkReq("http://mixfrontend.com/somewhere", http.StatusOK, "hit")
	checkReq("http://mixfrontend.com/somewhere", http.StatusOK, "hit")
	checkReq("http://mixfrontend.com/somewhere", http.StatusOK, "hit")
	checkReq("http://mixfrontend.com/somewhere", http.StatusOK, "hit")
}

func (s *S) TestServeHTTPCache(c *check.C) {
	var servers []*httptest.Server
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf("server-%d", i)
		srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			rw.Write([]byte(msg + req.URL.Path))
		}))
		defer srv.Close()
		servers = append(servers, srv)
	}
	_, err := s.redis.Do("RPUSH", "frontend:myfrontend.com", "myfrontend", servers[0].URL, servers[1].URL)
	c.Assert(err, check.IsNil)
	router := Router{}
	err = router.Init()
	c.Assert(err, check.IsNil)
	request, err := http.NewRequest("GET", "http://myfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "server-0/somewhere")
	_, ok := router.cache.Peek("myfrontend.com")
	c.Assert(ok, check.Equals, true)
	router.cache.Add("myfrontend.com", backendSet{
		id:       "myfrontend",
		backends: []string{servers[2].URL},
		dead:     nil,
		expires:  time.Now().Add(time.Hour),
	})
	request, err = http.NewRequest("GET", "http://myfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "server-2/somewhere")
	router.cache.Add("myfrontend.com", backendSet{
		id:       "myfrontend",
		backends: []string{servers[2].URL},
		dead:     nil,
		expires:  time.Now().Add(-2*time.Second - 1),
	})
	request, err = http.NewRequest("GET", "http://myfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "server-0/somewhere")
	request, err = http.NewRequest("GET", "http://myfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "server-1/somewhere")
}

func (s *S) TestServeHTTPWebSocket(c *check.C) {
	var servers []*httptest.Server
	for i := 0; i < 2; i++ {
		msg := fmt.Sprintf("server-%d", i)
		srv := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
			conn.Write([]byte(msg + conn.Request().URL.Path))
			buf := make([]byte, 5)
			conn.Read(buf)
			conn.Write(buf)
		}))
		defer srv.Close()
		servers = append(servers, srv)
	}
	var err error
	_, err = s.redis.Do("RPUSH", "frontend:myfrontend.com", "myfrontend", servers[0].URL, servers[1].URL)
	c.Assert(err, check.IsNil)
	router := Router{}
	err = router.Init()
	c.Assert(err, check.IsNil)
	proxyServer := httptest.NewServer(&router)
	defer proxyServer.Close()
	dialWS := func() *websocket.Conn {
		config, err := websocket.NewConfig("ws://myfrontend.com", "ws://localhost/")
		c.Assert(err, check.IsNil)
		url, _ := url.Parse(proxyServer.URL)
		client, err := net.Dial("tcp", url.Host)
		c.Assert(err, check.IsNil)
		conn, err := websocket.NewClient(config, client)
		c.Assert(err, check.IsNil)
		return conn
	}
	msgBuf := make([]byte, 100)
	conn := dialWS()
	defer conn.Close()
	n, err := conn.Read(msgBuf)
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 9)
	c.Assert(string(msgBuf[:n]), check.Equals, "server-0/")
	n, err = conn.Write([]byte("12345"))
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	n, err = conn.Read(msgBuf)
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	c.Assert(string(msgBuf[:n]), check.Equals, "12345")
	conn = dialWS()
	defer conn.Close()
	n, err = conn.Read(msgBuf)
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 9)
	c.Assert(string(msgBuf[:n]), check.Equals, "server-1/")
	n, err = conn.Write([]byte("12345"))
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	n, err = conn.Read(msgBuf)
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	c.Assert(string(msgBuf[:n]), check.Equals, "12345")
}

func (s *S) TestServeHTTPNoLogger(c *check.C) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("hit"))
	}))
	defer srv.Close()
	_, err := s.redis.Do("RPUSH", "frontend:goodfrontend.com", "goodfrontend", srv.URL)
	c.Assert(err, check.IsNil)
	router := Router{}
	err = router.Init()
	c.Assert(err, check.IsNil)
	router.logger = nil
	request, err := http.NewRequest("GET", "http://goodfrontend.com/", nil)
	c.Assert(err, check.IsNil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "hit")
}

func (s *S) TestChooseBackendRequestIDHeaderNotNil(c *check.C) {
	msg := fmt.Sprintf("server-1")
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(msg + req.URL.Path))
	}))
	var err error
	_, err = s.redis.Do("RPUSH", "frontend:myfrontend.com", "myfrontend", srv.URL)
	c.Assert(err, check.IsNil)
	router := Router{
		RequestIDHeader: "Xpto",
	}
	err = router.Init()
	c.Assert(err, check.IsNil)
	request, err := http.NewRequest("GET", "http://myfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	router.chooseBackend(request)
	c.Assert(request.Header.Get(router.RequestIDHeader), check.NotNil)
}

func (s *S) TestChooseBackendRequestIDHeaderIsSetWhenItCamesEmpty(c *check.C) {
	msg := fmt.Sprintf("server-1")
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(msg + req.URL.Path))
	}))
	var err error
	_, err = s.redis.Do("RPUSH", "frontend:myfrontend.com", "myfrontend", srv.URL)
	c.Assert(err, check.IsNil)
	router := Router{
		RequestIDHeader: "Xpto",
	}
	err = router.Init()
	c.Assert(err, check.IsNil)
	request, err := http.NewRequest("GET", "http://myfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	id := ""
	request.Header.Set(router.RequestIDHeader, id)
	router.chooseBackend(request)
	c.Assert(request.Header.Get(router.RequestIDHeader), check.Not(check.Equals), "")
}

func (s *S) TestChooseBackendRequestIDHeaderNotChangedWhenAlreadyExists(c *check.C) {
	msg := fmt.Sprintf("server-1")
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(msg + req.URL.Path))
	}))
	var err error
	_, err = s.redis.Do("RPUSH", "frontend:myfrontend.com", "myfrontend", srv.URL)
	c.Assert(err, check.IsNil)
	router := Router{
		RequestIDHeader: "Xpto",
	}
	err = router.Init()
	c.Assert(err, check.IsNil)
	request, err := http.NewRequest("GET", "http://myfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	id := "12345abcd"
	request.Header.Set(router.RequestIDHeader, id)
	router.chooseBackend(request)
	c.Assert(request.Header.Get(router.RequestIDHeader), check.Equals, "12345abcd")
}

func (s *S) TestChooseBackendRequestIDHeaderDoesNothingIfFlagIsNotSet(c *check.C) {
	msg := fmt.Sprintf("server-1")
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte(msg + req.URL.Path))
	}))
	var err error
	_, err = s.redis.Do("RPUSH", "frontend:myfrontend.com", "myfrontend", srv.URL)
	c.Assert(err, check.IsNil)
	router := Router{}
	err = router.Init()
	c.Assert(err, check.IsNil)
	request, err := http.NewRequest("GET", "http://myfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	router.chooseBackend(request)
	c.Assert(router.RequestIDHeader, check.Equals, "")
	c.Assert(request.Header.Get(router.RequestIDHeader), check.Equals, "")
}

func (s *S) TestServeHTTPStressAllLeakDetector(c *check.C) {
	if os.Getenv("PLANB_CHECK_LEAKS") == "" {
		return
	}
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
		_, err := s.redis.Do("RPUSH", "frontend:"+frontend, frontend)
		c.Assert(err, check.IsNil)
		ratio := nServers / nFrontends
		for j := 0; j < ratio; j++ {
			_, err := s.redis.Do("RPUSH", "frontend:"+frontend, servers[(i*ratio)+j].URL)
			c.Assert(err, check.IsNil)
		}
		if i > nFrontends/2 {
			// Add invalid backends forcing errors on half of the frontends
			_, err := s.redis.Do("RPUSH", "frontend:"+frontend, "http://127.0.0.1:32412", "http://127.0.0.1:32413")
			c.Assert(err, check.IsNil)
		}
	}
	nProffs := 4
	files := make([]*os.File, nProffs)
	for i := range files {
		files[i], _ = os.OpenFile(fmt.Sprintf("./planb_stress_%d_mem.pprof", i), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0660)
	}
	router := Router{
		DialTimeout: time.Second,
	}
	router.Init()
	nClients := 4
	rec := make(chan string, 1000)
	wg := sync.WaitGroup{}
	accessedBackends := map[string]struct{}{}
	mtx := sync.Mutex{}
	for i := 0; i < nClients; i++ {
		go func() {
			for host := range rec {
				request, _ := http.NewRequest("GET", "http://"+host, nil)
				recorder := httptest.NewRecorder()
				router.ServeHTTP(recorder, request)
				wg.Done()
				srvName := recorder.Body.String()
				if srvName != "" {
					mtx.Lock()
					accessedBackends[recorder.Body.String()] = struct{}{}
					mtx.Unlock()
				}
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
		runtime.GC()
		pprof.WriteHeapProfile(f)
	}
	for _, f := range files {
		f.Close()
	}
}

func (s *S) TestServeHTTPHostDestination(c *check.C) {
	var reqData *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		reqData = req
		rw.Write([]byte("hit"))
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	c.Assert(err, check.IsNil)
	_, port, _ := net.SplitHostPort(u.Host)
	c.Assert(port, check.Not(check.Equals), "")
	_, err = s.redis.Do("RPUSH", "frontend:goodfrontend.com", "goodfrontend", fmt.Sprintf("http://localhost:%s", port))
	c.Assert(err, check.IsNil)
	router := Router{}
	err = router.Init()
	c.Assert(err, check.IsNil)
	router.logger = nil
	request, err := http.NewRequest("GET", "http://goodfrontend.com/", nil)
	c.Assert(err, check.IsNil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "hit")
	c.Assert(reqData.Host, check.Equals, "localhost")
	c.Assert(reqData.Header.Get("X-Host"), check.Equals, "goodfrontend.com")
}

func (s *S) TestServeHTTPIPDestination(c *check.C) {
	var reqData *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		reqData = req
		rw.Write([]byte("hit"))
	}))
	defer srv.Close()
	u, err := url.Parse(srv.URL)
	c.Assert(err, check.IsNil)
	_, port, _ := net.SplitHostPort(u.Host)
	c.Assert(port, check.Not(check.Equals), "")
	_, err = s.redis.Do("RPUSH", "frontend:goodfrontend.com", "goodfrontend", fmt.Sprintf("http://127.0.0.1:%s", port))
	c.Assert(err, check.IsNil)
	router := Router{}
	err = router.Init()
	c.Assert(err, check.IsNil)
	router.logger = nil
	request, err := http.NewRequest("GET", "http://goodfrontend.com/", nil)
	c.Assert(err, check.IsNil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "hit")
	c.Assert(reqData.Host, check.Equals, "goodfrontend.com")
	c.Assert(reqData.Header.Get("X-Host"), check.Equals, "")
}

func BenchmarkServeHTTP(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("hit"))
	}))
	defer srv.Close()
	r, _ := redisConn()
	defer clearKeys(r)
	r.Do("RPUSH", "frontend:benchfrontend.com", "benchfrontend", srv.URL)
	router := Router{}
	router.Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request, _ := http.NewRequest("GET", "http://benchfrontend.com/", nil)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				b.Fatalf("invalid status code %d, expected 200", recorder.Code)
			}
		}
	})
}

func BenchmarkServeHTTPNoAccessLog(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("hit"))
	}))
	defer srv.Close()
	r, _ := redisConn()
	defer clearKeys(r)
	r.Do("RPUSH", "frontend:benchfrontend.com", "benchfrontend", srv.URL)
	router := Router{
		LogPath: "none",
	}
	router.Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request, _ := http.NewRequest("GET", "http://benchfrontend.com/", nil)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				b.Fatalf("invalid status code %d, expected 200", recorder.Code)
			}
		}
	})
}

func BenchmarkServeHTTPNoRedisCache(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("hit"))
	}))
	defer srv.Close()
	r, _ := redisConn()
	defer clearKeys(r)
	r.Do("RPUSH", "frontend:benchfrontend.com", "benchfrontend", srv.URL)
	router := Router{}
	router.Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request, _ := http.NewRequest("GET", "http://benchfrontend.com/", nil)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				b.Fatalf("invalid status code %d, expected 200", recorder.Code)
			}
			router.cache.Purge()
		}
	})
}

func BenchmarkServeHTTPMultipleBackendsNoCache(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Write([]byte("hit"))
	}))
	defer srv.Close()
	r, _ := redisConn()
	defer clearKeys(r)
	backends := make([]interface{}, 100)
	for i := range backends {
		backends[i] = srv.URL
	}
	backends = append([]interface{}{"frontend:benchfrontend.com", "benchfrontend"}, backends...)
	r.Do("RPUSH", backends...)
	router := Router{}
	router.Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request, _ := http.NewRequest("GET", "http://benchfrontend.com/", nil)
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusOK {
				b.Fatalf("invalid status code %d, expected 200", recorder.Code)
			}
			router.cache.Purge()
		}
	})
}

func BenchmarkServeHTTPInvalidFrontends(b *testing.B) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stderr)
	router := Router{}
	router.Init()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			request, _ := http.NewRequest("GET", "http://benchfrontend"+strconv.FormatInt(int64(i), 10), nil)
			i++
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				b.Fatalf("invalid status code %d, expected 400", recorder.Code)
			}
		}
	})
}
