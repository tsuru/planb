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
	"reflect"
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

func (s *S) SetUpTest(c *check.C) {
	var err error
	s.redis, err = redis.Dial("tcp", "127.0.0.1:6379")
	c.Assert(err, check.IsNil)
	keys, err := redis.Values(s.redis.Do("KEYS", "frontend:*"))
	c.Assert(err, check.IsNil)
	for _, k := range keys {
		_, err = s.redis.Do("DEL", k)
		c.Assert(err, check.IsNil)
	}
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
	ptr1 := reflect.ValueOf(router.rp.Director).Pointer()
	ptr2 := reflect.ValueOf(router.Director).Pointer()
	c.Assert(ptr1, check.Equals, ptr2)
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
	router.reqCtx[request] = &requestData{}
	rsp, err := router.RoundTrip(request)
	c.Assert(err, check.IsNil)
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
	router.reqCtx[request] = &requestData{
		debug:      true,
		backend:    "backend",
		backendIdx: 1,
		host:       "a.b.c",
	}
	rsp, err := router.RoundTrip(request)
	c.Assert(err, check.IsNil)
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
	router.reqCtx[request] = &requestData{}
	rsp, err := router.RoundTrip(request)
	c.Assert(err, check.IsNil)
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
	router.reqCtx[request] = &requestData{}
	rsp, err := router.RoundTrip(request)
	c.Assert(err, check.IsNil)
	c.Assert(rsp.StatusCode, check.Equals, http.StatusBadRequest)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(data, check.DeepEquals, noRouteData)
}

func (s *S) TestServeHTTPStress(c *check.C) {
	var logOutput bytes.Buffer
	log.SetOutput(&logOutput)
	defer log.SetOutput(nil)
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	wg := sync.WaitGroup{}
	nConnections := 50
	for i := 0; i < nConnections; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			url := fmt.Sprintf("a%d.com", i)
			recorder := httptest.NewRecorder()
			request, err := http.NewRequest("GET", "http://"+url, nil)
			c.Assert(err, check.IsNil)
			router.ServeHTTP(recorder, request)
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

func (s *S) TestDirectorRequestIDHeaderNotNil(c *check.C) {
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
	router.Director(request)
	c.Assert(request.Header.Get(router.RequestIDHeader), check.NotNil)
}

func (s *S) TestDirectorRequestIDHeaderIsSetWhenItCamesEmpty(c *check.C) {
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
	router.Director(request)
	c.Assert(request.Header.Get(router.RequestIDHeader), check.Not(check.Equals), "")
}

func (s *S) TestDirectorRequestIDHeaderNotChangedWhenAlreadyExists(c *check.C) {
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
	router.Director(request)
	c.Assert(request.Header.Get(router.RequestIDHeader), check.Equals, "12345abcd")
}

func (s *S) TestDirectorRequestIDHeaderDoesNothingIfFlagIsNotSet(c *check.C) {
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
	router.Director(request)
	c.Assert(router.RequestIDHeader, check.Equals, "")
	c.Assert(request.Header.Get(router.RequestIDHeader), check.Equals, "")
}
