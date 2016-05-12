// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reverseproxy

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tsuru/planb/log"
	"golang.org/x/net/websocket"
	"gopkg.in/check.v1"
)

type S struct {
	factory func() ReverseProxy
}

type noopRouter struct{ dst string }

func (r *noopRouter) ChooseBackend(host string) (*RequestData, error) {
	return &RequestData{
		Backend:    r.dst,
		BackendIdx: 0,
		BackendKey: host,
		BackendLen: 1,
		Host:       host,
	}, nil
}

func (r *noopRouter) EndRequest(reqData *RequestData, isDead bool, fn func() *log.LogEntry) error {
	return nil
}

type recoderRouter struct {
	dst           string
	resultHost    string
	resultReqData *RequestData
	resultIsDead  bool
	logEntry      *log.LogEntry
}

func (r *recoderRouter) ChooseBackend(host string) (*RequestData, error) {
	r.resultHost = host
	return &RequestData{
		Backend:    r.dst,
		BackendIdx: 0,
		BackendKey: host,
		BackendLen: 1,
		Host:       host,
	}, nil
}

func (r *recoderRouter) EndRequest(reqData *RequestData, isDead bool, fn func() *log.LogEntry) error {
	r.resultReqData = reqData
	r.logEntry = fn()
	r.resultIsDead = isDead
	return nil
}

var (
	nativeFactory = func() ReverseProxy { return &NativeReverseProxy{} }
	fastFactory   = func() ReverseProxy { return &FastReverseProxy{} }
	_             = check.Suite(&S{factory: nativeFactory})
	_             = check.Suite(&S{factory: fastFactory})
)

func Test(t *testing.T) {
	check.TestingT(t)
}

func (s *S) TestRoundTrip(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := s.factory()
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router, RequestIDHeader: "X-RID"})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	c.Assert(receivedReq.Host, check.Equals, "myhost.com")
	c.Assert(receivedReq.Header.Get("X-My-Header"), check.Equals, "myvalue")
	c.Assert(receivedReq.Header.Get("X-Host"), check.Equals, "")
	c.Assert(receivedReq.Header.Get("X-RID"), check.Not(check.Equals), "")
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    ts.URL,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	le := router.logEntry
	c.Assert(le.Now.IsZero(), check.Equals, false)
	c.Assert(le.BackendDuration, check.Not(check.Equals), 0)
	c.Assert(le.TotalDuration, check.Not(check.Equals), 0)
	c.Assert(le.RequestID, check.Not(check.Equals), "")
	c.Assert(le.RemoteAddr, check.Matches, `127\.0\.0\.1:\d+`)
	le.Now = time.Time{}
	le.BackendDuration = 0
	le.TotalDuration = 0
	le.RequestID = ""
	le.RemoteAddr = ""
	c.Assert(le, check.DeepEquals, &log.LogEntry{
		BackendKey:      "myhost.com",
		Method:          "GET",
		Path:            "/",
		Proto:           "HTTP/1.1",
		Referer:         "",
		UserAgent:       "Go-http-client/1.1",
		RequestIDHeader: "X-RID",
		StatusCode:      200,
		ContentLength:   9,
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func (s *S) TestRoundTripWithExistingRequestID(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := s.factory()
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router, RequestIDHeader: "X-RID"})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	req.Header.Set("X-RID", "abc")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	c.Assert(receivedReq.Host, check.Equals, "myhost.com")
	c.Assert(receivedReq.Header.Get("X-My-Header"), check.Equals, "myvalue")
	c.Assert(receivedReq.Header.Get("X-Host"), check.Equals, "")
	c.Assert(receivedReq.Header.Get("X-RID"), check.Equals, "abc")
}

func (s *S) TestRoundTripHostDestination(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	dstUrl, err := url.Parse(ts.URL)
	c.Assert(err, check.IsNil)
	_, port, _ := net.SplitHostPort(dstUrl.Host)
	c.Assert(port, check.Not(check.Equals), "")
	router := &recoderRouter{dst: fmt.Sprintf("http://localhost:%s", port)}
	rp := s.factory()
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	c.Assert(receivedReq.Host, check.Equals, "localhost")
	c.Assert(receivedReq.Header.Get("X-My-Header"), check.Equals, "myvalue")
	c.Assert(receivedReq.Header.Get("X-Host"), check.Equals, "myhost.com")
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    router.dst,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func (s *S) TestRoundTripWithError(c *check.C) {
	router := &recoderRouter{dst: "http://127.0.0.1:23771"}
	rp := s.factory()
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 503)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "")
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    router.dst,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	c.Assert(router.resultIsDead, check.Equals, true)
}

func (s *S) TestRoundTripDebugHeaders(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := s.factory()
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-Debug-Router", "1")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	c.Assert(rsp.Header.Get("X-Debug-Backend-Url"), check.Equals, ts.URL)
	c.Assert(rsp.Header.Get("X-Debug-Backend-Id"), check.Equals, "0")
	c.Assert(rsp.Header.Get("X-Debug-Frontend-Key"), check.Equals, "myhost.com")
	c.Assert(receivedReq.Header.Get("X-Debug-Router"), check.Equals, "")
}

func (s *S) TestRoundTripNoRoute(c *check.C) {
	router := &recoderRouter{dst: ""}
	rp := s.factory()
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	c.Assert(rsp.StatusCode, check.Equals, http.StatusBadRequest)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(data, check.DeepEquals, noRouteResponseBody.value)
}

func (s *S) TestRoundTripStress(c *check.C) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &noopRouter{dst: ts.URL}
	rp := s.factory()
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	u := fmt.Sprintf("http://%s/", addr)
	wg := sync.WaitGroup{}
	nConnections := 50
	for i := 0; i < nConnections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("GET", u, nil)
			c.Assert(err, check.IsNil)
			req.Host = "myhost.com"
			rsp, err := http.DefaultClient.Do(req)
			c.Assert(err, check.IsNil)
			defer rsp.Body.Close()
			c.Assert(rsp.StatusCode, check.Equals, 200)
		}()
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
}

func (s *S) TestRoundTripStressWithTimeoutBackend(c *check.C) {
	router := &noopRouter{dst: "http://127.0.0.1:23771"}
	rp := s.factory()
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	u := fmt.Sprintf("http://%s/", addr)
	wg := sync.WaitGroup{}
	nConnections := 50
	for i := 0; i < nConnections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("GET", u, nil)
			c.Assert(err, check.IsNil)
			req.Host = "myhost.com"
			rsp, err := http.DefaultClient.Do(req)
			c.Assert(err, check.IsNil)
			defer rsp.Body.Close()
			c.Assert(rsp.StatusCode, check.Equals, 503)
		}()
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
}

func (s *S) TestRoundTripPing(c *check.C) {
	rp := s.factory()
	router := &noopRouter{}
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "__ping__"
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "OK")
}

func (s *S) TestRoundTripWebSocket(c *check.C) {
	rp := s.factory()
	if strings.Contains(fmt.Sprintf("%T\n", rp), "FastReverseProxy") {
		c.Skip("websocket not supported by fasthttp reverse proxy")
	}
	srv := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
		conn.Write([]byte("server-" + conn.Request().URL.Path))
		buf := make([]byte, 5)
		conn.Read(buf)
		conn.Write(buf)
	}))
	defer srv.Close()
	router := &recoderRouter{dst: srv.URL}
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: router})
	c.Assert(err, check.IsNil)
	go rp.Listen()
	defer rp.Stop()
	dialWS := func() *websocket.Conn {
		config, err := websocket.NewConfig("ws://myfrontend.com", "ws://localhost/")
		c.Assert(err, check.IsNil)
		url, _ := url.Parse(fmt.Sprintf("http://%s/", addr))
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
	c.Assert(n, check.Equals, 8)
	c.Assert(string(msgBuf[:n]), check.Equals, "server-/")
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
	c.Assert(n, check.Equals, 8)
	c.Assert(string(msgBuf[:n]), check.Equals, "server-/")
	n, err = conn.Write([]byte("12345"))
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	n, err = conn.Read(msgBuf)
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	c.Assert(string(msgBuf[:n]), check.Equals, "12345")
}

func baseBenchmarkServeHTTP(rp ReverseProxy, b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: &noopRouter{dst: srv.URL}})
	if err != nil {
		b.Fatal(err)
	}
	url := fmt.Sprintf("http://%s/", addr)
	go rp.Listen()
	defer rp.Stop()
	b.ResetTimer()
	cli := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1000,
		},
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request, _ := http.NewRequest("GET", url, nil)
			rsp, err := cli.Do(request)
			if rsp == nil || rsp.StatusCode != http.StatusOK {
				b.Fatalf("invalid response %#v: %s", rsp, err)
			}
			ioutil.ReadAll(rsp.Body)
			rsp.Body.Close()
		}
	})
	b.StopTimer()
}

func baseBenchmarkServeHTTPInvalidFrontends(rp ReverseProxy, b *testing.B) {
	addr, err := rp.Initialize(ReverseProxyConfig{Listen: "127.0.0.1:0", Router: &noopRouter{}})
	if err != nil {
		b.Fatal(err)
	}
	url := fmt.Sprintf("http://%s/", addr)
	go rp.Listen()
	defer rp.Stop()
	b.ResetTimer()
	cli := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1000,
		},
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request, _ := http.NewRequest("GET", url, nil)
			rsp, err := cli.Do(request)
			if rsp == nil || rsp.StatusCode != http.StatusBadRequest {
				b.Fatalf("invalid response %#v: %s", rsp, err)
			}
			ioutil.ReadAll(rsp.Body)
			rsp.Body.Close()
		}
	})
	b.StopTimer()
}

func BenchmarkServeHTTP_Native(b *testing.B) {
	baseBenchmarkServeHTTP(nativeFactory(), b)
}

func BenchmarkServeHTTPInvalidFrontends_Native(b *testing.B) {
	baseBenchmarkServeHTTPInvalidFrontends(nativeFactory(), b)
}

func BenchmarkServeHTTP_Fast(b *testing.B) {
	baseBenchmarkServeHTTP(fastFactory(), b)
}

func BenchmarkServeHTTPInvalidFrontends_Fast(b *testing.B) {
	baseBenchmarkServeHTTPInvalidFrontends(fastFactory(), b)
}
