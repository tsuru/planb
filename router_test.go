package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/check.v1"
)

type S struct{}

var _ = check.Suite(&S{})

func Test(t *testing.T) {
	check.TestingT(t)
}

func (s *S) TestInit(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	c.Assert(router.roundRobin, check.DeepEquals, map[string]*uint64{})
	ptr1 := reflect.ValueOf(router.rp.Director).Pointer()
	ptr2 := reflect.ValueOf(router.Director).Pointer()
	c.Assert(ptr1, check.Equals, ptr2)
	c.Assert(router.rp.Transport, check.Equals, &router)
	c.Assert(router.readRedisPool, check.Not(check.IsNil))
	c.Assert(router.writeRedisPool, check.Not(check.IsNil))
	c.Assert(router.logger, check.Not(check.IsNil))
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
	c.Assert(msgs[0], check.Matches, ".*? GET / HTTP/1.1 .*?")
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
