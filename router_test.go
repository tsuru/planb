package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	c.Assert(router.roundRobin, check.Equals, uint64(0))
	ptr1 := reflect.ValueOf(router.rp.Director).Pointer()
	ptr2 := reflect.ValueOf(router.Director).Pointer()
	c.Assert(ptr1, check.Equals, ptr2)
	c.Assert(router.rp.Transport, check.Equals, &router)
	c.Assert(router.redisPool, check.Not(check.IsNil))
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
	rsp, err := router.RoundTrip(request)
	c.Assert(err, check.IsNil)
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	router.logger.Stop()
	msgs := strings.Split(buf.String(), "\n")
	testUrl, err := url.Parse(ts.URL)
	c.Assert(err, check.IsNil)
	c.Assert(msgs, check.HasLen, 2)
	c.Assert(msgs[0], check.Matches, fmt.Sprintf(`.*? %s GET / 200 in .*? ms`, testUrl.Host))
	c.Assert(msgs[1], check.Equals, "")
}

func (s *S) TestRoundTripDebugHeaders(c *check.C) {
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
	request.Header.Set("X-Debug-Router", "1")
	request.Header.Set("X-Debug-A", "a")
	request.Header.Set("X-Debug-B", "b")
	rsp, err := router.RoundTrip(request)
	c.Assert(err, check.IsNil)
	c.Assert(rsp.Header.Get("X-Debug-A"), check.Equals, "a")
	c.Assert(rsp.Header.Get("X-Debug-B"), check.Equals, "b")
	_, presentA := sentReq.Header["X-Debug-A"]
	_, presentB := sentReq.Header["X-Debug-B"]
	c.Assert(presentA, check.Equals, false)
	c.Assert(presentB, check.Equals, false)
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
	rsp, err := router.RoundTrip(request)
	c.Assert(err, check.IsNil)
	c.Assert(rsp.StatusCode, check.Equals, http.StatusBadRequest)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(data, check.DeepEquals, NO_ROUTE_DATA)
}
