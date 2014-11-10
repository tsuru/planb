package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"launchpad.net/gocheck"
)

type S struct{}

var _ = gocheck.Suite(&S{})

func Test(t *testing.T) {
	gocheck.TestingT(t)
}

func (s *S) TestExtractDomain(c *gocheck.C) {
	tests := [][]string{
		{"a.something.com", "something.com"},
		{"a.b.something.com", "something.com"},
		{"something.com", "something.com"},
		{"awesometld", "awesometld"},
	}
	for _, pair := range tests {
		c.Assert(extractDomain(pair[0]), gocheck.Equals, pair[1])
	}
}

func (s *S) TestInit(c *gocheck.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, gocheck.IsNil)
	c.Assert(router.roundRobin, gocheck.Equals, uint64(0))
	ptr1 := reflect.ValueOf(router.rp.Director).Pointer()
	ptr2 := reflect.ValueOf(router.Director).Pointer()
	c.Assert(ptr1, gocheck.Equals, ptr2)
	c.Assert(router.rp.Transport, gocheck.Equals, &router)
	c.Assert(router.redisPool, gocheck.Not(gocheck.IsNil))
	c.Assert(router.logChan, gocheck.Not(gocheck.IsNil))
}

func (s *S) TestRoundTrip(c *gocheck.C) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := Router{}
	router.logChan = make(chan string)
	err := router.Init()
	c.Assert(err, gocheck.IsNil)
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/", ts.URL), nil)
	c.Assert(err, gocheck.IsNil)
	rsp, err := router.RoundTrip(request)
	c.Assert(err, gocheck.IsNil)
	c.Assert(rsp.StatusCode, gocheck.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, gocheck.IsNil)
	c.Assert(string(data), gocheck.Equals, "my result")
	close(router.logChan)
	var msgs []string
	for msg := range router.logChan {
		msgs = append(msgs, msg)
	}
	testUrl, err := url.Parse(ts.URL)
	c.Assert(err, gocheck.IsNil)
	c.Assert(msgs, gocheck.HasLen, 1)
	c.Assert(msgs[0], gocheck.Matches, fmt.Sprintf(`.*? %s GET / 200 in .*? ms`, testUrl.Host))
}

func (s *S) TestRoundTripDebugHeaders(c *gocheck.C) {
	var sentReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		sentReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	router := Router{}
	err := router.Init()
	c.Assert(err, gocheck.IsNil)
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/", ts.URL), nil)
	c.Assert(err, gocheck.IsNil)
	request.Header.Set("X-Debug-Router", "1")
	request.Header.Set("X-Debug-A", "a")
	request.Header.Set("X-Debug-B", "b")
	rsp, err := router.RoundTrip(request)
	c.Assert(err, gocheck.IsNil)
	c.Assert(rsp.Header.Get("X-Debug-A"), gocheck.Equals, "a")
	c.Assert(rsp.Header.Get("X-Debug-B"), gocheck.Equals, "b")
	_, presentA := sentReq.Header["X-Debug-A"]
	_, presentB := sentReq.Header["X-Debug-B"]
	c.Assert(presentA, gocheck.Equals, false)
	c.Assert(presentB, gocheck.Equals, false)
}

func (s *S) TestRoundTripDebugHeadersNoXDebug(c *gocheck.C) {
	var sentReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		sentReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	router := Router{}
	err := router.Init()
	c.Assert(err, gocheck.IsNil)
	request, err := http.NewRequest("GET", fmt.Sprintf("%s/", ts.URL), nil)
	c.Assert(err, gocheck.IsNil)
	request.Header.Set("X-Debug-A", "a")
	request.Header.Set("X-Debug-B", "b")
	rsp, err := router.RoundTrip(request)
	c.Assert(err, gocheck.IsNil)
	c.Assert(rsp.Header.Get("X-Debug-A"), gocheck.Equals, "")
	c.Assert(rsp.Header.Get("X-Debug-B"), gocheck.Equals, "")
	c.Assert(sentReq.Header.Get("X-Debug-A"), gocheck.Equals, "a")
	c.Assert(sentReq.Header.Get("X-Debug-B"), gocheck.Equals, "b")
}

func (s *S) TestRoundTripNoRoute(c *gocheck.C) {
	router := Router{}
	router.logChan = make(chan string)
	err := router.Init()
	c.Assert(err, gocheck.IsNil)
	request, err := http.NewRequest("GET", "", nil)
	c.Assert(err, gocheck.IsNil)
	rsp, err := router.RoundTrip(request)
	c.Assert(err, gocheck.IsNil)
	c.Assert(rsp.StatusCode, gocheck.Equals, http.StatusBadRequest)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, gocheck.IsNil)
	c.Assert(data, gocheck.DeepEquals, NO_ROUTE_DATA)
}
