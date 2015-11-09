package main

import (
	"bytes"
	"fmt"
	"github.com/garyburd/redigo/redis"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"

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
	testUrl, err := url.Parse(ts.URL)
	c.Assert(err, check.IsNil)
	c.Assert(msgs, check.HasLen, 2)
	c.Assert(msgs[0], check.Matches, fmt.Sprintf(`.*? %s GET / 200 in .*? ms`, testUrl.Host))
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
	request1, err := http.NewRequest("GET", "http://myfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	request2, err := http.NewRequest("GET", "http://otherfrontend.com/somewhere", nil)
	c.Assert(err, check.IsNil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request1)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "server-0/somewhere")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request2)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "server-2/somewhere")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request1)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "server-1/somewhere")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request1)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "server-0/somewhere")
	recorder = httptest.NewRecorder()
	router.ServeHTTP(recorder, request2)
	c.Assert(recorder.Code, check.Equals, http.StatusOK)
	c.Assert(recorder.Body.String(), check.Equals, "server-3/somewhere")
}
