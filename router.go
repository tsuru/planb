// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/garyburd/redigo/redis"
	"github.com/hashicorp/golang-lru"
	"github.com/nu7hatch/gouuid"
)

var (
	noRouteData = []byte("no such route")
)

type requestData struct {
	backendLen int
	backend    string
	backendIdx int
	backendKey string
	host       string
	debug      bool
	startTime  time.Time
}

func (r *requestData) String() string {
	back := r.backend
	if back == "" {
		back = "?"
	}
	return r.host + " -> " + back
}

type Router struct {
	http.Transport
	ReadRedisHost   string
	ReadRedisPort   int
	WriteRedisHost  string
	WriteRedisPort  int
	LogPath         string
	DialTimeout     time.Duration
	RequestTimeout  time.Duration
	DeadBackendTTL  int
	FlushInterval   time.Duration
	RequestIDHeader string
	rp              *httputil.ReverseProxy
	dialer          *net.Dialer
	readRedisPool   *redis.Pool
	writeRedisPool  *redis.Pool
	logger          *Logger
	ctxMutex        sync.Mutex
	reqCtx          map[*http.Request]*requestData
	rrMutex         sync.RWMutex
	roundRobin      map[string]*uint64
	cache           *lru.Cache
}

func redisDialer(host string, port int) func() (redis.Conn, error) {
	readTimeout := time.Second
	writeTimeout := time.Second
	dialTimeout := time.Second
	if host == "" {
		host = "127.0.0.1"
	}
	if port == 0 {
		port = 6379
	}
	redisAddr := fmt.Sprintf("%s:%d", host, port)
	return func() (redis.Conn, error) {
		return redis.DialTimeout("tcp", redisAddr, dialTimeout, readTimeout, writeTimeout)
	}
}

func (router *Router) Init() error {
	var err error
	if router.LogPath == "" {
		router.LogPath = "./access.log"
	}
	router.readRedisPool = &redis.Pool{
		MaxIdle:     100,
		IdleTimeout: 1 * time.Minute,
		Dial:        redisDialer(router.ReadRedisHost, router.ReadRedisPort),
	}
	router.writeRedisPool = &redis.Pool{
		MaxIdle:     100,
		IdleTimeout: 1 * time.Minute,
		Dial:        redisDialer(router.WriteRedisHost, router.WriteRedisPort),
	}
	if router.logger == nil {
		router.logger, err = NewFileLogger(router.LogPath)
		if err != nil {
			return err
		}
	}
	if router.DeadBackendTTL == 0 {
		router.DeadBackendTTL = 30
	}
	if router.cache == nil {
		router.cache, err = lru.New(100)
		if err != nil {
			return err
		}
	}
	router.reqCtx = make(map[*http.Request]*requestData)
	router.dialer = &net.Dialer{
		Timeout:   router.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	router.Transport = http.Transport{
		Dial:                router.dialer.Dial,
		TLSHandshakeTimeout: router.DialTimeout,
		MaxIdleConnsPerHost: 100,
	}
	router.roundRobin = make(map[string]*uint64)
	router.rp = &httputil.ReverseProxy{
		Director:      router.Director,
		Transport:     router,
		FlushInterval: router.FlushInterval,
	}
	return nil
}

func (router *Router) Stop() {
	router.logger.Stop()
}

type backendSet struct {
	id       string
	backends []string
	dead     map[uint64]struct{}
	expires  time.Time
}

func (s *backendSet) Expired() bool {
	return time.Now().After(s.expires)
}

func (router *Router) getBackends(host string) (*backendSet, error) {
	if data, ok := router.cache.Get(host); ok {
		set := data.(backendSet)
		if !set.Expired() {
			return &set, nil
		}
	}
	var set backendSet
	conn := router.readRedisPool.Get()
	defer conn.Close()
	conn.Send("MULTI")
	conn.Send("LRANGE", "frontend:"+host, 0, -1)
	conn.Send("SMEMBERS", "dead:"+host)
	data, err := conn.Do("EXEC")
	if err != nil {
		return nil, fmt.Errorf("error running redis commands: %s", err)
	}
	responses := data.([]interface{})
	if len(responses) != 2 {
		return nil, fmt.Errorf("unexpected redis response: %#v", responses)
	}
	backends := responses[0].([]interface{})
	if len(backends) < 2 {
		return nil, errors.New("no backends available")
	}
	set.id = string(backends[0].([]byte))
	backends = backends[1:]
	set.backends = make([]string, len(backends))
	for i, backend := range backends {
		set.backends[i] = string(backend.([]byte))
	}
	deadMembers := responses[1].([]interface{})
	deadMap := map[uint64]struct{}{}
	for _, dead := range deadMembers {
		deadIdx, _ := strconv.ParseUint(string(dead.([]byte)), 10, 64)
		deadMap[deadIdx] = struct{}{}
	}
	set.dead = deadMap
	set.expires = time.Now().Add(2 * time.Second)
	router.cache.Add(host, set)
	return &set, nil
}

func (router *Router) getRequestData(req *http.Request, save bool) (*requestData, error) {
	host, _, _ := net.SplitHostPort(req.Host)
	if host == "" {
		host = req.Host
	}
	reqData := &requestData{
		debug:     req.Header.Get("X-Debug-Router") != "",
		startTime: time.Now(),
		host:      host,
	}
	req.Header.Del("X-Debug-Router")
	if save {
		router.ctxMutex.Lock()
		router.reqCtx[req] = reqData
		router.ctxMutex.Unlock()
	}
	set, err := router.getBackends(host)
	if err != nil {
		return reqData, err
	}
	reqData.backendKey = set.id
	reqData.backendLen = len(set.backends)
	router.rrMutex.RLock()
	roundRobin := router.roundRobin[host]
	if roundRobin == nil {
		router.rrMutex.RUnlock()
		router.rrMutex.Lock()
		roundRobin = router.roundRobin[host]
		if roundRobin == nil {
			roundRobin = new(uint64)
			router.roundRobin[host] = roundRobin
		}
		router.rrMutex.Unlock()
	} else {
		router.rrMutex.RUnlock()
	}
	// We always add, it will eventually overflow to zero which is fine.
	initialNumber := atomic.AddUint64(roundRobin, 1)
	initialNumber = (initialNumber - 1) % uint64(reqData.backendLen)
	toUseNumber := -1
	for chosenNumber := initialNumber; ; {
		_, isDead := set.dead[chosenNumber]
		if !isDead {
			toUseNumber = int(chosenNumber)
			break
		}
		chosenNumber = (chosenNumber + 1) % uint64(reqData.backendLen)
		if chosenNumber == initialNumber {
			break
		}
	}
	if toUseNumber == -1 {
		return reqData, errors.New("all backends are dead")
	}
	reqData.backendIdx = toUseNumber
	reqData.backend = set.backends[toUseNumber]
	return reqData, nil
}

func (router *Router) Director(req *http.Request) {
	reqData, err := router.getRequestData(req, true)
	if err != nil {
		logError(reqData.String(), req.URL.Path, err)
		return
	}
	url, err := url.Parse(reqData.backend)
	if err != nil {
		logError(reqData.String(), req.URL.Path, fmt.Errorf("invalid backend url: %s", err))
		return
	}
	req.URL.Scheme = url.Scheme
	req.URL.Host = url.Host
	if router.RequestIDHeader != "" && req.Header.Get(router.RequestIDHeader) == "" {
		unparsedID, err := uuid.NewV4()
		if err != nil {
			fmt.Println("error:", err)
			return
		}
		uniqueID := unparsedID.String()
		req.Header.Set(router.RequestIDHeader, uniqueID)
	}
}

func (router *Router) RoundTrip(req *http.Request) (*http.Response, error) {
	router.ctxMutex.Lock()
	reqData := router.reqCtx[req]
	delete(router.reqCtx, req)
	router.ctxMutex.Unlock()
	var rsp *http.Response
	var err error
	var backendDuration time.Duration
	var timedout int32
	if router.RequestTimeout > 0 {
		timer := time.AfterFunc(router.RequestTimeout, func() {
			router.Transport.CancelRequest(req)
			atomic.AddInt32(&timedout, 1)
		})
		defer timer.Stop()
	}
	if req.URL.Scheme == "" || req.URL.Host == "" {
		closerBuffer := ioutil.NopCloser(bytes.NewBuffer(noRouteData))
		rsp = &http.Response{
			Request:       req,
			StatusCode:    http.StatusBadRequest,
			ProtoMajor:    req.ProtoMajor,
			ProtoMinor:    req.ProtoMinor,
			ContentLength: int64(len(noRouteData)),
			Body:          closerBuffer,
		}
	} else {
		t0 := time.Now().UTC()
		rsp, err = router.Transport.RoundTrip(req)
		backendDuration = time.Since(t0)
		if err != nil {
			markAsDead := false
			if netErr, ok := err.(net.Error); ok {
				markAsDead = !netErr.Temporary()
			}
			isTimeout := atomic.LoadInt32(&timedout) == int32(1)
			if isTimeout {
				markAsDead = false
				err = fmt.Errorf("request timed out after %v: %s", router.RequestTimeout, err)
			} else {
				err = fmt.Errorf("error in backend request: %s", err)
			}
			if markAsDead {
				err = fmt.Errorf("%s *DEAD*", err)
			}
			logError(reqData.String(), req.URL.Path, err)
			if markAsDead {
				conn := router.writeRedisPool.Get()
				defer conn.Close()
				conn.Send("MULTI")
				conn.Send("SADD", "dead:"+reqData.host, reqData.backendIdx)
				conn.Send("EXPIRE", "dead:"+reqData.host, router.DeadBackendTTL)
				conn.Send("PUBLISH", "dead", fmt.Sprintf("%s;%s;%d;%d", reqData.host, reqData.backend, reqData.backendIdx, reqData.backendLen))
				_, redisErr := conn.Do("EXEC")
				if redisErr != nil {
					logError(reqData.String(), req.URL.Path, fmt.Errorf("error markind dead backend in redis: %s", redisErr))
				}
			}
			rsp = &http.Response{
				Request:    req,
				StatusCode: http.StatusServiceUnavailable,
				ProtoMajor: req.ProtoMajor,
				ProtoMinor: req.ProtoMinor,
				Header:     http.Header{},
				Body:       ioutil.NopCloser(&bytes.Buffer{}),
			}
		}
	}
	if reqData.debug {
		rsp.Header.Set("X-Debug-Backend-Url", reqData.backend)
		rsp.Header.Set("X-Debug-Backend-Id", strconv.FormatUint(uint64(reqData.backendIdx), 10))
		rsp.Header.Set("X-Debug-Frontend-Key", reqData.host)
	}
	router.logger.MessageRaw(&logEntry{
		now:             time.Now(),
		req:             req,
		rsp:             rsp,
		backendDuration: backendDuration,
		totalDuration:   time.Since(reqData.startTime),
		backendKey:      reqData.backendKey,
	})
	return rsp, nil
}

func (router *Router) serveWebsocket(rw http.ResponseWriter, req *http.Request) (*requestData, error) {
	reqData, err := router.getRequestData(req, false)
	if err != nil {
		return reqData, err
	}
	url, err := url.Parse(reqData.backend)
	if err != nil {
		return reqData, err
	}
	req.Host = url.Host
	dstConn, err := router.dialer.Dial("tcp", url.Host)
	if err != nil {
		return reqData, err
	}
	defer dstConn.Close()
	hj, ok := rw.(http.Hijacker)
	if !ok {
		return reqData, errors.New("not a hijacker")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return reqData, err
	}
	defer conn.Close()
	if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		if prior, ok := req.Header["X-Forwarded-For"]; ok {
			clientIP = strings.Join(prior, ", ") + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	err = req.Write(dstConn)
	if err != nil {
		return reqData, err
	}
	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go cp(dstConn, conn)
	go cp(conn, dstConn)
	<-errc
	return reqData, nil
}

func (router *Router) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Host == "__ping__" && req.URL.Path == "/" {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
		return
	}
	upgrade := req.Header.Get("Upgrade")
	if upgrade != "" && strings.ToLower(upgrade) == "websocket" {
		reqData, err := router.serveWebsocket(rw, req)
		if err != nil {
			logError(reqData.String(), req.URL.Path, err)
			http.Error(rw, "", http.StatusBadGateway)
		}
		return
	}
	router.rp.ServeHTTP(rw, req)
}
