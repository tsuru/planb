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
)

var (
	noRouteData       = []byte("no such route")
	emptyBufferReader = ioutil.NopCloser(&bytes.Buffer{})
)

type requestData struct {
	backendLen int
	backend    string
	backendIdx int
	host       string
	debug      bool
}

type Router struct {
	http.Transport
	ReadRedisHost  string
	ReadRedisPort  int
	WriteRedisHost string
	WriteRedisPort int
	LogPath        string
	DialTimeout    time.Duration
	RequestTimeout time.Duration
	rp             *httputil.ReverseProxy
	dialer         *net.Dialer
	readRedisPool  *redis.Pool
	writeRedisPool *redis.Pool
	logger         *Logger
	ctxMutex       sync.Mutex
	reqCtx         map[*http.Request]*requestData
	rrMutex        sync.RWMutex
	roundRobin     map[string]*uint64
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
		var err error
		router.logger, err = NewFileLogger(router.LogPath)
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
	router.rp = &httputil.ReverseProxy{Director: router.Director, Transport: router}
	return nil
}

func (router *Router) Stop() {
	router.logger.Stop()
}

func (router *Router) getRequestData(req *http.Request, save bool) (*requestData, error) {
	reqData := &requestData{
		debug: req.Header.Get("X-Debug-Router") != "",
	}
	req.Header.Del("X-Debug-Router")
	if save {
		router.ctxMutex.Lock()
		router.reqCtx[req] = reqData
		router.ctxMutex.Unlock()
	}
	conn := router.readRedisPool.Get()
	defer conn.Close()
	host, _, _ := net.SplitHostPort(req.Host)
	if host == "" {
		host = req.Host
	}
	reqData.host = host
	conn.Send("MULTI")
	conn.Send("LRANGE", "frontend:"+host, 1, -1)
	conn.Send("SMEMBERS", "dead:"+host)
	data, err := conn.Do("EXEC")
	if err != nil {
		return nil, err
	}
	responses := data.([]interface{})
	if len(responses) != 2 {
		return nil, fmt.Errorf("unexpected redis response: %#v", responses)
	}
	backends := responses[0].([]interface{})
	reqData.backendLen = len(backends)
	if reqData.backendLen == 0 {
		return nil, errors.New("no backends available")
	}
	deadMembers := responses[1].([]interface{})
	deadMap := map[uint64]struct{}{}
	for _, dead := range deadMembers {
		deadIdx, _ := strconv.ParseUint(string(dead.([]byte)), 10, 64)
		deadMap[deadIdx] = struct{}{}
	}
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
	initialNumber = initialNumber % uint64(reqData.backendLen)
	toUseNumber := -1
	for chosenNumber := initialNumber + 1; chosenNumber != initialNumber; chosenNumber++ {
		chosenNumber = chosenNumber % uint64(reqData.backendLen)
		_, isDead := deadMap[chosenNumber]
		if !isDead {
			toUseNumber = int(chosenNumber)
			break
		}
	}
	if toUseNumber == -1 {
		return nil, errors.New("all backends are dead")
	}
	reqData.backendIdx = toUseNumber
	reqData.backend = string(backends[toUseNumber].([]byte))
	return reqData, nil
}

func (router *Router) Director(req *http.Request) {
	reqData, err := router.getRequestData(req, true)
	if err != nil {
		logError(err)
		return
	}
	url, err := url.Parse(reqData.backend)
	if err != nil {
		logError(err)
		return
	}
	req.URL.Scheme = url.Scheme
	req.URL.Host = url.Host
}

func (router *Router) RoundTrip(req *http.Request) (*http.Response, error) {
	router.ctxMutex.Lock()
	reqData := router.reqCtx[req]
	delete(router.reqCtx, req)
	router.ctxMutex.Unlock()
	var rsp *http.Response
	var err error
	t0 := time.Now().UTC()
	if router.RequestTimeout > 0 {
		time.AfterFunc(router.RequestTimeout, func() {
			router.Transport.CancelRequest(req)
		})
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
		rsp, err = router.Transport.RoundTrip(req)
		if err != nil {
			logError(err)
			conn := router.writeRedisPool.Get()
			defer conn.Close()
			conn.Send("MULTI")
			conn.Send("SADD", "dead:"+reqData.host, reqData.backendIdx)
			conn.Send("EXPIRE", "dead:"+reqData.host, "30")
			conn.Send("PUBLISH", "dead", fmt.Sprintf("%s;%s;%d;%d", reqData.host, reqData.backend, reqData.backendIdx, reqData.backendLen))
			_, redisErr := conn.Do("EXEC")
			if redisErr != nil {
				logError(redisErr)
			}
			rsp = &http.Response{
				Request:    req,
				StatusCode: http.StatusServiceUnavailable,
				ProtoMajor: req.ProtoMajor,
				ProtoMinor: req.ProtoMinor,
				Header:     http.Header{},
				Body:       emptyBufferReader,
			}
		}
	}
	reqDuration := time.Since(t0)
	router.logger.MessageRaw(time.Now(), req, rsp, reqDuration)
	if reqData.debug {
		rsp.Header.Set("X-Debug-Backend-Url", reqData.backend)
		rsp.Header.Set("X-Debug-Backend-Id", strconv.FormatUint(uint64(reqData.backendIdx), 10))
		rsp.Header.Set("X-Debug-Frontend-Key", reqData.host)
	}
	return rsp, nil
}

func (router *Router) serveWebsocket(rw http.ResponseWriter, req *http.Request) error {
	reqData, err := router.getRequestData(req, false)
	if err != nil {
		return err
	}
	url, err := url.Parse(reqData.backend)
	if err != nil {
		return err
	}
	req.Host = url.Host
	dstConn, err := router.dialer.Dial("tcp", url.Host)
	if err != nil {
		return err
	}
	defer dstConn.Close()
	hj, ok := rw.(http.Hijacker)
	if !ok {
		return errors.New("not a hijacker")
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		return err
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
		return err
	}
	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go cp(dstConn, conn)
	go cp(conn, dstConn)
	<-errc
	return nil
}

func (router *Router) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Host == "__ping__" && req.URL.Path == "/" {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
		return
	}
	upgrade := req.Header.Get("Upgrade")
	if upgrade != "" && strings.ToLower(upgrade) == "websocket" {
		err := router.serveWebsocket(rw, req)
		if err != nil {
			logError(err)
			http.Error(rw, "", http.StatusBadGateway)
		}
		return
	}
	router.rp.ServeHTTP(rw, req)
}
