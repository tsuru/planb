package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/garyburd/redigo/redis"
)

const (
	TIME_ALIGNED_NANO = "2006-01-02T15:04:05.000000000Z07:00"
)

var (
	NO_ROUTE_DATA = []byte("no such route")
	domainRegexp  = regexp.MustCompile(`([^.]+\.[^.]+)$`)
)

func extractDomain(host string) string {
	matches := domainRegexp.FindStringSubmatch(host)
	if len(matches) > 0 {
		return matches[0]
	}
	return host
}

type Router struct {
	rp         *httputil.ReverseProxy
	redisPool  *redis.Pool
	logChan    chan string
	roundRobin uint64
}

func (router *Router) Init() error {
	redisDialFunc := func() (redis.Conn, error) {
		return redis.Dial("tcp", "127.0.0.1:6379")
	}
	router.redisPool = &redis.Pool{
		MaxIdle:     100,
		IdleTimeout: 1 * time.Minute,
		Dial:        redisDialFunc,
	}
	logChan, err := createLogger()
	if err != nil {
		return err
	}
	router.logChan = logChan
	router.rp = &httputil.ReverseProxy{Director: router.Director, Transport: router}
	return nil
}

func (router *Router) Director(req *http.Request) {
	conn := router.redisPool.Get()
	defer conn.Close()
	host := req.Host
	conn.Send("MULTI")
	conn.Send("LRANGE", "frontend:"+host, 1, -1)
	conn.Send("LRANGE", "frontend:*."+extractDomain(host), 1, -1)
	conn.Send("SMEMBERS", "dead:"+host)
	data, err := conn.Do("EXEC")
	if err != nil {
		logError(err)
		return
	}
	responses := data.([]interface{})
	if len(responses) != 3 {
		logError(fmt.Errorf("unexpected redis response: %#v", responses))
		return
	}
	backends := responses[0].([]interface{})
	if len(backends) == 0 {
		return
	}
	deadMembers := responses[2].([]interface{})
	deadMap := map[string]struct{}{}
	for _, dead := range deadMembers {
		deadName := string(dead.([]byte))
		deadMap[deadName] = struct{}{}
	}
	// We always add, it will eventually overflow to zero which is fine.
	toUseNumber := atomic.AddUint64(&router.roundRobin, 1)
	var backend string
	for {
		toUseNumber = toUseNumber % uint64(len(backends))
		backend = string(backends[toUseNumber].([]byte))
		_, isDead := deadMap[backend]
		if !isDead {
			break
		}
		toUseNumber++
	}
	url, err := url.Parse(backend)
	if err != nil {
		logError(err)
		return
	}
	req.URL.Scheme = url.Scheme
	req.URL.Host = url.Host
	if req.Header.Get("X-Debug-Router") != "" {
		req.Header.Set("X-Debug-Backend-Url", backend)
		req.Header.Set("X-Debug-Backend-Id", strconv.FormatUint(toUseNumber, 10))
		req.Header.Set("X-Debug-Frontend-Key", host)
	}
}

func (router *Router) RoundTrip(req *http.Request) (*http.Response, error) {
	var debugVars map[string]string
	if req.Header.Get("X-Debug-Router") != "" {
		debugVars = map[string]string{}
		for k, v := range req.Header {
			if strings.HasPrefix(k, "X-Debug") {
				debugVars[k] = v[0]
				req.Header.Del(k)
			}
		}
	}
	var rsp *http.Response
	var err error
	t0 := time.Now().UTC()
	if req.URL.Scheme == "" || req.URL.Host == "" {
		closerBuffer := ioutil.NopCloser(bytes.NewBuffer(NO_ROUTE_DATA))
		rsp = &http.Response{
			Request:       req,
			StatusCode:    http.StatusBadRequest,
			ProtoMajor:    req.ProtoMajor,
			ProtoMinor:    req.ProtoMinor,
			ContentLength: int64(len(NO_ROUTE_DATA)),
			Body:          closerBuffer,
		}
	} else {
		rsp, err = http.DefaultTransport.RoundTrip(req)
	}
	if err == nil {
		reqDuration := time.Since(t0)
		nowFormatted := time.Now().Format(TIME_ALIGNED_NANO)
		router.logChan <- fmt.Sprintf("%s %s %s %s %d in %0.6f ms", nowFormatted, req.Host, req.Method, req.URL.Path, rsp.StatusCode, float64(reqDuration)/float64(time.Millisecond))
		if debugVars != nil {
			for k, v := range debugVars {
				rsp.Header.Set(k, v)
			}
		}
	}
	return rsp, err
}

func (router *Router) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Host == "__ping__" && req.URL.Path == "/" {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
		return
	}
	router.rp.ServeHTTP(rw, req)
}
