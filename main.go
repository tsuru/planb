package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/garyburd/redigo/redis"
)

const (
	TIME_ALIGNED_NANO = "2006-01-02T15:04:05.000000000Z07:00"
)

var (
	domainRegexp = regexp.MustCompile(`([^.]+\.[^.]+)$`)
)

func logError(err error) {
	fmt.Printf("ERROR: %#v\n", err)
}

type debugTransport struct {
	logChan chan string
}

func (t *debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var debugVars map[string]string
	if req.Header.Get("X-Debug") != "" {
		debugVars = map[string]string{}
		for k, v := range req.Header {
			if strings.HasPrefix(k, "X-Debug") {
				debugVars[k] = v[0]
				req.Header.Del(k)
			}
		}
	}
	t0 := time.Now().UTC()
	rsp, err := http.DefaultTransport.RoundTrip(req)
	if err == nil {
		reqDuration := time.Since(t0)
		nowFormatted := time.Now().Format(TIME_ALIGNED_NANO)
		t.logChan <- fmt.Sprintf("%s %s %s %s %d in %0.6f ms", nowFormatted, req.Host, req.Method, req.URL.Path, rsp.StatusCode, float64(reqDuration)/float64(time.Millisecond))
		if debugVars != nil {
			for k, v := range debugVars {
				rsp.Header.Set(k, v)
			}
		}
	}
	return rsp, err
}

func logWriter(file *os.File, logs chan string) {
	lock := sync.Mutex{}
	for el := range logs {
		lock.Lock()
		fmt.Fprintf(file, "%s\n", el)
		file.Sync()
		lock.Unlock()
	}
}

func createLogger() (chan string, error) {
	file, err := os.OpenFile("./access.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		return nil, err
	}
	logChan := make(chan string, 100)
	go logWriter(file, logChan)
	return logChan, nil
}

func extractDomain(host string) string {
	matches := domainRegexp.FindStringSubmatch(host)
	if len(matches) > 0 {
		return matches[0]
	}
	return host
}

func main() {
	redisDialFunc := func() (redis.Conn, error) {
		return redis.Dial("tcp", "127.0.0.1:6379")
	}
	redisPool := &redis.Pool{
		MaxIdle:     100,
		IdleTimeout: 1 * time.Minute,
		Dial:        redisDialFunc,
	}
	logChan, err := createLogger()
	if err != nil {
		panic(err)
	}

	var roundRobin uint64 = 0

	director := func(req *http.Request) {
		conn := redisPool.Get()
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
		toUseNumber := atomic.AddUint64(&roundRobin, 1)
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
		if req.Header.Get("X-Debug") != "" {
			req.Header.Set("X-Debug-Backend-Url", backend)
			req.Header.Set("X-Debug-Backend-Id", strconv.FormatUint(toUseNumber, 10))
			req.Header.Set("X-Debug-Frontend-Key", host)
		}
	}
	transport := debugTransport{
		logChan: logChan,
	}
	rProxy := &httputil.ReverseProxy{Director: director, Transport: &transport}
	listener, err := net.Listen("tcp", "0.0.0.0:8081")
	if err != nil {
		panic(err)
	}
	http.Handle("/", rProxy)
	panic(http.Serve(listener, nil))
}
