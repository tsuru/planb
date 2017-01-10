// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reverseproxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/braintree/manners"
	"github.com/nu7hatch/gouuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/tsuru/planb/log"
)

var (
	emptyResponseBody   = &fixedReadCloser{}
	noRouteResponseBody = &fixedReadCloser{value: noRouteResponseContent}
	noopDirector        = func(*http.Request) {}

	_ ReverseProxy = &NativeReverseProxy{}

	openConnections = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "planb",
		Subsystem: "reverseproxy",
		Name:      "connections_open",
		Help:      "The current number of open connections.",
	})

	requestDurations = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "planb",
		Subsystem: "reverseproxy",
		Name:      "request_duration_seconds",
		Help:      "The total request latencies in seconds.",
	})

	backendDurations = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "planb",
		Subsystem: "reverseproxy",
		Name:      "backend_request_duration_seconds",
		Help:      "The backends HTTP request latencies in seconds.",
	})

	backendResponse = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: "planb",
		Subsystem: "reverseproxy",
		Name:      "backends_responses",
		Help:      "The total backends responses by status code.",
	}, []string{"status_code"})
)

func init() {
	prometheus.MustRegister(openConnections)
	prometheus.MustRegister(requestDurations)
	prometheus.MustRegister(backendResponse)
	prometheus.MustRegister(backendDurations)
}

type NativeReverseProxy struct {
	http.Transport
	ReverseProxyConfig
	servers []*manners.GracefulServer
	rp      *httputil.ReverseProxy
	dialer  *net.Dialer
}

type fixedReadCloser struct {
	value []byte
}

func (r *fixedReadCloser) Read(p []byte) (n int, err error) {
	return copy(p, r.value), io.EOF
}

func (r *fixedReadCloser) Close() error {
	return nil
}

type bufferPool struct {
	syncPool sync.Pool
}

func (p *bufferPool) Get() []byte {
	b := p.syncPool.Get()
	if b == nil {
		return make([]byte, 32*1024)
	}
	return b.([]byte)
}

func (p *bufferPool) Put(b []byte) {
	p.syncPool.Put(b)
}

func (rp *NativeReverseProxy) Initialize(rpConfig ReverseProxyConfig) error {
	rp.ReverseProxyConfig = rpConfig
	rp.servers = make([]*manners.GracefulServer, 0)

	rp.dialer = &net.Dialer{
		Timeout:   rp.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	rp.Transport = http.Transport{
		Dial:                rp.dialer.Dial,
		TLSHandshakeTimeout: rp.DialTimeout,
		MaxIdleConnsPerHost: 100,
	}
	rp.rp = &httputil.ReverseProxy{
		Director:      noopDirector,
		Transport:     rp,
		FlushInterval: rp.FlushInterval,
		BufferPool:    &bufferPool{},
	}
	return nil
}

func (rp *NativeReverseProxy) Listen(listener net.Listener) {
	server := manners.NewWithServer(&http.Server{
		Handler: rp,
		ConnState: func(c net.Conn, s http.ConnState) {
			switch s {
			case http.StateNew:
				openConnections.Inc()
			case http.StateClosed:
				openConnections.Dec()
			}
		},
	})
	rp.servers = append(rp.servers, server)
	server.Serve(listener)
}

func (rp *NativeReverseProxy) Stop() {
	for _, server := range rp.servers {
		server.Close()
	}
}

func (rp *NativeReverseProxy) ridString(req *http.Request) string {
	return rp.RequestIDHeader + ":" + req.Header.Get(rp.RequestIDHeader)
}

func (rp *NativeReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Host == "__ping__" && req.URL.Path == "/" {
		rw.WriteHeader(http.StatusOK)
		rw.Write(okResponse)
		return
	}
	if rp.RequestIDHeader != "" && req.Header.Get(rp.RequestIDHeader) == "" {
		unparsedID, err := uuid.NewV4()
		if err == nil {
			req.Header.Set(rp.RequestIDHeader, unparsedID.String())
		}
	}
	upgrade := req.Header.Get("Upgrade")
	if upgrade != "" && strings.ToLower(upgrade) == "websocket" {
		reqData, err := rp.serveWebsocket(rw, req)
		if err != nil {
			reqData.logError(req.URL.Path, rp.ridString(req), err)
			http.Error(rw, "", http.StatusBadGateway)
		}
		return
	}
	rp.rp.ServeHTTP(rw, req)
}

func (rp *NativeReverseProxy) serveWebsocket(rw http.ResponseWriter, req *http.Request) (*RequestData, error) {
	reqData, err := rp.Router.ChooseBackend(req.Host)
	if err != nil {
		return reqData, err
	}
	url, err := url.Parse(reqData.Backend)
	if err != nil {
		return reqData, err
	}
	req.Host = url.Host
	dstConn, err := rp.dialer.Dial("tcp", url.Host)
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
	var clientIP string
	if clientIP, _, err = net.SplitHostPort(req.RemoteAddr); err == nil {
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

func (rp *NativeReverseProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = ""
	req.URL.Host = ""
	reqData, err := rp.Router.ChooseBackend(req.Host)
	if err != nil {
		reqData.logError(req.URL.Path, rp.ridString(req), err)
		return rp.roundTripWithData(req, reqData, err), nil
	}
	u, err := url.Parse(reqData.Backend)
	if err == nil {
		req.URL.Host = u.Host
		req.URL.Scheme = u.Scheme
	}
	if req.URL.Host == "" {
		req.URL.Scheme = "http"
		req.URL.Host = reqData.Backend
	}
	return rp.roundTripWithData(req, reqData, nil), nil
}

func (rp *NativeReverseProxy) doResponse(req *http.Request, reqData *RequestData, rsp *http.Response, isDebug bool, isDead bool, backendDuration time.Duration) *http.Response {
	totalDuration := time.Since(reqData.StartTime)
	logEntry := func() *log.LogEntry {
		return &log.LogEntry{
			Now:             time.Now(),
			BackendDuration: backendDuration,
			TotalDuration:   totalDuration,
			BackendKey:      reqData.BackendKey,
			RemoteAddr:      req.RemoteAddr,
			Method:          req.Method,
			Path:            req.URL.Path,
			Proto:           req.Proto,
			Referer:         req.Referer(),
			UserAgent:       req.UserAgent(),
			RequestIDHeader: rp.RequestIDHeader,
			RequestID:       req.Header.Get(rp.RequestIDHeader),
			StatusCode:      rsp.StatusCode,
			ContentLength:   rsp.ContentLength,
		}
	}
	rsp.Request = req
	rsp.ProtoMajor = req.ProtoMajor
	rsp.ProtoMinor = req.ProtoMinor
	if rsp.Header == nil {
		rsp.Header = http.Header{}
	}
	if isDebug {
		rsp.Header.Set("X-Debug-Backend-Url", reqData.Backend)
		rsp.Header.Set("X-Debug-Backend-Id", strconv.FormatUint(uint64(reqData.BackendIdx), 10))
		rsp.Header.Set("X-Debug-Frontend-Key", reqData.Host)
	}
	err := rp.Router.EndRequest(reqData, isDead, logEntry)
	if err != nil {
		reqData.logError(req.URL.Path, rp.ridString(req), err)
	}
	backendResponse.WithLabelValues(strconv.Itoa(rsp.StatusCode)).Inc()
	backendDurations.Observe(backendDuration.Seconds())
	requestDurations.Observe(totalDuration.Seconds())
	return rsp
}

func (rp *NativeReverseProxy) roundTripWithData(req *http.Request, reqData *RequestData, err error) (rsp *http.Response) {
	isDebug := req.Header.Get("X-Debug-Router") != ""
	req.Header.Del("X-Debug-Router")
	if err != nil || req.URL.Scheme == "" || req.URL.Host == "" {
		switch err {
		case nil, ErrNoRegisteredBackends:
			rsp = &http.Response{
				StatusCode:    http.StatusBadRequest,
				ContentLength: int64(len(noRouteResponseBody.value)),
				Body:          noRouteResponseBody,
			}
		default:
			rsp = &http.Response{
				StatusCode: http.StatusServiceUnavailable,
				Body:       emptyResponseBody,
			}
		}
		return rp.doResponse(req, reqData, rsp, isDebug, false, 0)
	}
	var timedout int32
	if rp.RequestTimeout > 0 {
		timer := time.AfterFunc(rp.RequestTimeout, func() {
			atomic.AddInt32(&timedout, 1)
			rp.Transport.CancelRequest(req)
		})
		defer timer.Stop()
	}
	host, _, _ := net.SplitHostPort(req.URL.Host)
	if host == "" {
		host = req.URL.Host
	}
	isIP := net.ParseIP(host) != nil
	if !isIP {
		req.Header.Set("X-Host", req.Host)
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Host = host
	}
	t0 := time.Now().UTC()
	rsp, err = rp.Transport.RoundTrip(req)
	backendDuration := time.Since(t0)
	markAsDead := false
	if err != nil {
		var dialTimeout, requestTimeout bool
		if netErr, ok := err.(net.Error); ok {
			markAsDead = !netErr.Temporary()
			dialTimeout = netErr.Timeout()
		}
		requestTimeout = atomic.LoadInt32(&timedout) == int32(1)
		if requestTimeout {
			markAsDead = false
			err = fmt.Errorf("request timeout after %v: %s", time.Since(reqData.StartTime), err)
		} else if dialTimeout {
			markAsDead = true
			err = fmt.Errorf("dial timeout after %v: %s", time.Since(reqData.StartTime), err)
		} else {
			err = fmt.Errorf("error in backend request: %s", err)
		}
		if markAsDead {
			err = fmt.Errorf("%s *DEAD*", err)
		}
		reqData.logError(req.URL.Path, rp.ridString(req), err)
		rsp = &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       emptyResponseBody,
		}
	}
	return rp.doResponse(req, reqData, rsp, isDebug, markAsDead, backendDuration)
}
