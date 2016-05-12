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
	"github.com/tsuru/planb/log"
)

var (
	emptyResponseBody   = &fixedReadCloser{}
	noRouteResponseBody = &fixedReadCloser{value: []byte("no such route")}
	noopDirector        = func(*http.Request) {}

	_ ReverseProxy = &NativeReverseProxy{}
)

type NativeReverseProxy struct {
	http.Transport
	ReverseProxyConfig
	server   *manners.GracefulServer
	rp       *httputil.ReverseProxy
	dialer   *net.Dialer
	listener net.Listener
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

func (rp *NativeReverseProxy) Initialize(rpConfig ReverseProxyConfig) (string, error) {
	var err error
	rp.ReverseProxyConfig = rpConfig
	rp.listener, err = net.Listen("tcp", rpConfig.Listen)
	if err != nil {
		return "", err
	}
	rp.server = manners.NewWithServer(&http.Server{Handler: rp})
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
	return rp.listener.Addr().String(), nil
}

func (rp *NativeReverseProxy) Listen() {
	rp.server.Serve(rp.listener)
}

func (rp *NativeReverseProxy) Stop() {
	rp.server.Close()
}

func (rp *NativeReverseProxy) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Host == "__ping__" && req.URL.Path == "/" {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("OK"))
		return
	}
	upgrade := req.Header.Get("Upgrade")
	if upgrade != "" && strings.ToLower(upgrade) == "websocket" {
		reqData, err := rp.serveWebsocket(rw, req)
		if err != nil {
			log.LogError(reqData.String(), req.URL.Path, err)
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

func (rp *NativeReverseProxy) RoundTrip(req *http.Request) (*http.Response, error) {
	reqData, err := rp.Router.ChooseBackend(req.Host)
	if err != nil {
		log.LogError(reqData.String(), req.URL.Path, err)
	}
	req.URL.Scheme = ""
	req.URL.Host = ""
	u, err := url.Parse(reqData.Backend)
	if err == nil {
		req.URL.Host = u.Host
		req.URL.Scheme = u.Scheme
	} else {
		log.LogError(reqData.String(), req.URL.Path, err)
	}
	if req.URL.Host == "" {
		req.URL.Scheme = "http"
		req.URL.Host = reqData.Backend
	}
	if rp.RequestIDHeader != "" && req.Header.Get(rp.RequestIDHeader) == "" {
		unparsedID, err := uuid.NewV4()
		if err == nil {
			req.Header.Set(rp.RequestIDHeader, unparsedID.String())
		} else {
			log.LogError(reqData.String(), req.URL.Path, fmt.Errorf("unable to generate request id: %s", err))
		}
	}
	rsp := rp.roundTripWithData(req, reqData)
	return rsp, nil
}

func (rp *NativeReverseProxy) debugHeaders(rsp *http.Response, reqData *RequestData, isDebug bool) {
	if !isDebug {
		return
	}
	rsp.Header.Set("X-Debug-Backend-Url", reqData.Backend)
	rsp.Header.Set("X-Debug-Backend-Id", strconv.FormatUint(uint64(reqData.BackendIdx), 10))
	rsp.Header.Set("X-Debug-Frontend-Key", reqData.Host)
}

func (rp *NativeReverseProxy) roundTripWithData(req *http.Request, reqData *RequestData) *http.Response {
	var rsp *http.Response
	var backendDuration time.Duration
	logEntry := func() *log.LogEntry {
		return &log.LogEntry{
			Now:             time.Now(),
			BackendDuration: backendDuration,
			TotalDuration:   time.Since(reqData.StartTime),
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
	var err error
	isDebug := req.Header.Get("X-Debug-Router") != ""
	req.Header.Del("X-Debug-Router")
	if req.URL.Scheme == "" || req.URL.Host == "" {
		rsp = &http.Response{
			Request:       req,
			StatusCode:    http.StatusBadRequest,
			ProtoMajor:    req.ProtoMajor,
			ProtoMinor:    req.ProtoMinor,
			ContentLength: int64(len(noRouteResponseBody.value)),
			Header:        http.Header{},
			Body:          noRouteResponseBody,
		}
		rp.debugHeaders(rsp, reqData, isDebug)
		err = rp.Router.EndRequest(reqData, false, logEntry)
		if err != nil {
			log.LogError(reqData.String(), req.URL.Path, err)
		}
		return rsp
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
		req.Host = host
	}
	t0 := time.Now().UTC()
	rsp, err = rp.Transport.RoundTrip(req)
	backendDuration = time.Since(t0)
	markAsDead := false
	if err != nil {
		if netErr, ok := err.(net.Error); ok {
			markAsDead = !netErr.Temporary()
		}
		isTimeout := atomic.LoadInt32(&timedout) == int32(1)
		if isTimeout {
			markAsDead = false
			err = fmt.Errorf("request timed out after %v: %s", rp.RequestTimeout, err)
		} else {
			err = fmt.Errorf("error in backend request: %s", err)
		}
		if markAsDead {
			err = fmt.Errorf("%s *DEAD*", err)
		}
		log.LogError(reqData.String(), req.URL.Path, err)
		rsp = &http.Response{
			Request:    req,
			StatusCode: http.StatusServiceUnavailable,
			ProtoMajor: req.ProtoMajor,
			ProtoMinor: req.ProtoMinor,
			Header:     http.Header{},
			Body:       emptyResponseBody,
		}
	}
	rp.debugHeaders(rsp, reqData, isDebug)
	endErr := rp.Router.EndRequest(reqData, markAsDead, logEntry)
	if endErr != nil {
		log.LogError(reqData.String(), req.URL.Path, endErr)
	}
	return rsp
}
