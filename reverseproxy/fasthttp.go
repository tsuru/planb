// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reverseproxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/nu7hatch/gouuid"
	"github.com/tsuru/planb/log"
	"github.com/valyala/fasthttp"
)

type FastReverseProxy struct {
	ReverseProxyConfig
	server    *fasthttp.Server
	dialFunc  func(addr string) (net.Conn, error)
	mu        sync.Mutex
	clientMap map[string]*fasthttp.HostClient
}

func dialWithTimeout(t time.Duration) func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		return fasthttp.DialTimeout(addr, t)
	}
}

func (rp *FastReverseProxy) Initialize(rpConfig ReverseProxyConfig) error {
	rp.ReverseProxyConfig = rpConfig
	rp.server = &fasthttp.Server{
		Handler: rp.handler,
	}
	rp.dialFunc = dialWithTimeout(rp.DialTimeout)
	rp.clientMap = make(map[string]*fasthttp.HostClient)
	return nil
}

func (rp *FastReverseProxy) Listen(listener net.Listener) {
	rp.server.Serve(listener)
}

func (rp *FastReverseProxy) Stop() {
	// no special treatment for fast reverse proxy
}

func (rp *FastReverseProxy) getClient(addr string, tls bool) *fasthttp.HostClient {
	addr = addMissingPort(addr, tls)
	rp.mu.Lock()
	defer rp.mu.Unlock()
	client, ok := rp.clientMap[addr]
	if ok {
		return client
	}
	client = &fasthttp.HostClient{
		Addr:         addr,
		IsTLS:        tls,
		Dial:         rp.dialFunc,
		ReadTimeout:  rp.RequestTimeout,
		WriteTimeout: rp.RequestTimeout,
	}
	rp.clientMap[addr] = client
	return client
}

func addMissingPort(addr string, isTLS bool) string {
	n := strings.Index(addr, ":")
	if n >= 0 {
		return addr
	}
	port := 80
	if isTLS {
		port = 443
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

func (rp *FastReverseProxy) debugHeaders(rsp *fasthttp.Response, reqData *RequestData, isDebug bool) {
	if !isDebug {
		return
	}
	rsp.Header.Set("X-Debug-Backend-Url", reqData.Backend)
	rsp.Header.Set("X-Debug-Backend-Id", strconv.FormatUint(uint64(reqData.BackendIdx), 10))
	rsp.Header.Set("X-Debug-Frontend-Key", reqData.Host)
}

func (rp *FastReverseProxy) serveWebsocket(dstHost string, reqData *RequestData, ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	uri := req.URI()
	uri.SetHost(dstHost)
	dstConn, err := rp.dialFunc(dstHost)
	if err != nil {
		reqData.logError(string(uri.Path()), rp.ridString(req), err)
		return
	}
	_, err = req.WriteTo(dstConn)
	if err != nil {
		reqData.logError(string(uri.Path()), rp.ridString(req), err)
		return
	}
	ctx.Hijack(func(conn net.Conn) {
		defer dstConn.Close()
		defer conn.Close()
		errc := make(chan error, 2)
		cp := func(dst io.Writer, src io.Reader) {
			_, err := io.Copy(dst, src)
			errc <- err
		}
		go cp(dstConn, conn)
		go cp(conn, dstConn)
		<-errc
	})
}

func (rp *FastReverseProxy) chooseBackend(host string) (*RequestData, string, string, error) {
	var dstScheme string
	var dstHost string
	reqData, err := rp.Router.ChooseBackend(host)
	if err != nil {
		return reqData, dstScheme, dstHost, err
	}
	u, err := url.Parse(reqData.Backend)
	if err == nil {
		dstScheme = u.Scheme
		dstHost = u.Host
	}
	if dstHost == "" {
		dstHost = reqData.Backend
	}
	return reqData, dstScheme, dstHost, nil
}

func (rp *FastReverseProxy) ridString(req *fasthttp.Request) string {
	return rp.RequestIDHeader + ":" + string(req.Header.Peek(rp.RequestIDHeader))
}

func (rp *FastReverseProxy) handler(ctx *fasthttp.RequestCtx) {
	var backendDuration time.Duration
	req := &ctx.Request
	resp := &ctx.Response
	host := string(req.Header.Host())
	uri := req.URI()
	if host == "__ping__" && len(uri.Path()) == 1 && uri.Path()[0] == byte('/') {
		err := rp.Router.Healthcheck()
		if err != nil {
			resp.SetStatusCode(http.StatusInternalServerError)
			resp.SetBody([]byte(err.Error()))
			return
		}
		resp.SetBody(okResponse)
		return
	}
	if rp.RequestIDHeader != "" && len(req.Header.Peek(rp.RequestIDHeader)) == 0 {
		var unparsedID *uuid.UUID
		unparsedID, err := uuid.NewV4()
		if err == nil {
			req.Header.Set(rp.RequestIDHeader, unparsedID.String())
		}
	}
	originalForwardedFor := string(req.Header.Peek("X-Forwarded-For"))
	var clientIP string
	var err error
	if clientIP, _, err = net.SplitHostPort(ctx.RemoteAddr().String()); err == nil {
		if len(originalForwardedFor) > 0 {
			clientIP = originalForwardedFor + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	reqData, dstScheme, dstHost, err := rp.chooseBackend(host)
	logEntry := func() *log.LogEntry {
		proto := "HTTP/1.0"
		if req.Header.IsHTTP11() {
			proto = "HTTP/1.1"
		}
		return &log.LogEntry{
			Now:             time.Now(),
			BackendDuration: backendDuration,
			TotalDuration:   time.Since(reqData.StartTime),
			BackendKey:      reqData.BackendKey,
			RemoteAddr:      ctx.RemoteAddr().String(),
			Method:          string(ctx.Method()),
			Path:            string(uri.Path()),
			Proto:           proto,
			Referer:         string(ctx.Referer()),
			UserAgent:       string(ctx.UserAgent()),
			RequestIDHeader: rp.RequestIDHeader,
			RequestID:       string(req.Header.Peek(rp.RequestIDHeader)),
			StatusCode:      resp.StatusCode(),
			ContentLength:   int64(resp.Header.ContentLength()),
			ForwardedFor:    originalForwardedFor,
		}
	}
	isDebug := len(req.Header.Peek("X-Debug-Router")) > 0
	req.Header.Del("X-Debug-Router")
	if err != nil || dstHost == "" {
		if err != nil {
			reqData.logError(string(uri.Path()), rp.ridString(req), err)
		}
		var status int
		var body []byte
		switch err {
		case nil, ErrNoRegisteredBackends:
			status = http.StatusBadRequest
			body = noRouteResponseContent
		case ErrAllBackendsDead:
			status = http.StatusServiceUnavailable
			body = allBackendsDeadContent
		default:
			status = http.StatusServiceUnavailable
		}
		resp.SetStatusCode(status)
		resp.SetBody(body)
		rp.debugHeaders(resp, reqData, isDebug)
		endErr := rp.Router.EndRequest(reqData, false, logEntry)
		if endErr != nil {
			reqData.logError(string(uri.Path()), rp.ridString(req), endErr)
		}
		return
	}
	upgrade := req.Header.Peek("Upgrade")
	if len(upgrade) > 0 && bytes.Equal(bytes.ToLower(upgrade), websocketUpgrade) {
		resp.SkipResponse = true
		rp.serveWebsocket(dstHost, reqData, ctx)
		return
	}
	hostOnly, _, _ := net.SplitHostPort(dstHost)
	if hostOnly == "" {
		hostOnly = dstHost
	}
	isIP := net.ParseIP(hostOnly) != nil
	if !isIP {
		req.Header.SetBytesV("X-Host", uri.Host())
		req.Header.SetBytesV("X-Forwarded-Host", uri.Host())
		uri.SetHost(hostOnly)
	}
	client := rp.getClient(dstHost, dstScheme == "https")
	t0 := time.Now().UTC()
	err = client.Do(req, resp)
	backendDuration = time.Since(t0)
	markAsDead := false
	if err != nil {
		var isTimeout bool
		if netErr, ok := err.(net.Error); ok {
			markAsDead = !netErr.Temporary()
			isTimeout = netErr.Timeout()
		}
		if isTimeout {
			markAsDead = false
			err = fmt.Errorf("request timed out after %v: %s", time.Since(reqData.StartTime), err)
		} else {
			err = fmt.Errorf("error in backend request: %s", err)
		}
		if markAsDead {
			err = fmt.Errorf("%s *DEAD*", err)
		}
		resp.SetStatusCode(http.StatusServiceUnavailable)
		reqData.logError(string(uri.Path()), rp.ridString(req), err)
	}
	rp.debugHeaders(resp, reqData, isDebug)
	endErr := rp.Router.EndRequest(reqData, markAsDead, logEntry)
	if endErr != nil {
		reqData.logError(string(uri.Path()), rp.ridString(req), endErr)
	}
}
