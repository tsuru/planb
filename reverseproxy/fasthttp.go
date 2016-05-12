// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reverseproxy

import (
	"bytes"
	"errors"
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
	listener  net.Listener
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

func (rp *FastReverseProxy) Initialize(rpConfig ReverseProxyConfig) (string, error) {
	rp.ReverseProxyConfig = rpConfig
	var err error
	rp.listener, err = net.Listen("tcp", rpConfig.Listen)
	if err != nil {
		return "", err
	}
	rp.server = &fasthttp.Server{
		Handler: rp.handler,
	}
	rp.dialFunc = dialWithTimeout(rp.DialTimeout)
	rp.clientMap = make(map[string]*fasthttp.HostClient)
	return rp.listener.Addr().String(), nil
}

func (rp *FastReverseProxy) Listen() {
	rp.server.Serve(rp.listener)
}

func (rp *FastReverseProxy) Stop() {
	rp.listener.Close()
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
		log.LogError(reqData.String(), string(uri.Path()), err)
		return
	}
	if clientIP, _, err := net.SplitHostPort(ctx.RemoteAddr().String()); err == nil {
		if prior := string(req.Header.Peek("X-Forwarded-For")); len(prior) > 0 {
			clientIP = prior + ", " + clientIP
		}
		req.Header.Set("X-Forwarded-For", clientIP)
	}
	_, err = req.WriteTo(dstConn)
	if err != nil {
		log.LogError(reqData.String(), string(uri.Path()), err)
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

func (rp *FastReverseProxy) handler(ctx *fasthttp.RequestCtx) {
	req := &ctx.Request
	resp := &ctx.Response
	host := string(req.Header.Host())
	uri := req.URI()
	if host == "__ping__" && len(uri.Path()) == 1 && uri.Path()[0] == byte('/') {
		resp.SetBody(okResponse)
		return
	}
	reqData, err := rp.Router.ChooseBackend(host)
	if err != nil {
		log.LogError(reqData.String(), string(uri.Path()), err)
	}
	dstScheme := ""
	dstHost := ""
	u, err := url.Parse(reqData.Backend)
	if err == nil {
		dstScheme = u.Scheme
		dstHost = u.Host
	} else {
		log.LogError(reqData.String(), string(uri.Path()), err)
	}
	if dstHost == "" {
		dstHost = reqData.Backend
	}
	upgrade := req.Header.Peek("Upgrade")
	if len(upgrade) > 0 && bytes.Compare(bytes.ToLower(upgrade), websocketUpgrade) == 0 {
		log.LogError(reqData.String(), string(uri.Path()), errors.New("websocket not supported"))
		resp.SetStatusCode(http.StatusBadRequest)
		return
	}
	var backendDuration time.Duration
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
		}
	}
	isDebug := len(req.Header.Peek("X-Debug-Router")) > 0
	req.Header.Del("X-Debug-Router")

	if dstHost == "" {
		resp.SetStatusCode(http.StatusBadRequest)
		resp.SetBody(noRouteResponseContent)
		rp.debugHeaders(resp, reqData, isDebug)
		endErr := rp.Router.EndRequest(reqData, false, logEntry)
		if endErr != nil {
			log.LogError(reqData.String(), string(uri.Path()), endErr)
		}
		return
	}
	if rp.RequestIDHeader != "" && len(req.Header.Peek(rp.RequestIDHeader)) == 0 {
		unparsedID, err := uuid.NewV4()
		if err == nil {
			req.Header.Set(rp.RequestIDHeader, unparsedID.String())
		} else {
			log.LogError(reqData.String(), string(uri.Path()), fmt.Errorf("unable to generate request id: %s", err))
		}
	}
	hostOnly, _, _ := net.SplitHostPort(dstHost)
	if hostOnly == "" {
		hostOnly = dstHost
	}
	isIP := net.ParseIP(hostOnly) != nil
	if !isIP {
		req.Header.SetBytesV("X-Host", uri.Host())
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
		log.LogError(reqData.String(), string(uri.Path()), err)
	}
	rp.debugHeaders(resp, reqData, isDebug)
	endErr := rp.Router.EndRequest(reqData, markAsDead, logEntry)
	if endErr != nil {
		log.LogError(reqData.String(), string(uri.Path()), endErr)
	}
}
