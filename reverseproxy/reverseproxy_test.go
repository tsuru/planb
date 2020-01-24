// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reverseproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/edukorg/planb/log"
	"golang.org/x/net/websocket"
	"gopkg.in/check.v1"
)

type S struct {
	factory   func() ReverseProxy
	logBuffer *bytes.Buffer
}

type noopRouter struct{ dst string }

func (r *noopRouter) Healthcheck() error {
	return nil
}

func (r *noopRouter) ChooseBackend(host string) (*RequestData, error) {
	return &RequestData{
		Backend:    r.dst,
		BackendIdx: 0,
		BackendKey: host,
		BackendLen: 1,
		Host:       host,
	}, nil
}

func (r *noopRouter) EndRequest(reqData *RequestData, isDead bool, fn func() *log.LogEntry) error {
	return nil
}

type recoderRouter struct {
	dst           string
	resultHost    string
	resultReqData *RequestData
	resultIsDead  bool
	logEntry      *log.LogEntry
	errChoose     error
	healthErr     error
}

func (r *recoderRouter) Healthcheck() error {
	return r.healthErr
}

func (r *recoderRouter) ChooseBackend(host string) (*RequestData, error) {
	r.resultHost = host
	return &RequestData{
		Backend:    r.dst,
		BackendIdx: 0,
		BackendKey: host,
		BackendLen: 1,
		Host:       host,
	}, r.errChoose
}

func (r *recoderRouter) EndRequest(reqData *RequestData, isDead bool, fn func() *log.LogEntry) error {
	r.resultReqData = reqData
	r.logEntry = fn()
	r.resultIsDead = isDead
	return nil
}

var (
	nativeFactory = func() ReverseProxy { return &NativeReverseProxy{} }
	fastFactory   = func() ReverseProxy { return &FastReverseProxy{} }
	_             = check.Suite(&S{factory: nativeFactory})
	_             = check.Suite(&S{factory: fastFactory})
)

func Test(t *testing.T) {
	check.TestingT(t)
}

func getFreeListener() (string, net.Listener) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		stdlog.Fatal(err)
	}
	return listener.Addr().String(), listener
}

type nopCloseWriter struct{ io.Writer }

func (nopCloseWriter) Close() error { return nil }

func (s *S) SetUpTest(c *check.C) {
	c.Logf("testing %T", s.factory())
	s.logBuffer = bytes.NewBuffer(nil)
	log.ErrorLogger = log.NewWriterLogger(nopCloseWriter{s.logBuffer})
}

func (s *S) TestRoundTrip(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.Header().Set("X-Some-Rsp-Header", "rspvalue")
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "X-RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	c.Assert(rsp.Header.Get("X-Some-Rsp-Header"), check.Equals, "rspvalue")
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	c.Assert(receivedReq.Host, check.Equals, "myhost.com")
	c.Assert(receivedReq.Header.Get("X-RID"), check.Not(check.Equals), "")
	delete(receivedReq.Header, "X-Rid")
	c.Assert(receivedReq.Header, check.DeepEquals, http.Header{
		"User-Agent":        []string{"Go-http-client/1.1"},
		"Accept-Encoding":   []string{"gzip"},
		"X-My-Header":       []string{"myvalue"},
		"X-Forwarded-For":   []string{"127.0.0.1"},
		"X-Forwarded-Proto": []string{"http"},
	})
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    ts.URL,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	le := router.logEntry
	c.Assert(le.Now.IsZero(), check.Equals, false)
	c.Assert(le.BackendDuration, check.Not(check.Equals), 0)
	c.Assert(le.TotalDuration, check.Not(check.Equals), 0)
	c.Assert(le.RequestID, check.Not(check.Equals), "")
	c.Assert(le.RemoteAddr, check.Matches, `127\.0\.0\.1:\d+`)
	le.Now = time.Time{}
	le.BackendDuration = 0
	le.TotalDuration = 0
	le.RequestID = ""
	le.RemoteAddr = ""
	c.Assert(le, check.DeepEquals, &log.LogEntry{
		BackendKey:      "myhost.com",
		Method:          "GET",
		Path:            "/",
		Proto:           "HTTP/1.1",
		Referer:         "",
		UserAgent:       "Go-http-client/1.1",
		RequestIDHeader: "X-RID",
		StatusCode:      200,
		ContentLength:   9,
		ForwardedFor:    "",
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func (s *S) TestRoundTripForwarded(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.Header().Set("X-Some-Rsp-Header", "rspvalue")
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "X-RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	req.Header.Set("X-Forwarded-For", "10.9.8.7")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	c.Assert(rsp.Header.Get("X-Some-Rsp-Header"), check.Equals, "rspvalue")
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	c.Assert(receivedReq.Host, check.Equals, "myhost.com")
	c.Assert(receivedReq.Header.Get("X-RID"), check.Not(check.Equals), "")
	delete(receivedReq.Header, "X-Rid")
	c.Assert(receivedReq.Header, check.DeepEquals, http.Header{
		"User-Agent":        []string{"Go-http-client/1.1"},
		"Accept-Encoding":   []string{"gzip"},
		"X-My-Header":       []string{"myvalue"},
		"X-Forwarded-For":   []string{"10.9.8.7, 127.0.0.1"},
		"X-Forwarded-Proto": []string{"http"},
	})
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    ts.URL,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	le := router.logEntry
	c.Assert(le.Now.IsZero(), check.Equals, false)
	c.Assert(le.BackendDuration, check.Not(check.Equals), 0)
	c.Assert(le.TotalDuration, check.Not(check.Equals), 0)
	c.Assert(le.RequestID, check.Not(check.Equals), "")
	c.Assert(le.RemoteAddr, check.Matches, `127\.0\.0\.1:\d+`)
	le.Now = time.Time{}
	le.BackendDuration = 0
	le.TotalDuration = 0
	le.RequestID = ""
	le.RemoteAddr = ""
	c.Assert(le, check.DeepEquals, &log.LogEntry{
		BackendKey:      "myhost.com",
		Method:          "GET",
		Path:            "/",
		Proto:           "HTTP/1.1",
		Referer:         "",
		UserAgent:       "Go-http-client/1.1",
		RequestIDHeader: "X-RID",
		StatusCode:      200,
		ContentLength:   9,
		ForwardedFor:    "10.9.8.7",
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func (s *S) TestRoundTripRedirect(c *check.C) {
	var receivedReqs []*http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReqs = append(receivedReqs, req)
		if req.URL.Path == "/auth" {
			rw.Write([]byte("redirected"))
			return
		}
		http.Redirect(rw, req, "/auth", http.StatusFound)
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "X-RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	client := http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			req.Host = "myhost.com"
			req.Header.Set("X-My-Header", "myvalue")
			return nil
		},
	}
	rsp, err := client.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, http.StatusOK)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "redirected")
	c.Assert(receivedReqs, check.HasLen, 2)
	c.Assert(receivedReqs[0].Host, check.Equals, "myhost.com")
	c.Assert(receivedReqs[0].Header.Get("X-My-Header"), check.Equals, "myvalue")
	c.Assert(receivedReqs[0].Header.Get("X-Host"), check.Equals, "")
	c.Assert(receivedReqs[0].Header.Get("X-Forwarded-Host"), check.Equals, "")
	c.Assert(receivedReqs[0].Header.Get("X-RID"), check.Not(check.Equals), "")
	c.Assert(receivedReqs[1].Host, check.Equals, "myhost.com")
	c.Assert(receivedReqs[1].Header.Get("X-My-Header"), check.Equals, "myvalue")
	c.Assert(receivedReqs[1].Header.Get("X-Host"), check.Equals, "")
	c.Assert(receivedReqs[1].Header.Get("X-Forwarded-Host"), check.Equals, "")
	c.Assert(receivedReqs[1].Header.Get("X-RID"), check.Not(check.Equals), "")
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    ts.URL,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func (s *S) TestRoundTripWithExistingRequestID(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "X-Rid"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	req.Header.Set("X-RID", "abc")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	c.Assert(receivedReq.Host, check.Equals, "myhost.com")
	c.Assert(receivedReq.Header.Get("X-My-Header"), check.Equals, "myvalue")
	c.Assert(receivedReq.Header.Get("X-Host"), check.Equals, "")
	c.Assert(receivedReq.Header.Get("X-Forwarded-Host"), check.Equals, "")
	c.Assert(receivedReq.Header.Get("X-Rid"), check.Equals, "abc")
}

func (s *S) TestRoundTripHostDestination(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	dstUrl, err := url.Parse(ts.URL)
	c.Assert(err, check.IsNil)
	_, port, _ := net.SplitHostPort(dstUrl.Host)
	c.Assert(port, check.Not(check.Equals), "")
	router := &recoderRouter{dst: fmt.Sprintf("http://localhost:%s", port)}
	rp := s.factory()
	err = rp.Initialize(ReverseProxyConfig{Router: router})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	c.Assert(receivedReq.Host, check.Equals, "localhost")
	c.Assert(receivedReq.Header, check.DeepEquals, http.Header{
		"User-Agent":        []string{"Go-http-client/1.1"},
		"Accept-Encoding":   []string{"gzip"},
		"X-My-Header":       []string{"myvalue"},
		"X-Forwarded-For":   []string{"127.0.0.1"},
		"X-Forwarded-Proto": []string{"http"},
		"X-Forwarded-Host":  []string{"myhost.com"},
		"X-Host":            []string{"myhost.com"},
	})
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    router.dst,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func getFreeTLSListener() (string, net.Listener, *http.Client, *tls.Config) {
	localhostCert := []byte(`-----BEGIN CERTIFICATE-----
MIICEzCCAXygAwIBAgIQMIMChMLGrR+QvmQvpwAU6zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQKEwdBY21lIENvMCAXDTcwMDEwMTAwMDAwMFoYDzIwODQwMTI5MTYw
MDAwWjASMRAwDgYDVQQKEwdBY21lIENvMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCB
iQKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9SjY1bIw4
iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZBl2+XsDul
rKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQABo2gwZjAO
BgNVHQ8BAf8EBAMCAqQwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUw
AwEB/zAuBgNVHREEJzAlggtleGFtcGxlLmNvbYcEfwAAAYcQAAAAAAAAAAAAAAAA
AAAAATANBgkqhkiG9w0BAQsFAAOBgQCEcetwO59EWk7WiJsG4x8SY+UIAA+flUI9
tyC4lNhbcF2Idq9greZwbYCqTTTr2XiRNSMLCOjKyI7ukPoPjo16ocHj+P3vZGfs
h1fIw3cSS2OolhloGw/XM6RWPWtPAlGykKLciQrBru5NAPvCMsb/I1DAceTiotQM
fblo6RBxUQ==
-----END CERTIFICATE-----`)
	localhostKey := []byte(`-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDuLnQAI3mDgey3VBzWnB2L39JUU4txjeVE6myuDqkM/uGlfjb9
SjY1bIw4iA5sBBZzHi3z0h1YV8QPuxEbi4nW91IJm2gsvvZhIrCHS3l6afab4pZB
l2+XsDulrKBxKKtD1rGxlG4LjncdabFn9gvLZad2bSysqz/qTAUStTvqJQIDAQAB
AoGAGRzwwir7XvBOAy5tM/uV6e+Zf6anZzus1s1Y1ClbjbE6HXbnWWF/wbZGOpet
3Zm4vD6MXc7jpTLryzTQIvVdfQbRc6+MUVeLKwZatTXtdZrhu+Jk7hx0nTPy8Jcb
uJqFk541aEw+mMogY/xEcfbWd6IOkp+4xqjlFLBEDytgbIECQQDvH/E6nk+hgN4H
qzzVtxxr397vWrjrIgPbJpQvBsafG7b0dA4AFjwVbFLmQcj2PprIMmPcQrooz8vp
jy4SHEg1AkEA/v13/5M47K9vCxmb8QeD/asydfsgS5TeuNi8DoUBEmiSJwma7FXY
fFUtxuvL7XvjwjN5B30pNEbc6Iuyt7y4MQJBAIt21su4b3sjXNueLKH85Q+phy2U
fQtuUE9txblTu14q3N7gHRZB4ZMhFYyDy8CKrN2cPg/Fvyt0Xlp/DoCzjA0CQQDU
y2ptGsuSmgUtWj3NM9xuwYPm+Z/F84K6+ARYiZ6PYj013sovGKUFfYAqVXVlxtIX
qyUBnu3X9ps8ZfjLZO7BAkEAlT4R5Yl6cGhaJQYZHOde3JEMhNRcVFMO8dJDaFeo
f9Oeos0UUothgiDktdQHxdNEwLjQf7lJJBzV+5OtwswCWA==
-----END RSA PRIVATE KEY-----`)
	cert, err := tls.X509KeyPair(localhostCert, localhostKey)
	if err != nil {
		stdlog.Fatal(err)
	}
	tlsConfig := &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		Certificates: []tls.Certificate{cert},
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		stdlog.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		stdlog.Fatal(err)
	}
	certpool := x509.NewCertPool()
	certpool.AddCert(certificate)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		},
	}
	return listener.Addr().String(), tls.NewListener(listener, tlsConfig), client, tlsConfig
}

func (s *S) TestRoundTripTLSListener(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router})
	c.Assert(err, check.IsNil)
	addr, listener, client, tlsConfig := getFreeTLSListener()
	go rp.Listen(listener, tlsConfig)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := client.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	c.Assert(receivedReq.Host, check.Equals, "myhost.com")
	c.Assert(receivedReq.Header, check.DeepEquals, http.Header{
		"User-Agent":        []string{"Go-http-client/1.1"},
		"Accept-Encoding":   []string{"gzip"},
		"X-My-Header":       []string{"myvalue"},
		"X-Forwarded-For":   []string{"127.0.0.1"},
		"X-Forwarded-Proto": []string{"https"},
	})
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    router.dst,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func (s *S) TestRoundTripWithError(c *check.C) {
	router := &recoderRouter{dst: "http://127.0.0.1:23771"}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 503)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "")
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    router.dst,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	c.Assert(router.resultIsDead, check.Equals, true)
}

func (s *S) TestRoundTripWithErrNoRegisteredBackends(c *check.C) {
	router := &recoderRouter{errChoose: ErrNoRegisteredBackends}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 400)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "no such route")
	c.Assert(router.logEntry.RequestID, check.Not(check.Equals), "")
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    router.dst,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func (s *S) TestRoundTripWithErrAllBackendsDead(c *check.C) {
	router := &recoderRouter{errChoose: ErrAllBackendsDead}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 503)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "all backends are dead")
	c.Assert(router.logEntry.RequestID, check.Not(check.Equals), "")
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    router.dst,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func (s *S) TestRoundTripWithErrOther(c *check.C) {
	router := &recoderRouter{errChoose: errors.New("other error")}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-My-Header", "myvalue")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 503)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "")
	c.Assert(router.logEntry.RequestID, check.Not(check.Equals), "")
	c.Assert(router.resultHost, check.Equals, "myhost.com")
	c.Assert(router.resultReqData, check.DeepEquals, &RequestData{
		Backend:    router.dst,
		BackendIdx: 0,
		BackendKey: "myhost.com",
		BackendLen: 1,
		Host:       "myhost.com",
	})
	c.Assert(router.resultIsDead, check.Equals, false)
}

func (s *S) TestRoundTripDebugHeaders(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-Debug-Router", "1")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	c.Assert(rsp.Header.Get("X-Debug-Backend-Url"), check.Equals, ts.URL)
	c.Assert(rsp.Header.Get("X-Debug-Backend-Id"), check.Equals, "0")
	c.Assert(rsp.Header.Get("X-Debug-Frontend-Key"), check.Equals, "myhost.com")
	c.Assert(receivedReq.Header.Get("X-Debug-Router"), check.Equals, "")
}

func (s *S) TestRoundTripNoRouteDebugHeaders(c *check.C) {
	router := &recoderRouter{dst: ""}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("X-Debug-Router", "1")
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	c.Assert(rsp.StatusCode, check.Equals, http.StatusBadRequest)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(data, check.DeepEquals, noRouteResponseBody.value)
}

func (s *S) TestRoundTripNoRoute(c *check.C) {
	router := &recoderRouter{dst: ""}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	c.Assert(rsp.StatusCode, check.Equals, http.StatusBadRequest)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(data, check.DeepEquals, noRouteResponseBody.value)
}

func (s *S) TestRoundTripStress(c *check.C) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &noopRouter{dst: ts.URL}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router, ReadTimeout: time.Second})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	u := fmt.Sprintf("http://%s/", addr)
	wg := sync.WaitGroup{}
	nConnections := 50
	for i := 0; i < nConnections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("GET", u, nil)
			c.Assert(err, check.IsNil)
			req.Host = "myhost.com"
			rsp, err := http.DefaultClient.Do(req)
			c.Assert(err, check.IsNil)
			defer rsp.Body.Close()
			c.Assert(rsp.StatusCode, check.Equals, 200)
		}()
	}
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Minute):
		c.Fatal("timeout out after 1 minute")
	}
}

func (s *S) TestRoundTripStressWithTimeoutBackend(c *check.C) {
	router := &noopRouter{dst: "http://127.0.0.1:23771"}
	rp := s.factory()
	err := rp.Initialize(ReverseProxyConfig{Router: router, ReadTimeout: time.Second})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	u := fmt.Sprintf("http://%s/", addr)
	wg := sync.WaitGroup{}
	nConnections := 50
	for i := 0; i < nConnections; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, err := http.NewRequest("GET", u, nil)
			c.Assert(err, check.IsNil)
			req.Host = "myhost.com"
			rsp, err := http.DefaultClient.Do(req)
			c.Assert(err, check.IsNil)
			defer rsp.Body.Close()
			c.Assert(rsp.StatusCode, check.Equals, 503)
		}()
	}
	done := make(chan bool)
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Minute):
		c.Fatal("timeout out after 1 minute")
	}
}

func (s *S) TestRoundTripPing(c *check.C) {
	rp := s.factory()
	router := &noopRouter{}
	err := rp.Initialize(ReverseProxyConfig{Router: router})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "__ping__"
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "OK")
}

func (s *S) TestRoundTripPingFailingHC(c *check.C) {
	rp := s.factory()
	router := &recoderRouter{healthErr: errors.New("my hc err")}
	err := rp.Initialize(ReverseProxyConfig{Router: router})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "__ping__"
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, http.StatusInternalServerError)
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my hc err")
}

func (s *S) TestRoundTripStreamingRequest(c *check.C) {
	rp := s.factory()
	var receivedReq *http.Request
	msgCh := make(chan string)
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		flusher, ok := rw.(http.Flusher)
		c.Assert(ok, check.Equals, true)
		receivedReq = req
		rw.Write([]byte("wxyz"))
		flusher.Flush()
		for msg := range msgCh {
			rw.Write([]byte(msg))
			flusher.Flush()
		}
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}

	err := rp.Initialize(ReverseProxyConfig{
		Router:        router,
		FlushInterval: 100 * time.Millisecond,
	})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	defer close(msgCh)
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	req.Header.Set("Content-Encoding", "my/encoding")
	var rsp *http.Response
	select {
	case <-waitFor(func() {
		rsp, err = http.DefaultClient.Do(req)
		c.Assert(err, check.IsNil)
	}):
	case <-time.After(5 * time.Second):
		c.Fatal("timeout after 5 seconds waiting for server initial response")
	}
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	recv := func(msg string, send bool) {
		if send {
			msgCh <- msg
		}
		buf := make([]byte, len(msg))
		n, err := rsp.Body.Read(buf)
		c.Assert(err, check.IsNil)
		c.Assert(n, check.Equals, 4, check.Commentf("waiting for %s", msg))
		c.Assert(string(buf), check.Equals, msg)
	}
	select {
	case <-waitFor(func() { recv("wxyz", false) }):
	case <-time.After(5 * time.Second):
		c.Fatal("timeout after 5 seconds waiting for server message")
	}
	select {
	case <-waitFor(func() { recv("abcd", true) }):
	case <-time.After(5 * time.Second):
		c.Fatal("timeout after 5 seconds waiting for server message")
	}
	select {
	case <-waitFor(func() { recv("efjk", true) }):
	case <-time.After(5 * time.Second):
		c.Fatal("timeout after 5 seconds waiting for server message")
	}
	c.Assert(receivedReq.Host, check.Equals, "myhost.com")
	c.Assert(receivedReq.Header.Get("Content-Encoding"), check.Equals, "my/encoding")
}

func (s *S) TestRoundTripTimeout(c *check.C) {
	rp := s.factory()
	blk := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		<-blk
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	defer close(blk)
	router := &recoderRouter{dst: ts.URL}
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestTimeout: time.Second, RequestIDHeader: "RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 503)
	c.Assert(router.resultIsDead, check.Equals, false)
	log.ErrorLogger.Stop()
	c.Assert(s.logBuffer.String(), check.Matches, fmt.Sprintf(`(?s)ERROR in myhost.com -> %s - / - RID:.+? - request timeout after .+:.*`, ts.URL))
}

func (s *S) TestRoundTripTimeoutDial(c *check.C) {
	rp := s.factory()
	// Reserved TEST-NET IP should cause
	router := &recoderRouter{dst: "http://192.0.2.1:49151"}
	err := rp.Initialize(ReverseProxyConfig{Router: router, DialTimeout: time.Second, RequestTimeout: 10 * time.Second, RequestIDHeader: "RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("http://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "myhost.com"
	rsp, err := http.DefaultClient.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 503)
	c.Assert(router.resultIsDead, check.Equals, true)
	log.ErrorLogger.Stop()
	c.Assert(s.logBuffer.String(), check.Matches, `(?s)ERROR in myhost.com -> http://192.0.2.1:49151 - / - RID:.+? - dial timeout after .+:.*`)
}

func waitFor(fn func()) chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}

func (s *S) TestRoundTripWebSocket(c *check.C) {
	rp := s.factory()
	srv := httptest.NewServer(websocket.Handler(func(conn *websocket.Conn) {
		c.Assert(conn.Request().Header.Get("RID"), check.Not(check.Equals), "")
		conn.Write([]byte("server-" + conn.Request().URL.Path))
		buf := make([]byte, 5)
		conn.Read(buf)
		conn.Write(buf)
	}))
	defer srv.Close()
	router := &recoderRouter{dst: srv.URL}
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	dialWS := func() *websocket.Conn {
		config, dialErr := websocket.NewConfig("ws://myfrontend.com", "ws://localhost/")
		c.Assert(dialErr, check.IsNil)
		url, _ := url.Parse(fmt.Sprintf("http://%s/", addr))
		client, dialErr := net.Dial("tcp", url.Host)
		c.Assert(dialErr, check.IsNil)
		conn, dialErr := websocket.NewClient(config, client)
		c.Assert(dialErr, check.IsNil)
		return conn
	}
	msgBuf := make([]byte, 100)
	conn := dialWS()
	defer conn.Close()
	n, err := conn.Read(msgBuf)
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 8)
	c.Assert(string(msgBuf[:n]), check.Equals, "server-/")
	n, err = conn.Write([]byte("12345"))
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	n, err = conn.Read(msgBuf)
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	c.Assert(string(msgBuf[:n]), check.Equals, "12345")
	conn = dialWS()
	defer conn.Close()
	n, err = conn.Read(msgBuf)
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 8)
	c.Assert(string(msgBuf[:n]), check.Equals, "server-/")
	n, err = conn.Write([]byte("12345"))
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	n, err = conn.Read(msgBuf)
	c.Assert(err, check.IsNil)
	c.Assert(n, check.Equals, 5)
	c.Assert(string(msgBuf[:n]), check.Equals, "12345")
}

func baseBenchmarkServeHTTP(rp ReverseProxy, b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	err := rp.Initialize(ReverseProxyConfig{Router: &noopRouter{dst: srv.URL}, ReadTimeout: time.Second})
	if err != nil {
		b.Fatal(err)
	}
	addr, listener := getFreeListener()
	url := fmt.Sprintf("http://%s/", addr)
	go rp.Listen(listener, nil)
	defer rp.Stop()
	b.ResetTimer()
	cli := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1000,
		},
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request, _ := http.NewRequest("GET", url, nil)
			rsp, err := cli.Do(request)
			if rsp == nil || rsp.StatusCode != http.StatusOK {
				b.Fatalf("invalid response %#v: %s", rsp, err)
			}
			ioutil.ReadAll(rsp.Body)
			rsp.Body.Close()
		}
	})
	b.StopTimer()
}

func baseBenchmarkServeHTTPInvalidFrontends(rp ReverseProxy, b *testing.B) {
	addr, listener := getFreeListener()
	err := rp.Initialize(ReverseProxyConfig{Router: &noopRouter{}, ReadTimeout: time.Second})
	if err != nil {
		b.Fatal(err)
	}
	url := fmt.Sprintf("http://%s/", addr)
	go rp.Listen(listener, nil)
	defer rp.Stop()
	defer listener.Close()
	b.ResetTimer()
	cli := &http.Client{
		Transport: &http.Transport{
			MaxIdleConnsPerHost: 1000,
		},
	}
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			request, _ := http.NewRequest("GET", url, nil)
			rsp, err := cli.Do(request)
			if rsp == nil || rsp.StatusCode != http.StatusBadRequest {
				b.Fatalf("invalid response %#v: %s", rsp, err)
			}
			ioutil.ReadAll(rsp.Body)
			rsp.Body.Close()
		}
	})
	b.StopTimer()
}

func BenchmarkServeHTTP_Native(b *testing.B) {
	baseBenchmarkServeHTTP(nativeFactory(), b)
}

func BenchmarkServeHTTPInvalidFrontends_Native(b *testing.B) {
	baseBenchmarkServeHTTPInvalidFrontends(nativeFactory(), b)
}

func BenchmarkServeHTTP_Fast(b *testing.B) {
	baseBenchmarkServeHTTP(fastFactory(), b)
}

func BenchmarkServeHTTPInvalidFrontends_Fast(b *testing.B) {
	baseBenchmarkServeHTTPInvalidFrontends(fastFactory(), b)
}
