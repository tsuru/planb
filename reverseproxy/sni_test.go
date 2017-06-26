// // Copyright 2016 tsuru authors. All rights reserved.
// // Use of this source code is governed by a BSD-style
// // license that can be found in the LICENSE file.

package reverseproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"

	"gopkg.in/check.v1"
)

type SNI struct {
	factory   func() ReverseProxy
	logBuffer *bytes.Buffer
}

var (
	sniFactory = func() ReverseProxy { return &SNIReverseProxy{} }
	_          = check.Suite(&SNI{factory: sniFactory})
)

// TestRoundTripSNI test SNI reverseproxy using example.com domain
func (s *SNI) TestRoundTripSNI(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.Header().Set("X-Some-Rsp-Header", "rspvalue")
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := &SNIReverseProxy{}
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "X-RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "example.com"
	req.Header.Set("X-My-Header", "myvalue")
	cert, err := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
	c.Assert(err, check.IsNil)
	certpool := x509.NewCertPool()
	certpool.AddCert(cert)
	cli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:    certpool,
				ServerName: req.Host,
			},
		},
	}
	rsp, err := cli.Do(req)
	c.Assert(err, check.IsNil)
	defer rsp.Body.Close()
	c.Assert(rsp.StatusCode, check.Equals, 200)
	c.Assert(rsp.Header.Get("X-Some-Rsp-Header"), check.Equals, "rspvalue")
	data, err := ioutil.ReadAll(rsp.Body)
	c.Assert(err, check.IsNil)
	c.Assert(string(data), check.Equals, "my result")
	c.Assert(receivedReq.Host, check.Equals, "example.com")
	c.Assert(receivedReq.Header.Get("X-My-Header"), check.Equals, "myvalue")
	c.Assert(receivedReq.Header.Get("X-Host"), check.Equals, "")
	c.Assert(receivedReq.Header.Get("X-Forwarded-Host"), check.Equals, "")
	c.Assert(router.resultHost, check.Equals, "example.com")
}

// TestRoundTripSNIWithoutHostname test SNI reverseproxy using example.com domain without SNI
func (s *SNI) TestRoundTripSNIWithoutHostname(c *check.C) {
	var receivedReq *http.Request
	ts := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		receivedReq = req
		rw.Header().Set("X-Some-Rsp-Header", "rspvalue")
		rw.WriteHeader(200)
		rw.Write([]byte("my result"))
	}))
	defer ts.Close()
	router := &recoderRouter{dst: ts.URL}
	rp := &SNIReverseProxy{}
	err := rp.Initialize(ReverseProxyConfig{Router: router, RequestIDHeader: "X-RID"})
	c.Assert(err, check.IsNil)
	addr, listener := getFreeListener()
	go rp.Listen(listener)
	defer rp.Stop()
	defer listener.Close()
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/", addr), nil)
	c.Assert(err, check.IsNil)
	req.Host = "example.com"
	req.Header.Set("X-My-Header", "myvalue")
	cert, err := x509.ParseCertificate(ts.TLS.Certificates[0].Certificate[0])
	c.Assert(err, check.IsNil)
	certpool := x509.NewCertPool()
	certpool.AddCert(cert)
	cli := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certpool,
			},
		},
	}
	_, err = cli.Do(req)
	c.Assert(err, check.NotNil)
}
