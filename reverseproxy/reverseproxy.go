// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reverseproxy

import (
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/edukorg/planb/log"
)

var (
	noRouteResponseContent = []byte("no such route")
	allBackendsDeadContent = []byte("all backends are dead")
	okResponse             = []byte("OK")
	websocketUpgrade       = []byte("websocket")

	ErrAllBackendsDead      = errors.New(string(allBackendsDeadContent))
	ErrNoRegisteredBackends = errors.New("no backends registered for host")
)

type Router interface {
	Healthcheck() error
	ChooseBackend(host string) (*RequestData, error)
	EndRequest(reqData *RequestData, isDead bool, fn func() *log.LogEntry) error
}

type ReverseProxy interface {
	Initialize(rpConfig ReverseProxyConfig) error
	Listen(net.Listener, *tls.Config)
	Stop()
}

type ReverseProxyConfig struct {
	Router            Router
	FlushInterval     time.Duration
	DialTimeout       time.Duration
	RequestTimeout    time.Duration
	ReadTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	RequestIDHeader   string
}

type RequestData struct {
	BackendLen int
	Backend    string
	BackendIdx int
	BackendKey string
	Host       string
	StartTime  time.Time
	AllDead    bool
}

func (r *RequestData) logError(path string, rid string, err error) {
	log.ErrorLogger.MessageRaw(&log.LogEntry{
		Err: &log.ErrEntry{
			Backend: r.Backend,
			Host:    r.Host,
			Path:    path,
			Rid:     rid,
			Err:     err.Error(),
		},
	})
}
