// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reverseproxy

import (
	"time"

	"github.com/tsuru/planb/log"
)

var (
	noRouteResponseContent = []byte("no such route")
	okResponse             = []byte("OK")
	websocketUpgrade       = []byte("websocket")
)

type Router interface {
	ChooseBackend(host string) (*RequestData, error)
	EndRequest(reqData *RequestData, isDead bool, fn func() *log.LogEntry) error
}

type ReverseProxy interface {
	Initialize(rpConfig ReverseProxyConfig) (string, error)
	Listen()
	Stop()
}

type ReverseProxyConfig struct {
	Listen          string
	Router          Router
	FlushInterval   time.Duration
	DialTimeout     time.Duration
	RequestTimeout  time.Duration
	RequestIDHeader string
}

type RequestData struct {
	BackendLen int
	Backend    string
	BackendIdx int
	BackendKey string
	Host       string
	StartTime  time.Time
}

func (r *RequestData) String() string {
	back := r.Backend
	if back == "" {
		back = "?"
	}
	return r.Host + " -> " + back
}
