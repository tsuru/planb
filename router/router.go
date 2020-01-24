// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/golang-lru"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/edukorg/planb/backend"
	"github.com/edukorg/planb/log"
	"github.com/edukorg/planb/reverseproxy"
)

var (
	cacheTTLExpires = 2 * time.Second

	markedDeadCount = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "planb",
		Subsystem: "router",
		Name:      "backend_markdead_total",
		Help:      "The total number of backend mark dead occurencies.",
	})
)

type Router struct {
	LogPath        string
	DeadBackendTTL int
	Backend        backend.RoutesBackend
	CacheEnabled   bool
	logger         *log.Logger
	rrMutex        sync.RWMutex
	roundRobin     map[string]*uint32
	cache          *lru.Cache
}

type backendSet struct {
	id       string
	backends []string
	dead     map[int]struct{}
	expires  time.Time
}

func init() {
	prometheus.MustRegister(markedDeadCount)
}

func (s *backendSet) Expired() bool {
	return time.Now().After(s.expires)
}

func (router *Router) Init() error {
	var err error
	if router.Backend == nil {
		var be backend.RoutesBackend
		be, err = backend.NewRedisBackend(backend.RedisOptions{}, backend.RedisOptions{})
		if err != nil {
			return err
		}
		router.Backend = be
	}
	if router.LogPath == "" {
		router.LogPath = "none"
	}
	if router.logger == nil && router.LogPath != "none" {
		router.logger, err = log.NewFileLogger(router.LogPath)
		if err != nil {
			return err
		}
	}
	if router.DeadBackendTTL == 0 {
		router.DeadBackendTTL = 30
	}
	if router.CacheEnabled && router.cache == nil {
		router.cache, err = lru.New(100)
		if err != nil {
			return err
		}
	}
	router.roundRobin = make(map[string]*uint32)
	return nil
}

func (router *Router) ChooseBackend(host string) (*reverseproxy.RequestData, error) {
	reqData := &reverseproxy.RequestData{
		StartTime: time.Now(),
		Host:      host,
	}
	set, err := router.getBackends(host)
	if err == reverseproxy.ErrNoRegisteredBackends {
		noPortHost, _, _ := net.SplitHostPort(host)
		if noPortHost != "" {
			reqData.Host = noPortHost
			set, err = router.getBackends(noPortHost)
		}
	}
	if err != nil {
		return reqData, err
	}
	reqData.BackendKey = set.id
	reqData.BackendLen = len(set.backends)
	router.rrMutex.RLock()
	roundRobin := router.roundRobin[host]
	if roundRobin == nil {
		router.rrMutex.RUnlock()
		router.rrMutex.Lock()
		roundRobin = router.roundRobin[host]
		if roundRobin == nil {
			roundRobin = new(uint32)
			router.roundRobin[host] = roundRobin
		}
		router.rrMutex.Unlock()
	} else {
		router.rrMutex.RUnlock()
	}
	// We always add, it will eventually overflow to zero which is fine.
	initialNumber := atomic.AddUint32(roundRobin, 1)
	initialNumber = (initialNumber - 1) % uint32(reqData.BackendLen)
	toUseNumber := -1
	for chosenNumber := initialNumber; ; {
		_, isDead := set.dead[int(chosenNumber)]
		if !isDead {
			toUseNumber = int(chosenNumber)
			break
		}
		chosenNumber = (chosenNumber + 1) % uint32(reqData.BackendLen)
		if chosenNumber == initialNumber {
			break
		}
	}
	if toUseNumber == -1 {
		return reqData, reverseproxy.ErrAllBackendsDead
	}
	reqData.BackendIdx = toUseNumber
	reqData.Backend = set.backends[toUseNumber]
	return reqData, nil
}

func (router *Router) EndRequest(reqData *reverseproxy.RequestData, isDead bool, fn func() *log.LogEntry) error {
	var markErr error
	if isDead {
		markedDeadCount.Inc()
		markErr = router.Backend.MarkDead(reqData.Host, reqData.Backend, reqData.BackendIdx, reqData.BackendLen, router.DeadBackendTTL)
	}
	if router.logger != nil && fn != nil {
		router.logger.MessageRaw(fn())
	}
	return markErr
}

func (router *Router) Stop() {
	if router.logger != nil {
		router.logger.Stop()
	}
}

func (router *Router) Healthcheck() error {
	return router.Backend.Healthcheck()
}

func (router *Router) getBackends(host string) (*backendSet, error) {
	if router.cache != nil {
		if data, ok := router.cache.Get(host); ok {
			set := data.(backendSet)
			if !set.Expired() {
				return &set, nil
			}
		}
	}
	var set backendSet
	var err error
	set.id, set.backends, set.dead, err = router.Backend.Backends(host)
	if err != nil {
		if err == backend.ErrNoBackends {
			return nil, reverseproxy.ErrNoRegisteredBackends
		}
		return nil, err
	}
	set.expires = time.Now().Add(cacheTTLExpires)
	if router.cache != nil {
		router.cache.Add(host, set)
	}
	return &set, nil
}
