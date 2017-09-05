// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gopkg.in/redis.v3"
)

type redisBackend struct {
	readClient  *redis.Client
	writeClient *redis.Client
	monitor     *redisMonitor
}

type RedisOptions struct {
	Network       string
	Host          string
	Port          int
	SentinelAddrs string
	SentinelName  string
	Password      string
	DB            int
}

func (opts RedisOptions) Client() (*redis.Client, error) {
	if opts.SentinelAddrs == "" {
		if opts.Host == "" {
			opts.Host = "127.0.0.1"
		}
		if opts.Port == 0 {
			opts.Port = 6379
		}
		var addr string
		if opts.Network == "unix" {
			addr = opts.Host
		} else {
			addr = fmt.Sprintf("%s:%d", opts.Host, opts.Port)
		}
		return redis.NewClient(&redis.Options{
			Network:      opts.Network,
			Addr:         addr,
			Password:     opts.Password,
			DB:           int64(opts.DB),
			MaxRetries:   maxRetries,
			DialTimeout:  dialTimeout,
			ReadTimeout:  readTimeout,
			WriteTimeout: writeTimeout,
			PoolSize:     poolSize,
			PoolTimeout:  poolTimeout,
			IdleTimeout:  idleTimeout,
		}), nil
	}
	addrs := strings.Split(opts.SentinelAddrs, ",")
	for i := range addrs {
		addrs[i] = strings.TrimSpace(addrs[i])
		if addrs[i] == "" {
			return nil, errors.New("redis sentinel addrs cannot be empty")
		}
	}
	if opts.SentinelName == "" {
		return nil, errors.New("redis sentinel name cannot be empty")
	}
	return redis.NewFailoverClient(&redis.FailoverOptions{
		MasterName:    opts.SentinelName,
		SentinelAddrs: addrs,
		Password:      opts.Password,
		DB:            int64(opts.DB),
		MaxRetries:    maxRetries,
		DialTimeout:   dialTimeout,
		ReadTimeout:   readTimeout,
		WriteTimeout:  writeTimeout,
		PoolSize:      poolSize,
		PoolTimeout:   poolTimeout,
		IdleTimeout:   idleTimeout,
	}), nil
}

const (
	dialTimeout  = time.Second
	readTimeout  = time.Second
	writeTimeout = time.Second
	poolTimeout  = time.Second
	poolSize     = 1000
	idleTimeout  = time.Minute
	maxRetries   = 1
)

func NewRedisBackend(readOpts, writeOpts RedisOptions) (RoutesBackend, error) {
	rClient, err := readOpts.Client()
	if err != nil {
		return nil, err
	}
	err = rClient.Ping().Err()
	if err != nil {
		return nil, err
	}
	wClient, err := writeOpts.Client()
	if err != nil {
		return nil, err
	}
	err = wClient.Ping().Err()
	if err != nil {
		return nil, err
	}
	return &redisBackend{
		readClient:  rClient,
		writeClient: wClient,
	}, nil
}

func (b *redisBackend) Backends(host string) (string, []string, map[int]struct{}, error) {
	pipe := b.readClient.Pipeline()
	defer pipe.Close()
	rangeVal := pipe.LRange("frontend:"+host, 0, -1)
	membersVal := pipe.SMembers("dead:" + host)
	_, err := pipe.Exec()
	if err != nil {
		return "", nil, nil, err
	}
	deadMap := map[int]struct{}{}
	for _, item := range membersVal.Val() {
		intVal, _ := strconv.ParseInt(item, 10, 32)
		deadMap[int(intVal)] = struct{}{}
	}
	backends := rangeVal.Val()
	if len(backends) < 2 {
		return "", nil, nil, ErrNoBackends
	}
	return host, backends[1:], deadMap, nil
}

func (b *redisBackend) MarkDead(host string, backend string, backendIdx int, backendLen int, deadTTL int) error {
	pipe := b.writeClient.Pipeline()
	defer pipe.Close()
	deadKey := "dead:" + host
	pipe.SAdd(deadKey, strconv.Itoa(backendIdx))
	pipe.Expire(deadKey, time.Duration(deadTTL)*time.Second)
	_, err := pipe.Exec()
	if err != nil {
		return err
	}
	deadMsg := fmt.Sprintf("%s;%s;%d;%d", host, backend, backendIdx, backendLen)
	return b.writeClient.Publish("dead", deadMsg).Err()
}

func (b *redisBackend) StartMonitor() error {
	var err error
	b.monitor, err = newRedisMonitor(b.writeClient)
	return err
}

func (b *redisBackend) StopMonitor() {
	if b.monitor != nil {
		b.monitor.stop()
	}
}
