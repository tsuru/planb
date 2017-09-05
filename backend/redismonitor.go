// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-redis/redis"
)

var (
	errBackendIdxNotFound = errors.New("backend not in backends list")
)

type redisMonitor struct {
	mu          sync.Mutex
	reserved    map[string]struct{}
	hostID      string
	quit        chan struct{}
	done        chan struct{}
	limiter     chan struct{}
	redisClient *redis.Client
	httpClient  *http.Client
}

func newRedisMonitor(redisClient *redis.Client) (*redisMonitor, error) {
	hostID, err := os.Hostname()
	if err != nil {
		return nil, err
	}
	mon := &redisMonitor{
		hostID:      hostID,
		quit:        make(chan struct{}),
		done:        make(chan struct{}),
		limiter:     make(chan struct{}, 5),
		reserved:    make(map[string]struct{}),
		redisClient: redisClient,
		httpClient: &http.Client{
			Transport: &http.Transport{
				Dial: (&net.Dialer{
					Timeout: 10 * time.Second,
				}).Dial,
				// Disable connections reuse for effective dial timeouts.
				DisableKeepAlives:   true,
				MaxIdleConnsPerHost: -1,
				TLSHandshakeTimeout: 10 * time.Second,
			},
			Timeout: 15 * time.Second,
		},
	}
	err = mon.start()
	if err != nil {
		return nil, err
	}
	return mon, nil
}

func (b *redisMonitor) start() error {
	pubsub := b.redisClient.Subscribe("dead")
	go b.loop(pubsub)
	return nil
}

func (b *redisMonitor) loop(pubsub *redis.PubSub) {
	wg := sync.WaitGroup{}
	defer close(b.done)
	defer wg.Wait()
	defer pubsub.Close()
	msgCh := make(chan string)
	for {
		go func() {
			msg, _ := pubsub.ReceiveMessage()
			if msg == nil {
				msgCh <- ""
			} else {
				msgCh <- msg.Payload
			}
		}()
		select {
		case <-b.quit:
			return
		case msg := <-msgCh:
			if msg == "" {
				continue
			}
			wg.Add(1)
			go func(msg string) {
				defer wg.Done()
				b.watch(msg)
			}(msg)
		}
	}
}

func (b *redisMonitor) reserve(host, backend string) bool {
	key := "dead:" + host + ":" + backend
	reserved := false
	err := b.redisClient.Watch(func(tx *redis.Tx) error {
		watchKey := tx.Get(key).Val()
		if watchKey != "" && watchKey != b.hostID {
			return nil
		}
		_, txErr := tx.Pipelined(func(pipe redis.Pipeliner) error {
			pipe.Set(key, b.hostID, 30*time.Second)
			return nil
		})
		reserved = txErr != redis.TxFailedErr
		return nil
	}, key)
	if err != nil {
		return false
	}
	return reserved
}

func (b *redisMonitor) free(host, backend string) {
	key := "dead:" + host + ":" + backend
	b.redisClient.Del(key)
}

func (b *redisMonitor) watch(msg string) {
	parts := strings.Split(msg, ";")
	if len(parts) != 4 {
		return
	}
	host := parts[0]
	backend := parts[1]
	localKey := host + "-" + backend
	b.mu.Lock()
	if _, ok := b.reserved[localKey]; ok {
		b.mu.Unlock()
		return
	}
	b.reserved[localKey] = struct{}{}
	b.mu.Unlock()
	defer func() {
		b.mu.Lock()
		delete(b.reserved, localKey)
		b.mu.Unlock()
	}()
	if !b.reserve(host, backend) {
		return
	}
out:
	for {
		select {
		case <-b.quit:
			break out
		case <-time.After(time.Second):
		}
		b.limiter <- struct{}{}
		if !b.reserve(host, backend) {
			<-b.limiter
			return
		}
		isOk := b.check(host, backend)
		err := b.updateDead(host, backend, isOk)
		<-b.limiter
		if (err == nil && isOk) || err == errBackendIdxNotFound {
			break out
		}
	}
	b.free(host, backend)
}

func (b *redisMonitor) updateDead(host, backend string, isOk bool) error {
	frontend := "frontend:" + host
	return b.redisClient.Watch(func(tx *redis.Tx) error {
		entries, err := tx.LRange(frontend, 1, -1).Result()
		if err != nil {
			if err == redis.Nil {
				return errBackendIdxNotFound
			}
			return err
		}
		var idx string
		for i := range entries {
			if entries[i] == backend {
				idx = strconv.Itoa(i)
				break
			}
		}
		if idx == "" {
			return errBackendIdxNotFound
		}
		deadKey := "dead:" + host
		_, err = tx.Pipelined(func(pipe redis.Pipeliner) error {
			if isOk {
				pipe.SRem(deadKey, idx)
			} else {
				pipe.SAdd(deadKey, idx)
				pipe.Expire(deadKey, 30*time.Second)
			}
			return nil
		})
		return err
	}, frontend)
}

type hcData struct {
	path   string
	body   string
	status int
}

func (b *redisMonitor) hcData(host string) (hcData, error) {
	mapData, err := b.redisClient.HGetAll("healthcheck:" + host).Result()
	if err != nil && err != redis.Nil {
		return hcData{}, err
	}
	status, _ := strconv.Atoi(mapData["status"])
	return hcData{
		path:   mapData["path"],
		body:   mapData["body"],
		status: status,
	}, nil
}

func (b *redisMonitor) check(host, backend string) bool {
	hcData, err := b.hcData(host)
	if err != nil {
		return false
	}
	url := fmt.Sprintf("%s/%s", backend, strings.TrimLeft(hcData.path, "/"))
	if !strings.HasPrefix(url, "http") {
		url = "http://" + url
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	rsp, err := b.httpClient.Do(req)
	if err != nil {
		return false
	}
	defer rsp.Body.Close()
	if hcData.status != 0 && rsp.StatusCode != hcData.status {
		return false
	}
	if hcData.body != "" {
		data, _ := ioutil.ReadAll(rsp.Body)
		return strings.Contains(string(data), hcData.body)
	}
	return true
}

func (b *redisMonitor) stop() {
	if b.quit != nil {
		close(b.quit)
	}
	if b.done != nil {
		<-b.done
	}
}
