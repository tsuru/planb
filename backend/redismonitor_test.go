// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"time"

	"gopkg.in/check.v1"
	"gopkg.in/redis.v3"
)

func (s *S) TestStartMonitorNotDead(c *check.C) {
	var s1CallCount, s2CallCount int32
	s1 := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&s1CallCount, 1)
		rw.WriteHeader(200)
	}))
	s2 := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&s2CallCount, 1)
		rw.WriteHeader(200)
	}))
	err := s.redisConn.RPush("frontend:f1.com", "f1.com", s1.URL, s2.URL).Err()
	c.Assert(err, check.IsNil)
	err = s.be.StartMonitor()
	c.Assert(err, check.IsNil)
	err = s.be.MarkDead("f1.com", s1.URL, 0, 2, 30)
	c.Assert(err, check.IsNil)
	incCh := make(chan bool)
	go func() {
		for {
			if atomic.LoadInt32(&s1CallCount) > 0 {
				incCh <- true
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	select {
	case <-incCh:
	case <-time.After(10 * time.Second):
		c.Fatal("timeout waiting for server call")
	}
	s.be.StopMonitor()
	c.Assert(atomic.LoadInt32(&s1CallCount), check.Equals, int32(1))
	c.Assert(atomic.LoadInt32(&s2CallCount), check.Equals, int32(0))
	members, err := s.redisConn.SMembers("dead:f1.com").Result()
	c.Assert(err, check.IsNil)
	c.Assert(members, check.DeepEquals, []string{})
	val, err := s.redisConn.Get("dead:f1.com:" + s1.URL).Result()
	c.Assert(err, check.Equals, redis.Nil)
	c.Assert(val, check.Equals, "")
}

func (s *S) TestStartMonitorDeadAndBack(c *check.C) {
	var s1CallCount, s2CallCount int32
	rsp := int32(500)
	s1 := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&s1CallCount, 1)
		rw.WriteHeader(int(atomic.LoadInt32(&rsp)))
	}))
	s2 := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&s2CallCount, 1)
		rw.WriteHeader(200)
	}))
	err := s.redisConn.RPush("frontend:f1.com", "f1.com", s1.URL, s2.URL).Err()
	c.Assert(err, check.IsNil)
	err = s.redisConn.HSet("healthcheck:f1.com", "status", "200").Err()
	c.Assert(err, check.IsNil)
	err = s.be.StartMonitor()
	c.Assert(err, check.IsNil)
	err = s.be.MarkDead("f1.com", s1.URL, 0, 2, 30)
	c.Assert(err, check.IsNil)
	incCh := make(chan bool)
	go func() {
		for {
			if atomic.LoadInt32(&s1CallCount) > 0 {
				incCh <- true
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	select {
	case <-incCh:
	case <-time.After(10 * time.Second):
		c.Fatal("timeout waiting for server call")
	}
	c.Assert(atomic.LoadInt32(&s1CallCount) > int32(0), check.Equals, true)
	c.Assert(atomic.LoadInt32(&s2CallCount), check.Equals, int32(0))
	members, err := s.redisConn.SMembers("dead:f1.com").Result()
	c.Assert(err, check.IsNil)
	c.Assert(members, check.DeepEquals, []string{"0"})
	val, err := s.redisConn.Get("dead:f1.com:" + s1.URL).Result()
	c.Assert(err, check.IsNil)
	hostname, _ := os.Hostname()
	c.Assert(val, check.Equals, hostname)
	atomic.StoreInt32(&rsp, 200)
	aliveCh := make(chan bool)
	go func() {
		for {
			if s.redisConn.Get("dead:f1.com:"+s1.URL).Err() == redis.Nil {
				aliveCh <- true
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	select {
	case <-aliveCh:
	case <-time.After(10 * time.Second):
		c.Fatal("timeout waiting for alive call")
	}
	s.be.StopMonitor()
	members, err = s.redisConn.SMembers("dead:f1.com").Result()
	c.Assert(err, check.IsNil)
	c.Assert(members, check.DeepEquals, []string{})
}
