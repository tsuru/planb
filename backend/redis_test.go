// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package backend

import (
	"testing"

	"gopkg.in/check.v1"
	"gopkg.in/redis.v3"
)

type S struct {
	redisConn *redis.Client
	be        RoutesBackend
}

var _ = check.Suite(&S{})

func Test(t *testing.T) {
	check.TestingT(t)
}

func (s *S) SetUpTest(c *check.C) {
	s.redisConn = redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379", DB: 1})
	val := s.redisConn.Keys("frontend:*").Val()
	val = append(val, s.redisConn.Keys("dead:*").Val()...)
	var err error
	if len(val) > 0 {
		err = s.redisConn.Del(val...).Err()
		c.Assert(err, check.IsNil)
	}
	s.be, err = NewRedisBackend(RedisOptions{DB: 1}, RedisOptions{DB: 1})
	c.Assert(err, check.IsNil)
}

func (s *S) TearDownTest(c *check.C) {
	s.redisConn.Close()
}

func (s *S) TestBackends(c *check.C) {
	err := s.redisConn.RPush("frontend:f1.com", "f1.com", "srv1", "srv2").Err()
	c.Assert(err, check.IsNil)
	key, backends, deadMap, err := s.be.Backends("f1.com")
	c.Assert(err, check.IsNil)
	c.Assert(key, check.Equals, "f1.com")
	c.Assert(backends, check.DeepEquals, []string{"srv1", "srv2"})
	c.Assert(deadMap, check.DeepEquals, map[int]struct{}{})
}

func (s *S) TestBackendsIgnoresName(c *check.C) {
	err := s.redisConn.RPush("frontend:f1.com", "xxxxxxx", "srv1", "srv2").Err()
	c.Assert(err, check.IsNil)
	key, backends, deadMap, err := s.be.Backends("f1.com")
	c.Assert(err, check.IsNil)
	c.Assert(key, check.Equals, "f1.com")
	c.Assert(backends, check.DeepEquals, []string{"srv1", "srv2"})
	c.Assert(deadMap, check.DeepEquals, map[int]struct{}{})
}

func (s *S) TestBackendsWithDead(c *check.C) {
	err := s.redisConn.RPush("frontend:f1.com", "xxxxxxx", "srv1", "srv2").Err()
	c.Assert(err, check.IsNil)
	err = s.be.MarkDead("f1.com", "srv1", 0, 2, 30)
	c.Assert(err, check.IsNil)
	err = s.be.MarkDead("f1.com", "srv2", 1, 2, 30)
	c.Assert(err, check.IsNil)
	key, backends, deadMap, err := s.be.Backends("f1.com")
	c.Assert(err, check.IsNil)
	c.Assert(key, check.Equals, "f1.com")
	c.Assert(backends, check.DeepEquals, []string{"srv1", "srv2"})
	c.Assert(deadMap, check.DeepEquals, map[int]struct{}{0: {}, 1: {}})
}

func (s *S) TestMarkDead(c *check.C) {
	pubsub, err := s.redisConn.Subscribe("dead")
	c.Assert(err, check.IsNil)
	err = s.be.MarkDead("f1.com", "url1", 0, 2, 30)
	c.Assert(err, check.IsNil)
	members, err := s.redisConn.SMembers("dead:f1.com").Result()
	c.Assert(err, check.IsNil)
	c.Assert(members, check.DeepEquals, []string{"0"})
	msg, err := pubsub.ReceiveMessage()
	c.Assert(err, check.IsNil)
	c.Assert(msg.Payload, check.Equals, "f1.com;url1;0;2")
}
