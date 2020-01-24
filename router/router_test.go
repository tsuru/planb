// Copyright 2016 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package router

import (
	"bytes"
	"sync"
	"testing"
	"time"

	"github.com/go-redis/redis"
	"github.com/edukorg/planb/log"
	"github.com/edukorg/planb/reverseproxy"
	"gopkg.in/check.v1"
)

type S struct {
	redis *redis.Client
}

var _ = check.Suite(&S{})

func Test(t *testing.T) {
	check.TestingT(t)
}

func clearKeys(r *redis.Client) error {
	val := r.Keys("frontend:*").Val()
	val = append(val, r.Keys("dead:*").Val()...)
	if len(val) > 0 {
		return r.Del(val...).Err()
	}
	return nil
}

func redisConn() (*redis.Client, error) {
	return redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379", DB: 0}), nil
}

func (s *S) SetUpTest(c *check.C) {
	var err error
	s.redis, err = redisConn()
	c.Assert(err, check.IsNil)
	err = clearKeys(s.redis)
	c.Assert(err, check.IsNil)
}

func (s *S) TearDownTest(c *check.C) {
	s.redis.Close()
}

func (s *S) TestInit(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	c.Assert(router.roundRobin, check.DeepEquals, map[string]*uint32{})
	c.Assert(router.logger, check.IsNil)
	c.Assert(router.cache, check.IsNil)
	c.Assert(router.Backend, check.NotNil)
}

func (s *S) TestInitCacheEnabled(c *check.C) {
	router := Router{CacheEnabled: true}
	err := router.Init()
	c.Assert(err, check.IsNil)
	c.Assert(router.roundRobin, check.DeepEquals, map[string]*uint32{})
	c.Assert(router.logger, check.IsNil)
	c.Assert(router.cache, check.NotNil)
	c.Assert(router.Backend, check.NotNil)
}

func (s *S) TestChooseBackend(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com", "myfrontend", "http://url1:123").Err()
	c.Assert(err, check.IsNil)
	reqData, err := router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.StartTime.IsZero(), check.Equals, false)
	reqData.StartTime = time.Time{}
	c.Assert(reqData, check.DeepEquals, &reverseproxy.RequestData{
		Backend:    "http://url1:123",
		BackendIdx: 0,
		BackendKey: "myfrontend.com",
		BackendLen: 1,
		Host:       "myfrontend.com",
	})
}

func (s *S) TestChooseBackendConsiderPort(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com:1234", "myfrontend", "http://url1:123").Err()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com", "myfrontend", "http://url2:123").Err()
	c.Assert(err, check.IsNil)
	reqData, err := router.ChooseBackend("myfrontend.com:1234")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.StartTime.IsZero(), check.Equals, false)
	reqData.StartTime = time.Time{}
	c.Assert(reqData, check.DeepEquals, &reverseproxy.RequestData{
		Backend:    "http://url1:123",
		BackendIdx: 0,
		BackendKey: "myfrontend.com:1234",
		BackendLen: 1,
		Host:       "myfrontend.com:1234",
	})
	reqData, err = router.ChooseBackend("myfrontend.com:9999")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.StartTime.IsZero(), check.Equals, false)
	reqData.StartTime = time.Time{}
	c.Assert(reqData, check.DeepEquals, &reverseproxy.RequestData{
		Backend:    "http://url2:123",
		BackendIdx: 0,
		BackendKey: "myfrontend.com",
		BackendLen: 1,
		Host:       "myfrontend.com",
	})
}

func (s *S) TestChooseBackendIgnorePort(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com", "myfrontend", "http://url1:123").Err()
	c.Assert(err, check.IsNil)
	reqData, err := router.ChooseBackend("myfrontend.com:80")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.StartTime.IsZero(), check.Equals, false)
	reqData.StartTime = time.Time{}
	c.Assert(reqData, check.DeepEquals, &reverseproxy.RequestData{
		Backend:    "http://url1:123",
		BackendIdx: 0,
		BackendKey: "myfrontend.com",
		BackendLen: 1,
		Host:       "myfrontend.com",
	})
}

func (s *S) TestChooseBackendNotFound(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	reqData, err := router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.Equals, reverseproxy.ErrNoRegisteredBackends)
	c.Assert(reqData.StartTime.IsZero(), check.Equals, false)
	reqData.StartTime = time.Time{}
	c.Assert(reqData, check.DeepEquals, &reverseproxy.RequestData{
		Backend:    "",
		BackendIdx: 0,
		BackendLen: 0,
		BackendKey: "",
		Host:       "myfrontend.com",
	})
}

func (s *S) TestChooseBackendNoBackends(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com", "myfrontend").Err()
	c.Assert(err, check.IsNil)
	reqData, err := router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.Equals, reverseproxy.ErrNoRegisteredBackends)
	c.Assert(reqData.StartTime.IsZero(), check.Equals, false)
	reqData.StartTime = time.Time{}
	c.Assert(reqData, check.DeepEquals, &reverseproxy.RequestData{
		Backend:    "",
		BackendIdx: 0,
		BackendLen: 0,
		BackendKey: "",
		Host:       "myfrontend.com",
	})
}

func (s *S) TestChooseBackendAllDead(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com", "myfrontend", "http://url1:123").Err()
	c.Assert(err, check.IsNil)
	err = s.redis.SAdd("dead:myfrontend.com", "0").Err()
	c.Assert(err, check.IsNil)
	reqData, err := router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.Equals, reverseproxy.ErrAllBackendsDead)
	c.Assert(reqData.StartTime.IsZero(), check.Equals, false)
	reqData.StartTime = time.Time{}
	c.Assert(reqData, check.DeepEquals, &reverseproxy.RequestData{
		Backend:    "",
		BackendIdx: 0,
		BackendLen: 1,
		BackendKey: "myfrontend.com",
		Host:       "myfrontend.com",
	})
}

func (s *S) TestChooseBackendRoundRobin(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com", "myfrontend", "http://url1:123", "http://url2:123", "http://url3:123").Err()
	c.Assert(err, check.IsNil)
	reqData, err := router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.StartTime.IsZero(), check.Equals, false)
	reqData.StartTime = time.Time{}
	c.Assert(reqData, check.DeepEquals, &reverseproxy.RequestData{
		Backend:    "http://url1:123",
		BackendIdx: 0,
		BackendKey: "myfrontend.com",
		BackendLen: 3,
		Host:       "myfrontend.com",
	})
	err = s.redis.RPush("frontend:myfrontend.com", "http://url4:123").Err()
	c.Assert(err, check.IsNil)
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url2:123")
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url3:123")
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url4:123")
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url1:123")
}

func (s *S) TestChooseBackendRoundRobinWithCache(c *check.C) {
	router := Router{CacheEnabled: true}
	err := router.Init()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com", "myfrontend", "http://url1:123", "http://url2:123", "http://url3:123").Err()
	c.Assert(err, check.IsNil)
	reqData, err := router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url1:123")
	err = s.redis.RPush("frontend:myfrontend.com", "http://url4:123").Err()
	c.Assert(err, check.IsNil)
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url2:123")
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url3:123")
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url1:123")
	time.Sleep(cacheTTLExpires)
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url1:123")
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url2:123")
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url3:123")
	reqData, err = router.ChooseBackend("myfrontend.com")
	c.Assert(err, check.IsNil)
	c.Assert(reqData.Backend, check.Equals, "http://url4:123")
}

func (s *S) TestChooseBackendRoundRobinStress(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com", "myfrontend",
		"http://url1",
		"http://url2",
		"http://url3",
		"http://url4",
		"http://url5").Err()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend2.com", "myfrontend",
		"http://url1",
		"http://url2").Err()
	c.Assert(err, check.IsNil)
	freq1 := map[int]int{}
	freq2 := map[int]int{}
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	nParallel := 10
	nSeq := 1000
	for i := 0; i < nParallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < nSeq; j++ {
				reqData1, err := router.ChooseBackend("myfrontend.com")
				c.Assert(err, check.IsNil)
				reqData2, err := router.ChooseBackend("myfrontend2.com")
				c.Assert(err, check.IsNil)
				mu.Lock()
				freq1[reqData1.BackendIdx]++
				freq2[reqData2.BackendIdx]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	expected1 := (nParallel * nSeq) / 5
	expected2 := (nParallel * nSeq) / 2
	c.Assert(freq1, check.DeepEquals, map[int]int{
		0: expected1,
		1: expected1,
		2: expected1,
		3: expected1,
		4: expected1,
	})
	c.Assert(freq2, check.DeepEquals, map[int]int{
		0: expected2,
		1: expected2,
	})
}

func (s *S) TestChooseBackendRoundRobinStressOverflow(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	err = s.redis.RPush("frontend:myfrontend.com", "myfrontend",
		"http://url1",
		"http://url2",
		"http://url3",
		"http://url4",
		"http://url5").Err()
	c.Assert(err, check.IsNil)
	freq := map[int]int{}
	mu := sync.Mutex{}
	wg := sync.WaitGroup{}
	nParallel := 10
	nSeq := 1000
	initialNumber := uint32(1<<32 - 2)
	router.roundRobin["myfrontend.com"] = &initialNumber
	for i := 0; i < nParallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < nSeq; j++ {
				reqData, err := router.ChooseBackend("myfrontend.com")
				c.Assert(err, check.IsNil)
				mu.Lock()
				freq[reqData.BackendIdx]++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	expected := (nParallel * nSeq) / 5
	c.Assert(freq, check.DeepEquals, map[int]int{
		0: expected + 1,
		1: expected,
		2: expected,
		3: expected - 1,
		4: expected,
	})
}

type bufferCloser struct {
	bytes.Buffer
}

func (b *bufferCloser) Close() error {
	return nil
}

func (s *S) TestEndRequest(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	buf := bufferCloser{}
	router.logger = log.NewWriterLogger(&buf)
	data := &reverseproxy.RequestData{
		Host: "myfe.com",
	}
	err = router.EndRequest(data, false, nil)
	c.Assert(err, check.IsNil)
	members := s.redis.SMembers("dead:myfe.com").Val()
	c.Assert(members, check.DeepEquals, []string{})
	router.Stop()
	c.Assert(buf.String(), check.Equals, "")
}

func (s *S) TestEndRequestWithLogFunc(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	buf := bufferCloser{}
	router.logger = log.NewWriterLogger(&buf)
	data := &reverseproxy.RequestData{
		Host: "myfe.com",
	}
	err = router.EndRequest(data, false, func() *log.LogEntry { return &log.LogEntry{} })
	c.Assert(err, check.IsNil)
	members := s.redis.SMembers("dead:myfe.com").Val()
	c.Assert(members, check.DeepEquals, []string{})
	router.Stop()
	c.Assert(buf.String(), check.Equals, "::ffff: - - [01/Jan/0001:00:00:00 +0000] \"  \" 0 0 \"\" \"\" \":\" \"\" \"\" 0.000 0.000\n")
}

func (s *S) TestEndRequestWithError(c *check.C) {
	router := Router{}
	err := router.Init()
	c.Assert(err, check.IsNil)
	data := &reverseproxy.RequestData{
		Host: "myfe.com",
	}
	err = router.EndRequest(data, true, nil)
	c.Assert(err, check.IsNil)
	members := s.redis.SMembers("dead:myfe.com").Val()
	c.Assert(members, check.DeepEquals, []string{"0"})
}

func BenchmarkChooseBackend(b *testing.B) {
	r, err := redisConn()
	if err != nil {
		b.Fatal(err)
	}
	defer clearKeys(r)
	err = r.RPush("frontend:myfrontend.com", "myfrontend", "http://url1:123", "http://url2:123", "http://url3:123").Err()
	if err != nil {
		b.Fatal(err)
	}
	router := Router{
		CacheEnabled: true,
	}
	err = router.Init()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			router.ChooseBackend("myfrontend.com")
		}
	})
	b.StopTimer()
}

func BenchmarkChooseBackendNoCache(b *testing.B) {
	r, err := redisConn()
	if err != nil {
		b.Fatal(err)
	}
	defer clearKeys(r)
	err = r.RPush("frontend:myfrontend.com", "myfrontend", "http://url1:123", "http://url2:123", "http://url3:123").Err()
	if err != nil {
		b.Fatal(err)
	}
	router := Router{}
	err = router.Init()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			router.ChooseBackend("myfrontend.com")
		}
	})
	b.StopTimer()
}

func BenchmarkChooseBackendManyNoCache(b *testing.B) {
	r, err := redisConn()
	if err != nil {
		b.Fatal(err)
	}
	defer clearKeys(r)
	backends := make([]interface{}, 100)
	for i := range backends {
		backends[i] = "http://urlx:123"
	}
	backends = append([]interface{}{"benchfrontend"}, backends...)
	err = r.RPush("frontend:myfrontend.com", backends...).Err()
	if err != nil {
		b.Fatal(err)
	}
	router := Router{}
	err = router.Init()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			router.ChooseBackend("myfrontend.com")
		}
	})
	b.StopTimer()
}
