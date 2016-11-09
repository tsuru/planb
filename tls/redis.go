// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/tls"
	"time"

	"github.com/hashicorp/golang-lru"
	"gopkg.in/redis.v3"
)

type RedisCertificateLoader struct {
	*redis.Client
	cache *lru.Cache
}

func NewRedisCertificateLoader(client *redis.Client) *RedisCertificateLoader {
	cache, _ := lru.New(100)
	return &RedisCertificateLoader{
		Client: client,
		cache:  cache,
	}
}

func (r *RedisCertificateLoader) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if data, ok := r.cache.Get(clientHello.ServerName); ok {
		c := data.(certCached)
		if !c.Expired() {
			return c.cert, nil
		}
	}
	return r.getCertificateFromRedis(clientHello.ServerName)
}

func (r *RedisCertificateLoader) getCertificateFromRedis(serverName string) (*tls.Certificate, error) {
	data, err := r.Client.HMGet("tls:"+serverName, "certificate", "key").Result()
	if err != nil {
		return nil, err
	}

	var certificate string
	var key string

	if data[0] != nil {
		certificate = data[0].(string)
	}
	if data[1] != nil {
		key = data[1].(string)
	}

	if certificate == "" || key == "" {
		return nil, ErrCertificateNotFound{serverName}
	}
	cert, err := tls.X509KeyPair([]byte(certificate), []byte(key))
	if err != nil {
		return nil, err
	}
	r.cache.Add(serverName, certCached{
		cert:    &cert,
		expires: time.Now().Add(30 * time.Second),
	})
	return &cert, nil
}

type certCached struct {
	cert    *tls.Certificate
	expires time.Time
}

func (c *certCached) Expired() bool {
	return time.Now().After(c.expires)
}
