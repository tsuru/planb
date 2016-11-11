package tls

import (
	"crypto/tls"
	"testing"

	"gopkg.in/check.v1"
	"gopkg.in/redis.v3"
)

var rsaCertPEM = `-----BEGIN CERTIFICATE-----
MIIB0zCCAX2gAwIBAgIJAI/M7BYjwB+uMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTIwOTEyMjE1MjAyWhcNMTUwOTEyMjE1MjAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANLJ
hPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wok/4xIA+ui35/MmNa
rtNuC+BdZ1tMuVCPFZcCAwEAAaNQME4wHQYDVR0OBBYEFJvKs8RfJaXTH08W+SGv
zQyKn0H8MB8GA1UdIwQYMBaAFJvKs8RfJaXTH08W+SGvzQyKn0H8MAwGA1UdEwQF
MAMBAf8wDQYJKoZIhvcNAQEFBQADQQBJlffJHybjDGxRMqaRmDhX0+6v02TUKZsW
r5QuVbpQhH6u+0UgcW0jp9QwpxoPTLTWGXEWBBBurxFwiCBhkQ+V
-----END CERTIFICATE-----
`

var rsaKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END RSA PRIVATE KEY-----
`

type S struct {
	redisClient *redis.Client
	be          CertificateLoader
}

var _ = check.Suite(&S{})

func Test(t *testing.T) {
	check.TestingT(t)
}

func (s *S) SetUpTest(c *check.C) {
	s.redisClient = redis.NewClient(&redis.Options{Addr: "127.0.0.1:6379", DB: 1})
	s.be = NewRedisCertificateLoader(s.redisClient)
}

func (s *S) TestRedisCertificateNotFound(c *check.C) {
	clientHello := &tls.ClientHelloInfo{
		ServerName: "certificate-not-found.com",
	}
	_, err := s.be.GetCertificate(clientHello)
	c.Assert(err, check.ErrorMatches, `Certificate for \"certificate-not-found.com\" not is found`)
}

func (s *S) TestRedisCertificateFound(c *check.C) {
	result, err := s.redisClient.HMSet("tls:certificate.com", "certificate", rsaCertPEM, "key", rsaKeyPEM).Result()
	c.Assert(err, check.IsNil)
	c.Assert(result, check.Equals, "OK")
	clientHello := &tls.ClientHelloInfo{
		ServerName: "certificate.com",
	}
	_, err = s.be.GetCertificate(clientHello)
	c.Assert(err, check.IsNil)
}

func (s *S) TestRedisWildcardCertificateFound(c *check.C) {
	result, err := s.redisClient.HMSet("tls:*.tsuru.io", "certificate", rsaCertPEM, "key", rsaKeyPEM).Result()
	c.Assert(err, check.IsNil)
	c.Assert(result, check.Equals, "OK")
	clientHello := &tls.ClientHelloInfo{
		ServerName: "hello.tsuru.io",
	}
	_, err = s.be.GetCertificate(clientHello)
	c.Assert(err, check.IsNil)
}

func (s *S) TestRedisCertificateCached(c *check.C) {
	result, err := s.redisClient.HMSet("tls:certificate-cached.com", "certificate", rsaCertPEM, "key", rsaKeyPEM).Result()
	c.Assert(err, check.IsNil)
	c.Assert(result, check.Equals, "OK")
	clientHello := &tls.ClientHelloInfo{
		ServerName: "certificate-cached.com",
	}

	_, err = s.be.GetCertificate(clientHello)
	c.Assert(err, check.IsNil)

	deleted, err := s.redisClient.Del("tls:certificate-cached.com").Result()
	c.Assert(err, check.IsNil)
	c.Assert(deleted, check.Equals, int64(1))
	_, err = s.be.GetCertificate(clientHello)
	c.Assert(err, check.IsNil)
}
