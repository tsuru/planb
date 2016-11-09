package tls

import (
	"crypto/tls"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/check.v1"
)

var fileCertPEM = `-----BEGIN CERTIFICATE-----
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

var fileKeyPEM = `-----BEGIN RSA PRIVATE KEY-----
MIIBOwIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo
k/4xIA+ui35/MmNartNuC+BdZ1tMuVCPFZcCAwEAAQJAEJ2N+zsR0Xn8/Q6twa4G
6OB1M1WO+k+ztnX/1SvNeWu8D6GImtupLTYgjZcHufykj09jiHmjHx8u8ZZB/o1N
MQIhAPW+eyZo7ay3lMz1V01WVjNKK9QSn1MJlb06h/LuYv9FAiEA25WPedKgVyCW
SmUwbPw8fnTcpqDWE3yTO3vKcebqMSsCIBF3UmVue8YU3jybC3NxuXq3wNm34R8T
xVLHwDXh/6NJAiEAl2oHGGLz64BuAfjKrqwz7qMYr9HCLIe/YsoWq/olzScCIQDi
D2lWusoe2/nEqfDVVWGWlyJ7yOmqaVm/iNUN9B2N2g==
-----END RSA PRIVATE KEY-----
`

type FSSuite struct {
	path string
	be   CertificateLoader
}

var _ = check.Suite(&FSSuite{})

func (s *FSSuite) SetUpTest(c *check.C) {
	var err error
	s.path, err = ioutil.TempDir("", "cert-path")
	c.Assert(err, check.IsNil)

	tmpfn := filepath.Join(s.path, "*.tsuru.io.key")
	err = ioutil.WriteFile(tmpfn, []byte(fileKeyPEM), 0666)
	c.Assert(err, check.IsNil)

	tmpfn = filepath.Join(s.path, "*.tsuru.io.crt")
	err = ioutil.WriteFile(tmpfn, []byte(fileCertPEM), 0666)
	c.Assert(err, check.IsNil)

	tmpfn = filepath.Join(s.path, "tsuru.com.key")
	err = ioutil.WriteFile(tmpfn, []byte(fileKeyPEM), 0666)
	c.Assert(err, check.IsNil)

	tmpfn = filepath.Join(s.path, "tsuru.com.crt")
	err = ioutil.WriteFile(tmpfn, []byte(fileCertPEM), 0666)
	c.Assert(err, check.IsNil)

	s.be = NewFSCertificateLoader(s.path)
}

func (s *FSSuite) TearDownTest(c *check.C) {
	os.RemoveAll(s.path)
}

func (s *FSSuite) TestCertificateNotFound(c *check.C) {
	clientHello := &tls.ClientHelloInfo{
		ServerName: "blah.com",
	}
	_, err := s.be.GetCertificate(clientHello)
	c.Assert(err, check.ErrorMatches, `Certificate for \"blah.com\" not is found`)
}

func (s *FSSuite) TestCertificateFound(c *check.C) {
	clientHello := &tls.ClientHelloInfo{
		ServerName: "tsuru.com",
	}
	_, err := s.be.GetCertificate(clientHello)
	c.Assert(err, check.IsNil)
}

func (s *FSSuite) TestWildCardCertificate(c *check.C) {
	clientHello := &tls.ClientHelloInfo{
		ServerName: "hello.tsuru.io",
	}

	_, err := s.be.GetCertificate(clientHello)
	c.Assert(err, check.IsNil)
}
