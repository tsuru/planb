// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/tls"
	"fmt"
)

type CertificateLoader interface {
	GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error)
}

type ErrCertificateNotFound struct {
	ServerName string
}

func (e ErrCertificateNotFound) Error() string {
	return fmt.Sprintf(`Certificate for "%s" not is found`, e.ServerName)
}

func getWildCard(domain string) string {
	length := len(domain)
	for i := 0; i < length; i++ {
		if domain[i] == '.' {
			return "*" + domain[i:length]
		}
	}
	return domain
}
