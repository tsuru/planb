// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/tls"
	"io/ioutil"
	"log"
	"path/filepath"
)

type FSCertificateLoader struct {
	certificates map[string]*tls.Certificate
}

func NewFSCertificateLoader(path string) *FSCertificateLoader {
	loader := &FSCertificateLoader{
		certificates: make(map[string]*tls.Certificate),
	}
	matches, err := filepath.Glob(filepath.Join(path, "*.key"))
	if err != nil {
		log.Fatal(err)
	}

	for _, match := range matches {
		keyPath := filepath.Base(match)
		cname := keyPath[0 : len(keyPath)-4]
		cert, err := loadPrivateKeyPair(path, cname)

		if err != nil {
			log.Fatal(err)
		}

		loader.certificates[cname] = cert
	}

	return loader
}

func loadPrivateKeyPair(path string, cname string) (*tls.Certificate, error) {
	keyPath := cname + ".key"
	certPath := cname + ".crt"

	key, err := ioutil.ReadFile(filepath.Join(path, keyPath))
	if err != nil {
		return nil, err
	}

	certificate, err := ioutil.ReadFile(filepath.Join(path, certPath))
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return nil, err
	}
	return &cert, nil
}

func (f *FSCertificateLoader) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if f.certificates[clientHello.ServerName] != nil {
		return f.certificates[clientHello.ServerName], nil
	}

	wildcard := getWildCard(clientHello.ServerName)
	if f.certificates[wildcard] != nil {
		return f.certificates[wildcard], nil
	}

	return nil, ErrCertificateNotFound{clientHello.ServerName}
}
