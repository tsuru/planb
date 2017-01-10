package router

import (
	stdtls "crypto/tls"
	"log"
	"net"
	"sync"

	"github.com/tsuru/planb/reverseproxy"
	"github.com/tsuru/planb/tls"
)

type RouterListener struct {
	wg        sync.WaitGroup
	listeners []net.Listener

	ReverseProxy reverseproxy.ReverseProxy
	Listen       string
	TLSListen    string
	CertLoader   tls.CertificateLoader
}

func (r *RouterListener) Serve() {
	var listener net.Listener
	r.listeners = make([]net.Listener, 0, 2)

	if r.Listen != "disabled" {
		r.wg.Add(1)
		listener = r.httpListener()
		r.listeners = append(r.listeners, listener)

		log.Printf("Listening on %s...\n", listener.Addr().String())
		go r.listen(listener)
	}

	if r.TLSListen != "" {
		r.wg.Add(1)
		listener = r.httpsListener()
		r.listeners = append(r.listeners, listener)

		log.Printf("Listening tls on %s...\n", listener.Addr().String())
		go r.listen(listener)
	}

	r.wg.Wait()
}

func (r *RouterListener) Stop() {
	r.ReverseProxy.Stop()

	for _, listener := range r.listeners {
		log.Printf("Stopping listening on %s...\n", listener.Addr().String())
		listener.Close()
	}
}

func (r *RouterListener) httpListener() net.Listener {
	listener, err := net.Listen("tcp", r.Listen)
	if err != nil {
		log.Fatal(err)
	}
	return listener
}

func (r *RouterListener) httpsListener() net.Listener {
	tlsConfig := &stdtls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []stdtls.CurveID{
			stdtls.CurveP256,
		},
		MinVersion: stdtls.VersionTLS12,
		CipherSuites: []uint16{
			stdtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			stdtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			stdtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			stdtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		GetCertificate: r.CertLoader.GetCertificate,
	}
	listener, err := net.Listen("tcp", r.TLSListen)
	if err != nil {
		log.Fatal(err)
	}
	return stdtls.NewListener(listener, tlsConfig)
}

func (r *RouterListener) listen(listener net.Listener) {
	r.ReverseProxy.Listen(listener)
	listener.Close()
	r.wg.Done()
}
