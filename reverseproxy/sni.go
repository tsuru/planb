// Copyright 2017 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reverseproxy

import (
	"io"
	"net"
	"net/url"

	"github.com/nu7hatch/gouuid"
	"github.com/tsuru/planb/log"
)

type SNIReverseProxy struct {
	ReverseProxyConfig
}

func (rp *SNIReverseProxy) Initialize(rpConfig ReverseProxyConfig) error {
	rp.ReverseProxyConfig = rpConfig
	return nil
}

func (rp *SNIReverseProxy) Stop() {
	// no special treatment for fast reverse proxy
}

func (rp *SNIReverseProxy) Listen(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		ConnID, _ := uuid.NewV4()
		if err != nil {
			log.ErrorLogger.Print("ERROR in ACCEPT - ", listener.Addr(), " - ", ConnID.String(), " - ", err.Error())
			return
		}
		go rp.handleSNIConnection(connection, ConnID.String())
	}
}

func (rp *SNIReverseProxy) handleSNIConnection(downstream net.Conn, ConnID string) {
	firstByte := make([]byte, 1)
	_, err := downstream.Read(firstByte)
	if err != nil {
		log.ErrorLogger.Print("ERROR - Couldn't read first byte - ", ConnID)
		return
	}
	if firstByte[0] != 0x16 {
		log.ErrorLogger.Print("ERROR - Not TLS - ", ConnID)
	}

	versionBytes := make([]byte, 2)
	_, err = downstream.Read(versionBytes)
	if err != nil {
		log.ErrorLogger.Print("ERROR - Couldn't read version bytes - ", ConnID)
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		log.ErrorLogger.Print("ERROR -  SSL < 3.1 so it's still not TLS - ", ConnID)
		return
	}

	restLengthBytes := make([]byte, 2)
	_, err = downstream.Read(restLengthBytes)
	if err != nil {
		log.ErrorLogger.Print("ERROR - Couldn't read restLength bytes - ", ConnID)
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, err = downstream.Read(rest)
	if err != nil {
		log.ErrorLogger.Print("ERROR - Couldn't read rest of bytes - ", ConnID)
		return
	}

	current := 0

	handshakeType := rest[0]
	current++
	if handshakeType != 0x1 {
		log.ErrorLogger.Print("ERROR - Not a ClientHello - ", ConnID)
		return
	}

	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current++
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current++
	current += compressionMethodLength

	if current > restLength {
		log.ErrorLogger.Print("ERROR - no extensions - ", ConnID)
		return
	}

	// Skip over extensionsLength
	// extensionsLength := (int(rest[current]) << 8) + int(rest[current + 1])
	current += 2

	hostname := ""
	for current < restLength && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		if extensionType == 0 {

			// Skip over number of names as we're assuming there's just one
			current += 2

			nameType := rest[current]
			current++
			if nameType != 0 {
				log.ErrorLogger.Print("ERROR - Not a hostname - ", ConnID)
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}
	if hostname == "" {
		log.ErrorLogger.Print("ERROR - No hostname - ", ConnID)
		return
	}

	reqData, err := rp.Router.ChooseBackend(hostname)
	if err != nil {
		log.ErrorLogger.Print("ERROR - ChooseBackend - ", ConnID, " - ", err)
		return
	}
	url, err := url.Parse(reqData.Backend)
	if err != nil {
		log.ErrorLogger.Print("ERROR - url.Parse - ", ConnID, " - ", err)
		return
	}
	backendAddress := url.Host
	upstream, err := net.Dial("tcp", backendAddress)
	if err != nil {
		log.ErrorLogger.Print("ERROR - ConnectBackend - ", ConnID, " - ", err)
		return
	}

	upstream.Write(firstByte)
	upstream.Write(versionBytes)
	upstream.Write(restLengthBytes)
	upstream.Write(rest)

	errc := make(chan error, 2)
	cp := func(dst io.Writer, src io.Reader) {
		_, err := io.Copy(dst, src)
		errc <- err
	}
	go cp(upstream, downstream)
	go cp(downstream, upstream)
	<-errc
}
