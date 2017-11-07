// Copyright 2017 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package reverseproxy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type proxyHdrV2 struct {
	Sig    [12]byte /* hex 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A */
	VerCmd byte     /* protocol version and command */
	Fam    byte     /* protocol family and address */
	Len    uint16   /* number of following bytes part of the header */
}

type proxyHdrV2Ipv4 struct { /* for TCP/UDP over IPv4, len = 12 */
	SrcAddr [4]byte
	DstAddr [4]byte
	SrcPort uint16
	DstPort uint16
}

type proxyHdrV2Ipv6 struct { /* for TCP/UDP over IPv6, len = 36 */
	SrcAddr [16]byte
	DstAddr [16]byte
	SrcPort uint16
	DstPort uint16
}

type proxyHdrV2Sock struct { /* for AF_UNIX sockets, len = 216 */
	SrcAddr [108]byte
	DstAddr [108]byte
}

var proxyHdrSig = []byte("\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A")

func readProxyProtoV2Header(conn net.Conn) (string, error) {
	var proxyHdr proxyHdrV2
	err := binary.Read(conn, binary.BigEndian, &proxyHdr)
	if err != nil {
		return "", err
	}
	if !bytes.Equal(proxyHdr.Sig[:], proxyHdrSig) {
		return "", errors.New("invalid proxy protocol header")
	}
	switch proxyHdr.Len {
	case 12:
		var data proxyHdrV2Ipv4
		err := binary.Read(conn, binary.BigEndian, &data)
		if err != nil {
			return "", err
		}
		ip := net.IP(data.SrcAddr[:])
		return fmt.Sprintf("%s:%d", ip.String(), data.SrcPort), nil
	case 36:
		var data proxyHdrV2Ipv6
		err := binary.Read(conn, binary.BigEndian, &data)
		if err != nil {
			return "", err
		}
		ip := net.IP(data.SrcAddr[:])
		return fmt.Sprintf("%s:%d", ip.String(), data.SrcPort), nil
	case 216:
		var data proxyHdrV2Sock
		err := binary.Read(conn, binary.BigEndian, &data)
		if err != nil {
			return "", err
		}
		return string(data.SrcAddr[:]), nil
	default:
		return "", errors.New("invalid proxy protocol header")
	}
}
