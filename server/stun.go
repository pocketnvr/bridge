package server

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"time"
)

var stunServers = []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302"}

const stunMagicCookie = 0x2112A442

func publicIPv4(ctx context.Context) (netip.Addr, error) {
	var lastErr error
	for _, server := range stunServers {
		ip, err := stunQuery(ctx, server)
		if err == nil {
			return ip, nil
		}
		lastErr = err
	}
	return netip.Addr{}, lastErr
}

func stunQuery(ctx context.Context, server string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp4", server)
	if err != nil {
		return netip.Addr{}, err
	}
	defer c.Close()

	req := make([]byte, 20)
	binary.BigEndian.PutUint16(req[0:], 0x0001)
	binary.BigEndian.PutUint32(req[4:], stunMagicCookie)
	if _, err := rand.Read(req[8:20]); err != nil {
		return netip.Addr{}, err
	}
	buf := make([]byte, 1500)
	for attempt := 0; attempt < 2; attempt++ {
		_ = c.SetDeadline(time.Now().Add(1400 * time.Millisecond))
		if _, err := c.Write(req); err != nil {
			return netip.Addr{}, err
		}
		n, err := c.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		if ip, ok := parseStunResponse(buf[:n], req[8:20]); ok {
			return ip, nil
		}
	}
	return netip.Addr{}, errors.New("no STUN answer")
}

func parseStunResponse(b, txID []byte) (netip.Addr, bool) {
	if len(b) < 20 || binary.BigEndian.Uint16(b[0:]) != 0x0101 ||
		binary.BigEndian.Uint32(b[4:]) != stunMagicCookie || string(b[8:20]) != string(txID) {
		return netip.Addr{}, false
	}
	length := int(binary.BigEndian.Uint16(b[2:]))
	if 20+length > len(b) {
		return netip.Addr{}, false
	}
	attrs := b[20 : 20+length]
	var mapped netip.Addr
	for len(attrs) >= 4 {
		typ := binary.BigEndian.Uint16(attrs[0:])
		l := int(binary.BigEndian.Uint16(attrs[2:]))
		if 4+l > len(attrs) {
			break
		}
		v := attrs[4 : 4+l]
		if l >= 8 && v[1] == 0x01 {
			var ip [4]byte
			copy(ip[:], v[4:8])
			switch typ {
			case 0x0020:
				binary.BigEndian.PutUint32(ip[:], binary.BigEndian.Uint32(ip[:])^stunMagicCookie)
				return netip.AddrFrom4(ip), true
			case 0x0001:
				mapped = netip.AddrFrom4(ip)
			}
		}
		next := 4 + (l+3)&^3
		if next > len(attrs) {
			break
		}
		attrs = attrs[next:]
	}
	return mapped, mapped.IsValid()
}
