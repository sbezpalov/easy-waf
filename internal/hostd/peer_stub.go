//go:build !linux

package hostd

import "net"

func allowPeer(_ *net.UnixConn) error {
	return nil
}
