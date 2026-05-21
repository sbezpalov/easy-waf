//go:build linux

package hostd

import (
	"fmt"
	"net"
	"syscall"
)

func allowPeer(conn *net.UnixConn) error {
	raw, err := conn.File()
	if err != nil {
		return err
	}
	defer raw.Close()
	fd := int(raw.Fd())
	ucred, err := syscall.GetsockoptUcred(fd, syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return err
	}
	uid := int(ucred.Uid)
	if uid != 0 && uid != easyWafUID {
		return fmt.Errorf("uid %d", uid)
	}
	return nil
}
