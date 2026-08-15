//go:build linux

package hostd

import (
	"fmt"
	"net"
	"syscall"
)

func allowPeer(conn *net.UnixConn) error {
	if peerCheckBypassed() {
		return nil
	}
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
	// easyWafUID < 0 means the service account could not be resolved at startup:
	// accept root only, instead of letting the check degrade into "allow anyone".
	if uid != 0 && (easyWafUID < 0 || uid != easyWafUID) {
		return fmt.Errorf("uid %d", uid)
	}
	return nil
}
