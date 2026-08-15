//go:build linux

package hostd

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const authorizedKeysTmpName = ".authorized_keys.easy-waf"

// writeAuthorizedKeys installs authorized_keys for a managed account without ever
// following a symlink.
//
// `install -d -m 0700 -o user ~/.ssh` (the previous implementation) resolves the
// destination path as root: a local account could point its own ~/.ssh at any
// directory and have root chown/chmod the target. Here every step is taken
// relative to an open descriptor with RESOLVE_NO_SYMLINKS, and ownership and mode
// are set through the descriptor (fchown/fchmod), so there is no path to swap
// between check and use.
func writeAuthorizedKeys(home string, uid, gid int, content []byte) error {
	if err := checkHomeDirNotSymlink(home); err != nil {
		return err
	}

	homeFD, err := unix.Open(home, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open home: %w", err)
	}
	defer unix.Close(homeFD)

	var homeStat unix.Stat_t
	if err := unix.Fstat(homeFD, &homeStat); err != nil {
		return fmt.Errorf("stat home: %w", err)
	}
	if int(homeStat.Uid) != uid {
		return fmt.Errorf("home is not owned by the account")
	}

	if err := unix.Mkdirat(homeFD, ".ssh", 0o700); err != nil && err != unix.EEXIST {
		return fmt.Errorf("mkdir .ssh: %w", err)
	}
	sshFD, err := openatBeneath(homeFD, ".ssh", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("open .ssh: %w", err)
	}
	defer unix.Close(sshFD)
	if err := unix.Fchown(sshFD, uid, gid); err != nil {
		return fmt.Errorf("chown .ssh: %w", err)
	}
	if err := unix.Fchmod(sshFD, 0o700); err != nil {
		return fmt.Errorf("chmod .ssh: %w", err)
	}

	// Write to a temporary file inside .ssh and rename over authorized_keys, so a
	// failed write can never leave a truncated key file (which would lock the
	// account's operator out on the next login).
	tmpFD, err := openatBeneath(sshFD, authorizedKeysTmpName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create authorized_keys: %w", err)
	}
	tmp := os.NewFile(uintptr(tmpFD), authorizedKeysTmpName)
	cleanup := func() {
		_ = tmp.Close()
		_ = unix.Unlinkat(sshFD, authorizedKeysTmpName, 0)
	}
	if _, err := tmp.Write(content); err != nil {
		cleanup()
		return fmt.Errorf("write authorized_keys: %w", err)
	}
	if err := unix.Fchown(int(tmp.Fd()), uid, gid); err != nil {
		cleanup()
		return fmt.Errorf("chown authorized_keys: %w", err)
	}
	if err := unix.Fchmod(int(tmp.Fd()), 0o600); err != nil {
		cleanup()
		return fmt.Errorf("chmod authorized_keys: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync authorized_keys: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = unix.Unlinkat(sshFD, authorizedKeysTmpName, 0)
		return fmt.Errorf("close authorized_keys: %w", err)
	}
	if err := unix.Renameat(sshFD, authorizedKeysTmpName, sshFD, "authorized_keys"); err != nil {
		_ = unix.Unlinkat(sshFD, authorizedKeysTmpName, 0)
		return fmt.Errorf("rename authorized_keys: %w", err)
	}
	return nil
}

// openatBeneath opens name relative to dirFD, refusing symlinks and any escape
// from the directory.
func openatBeneath(dirFD int, name string, flags int, mode uint64) (int, error) {
	return unix.Openat2(dirFD, name, &unix.OpenHow{
		Flags:   uint64(flags) | unix.O_NOFOLLOW,
		Mode:    mode,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
}
