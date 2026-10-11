//go:build windows

package relay

import (
	"context"
	"net"
	"syscall"
)

func listenEntry(network, addr string) (net.Listener, error) {
	// On Windows a wildcard bind may otherwise succeed while another process
	// owns the same port on loopback, reporting a misleading ready listener.
	// https://learn.microsoft.com/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
	lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			socketErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, ^syscall.SO_REUSEADDR, 1)
		})
		if err != nil {
			return err
		}
		return socketErr
	}}
	return lc.Listen(context.Background(), network, addr)
}
