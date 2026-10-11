//go:build !windows

package relay

import "net"

func listenEntry(network, addr string) (net.Listener, error) { return net.Listen(network, addr) }
