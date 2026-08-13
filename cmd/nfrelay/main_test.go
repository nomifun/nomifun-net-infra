package main

import (
	"net"
	"testing"
)

func TestAdvertisedAddrOverride(t *testing.T) {
	got := advertisedAddr("0.0.0.0:8443", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8443}, "relay.example.com:443")
	if got != "relay.example.com:443" {
		t.Fatalf("override = %q", got)
	}
}

func TestValidateAdvertisedAddr(t *testing.T) {
	for _, raw := range []string{"relay.example.com:8443", "127.0.0.1:19043", "[::1]:8443"} {
		if err := validateAdvertisedAddr(raw); err != nil {
			t.Errorf("%q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{"", "relay.example.com", "0.0.0.0:8443", "relay.example.com:0", "bad host:8443"} {
		if err := validateAdvertisedAddr(raw); raw != "" && err == nil {
			t.Errorf("%q unexpectedly accepted", raw)
		}
	}
}

func TestValidateDesktopBusinessURL(t *testing.T) {
	for _, raw := range []string{
		"",
		"http://127.0.0.1:19090",
		"https://desktop.example.com",
		"https://desktop.example.com/",
	} {
		if err := validateDesktopBusinessURL(raw); err != nil {
			t.Errorf("%q rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"desktop.example.com",
		"ftp://desktop.example.com",
		"https://user:pass@desktop.example.com",
		"https://desktop.example.com/prefix",
		"https://desktop.example.com?token=x",
		"https://desktop.example.com/#fragment",
	} {
		if err := validateDesktopBusinessURL(raw); err == nil {
			t.Errorf("%q unexpectedly accepted", raw)
		}
	}
}
