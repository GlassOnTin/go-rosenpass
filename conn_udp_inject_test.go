// SPDX-FileCopyrightText: 2026 GlassHaven
// SPDX-License-Identifier: Apache-2.0

package rosenpass

import (
	"net"
	"testing"
	"time"
)

// fakePacketConn is an in-memory net.PacketConn standing in for an in-stack
// socket (e.g. a gonet.UDPConn). It records binds/writes so the test can prove
// the transport routes through the injected socket rather than a host socket.
type fakePacketConn struct {
	localAddr net.Addr
	closed    bool
	writes    int
}

func (f *fakePacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// No traffic in this test; report closed so a receive loop would exit.
	return 0, nil, net.ErrClosed
}

func (f *fakePacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	f.writes++
	return len(b), nil
}

func (f *fakePacketConn) Close() error                       { f.closed = true; return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                { return f.localAddr }
func (f *fakePacketConn) SetDeadline(t time.Time) error      { return nil }
func (f *fakePacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error { return nil }

// TestUDPConnInjectsSocket proves NewUDPConnWithListenFunc binds via the
// injected function (not net.ListenUDP) and stores/routes through the supplied
// net.PacketConn. This is the #662 phase-2 primitive: an embedder can hand in
// an in-stack gonet.UDPConn so the Rosenpass exchange rides the tunnel overlay.
func TestUDPConnInjectsSocket(t *testing.T) {
	fake := &fakePacketConn{localAddr: &net.UDPAddr{IP: net.IPv4zero, Port: 12345}}

	var gotNetwork string
	var gotAddr *net.UDPAddr
	lf := func(network string, addr *net.UDPAddr) (net.PacketConn, error) {
		gotNetwork = network
		gotAddr = addr
		return fake, nil
	}

	// IP nil -> networkFromAddr returns "udp" (single wildcard socket).
	c, err := NewUDPConnWithListenFunc([]*net.UDPAddr{{Port: 0}}, lf)
	if err != nil {
		t.Fatalf("NewUDPConnWithListenFunc: %v", err)
	}

	rfns, err := c.Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(rfns) != 1 {
		t.Fatalf("want 1 ReceiveFunc, got %d", len(rfns))
	}
	if gotAddr == nil {
		t.Fatal("listenFunc never called — Open() bound a host socket instead of the injected one")
	}
	if gotNetwork != "udp" {
		t.Fatalf("listenFunc network = %q, want udp", gotNetwork)
	}
	if c.conns["udp"] != fake {
		t.Fatal("injected net.PacketConn not stored in conns; send/receive would not route through it")
	}

	// LocalEndpoints must reflect the injected socket's address.
	eps, err := c.LocalEndpoints()
	if err != nil {
		t.Fatalf("LocalEndpoints: %v", err)
	}
	if len(eps) != 1 || eps[0].String() != "0.0.0.0:12345" {
		t.Fatalf("LocalEndpoints = %v, want [0.0.0.0:12345]", eps)
	}

	// Close must close the injected socket.
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !fake.closed {
		t.Fatal("Close() did not close the injected socket")
	}
}

// TestUDPConnNilListenFuncFallsBack proves a nil listenFunc preserves the
// original net.ListenUDP behaviour (NewUDPConn equivalence).
func TestUDPConnNilListenFuncFallsBack(t *testing.T) {
	c, err := NewUDPConnWithListenFunc([]*net.UDPAddr{{IP: net.IPv4(127, 0, 0, 1), Port: 0}}, nil)
	if err != nil {
		t.Fatalf("NewUDPConnWithListenFunc: %v", err)
	}
	rfns, err := c.Open()
	if err != nil {
		t.Fatalf("Open with nil listenFunc should bind a real host socket: %v", err)
	}
	if len(rfns) != 1 {
		t.Fatalf("want 1 ReceiveFunc, got %d", len(rfns))
	}
	if _, ok := c.conns["udp4"].(*net.UDPConn); !ok {
		t.Fatalf("nil listenFunc should produce a *net.UDPConn, got %T", c.conns["udp4"])
	}
	_ = c.Close()
}