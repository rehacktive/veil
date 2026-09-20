// Package socks5 serves a bounded, loopback-only SOCKS5 CONNECT endpoint.
// Its supplied dialer owns routing; this package never resolves or dials a
// destination itself. BIND, UDP, SOCKS4, and GSSAPI are unsupported.
package socks5

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"veil/isolation"
	"veil/onion"
)

type DialFunc func(context.Context, string, string) (net.Conn, error)

type Options struct {
	MaxConnections   int           // Default 16, maximum 256; includes pending handshakes.
	HandshakeTimeout time.Duration // Default 10 seconds.
	ConnectTimeout   time.Duration // Default 1 minute, including circuit build.
	OnionTimeout     time.Duration // Default 3 minutes for v3 onion connection setup.
	IdleTimeout      time.Duration // Default 5 minutes, reset by traffic in either direction.
	MaxLifetime      time.Duration // Default 1 hour; bounds each connection/circuit lifetime.
}

func (o Options) defaults() (Options, error) {
	if o.MaxConnections == 0 {
		o.MaxConnections = 16
	}
	if o.HandshakeTimeout == 0 {
		o.HandshakeTimeout = 10 * time.Second
	}
	if o.ConnectTimeout == 0 {
		o.ConnectTimeout = time.Minute
	}
	if o.OnionTimeout == 0 {
		o.OnionTimeout = 3 * time.Minute
	}
	if o.IdleTimeout == 0 {
		o.IdleTimeout = 5 * time.Minute
	}
	if o.MaxLifetime == 0 {
		o.MaxLifetime = time.Hour
	}
	if o.MaxConnections < 1 || o.MaxConnections > 256 || o.HandshakeTimeout < 0 || o.ConnectTimeout < 0 || o.OnionTimeout < 0 || o.IdleTimeout < 0 || o.MaxLifetime < 0 {
		return o, errors.New("invalid SOCKS resource limits")
	}
	return o, nil
}

// ReplyError provides a SOCKS failure code without disclosing a destination.
// Codes outside 1..8 are replaced by general failure.
type ReplyError struct {
	Code byte
	Err  error
}

func (e *ReplyError) Error() string { return "SOCKS destination connection failed" }
func (e *ReplyError) Unwrap() error { return e.Err }

// Listen accepts only numeric loopback addresses, including an ephemeral port.
func Listen(ctx context.Context, address string) (net.Listener, error) {
	a, err := netip.ParseAddrPort(address)
	if err != nil || !a.Addr().IsLoopback() || a.Addr().Zone() != "" {
		return nil, errors.New("SOCKS listener must be a numeric loopback IP:port")
	}
	var lc net.ListenConfig
	return lc.Listen(ctx, "tcp", a.String())
}

// Serve owns and closes listener and all accepted connections. It waits for
// handlers to stop before returning. dial must obey its context and return a
// net.Conn whose Close interrupts I/O. No destinations or credentials are logged.
func Serve(ctx context.Context, listener net.Listener, dial DialFunc, options Options) error {
	opts, err := options.defaults()
	if err != nil || dial == nil {
		if err == nil {
			err = errors.New("SOCKS dialer is required")
		}
		return err
	}
	a, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil || !a.Addr().IsLoopback() {
		return errors.New("SOCKS listener must be loopback")
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	slots := make(chan struct{}, opts.MaxConnections)
	var wg sync.WaitGroup
	defer func() { cancel(); wg.Wait() }()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		select {
		case slots <- struct{}{}:
			wg.Add(1)
			go func() { defer wg.Done(); defer func() { <-slots }(); handle(ctx, conn, dial, opts) }()
		default:
			_ = conn.Close()
		}
	}
}

func handle(parent context.Context, local net.Conn, dial DialFunc, o Options) {
	defer local.Close()
	ctx, cancel := context.WithTimeout(parent, o.MaxLifetime)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = local.Close() })
	defer stop()
	if err := local.SetDeadline(time.Now().Add(o.HandshakeTimeout)); err != nil {
		return
	}
	var err error
	ctx, err = negotiate(ctx, local)
	if err != nil {
		return
	}
	applicationIP, _, splitErr := net.SplitHostPort(local.RemoteAddr().String())
	if splitErr != nil {
		applicationIP = local.RemoteAddr().String()
	}
	ctx = isolation.WithProxyBoundary(ctx, applicationIP, local.LocalAddr().String())
	network, address, code, err := request(local)
	if err != nil {
		_ = reply(local, code)
		return
	}
	// The connect timeout covers the native circuit build as well as BEGIN.
	budget := o.ConnectTimeout
	host, _, _ := net.SplitHostPort(address)
	if onion.IsAddress(host) {
		budget = o.OnionTimeout
	}
	connect, cancelConnect := context.WithTimeout(ctx, budget)
	if err = local.SetDeadline(time.Now().Add(budget)); err != nil {
		cancelConnect()
		return
	}
	remote, err := dial(connect, network, address)
	cancelConnect()
	// Give a timed-out dial a bounded chance to return its failure reply.
	if deadlineErr := local.SetDeadline(time.Now().Add(o.HandshakeTimeout)); deadlineErr != nil {
		if remote != nil {
			_ = remote.Close()
		}
		return
	}
	if err != nil {
		code = 1
		var re *ReplyError
		if errors.As(err, &re) && re.Code >= 1 && re.Code <= 8 {
			code = re.Code
		} else if errors.Is(err, context.DeadlineExceeded) {
			code = 6
		}
		_ = reply(local, code)
		return
	}
	if remote == nil {
		_ = reply(local, 1)
		return
	}
	defer remote.Close()
	if ctx.Err() != nil {
		return
	}
	if err = reply(local, 0); err != nil {
		return
	}
	bridge(ctx, local, remote, o.IdleTimeout)
}

func negotiate(ctx context.Context, c io.ReadWriter) (context.Context, error) {
	var header [2]byte
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return ctx, err
	}
	if header[0] != 5 || header[1] == 0 {
		return ctx, errors.New("invalid SOCKS greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(c, methods); err != nil {
		return ctx, err
	}
	method := byte(255)
	for _, m := range methods {
		if m == 0 && method == 255 {
			method = 0
		}
		if m == 2 {
			method = 2
		}
	}
	if err := writeAll(c, []byte{5, method}); err != nil {
		return ctx, err
	}
	if method == 255 {
		return ctx, errors.New("no supported SOCKS authentication method")
	}
	if method == 0 {
		return isolation.WithToken(ctx, ""), nil
	}
	// Credentials identify an explicit sharing scope, not access control.
	if _, err := io.ReadFull(c, header[:]); err != nil {
		return ctx, err
	}
	if header[0] != 1 || header[1] == 0 {
		_ = writeAll(c, []byte{1, 1})
		return ctx, errors.New("invalid SOCKS tokens")
	}
	user := make([]byte, int(header[1]))
	defer clear(user)
	if _, err := io.ReadFull(c, user); err != nil {
		return ctx, err
	}
	var length [1]byte
	if _, err := io.ReadFull(c, length[:]); err != nil {
		return ctx, err
	}
	if length[0] == 0 {
		_ = writeAll(c, []byte{1, 1})
		return ctx, errors.New("empty SOCKS token")
	}
	password := make([]byte, int(length[0]))
	defer clear(password)
	if _, err := io.ReadFull(c, password); err != nil {
		return ctx, err
	}
	return isolation.WithSOCKS(ctx, user, password), writeAll(c, []byte{1, 0})
}

func request(r io.Reader) (network, address string, code byte, err error) {
	var header [4]byte
	if _, err = io.ReadFull(r, header[:]); err != nil {
		return "", "", 1, err
	}
	if header[0] != 5 || header[2] != 0 {
		return "", "", 1, errors.New("invalid SOCKS request header")
	}
	if header[1] != 1 {
		return "", "", 7, errors.New("only SOCKS CONNECT is supported")
	}
	network = "tcp4"
	var host string
	switch header[3] {
	case 1:
		var ip [4]byte
		if _, err = io.ReadFull(r, ip[:]); err != nil {
			return "", "", 1, err
		}
		host = netip.AddrFrom4(ip).String()
	case 4:
		var ip [16]byte
		if _, err = io.ReadFull(r, ip[:]); err != nil {
			return "", "", 1, err
		}
		a := netip.AddrFrom16(ip).Unmap()
		host = a.String()
		if a.Is6() {
			network = "tcp6"
		}
	case 3:
		var length [1]byte
		if _, err = io.ReadFull(r, length[:]); err != nil {
			return "", "", 1, err
		}
		raw := make([]byte, int(length[0]))
		if _, err = io.ReadFull(r, raw); err != nil {
			return "", "", 1, err
		}
		host = strings.ToLower(string(raw))
		if !validName(host) {
			return "", "", 4, errors.New("invalid destination hostname")
		}
	default:
		return "", "", 8, errors.New("unsupported SOCKS address type")
	}
	var port [2]byte
	if _, err = io.ReadFull(r, port[:]); err != nil {
		return "", "", 1, err
	}
	number := binary.BigEndian.Uint16(port[:])
	if number == 0 {
		return "", "", 1, errors.New("zero destination port")
	}
	return network, net.JoinHostPort(host, strconv.FormatUint(uint64(number), 10)), 0, nil
}
func validName(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if onion.IsAddress(host) {
		_, err := onion.ParseAddress(host)
		return err == nil
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if !(b >= 'a' && b <= 'z' || b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return true
}
func reply(w io.Writer, code byte) error { return writeAll(w, []byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0}) }
func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

type activity struct {
	mu            sync.Mutex
	local, remote net.Conn
	idle          time.Duration
}

func (a *activity) touch() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	deadline := time.Now().Add(a.idle)
	return errors.Join(a.local.SetDeadline(deadline), a.remote.SetDeadline(deadline))
}

type activeConn struct {
	net.Conn
	a *activity
}

func (c activeConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		err = errors.Join(err, c.a.touch())
	}
	return n, err
}
func (c activeConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		err = errors.Join(err, c.a.touch())
	}
	return n, err
}
func bridge(ctx context.Context, local, remote net.Conn, idle time.Duration) {
	a := &activity{local: local, remote: remote, idle: idle}
	if a.touch() != nil {
		return
	}
	done := make(chan struct{}, 2)
	copyData := func(dst, src net.Conn) {
		_, _ = io.CopyBuffer(activeConn{dst, a}, activeConn{src, a}, make([]byte, 32*1024))
		done <- struct{}{}
	}
	go copyData(local, remote)
	go copyData(remote, local)
	completed := 0
	select {
	case <-ctx.Done():
	case <-done:
		completed = 1
	}
	// Tor END has no half-close. Close both directions, then join both copies.
	_ = local.Close()
	_ = remote.Close()
	for completed < 2 {
		<-done
		completed++
	}
}
