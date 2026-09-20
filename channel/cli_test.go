package channel

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// Exercise the real command line, TLS transport, chain validation, JSON output,
// and connection teardown together against the local relay fixture.
func TestChannelCheckBinary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "veil")
	if output, err := exec.CommandContext(ctx, "go", "build", "-o", binary, "../cmd/veil").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	f := fixture(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	f.target.Address = listener.Addr().(*net.TCPAddr).AddrPort()
	frames := f.frames(t)
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(5 * time.Second))
		conn, _, err := serveHandshake(raw, f, frames, []uint16{4, 5}, 0)
		if err == nil {
			var n int64
			n, err = io.Copy(io.Discard, conn)
			if n != 0 {
				err = fmt.Errorf("channel-check sent %d bytes after NETINFO", n)
			}
		}
		done <- err
	}()
	output, err := exec.CommandContext(ctx, binary, "channel-check", "-address", f.target.Address.String(), "-rsa", hex.EncodeToString(f.target.Identity.RSA[:]), "-ed25519", hex.EncodeToString(f.target.Identity.Ed25519[:]), "-timeout", "3s").CombinedOutput()
	if err != nil {
		t.Fatalf("command: %v\n%s", err, output)
	}
	var info struct {
		Address string    `json:"address"`
		RSA     string    `json:"rsa_identity"`
		Ed      string    `json:"ed25519_identity"`
		Link    int       `json:"link_protocol"`
		Expires time.Time `json:"certificates_expire"`
	}
	if err := json.Unmarshal(output, &info); err != nil {
		t.Fatal(err)
	}
	if info.Address != f.target.Address.String() || info.RSA != hex.EncodeToString(f.target.Identity.RSA[:]) || info.Ed != hex.EncodeToString(f.target.Identity.Ed25519[:]) || info.Link != 5 || !info.Expires.After(time.Now()) {
		t.Fatalf("bad CLI metadata %s", output)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("CLI did not close the channel")
	}
}
