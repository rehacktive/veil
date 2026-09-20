package main

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"veil/cell"
)

func TestInspect(t *testing.T) {
	var input, output, diagnostics bytes.Buffer
	if err := cell.WriteVersions(&input, []uint16{4, 5}); err != nil {
		t.Fatal(err)
	}
	c, _ := cell.NewCodec(5)
	if err := c.Write(&input, cell.Cell{Command: cell.Certs, Payload: []byte{0}}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"inspect", "-handshake", "-payload"}, &input, &output, &diagnostics); err != nil {
		t.Fatal(err)
	}
	want := "{\"command\":\"VERSIONS\",\"versions\":[4,5],\"selected\":5}\n{\"circuit_id\":0,\"command\":\"CERTS\",\"command_id\":129,\"length\":1,\"payload_hex\":\"00\"}\n"
	if output.String() != want {
		t.Fatalf("%s", output.String())
	}
}

func TestCLIErrorPaths(t *testing.T) {
	for _, args := range [][]string{
		{"proxy"}, {"unknown"}, {"version", "extra"}, {"inspect", "extra"},
		{"inspect", "-link", "3"}, {"inspect", "-link", "65540"},
		{"inspect", "-handshake", "-link", "4"}, {"inspect", "-no-such-flag"},
		{"inspect", "-handshake"},
	} {
		if err := run(args, strings.NewReader(""), io.Discard, io.Discard); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
	for _, args := range [][]string{nil, {"help"}, {"version"}, {"inspect", "-h"}, {"inspect"}} {
		if err := run(args, strings.NewReader(""), io.Discard, io.Discard); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if err := run([]string{"inspect"}, bytes.NewReader([]byte{0, 0, 0, 0, 128}), io.Discard, io.Discard); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	var b bytes.Buffer
	_ = cell.WriteVersions(&b, []uint16{3})
	if err := run([]string{"inspect", "-handshake"}, &b, io.Discard, io.Discard); err == nil {
		t.Fatal("accepted unsupported peer")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestOutputErrors(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"version"}, {"inspect", "-handshake"}, {"inspect"}} {
		var b bytes.Buffer
		if len(args) > 1 {
			_ = cell.WriteVersions(&b, []uint16{4})
		} else {
			c, _ := cell.NewCodec(4)
			_ = c.Write(&b, cell.Cell{Command: cell.Padding})
		}
		if err := run(args, &b, failingWriter{}, io.Discard); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("%v: %v", args, err)
		}
	}
}
