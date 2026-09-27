package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"veil/service"
)

func TestServiceCLIFlags(t *testing.T) {
	for _, args := range [][]string{nil, {"-public"}, {"-public", "-config", "x", "-state", "x"}, {"-public", "-state", "x", "-port", "0"}, {"-public", "-state", "x", "-port", "65536"}, {"-public", "-state", "x", "-bootstrap-timeout", "0"}} {
		var logs bytes.Buffer
		if err := hostService(context.Background(), args, io.Discard, &logs); err == nil {
			t.Fatal("bad flags accepted", args)
		}
		if logs.Len() != 0 {
			t.Fatal("normal logs emitted without debug")
		}
	}
	var help bytes.Buffer
	if err := hostService(context.Background(), []string{"-h"}, io.Discard, &help); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(help.Bytes(), []byte("-target")) || !bytes.Contains(help.Bytes(), []byte("-debug")) || !bytes.Contains(help.Bytes(), []byte("-quiet")) || !bytes.Contains(help.Bytes(), []byte("-status-json")) {
		t.Fatal("missing help")
	}
}

func TestServiceCLIOperationalLogging(t *testing.T) {
	for _, mode := range []string{"", "-debug", "-quiet"} {
		var logs, out bytes.Buffer
		args := []string{"-config", "missing-bootstrap.json", "-state", t.TempDir()}
		if mode != "" {
			args = append(args, mode)
		}
		if err := hostService(context.Background(), args, &out, &logs); err == nil {
			t.Fatal("missing config accepted")
		}
		if out.Len() != 0 {
			t.Fatal("operational logs polluted stdout")
		}
		for _, event := range []string{"service_starting", "service_stopped"} {
			if strings.Contains(logs.String(), event) != (mode != "-quiet") {
				t.Fatal(logs.String())
			}
		}
		if strings.Contains(logs.String(), "service_ready") {
			t.Fatal("failed startup reported ready")
		}
	}
	var logs bytes.Buffer
	err := hostService(context.Background(), []string{"-public", "-state", "unused", "-debug", "-quiet"}, io.Discard, &logs)
	if err == nil || logs.Len() != 0 {
		t.Fatal("conflicting modes accepted", err, logs.String())
	}
}

type statusWriterFunc func([]byte) (int, error)

func (f statusWriterFunc) Write(b []byte) (int, error) { return f(b) }

func TestServiceStatusJSONChangesAndFinalState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var output bytes.Buffer
	value := serviceStatusSnapshot{Service: service.Status{Phase: "partial", Running: true}}
	writes := 0
	writer := statusWriterFunc(func(b []byte) (int, error) {
		writes++
		n, err := output.Write(b)
		if writes == 1 {
			value.Service.Phase = "stopped"
			value.Service.Running = false
			cancel()
		}
		return n, err
	})
	if err := writeServiceStatus(ctx, writer, func() serviceStatusSnapshot { return value }); err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(&output)
	for _, phase := range []string{"partial", "stopped"} {
		var got serviceStatusSnapshot
		if err := decoder.Decode(&got); err != nil || got.Service.Phase != phase {
			t.Fatal(got, err)
		}
	}
	if writes != 2 {
		t.Fatal(writes)
	}
	// An unchanged final snapshot is suppressed.
	writes = 0
	if err := writeServiceStatus(ctx, statusWriterFunc(func(b []byte) (int, error) { writes++; return len(b), nil }), func() serviceStatusSnapshot { return value }); err != nil || writes != 1 {
		t.Fatal(err, writes)
	}
}

func TestServiceStatusOutputErrors(t *testing.T) {
	for _, failure := range []error{io.ErrClosedPipe, nil} {
		writer := statusWriterFunc(func([]byte) (int, error) { return 0, failure })
		err := writeServiceStatus(context.Background(), writer, func() serviceStatusSnapshot { return serviceStatusSnapshot{} })
		want := failure
		if want == nil {
			want = io.ErrShortWrite
		}
		if !errors.Is(err, want) {
			t.Fatal(err)
		}
	}
}
