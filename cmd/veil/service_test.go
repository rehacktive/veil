package main

import (
	"bytes"
	"context"
	"testing"
)

func TestServiceCLIFlags(t *testing.T) {
	for _, args := range [][]string{nil, {"-public"}, {"-public", "-config", "x", "-state", "x"}, {"-public", "-state", "x", "-port", "0"}, {"-public", "-state", "x", "-port", "65536"}, {"-public", "-state", "x", "-bootstrap-timeout", "0"}} {
		var logs bytes.Buffer
		if err := hostService(context.Background(), args, &logs); err == nil {
			t.Fatal("bad flags accepted", args)
		}
		if logs.Len() != 0 {
			t.Fatal("normal logs emitted without debug")
		}
	}
	var help bytes.Buffer
	if err := hostService(context.Background(), []string{"-h"}, &help); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(help.Bytes(), []byte("-target")) || !bytes.Contains(help.Bytes(), []byte("-debug")) {
		t.Fatal("missing help")
	}
}
