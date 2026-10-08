package server

import (
	"bytes"
	"testing"

	"github.com/gorilla/websocket"
)

func TestTermSessionCloseRemovesFromManager(t *testing.T) {
	m := NewTerminalManager()
	ts := &TermSession{adminID: 7, conns: map[*websocket.Conn]struct{}{}}
	m.Put(ts)
	if m.Get(7) != ts {
		t.Fatal("Put did not register the session")
	}

	ts.Close()
	if m.Get(7) != nil {
		t.Fatal("Close did not remove the session from the manager")
	}
	ts.Close() // must be idempotent
	if !ts.isClosed() {
		t.Fatal("isClosed = false after Close")
	}
}

func TestTermSessionBroadcastCapsReplay(t *testing.T) {
	ts := &TermSession{adminID: 1, conns: map[*websocket.Conn]struct{}{}}
	payload := bytes.Repeat([]byte("0123456789abcdef"), 2500) // 40_000 bytes
	ts.broadcast(payload)

	if len(ts.replay) != replayCap {
		t.Fatalf("replay length = %d, want %d", len(ts.replay), replayCap)
	}
	want := payload[len(payload)-replayCap:]
	if !bytes.Equal(ts.replay, want) {
		t.Fatal("replay does not hold the tail of the stream")
	}
}
