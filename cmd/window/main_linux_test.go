//go:build linux

package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func TestObservedOutputDropsOverlongLineWithoutChunkLeak(t *testing.T) {
	lines := make(chan string, 4)
	collector := &liveCollector{lines: lines}
	_, _ = collector.Write([]byte("PASS\r\n"))
	_, _ = collector.Write([]byte(strings.Repeat("x", 2048)))
	_, _ = collector.Write([]byte("secret-tail\n"))
	first, second := <-lines, <-lines
	if first != "PASS" || second != "[long output line omitted]" {
		t.Fatalf("unexpected live output: %q, %q", first, second)
	}
	if len(lines) != 0 {
		t.Fatal("trailing part of an overlong line leaked")
	}
}

func TestObservedInputStopsWithoutConsumingMoreTerminalInput(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		copyObservedInput(int(read.Fd()), io.Discard, stop)
		close(done)
	}()
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("observed input retained the TUI stdin after shell exit")
	}
}
