package main

import (
	"sync/atomic"
	"testing"
	"time"
)

// A shutdown that finishes within the grace window must NOT force-exit or dump.
func TestShutdownWithDeadlineClean(t *testing.T) {
	origExit, origDump := osExit, dumpGoroutines
	defer func() { osExit, dumpGoroutines = origExit, origDump }()

	var exitCode atomic.Int32
	exitCode.Store(-1)
	osExit = func(c int) { exitCode.Store(int32(c)) }
	var dumped atomic.Bool
	dumpGoroutines = func() { dumped.Store(true) }

	start := time.Now()
	shutdownWithDeadline(time.Second, func() { /* returns immediately */ })

	if exitCode.Load() != -1 {
		t.Errorf("clean shutdown force-exited with code %d; want none", exitCode.Load())
	}
	if dumped.Load() {
		t.Error("clean shutdown must not dump goroutines")
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Errorf("clean shutdown returned in %v; should be near-instant", d)
	}
}

// A shutdown that stalls past the grace window must dump goroutines and force-exit(1) —
// the watchdog that keeps a wedged connection from blocking the stop forever.
func TestShutdownWithDeadlineStalled(t *testing.T) {
	origExit, origDump := osExit, dumpGoroutines
	defer func() { osExit, dumpGoroutines = origExit, origDump }()

	exited := make(chan int, 1)
	osExit = func(c int) { exited <- c }
	var dumped atomic.Bool
	dumpGoroutines = func() { dumped.Store(true) }

	release := make(chan struct{})
	defer close(release) // let the stalled shut() goroutine unwind after the test

	shutdownWithDeadline(30*time.Millisecond, func() { <-release }) // never completes in time

	select {
	case c := <-exited:
		if c != 1 {
			t.Errorf("force-exit code = %d, want 1", c)
		}
	default:
		t.Fatal("stalled shutdown did not force-exit")
	}
	if !dumped.Load() {
		t.Error("stalled shutdown must dump goroutines for investigation")
	}
}
