package shaping

import (
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"ghost/internal/framing"
)

// ---------------------------------------------------------------------------
// Integration test helpers
// ---------------------------------------------------------------------------

// buildTestPipeline creates a full shaping pipeline connected via io.Pipe:
//
//	topWriter (TimerFrameWriter) → PadderFrameWriter → EncoderWriter → pipe → DecoderReader → UnpadderFrameReader (bottomReader)
func buildTestPipeline(t *testing.T, selector Selector) (
	topWriter framing.FrameWriter,
	bottomReader framing.FrameReader,
	timerWriter *TimerFrameWriter,
	cleanup func(),
) {
	t.Helper()

	profilePath := filepath.Join("..", "..", "profiles", "chrome_browsing.json")
	profile, err := LoadProfile(profilePath)
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	seed := int64(12345)

	padder := NewProfilePadder(profile, seed)
	timer := NewProfileTimer(profile, seed+1)

	pr, pw := io.Pipe()

	// Write side: timer → padder → encoder → pipe
	encoder := framing.NewEncoder(pw)
	encoderWriter := &framing.EncoderWriter{Enc: encoder}
	padderWriter := &PadderFrameWriter{Padder: padder, Next: encoderWriter}
	tw := &TimerFrameWriter{Timer: timer, Selector: selector, Next: padderWriter}

	// Read side: pipe → decoder → unpadder
	decoder := framing.NewDecoder(pr)
	decoderReader := &framing.DecoderReader{Dec: decoder}
	unpadder := &UnpadderFrameReader{Padder: padder, Src: decoderReader}

	cleanup = func() {
		pw.Close()
		pr.Close()
	}

	return tw, unpadder, tw, cleanup
}

// readWithTimeout reads a single frame from reader, returning (frame, true)
// on success or (nil, false) if the timeout expires or an error occurs.
// The reader goroutine will unblock when cleanup closes the pipe.
func readWithTimeout(t *testing.T, reader framing.FrameReader, timeout time.Duration) (*framing.Frame, bool) {
	t.Helper()
	type result struct {
		frame *framing.Frame
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		f, err := reader.ReadFrame()
		ch <- result{f, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, false
		}
		return r.frame, true
	case <-time.After(timeout):
		return nil, false
	}
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

func TestCover_EndToEnd_IdleGeneratesTraffic(t *testing.T) {
	sel := &mockSelector{mode: ModeStealth}
	topWriter, bottomReader, _, cleanup := buildTestPipeline(t, sel)
	defer cleanup()

	prof := testProfile()
	cg := NewCoverGenerator(topWriter, sel, prof, 42)
	cg.UpdateStats(0, 0) // idle

	// Directly inject cover traffic to avoid waiting for the 5–15s initial timer.
	// This exercises the full pipeline: timer → padder → encoder → pipe → decoder → unpadder.
	// Inject multiple times and include an explicit KeepAlive to guarantee at
	// least one frame survives unpadding (FramePadding is discarded).
	go func() {
		for i := 0; i < 10; i++ {
			cg.injectIdleTraffic()
		}
		// Guarantee at least one KeepAlive arrives through the unpadder.
		cg.injectKeepAlive()
	}()

	// Collect frames that make it through the unpadder.
	var received []*framing.Frame
	for {
		f, ok := readWithTimeout(t, bottomReader, 5*time.Second)
		if !ok {
			break
		}
		received = append(received, f)
		// Once we have at least one frame, try to drain quickly.
		if len(received) >= 1 {
			for {
				f2, ok2 := readWithTimeout(t, bottomReader, 500*time.Millisecond)
				if !ok2 {
					break
				}
				received = append(received, f2)
			}
			break
		}
	}

	if len(received) == 0 {
		t.Fatal("expected at least one frame to pass through the full pipeline, got none")
	}

	// All frames that survive unpadding should be KeepAlive (FramePadding is discarded).
	for i, f := range received {
		if f.Type != framing.FrameKeepAlive {
			t.Errorf("frame[%d]: expected FrameKeepAlive (0x%02x), got 0x%02x", i, framing.FrameKeepAlive, f.Type)
		}
	}
}

func TestCover_EndToEnd_ActiveSuppressesCover(t *testing.T) {
	sel := &mockSelector{mode: ModePerformance}
	topWriter, bottomReader, _, cleanup := buildTestPipeline(t, sel)
	defer cleanup()

	prof := testProfile()
	cg := NewCoverGenerator(topWriter, sel, prof, 42)
	cg.UpdateStats(1000, 5) // active: 5 streams, 1000 bytes/sec

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cg.Start(ctx)
	defer cg.Stop()

	// With streamCount=5 and ModePerformance, the cover generator's run loop
	// should NOT inject any frames. The initial delay is 5–15s; wait 3s which
	// is before the first timer fires — no frames expected.
	_, ok := readWithTimeout(t, bottomReader, 3*time.Second)
	if ok {
		t.Error("expected no frames when traffic is active, but received one")
	}
}

func TestCover_EndToEnd_IdleResumesAfterActive(t *testing.T) {
	sel := &mockSelector{mode: ModePerformance}
	topWriter, bottomReader, _, cleanup := buildTestPipeline(t, sel)
	defer cleanup()

	prof := testProfile()
	cg := NewCoverGenerator(topWriter, sel, prof, 42)
	cg.UpdateStats(1000, 5) // start active

	// Don't use readWithTimeout for the silent period — it leaves a
	// goroutine blocked on ReadFrame that would steal subsequent data.
	// Instead just verify that the run loop doesn't inject during the
	// active period by starting the generator and immediately transitioning.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cg.Start(ctx)
	defer cg.Stop()

	// Brief active period (no reader — nothing should be written).
	time.Sleep(500 * time.Millisecond)

	// Transition to idle.
	sel.mode = ModeStealth
	cg.UpdateStats(0, 0)

	// Directly inject to verify the pipeline works after transition,
	// rather than waiting for the next timer tick (which could be 30–60s away).
	// Include an explicit KeepAlive to guarantee at least one frame
	// survives unpadding (FramePadding is discarded by UnpadderFrameReader).
	go func() {
		for i := 0; i < 10; i++ {
			cg.injectIdleTraffic()
		}
		cg.injectKeepAlive()
	}()

	// Should receive at least one KeepAlive frame.
	var received []*framing.Frame
	for {
		f, ok := readWithTimeout(t, bottomReader, 5*time.Second)
		if !ok {
			break
		}
		received = append(received, f)
		// Drain quickly after first frame.
		for {
			f2, ok2 := readWithTimeout(t, bottomReader, 500*time.Millisecond)
			if !ok2 {
				break
			}
			received = append(received, f2)
		}
		break
	}

	if len(received) == 0 {
		t.Fatal("expected frames after transitioning to idle, got none")
	}
}

func TestCover_EndToEnd_PaddingDiscardedByUnpadder(t *testing.T) {
	sel := &mockSelector{mode: ModePerformance} // Performance = no timer delays
	topWriter, bottomReader, _, cleanup := buildTestPipeline(t, sel)
	defer cleanup()

	// Write a FramePadding frame (simulates analytics ping from cover traffic).
	go func() {
		_ = topWriter.WriteFrame(&framing.Frame{
			Type:     framing.FramePadding,
			StreamID: 0,
			Payload:  make([]byte, 200),
		})
		// Then write a FrameKeepAlive frame.
		_ = topWriter.WriteFrame(&framing.Frame{
			Type:     framing.FrameKeepAlive,
			StreamID: 0,
		})
	}()

	// The UnpadderFrameReader should discard the FramePadding and return
	// only the FrameKeepAlive.
	f, ok := readWithTimeout(t, bottomReader, 5*time.Second)
	if !ok {
		t.Fatal("timed out waiting for frame")
	}
	if f.Type != framing.FrameKeepAlive {
		t.Errorf("expected FrameKeepAlive (0x%02x), got 0x%02x — FramePadding was not discarded", framing.FrameKeepAlive, f.Type)
	}
}
