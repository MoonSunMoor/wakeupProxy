package proxy

import (
	"io"
	"net"
	"sync/atomic"
	"time"
)

type closeWriter interface {
	CloseWrite() error
}

func configureKeepAlive(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
}

func halfCloseWrite(c net.Conn) {
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

type countingReader struct {
	r       io.Reader
	counter *atomic.Int64
}

func (cr countingReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 {
		cr.counter.Add(int64(n))
	}
	return n, err
}

type byteSample struct {
	at    time.Time
	total int64
}

const (
	idleRingCap     = 128
	idleTargetSlots = 96
)

// idleState tracks rolling-window bidirectional byte throughput when idle_timeout > 0
// using a fixed-size bucketed ring buffer (O(1) time and zero heap allocations per tick).
type idleState struct {
	timeout    time.Duration
	maxBytes   int64
	startedAt  time.Time
	step       time.Duration
	counter    atomic.Int64
	buf        [idleRingCap]byteSample
	head       int
	count      int
	lastBucket int64
}

func newIdleState(now time.Time, timeout time.Duration, maxBytes int64) *idleState {
	step := max(timeout/idleTargetSlots, time.Millisecond)
	st := &idleState{
		timeout:    timeout,
		maxBytes:   maxBytes,
		startedAt:  now,
		step:       step,
		count:      1,
		lastBucket: -1,
	}
	st.buf[0] = byteSample{at: now, total: 0}
	return st
}

func (s *idleState) sampleAt(offset int) *byteSample {
	return &s.buf[(s.head+offset)%idleRingCap]
}

func (s *idleState) recordSample(now time.Time, total int64) {
	elapsed := now.Sub(s.startedAt)
	if elapsed < 0 {
		elapsed = 0
	}
	b := int64(elapsed / s.step)
	if s.count >= 2 && b == s.lastBucket {
		tail := s.sampleAt(s.count - 1)
		if !now.Before(tail.at) {
			tail.at = now
			tail.total = total
		}
		return
	}
	if s.count == idleRingCap {
		s.head = (s.head + 1) % idleRingCap
		s.count--
	}
	*s.sampleAt(s.count) = byteSample{at: now, total: total}
	s.count++
	if b > s.lastBucket {
		s.lastBucket = b
	}
}

// check records a sample at now and reports true if at least s.timeout has elapsed
// since relay start and bidirectional bytes transferred over the last s.timeout window
// are <= s.maxBytes.
func (s *idleState) check(now time.Time) bool {
	total := s.counter.Load()
	if now.Sub(s.startedAt) < s.timeout {
		s.recordSample(now, total)
		return false
	}

	cutoff := now.Add(-s.timeout)
	// Advance head while a newer sample is also at or before cutoff, so sampleAt(0)
	// remains the newest recorded sample with at <= cutoff.
	for s.count >= 2 && !s.sampleAt(1).at.After(cutoff) {
		s.head = (s.head + 1) % idleRingCap
		s.count--
	}
	baseline := s.sampleAt(0).total
	s.recordSample(now, total)

	transferredInWindow := total - baseline
	return transferredInWindow <= s.maxBytes
}

// relayBidirectional copies bytes between clientConn and targetConn using 2 goroutines
// total (the caller goroutine + 1 helper goroutine). When idleState is nil (idle_timeout == 0),
// unwrapped io.Copy(dstTCP, srcTCP) is used so Go utilizes Linux zero-copy splice(2).
func relayBidirectional(clientConn, targetConn net.Conn, idle *idleState) (int64, error, error) {
	configureKeepAlive(clientConn)
	configureKeepAlive(targetConn)

	type copyResult struct {
		n   int64
		err error
	}
	upCh := make(chan copyResult, 1)

	go func() {
		var n int64
		var err error
		if idle == nil {
			n, err = io.Copy(targetConn, clientConn)
		} else {
			n, err = io.Copy(targetConn, countingReader{r: clientConn, counter: &idle.counter})
		}
		if err == nil {
			halfCloseWrite(targetConn)
		} else {
			// Abnormal read/write failure: close target to unblock reverse direction promptly.
			_ = targetConn.Close()
		}
		upCh <- copyResult{n: n, err: err}
	}()

	var downN int64
	var downErr error
	if idle == nil {
		downN, downErr = io.Copy(clientConn, targetConn)
	} else {
		downN, downErr = io.Copy(clientConn, countingReader{r: targetConn, counter: &idle.counter})
	}
	if downErr == nil {
		halfCloseWrite(clientConn)
	} else {
		_ = clientConn.Close()
	}

	upRes := <-upCh
	_ = clientConn.Close()
	_ = targetConn.Close()

	return upRes.n + downN, upRes.err, downErr
}
