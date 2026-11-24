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

// idleState tracks rolling-window bidirectional byte throughput when idle_timeout > 0.
type idleState struct {
	timeout   time.Duration
	maxBytes  int64
	startedAt time.Time
	counter   atomic.Int64
	samples   []byteSample
}

func newIdleState(now time.Time, timeout time.Duration, maxBytes int64) *idleState {
	return &idleState{
		timeout:   timeout,
		maxBytes:  maxBytes,
		startedAt: now,
		samples:   []byteSample{{at: now, total: 0}},
	}
}

// check records a sample at now and reports true if at least s.timeout has elapsed
// since relay start and bidirectional bytes transferred over the last s.timeout window
// are <= s.maxBytes.
func (s *idleState) check(now time.Time) bool {
	total := s.counter.Load()
	cutoff := now.Add(-s.timeout)

	if now.Sub(s.startedAt) < s.timeout {
		s.samples = append(s.samples, byteSample{at: now, total: total})
		return false
	}

	// Find the newest sample at or before cutoff (baseline at window start).
	baseline := s.samples[0].total
	pruneIdx := 0
	for i, smp := range s.samples {
		if !smp.at.After(cutoff) {
			baseline = smp.total
			pruneIdx = i
		} else {
			break
		}
	}
	if pruneIdx > 0 {
		// Keep pruneIdx as anchor for subsequent ticks until superseded.
		s.samples = append([]byteSample(nil), s.samples[pruneIdx:]...)
	}
	s.samples = append(s.samples, byteSample{at: now, total: total})

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
