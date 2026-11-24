package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func benchmarkRelay(b *testing.B, withIdle bool) {
	const chunkSize = 64 * 1024
	payload := bytes.Repeat([]byte("A"), chunkSize)

	backendLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer backendLn.Close()

	go func() {
		conn, err := backendLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	proxyLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer proxyLn.Close()

	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		cConn, err := proxyLn.Accept()
		if err != nil {
			return
		}
		tConn, err := net.Dial("tcp4", backendLn.Addr().String())
		if err != nil {
			_ = cConn.Close()
			return
		}
		var idle *idleState
		if withIdle {
			idle = newIdleState(time.Now(), 30*time.Minute, 1024)
		}
		_, _, _ = relayBidirectional(cConn, tConn, idle)
	}()

	client, err := net.Dial("tcp4", proxyLn.Addr().String())
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(chunkSize * 2) // upstream + echoed downstream
	b.ReportAllocs()
	b.ResetTimer()

	recvBuf := make([]byte, chunkSize)
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(client, recvBuf); err != nil {
			b.Fatal(err)
		}
	}

	b.StopTimer()
	_ = client.Close()
	<-relayDone
}

func BenchmarkRelayWithoutIdleTracking(b *testing.B) {
	benchmarkRelay(b, false)
}

func BenchmarkRelayWithIdleTracking(b *testing.B) {
	benchmarkRelay(b, true)
}
