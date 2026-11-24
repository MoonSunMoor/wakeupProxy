package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/md5"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type tarEntry struct {
	name    string
	mode    int64
	isDir   bool
	content []byte
}

func main() {
	var (
		version = flag.String("version", "0.1.0", "Package version")
		arch    = flag.String("arch", "arm64", "Debian architecture (arm64, amd64)")
		outDir  = flag.String("out", "dist", "Output directory for .deb package")
		binPath = flag.String("bin", "", "Optional prebuilt binary path; if empty, cross-compiles cmd/wolproxy")
	)
	flag.Parse()

	goarch := *arch
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fatalf("출력 디렉터리 생성 실패: %v", err)
	}

	var binaryData []byte
	if *binPath != "" {
		var err error
		binaryData, err = os.ReadFile(*binPath)
		if err != nil {
			fatalf("바이너리 읽기 실패(%s): %v", *binPath, err)
		}
	} else {
		tmpBin := filepath.Join(*outDir, fmt.Sprintf("wolproxy-%s-tmp", goarch))
		defer os.Remove(tmpBin)

		ldflags := fmt.Sprintf("-s -w -X main.version=%s", *version)
		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", ldflags, "-o", tmpBin, "./cmd/wolproxy")
		cmd.Env = append(os.Environ(),
			"CGO_ENABLED=0",
			"GOOS=linux",
			"GOARCH="+goarch,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fatalf("linux/%s 바이너리 빌드 실패: %v", goarch, err)
		}
		var err error
		binaryData, err = os.ReadFile(tmpBin)
		if err != nil {
			fatalf("빌드된 바이너리 읽기 실패: %v", err)
		}
	}

	cfgBytes := mustReadLF("packaging/config.yaml")
	unitBytes := mustReadLF("packaging/wolproxy.service")
	postinstBytes := mustReadLF("packaging/postinst")
	prermBytes := mustReadLF("packaging/prerm")
	postrmBytes := mustReadLF("packaging/postrm")

	now := time.Now().UTC().Truncate(time.Second)

	dataEntries := []tarEntry{
		{name: "./", mode: 0o755, isDir: true},
		{name: "./usr/", mode: 0o755, isDir: true},
		{name: "./usr/bin/", mode: 0o755, isDir: true},
		{name: "./usr/bin/wolproxy", mode: 0o755, content: binaryData},
		{name: "./etc/", mode: 0o755, isDir: true},
		{name: "./etc/wolproxy/", mode: 0o755, isDir: true},
		{name: "./etc/wolproxy/config.yaml", mode: 0o644, content: cfgBytes},
		{name: "./lib/", mode: 0o755, isDir: true},
		{name: "./lib/systemd/", mode: 0o755, isDir: true},
		{name: "./lib/systemd/system/", mode: 0o755, isDir: true},
		{name: "./lib/systemd/system/wolproxy.service", mode: 0o644, content: unitBytes},
	}

	var installedBytes int64
	var md5Buf strings.Builder
	for _, e := range dataEntries {
		if e.isDir {
			continue
		}
		installedBytes += int64(len(e.content))
		sum := md5.Sum(e.content)
		relPath := strings.TrimPrefix(e.name, "./")
		fmt.Fprintf(&md5Buf, "%s  %s\n", hex.EncodeToString(sum[:]), relPath)
	}
	installedKB := (installedBytes + 1023) / 1024

	controlContent := fmt.Sprintf(`Package: wolproxy
Version: %s
Section: net
Priority: optional
Architecture: %s
Maintainer: Seowoo Kang <noreply@github.com>
Installed-Size: %d
Depends: nftables, systemd, adduser
Recommends: wireguard-tools
Description: Transparent TCP Wake-on-LAN proxy and TUI editor
 wolproxy intercepts configured TCP ports arriving on trusted ingress
 interfaces (such as WireGuard) via nftables, wakes sleeping LAN targets
 with Wake-on-LAN magic packets when needed, and relays TCP streams.
`, *version, *arch, installedKB)

	conffilesContent := "/etc/wolproxy/config.yaml\n"

	controlEntries := []tarEntry{
		{name: "./", mode: 0o755, isDir: true},
		{name: "./control", mode: 0o644, content: []byte(controlContent)},
		{name: "./conffiles", mode: 0o644, content: []byte(conffilesContent)},
		{name: "./md5sums", mode: 0o644, content: []byte(md5Buf.String())},
		{name: "./postinst", mode: 0o755, content: postinstBytes},
		{name: "./prerm", mode: 0o755, content: prermBytes},
		{name: "./postrm", mode: 0o755, content: postrmBytes},
	}

	controlTarGz, err := buildTarGz(controlEntries, now)
	if err != nil {
		fatalf("control.tar.gz 생성 실패: %v", err)
	}
	dataTarGz, err := buildTarGz(dataEntries, now)
	if err != nil {
		fatalf("data.tar.gz 생성 실패: %v", err)
	}

	debName := fmt.Sprintf("wolproxy_%s_%s.deb", *version, *arch)
	debPath := filepath.Join(*outDir, debName)

	var arBuf bytes.Buffer
	arBuf.WriteString("!<arch>\n")
	writeArMember(&arBuf, "debian-binary", now, 0o100644, []byte("2.0\n"))
	writeArMember(&arBuf, "control.tar.gz", now, 0o100644, controlTarGz)
	writeArMember(&arBuf, "data.tar.gz", now, 0o100644, dataTarGz)

	if err := os.WriteFile(debPath, arBuf.Bytes(), 0o644); err != nil {
		fatalf("deb 파일 쓰기 실패(%s): %v", debPath, err)
	}

	fmt.Printf("패키지 생성 완료: %s (%d bytes)\n", debPath, arBuf.Len())
}

func mustReadLF(path string) []byte {
	raw, err := os.ReadFile(filepath.FromSlash(path))
	if err != nil {
		fatalf("파일 읽기 실패(%s): %v", path, err)
	}
	return bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
}

func buildTarGz(entries []tarEntry, modTime time.Time) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)

	for _, e := range entries {
		hdr := &tar.Header{
			Name:     e.name,
			Mode:     e.mode,
			Uid:      0,
			Gid:      0,
			Uname:    "root",
			Gname:    "root",
			ModTime:  modTime,
			Format:   tar.FormatGNU,
			Typeflag: tar.TypeReg,
		}
		if e.isDir {
			hdr.Typeflag = tar.TypeDir
		} else {
			hdr.Size = int64(len(e.content))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if !e.isDir {
			if _, err := tw.Write(e.content); err != nil {
				return nil, err
			}
		}
	}

	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeArMember(w io.Writer, name string, modTime time.Time, mode int, data []byte) {
	hdr := fmt.Sprintf("%-16s%-12d%-6d%-6d%-8o%-10d`\n",
		name,
		modTime.Unix(),
		0,
		0,
		mode,
		len(data),
	)
	_, _ = io.WriteString(w, hdr)
	_, _ = w.Write(data)
	if len(data)%2 != 0 {
		_, _ = w.Write([]byte{'\n'})
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
