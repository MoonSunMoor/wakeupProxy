package daemon

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/MoonSunMoor/wakeupProxy/internal/proxy"
)

const (
	DefaultRuntimeDir = "/run/wolproxy"
	RuntimeDirEnv     = "WOLPROXY_RUNTIME_DIR"
	stateFileName     = "state.json"
	controlSockName   = "control.sock"
)

// RuntimeDir returns the directory for daemon runtime state and control socket.
func RuntimeDir() string {
	if v := os.Getenv(RuntimeDirEnv); v != "" {
		return v
	}
	return DefaultRuntimeDir
}

// RuntimeState records the configuration actively bound by a running wolproxy daemon.
type RuntimeState struct {
	PID               int       `json:"pid"`
	ConfigPath        string    `json:"config_path"`
	LANInterface      string    `json:"lan_interface"`
	IngressInterfaces []string  `json:"ingress_interfaces"`
	ProxyPort         int       `json:"proxy_port"`
	ListenAddrs       []string  `json:"listen_addrs"`
	StartedAt         time.Time `json:"started_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// NormalizeConfigPath canonicalizes a config file path for equality comparison,
// resolving symlinks via filepath.EvalSymlinks and falling back to filepath.Abs + filepath.Clean
// (including resolving an existing parent directory when the target file does not yet exist).
func NormalizeConfigPath(p string) string {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		return ""
	}
	abs, err := filepath.Abs(trimmed)
	if err != nil {
		abs = filepath.Clean(trimmed)
	} else {
		abs = filepath.Clean(abs)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved)
	}
	dir := filepath.Dir(abs)
	base := filepath.Base(abs)
	if dir != "" && dir != abs {
		if resolvedDir, err := filepath.EvalSymlinks(dir); err == nil {
			return filepath.Join(filepath.Clean(resolvedDir), base)
		}
	}
	return abs
}

// SameConfigPath reports whether two config paths refer to the same canonical file location.
func SameConfigPath(a, b string) bool {
	na := NormalizeConfigPath(a)
	nb := NormalizeConfigPath(b)
	if na == "" || nb == "" {
		return na == nb
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(na, nb)
	}
	return na == nb
}

func NewRuntimeState(cfgPath string, snap proxy.RuntimeSnapshot, startedAt time.Time) RuntimeState {
	now := time.Now().UTC()
	if startedAt.IsZero() {
		startedAt = now
	}
	return RuntimeState{
		PID:               os.Getpid(),
		ConfigPath:        NormalizeConfigPath(cfgPath),
		LANInterface:      snap.LANInterface,
		IngressInterfaces: append([]string(nil), snap.IngressInterfaces...),
		ProxyPort:         snap.ProxyPort,
		ListenAddrs:       append([]string(nil), snap.ListenAddrs...),
		StartedAt:         startedAt,
		UpdatedAt:         now,
	}
}

// WriteRuntimeState atomically writes state.json into dir (mode 0644).
func WriteRuntimeState(dir string, st RuntimeState) error {
	if strings.TrimSpace(dir) == "" {
		return errors.New("런타임 디렉터리가 비어 있습니다")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, ".state.json.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	_ = tmp.Chmod(0o644)
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	dst := filepath.Join(dir, stateFileName)
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// ReadRuntimeState reads state.json from dir if present.
func ReadRuntimeState(dir string) (RuntimeState, bool, error) {
	if dir == "" {
		return RuntimeState{}, false, nil
	}
	data, err := os.ReadFile(filepath.Join(dir, stateFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RuntimeState{}, false, nil
		}
		return RuntimeState{}, false, err
	}
	var st RuntimeState
	if err := json.Unmarshal(data, &st); err != nil {
		return RuntimeState{}, false, err
	}
	return st, true, nil
}

// RemoveRuntimeState deletes state.json from dir on clean daemon shutdown.
func RemoveRuntimeState(dir string) {
	if dir == "" {
		return
	}
	_ = os.Remove(filepath.Join(dir, stateFileName))
}

// HasControlSocket reports whether control.sock currently exists in dir.
func HasControlSocket(dir string) bool {
	if strings.TrimSpace(dir) == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(dir, controlSockName))
	return err == nil
}

type controlRequest struct {
	Cmd string `json:"cmd"`
}

type controlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// ControlServer exposes a synchronous Unix domain control socket (`control.sock`)
// so `wolproxy reload` (`ExecReload`) waits for actual reload validation & nft application.
type ControlServer struct {
	sockPath  string
	ln        net.Listener
	reloadFn  func(ctx context.Context) error
	wg        sync.WaitGroup
	closeOnce sync.Once
	closeErr  error
}

func StartControlServer(dir string, reloadFn func(ctx context.Context) error) (*ControlServer, error) {
	if dir == "" {
		return nil, errors.New("런타임 디렉터리가 비어 있습니다")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	sockPath := filepath.Join(dir, controlSockName)
	_ = os.Remove(sockPath)

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(sockPath, 0o660)

	cs := &ControlServer{
		sockPath: sockPath,
		ln:       ln,
		reloadFn: reloadFn,
	}
	cs.wg.Add(1)
	go func() {
		defer cs.wg.Done()
		cs.acceptLoop()
	}()
	return cs, nil
}

func (cs *ControlServer) acceptLoop() {
	for {
		conn, err := cs.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		cs.wg.Add(1)
		go func(c net.Conn) {
			defer cs.wg.Done()
			cs.handleConn(c)
		}(conn)
	}
}

func (cs *ControlServer) handleConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))

	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		writeControlResp(conn, controlResponse{OK: false, Error: "잘못된 제어 요청입니다"})
		return
	}
	var req controlRequest
	if err := json.Unmarshal(line, &req); err != nil || req.Cmd != "reload" {
		writeControlResp(conn, controlResponse{OK: false, Error: "지원하지 않는 제어 명령입니다"})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := cs.reloadFn(ctx); err != nil {
		writeControlResp(conn, controlResponse{OK: false, Error: err.Error()})
		return
	}
	writeControlResp(conn, controlResponse{OK: true})
}

func writeControlResp(conn net.Conn, resp controlResponse) {
	b, _ := json.Marshal(resp)
	b = append(b, '\n')
	_, _ = conn.Write(b)
}

func (cs *ControlServer) Close() error {
	if cs == nil {
		return nil
	}
	cs.closeOnce.Do(func() {
		cs.closeErr = cs.ln.Close()
		cs.wg.Wait()
		_ = os.Remove(cs.sockPath)
	})
	return cs.closeErr
}

// RequestReload connects to the daemon's Unix control socket and waits synchronously
// for the configuration reload to finish, returning an error if validation or nftables failed.
func RequestReload(ctx context.Context, dir string) error {
	sockPath := filepath.Join(dir, controlSockName)
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return fmt.Errorf("실행 중인 wolproxy 제어 소켓(%s) 연결 실패: %w", sockPath, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	}

	reqBytes, _ := json.Marshal(controlRequest{Cmd: "reload"})
	reqBytes = append(reqBytes, '\n')
	if _, err := conn.Write(reqBytes); err != nil {
		return fmt.Errorf("재적재 요청 전송 실패: %w", err)
	}

	respLine, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return fmt.Errorf("재적재 응답 수신 실패: %w", err)
	}
	var resp controlResponse
	if err := json.Unmarshal(respLine, &resp); err != nil {
		return fmt.Errorf("재적재 응답 파싱 실패: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("설정 재적재 거부됨: %s", resp.Error)
	}
	return nil
}
