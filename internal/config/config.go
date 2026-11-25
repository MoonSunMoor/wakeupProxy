package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	DefaultConfigPath = "/etc/wolproxy/config.yaml"
	ManagedHeader     = "# 이 파일은 wolproxy TUI가 관리한다. 주석은 저장 시 사라지므로 메모는 note에 쓴다."

	MinProxyPort        = 1024
	MaxPort             = 65535
	DefaultProxyPort    = 13389
	DefaultWakeTimeout  = 120 * time.Second
	DefaultWakeCooldown = 10 * time.Second
	DefaultPollInterval = 2 * time.Second

	WakeAuto  = "auto"
	WakeNever = "never"
)

// Duration wraps time.Duration for clean YAML marshaling/unmarshaling (including integer 0).
type Duration time.Duration

func (d Duration) Std() time.Duration {
	return time.Duration(d)
}

func (d Duration) String() string {
	td := time.Duration(d)
	if td == 0 {
		return "0s"
	}
	// Prefer concise single-unit output (e.g. "120s" instead of "2m0s", "30m" instead of "30m0s").
	if td > 0 {
		if td%(time.Hour) == 0 {
			return fmt.Sprintf("%dh", td/time.Hour)
		}
		if td%(time.Minute) == 0 && td >= 5*time.Minute {
			return fmt.Sprintf("%dm", td/time.Minute)
		}
		if td%(time.Second) == 0 {
			return fmt.Sprintf("%ds", td/time.Second)
		}
	}
	return td.String()
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	raw := strings.TrimSpace(value.Value)
	if raw == "" || raw == "0" {
		*d = 0
		return nil
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if n == 0 {
			*d = 0
			return nil
		}
		return fmt.Errorf("시간 값에는 단위가 필요합니다(예: %ds): %q", n, raw)
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("잘못된 시간 형식입니다(%q): %w", raw, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) MarshalYAML() (any, error) {
	return d.String(), nil
}

// ParseDurationInput parses user input from TUI forms (accepts "", "0", "0s", "120s", "30m", etc.).
func ParseDurationInput(s string) (Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		if n == 0 {
			return 0, nil
		}
		return 0, fmt.Errorf("단위를 함께 입력해 주세요 (예: %ds, %dm)", n, n)
	}
	td, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("잘못된 시간 형식입니다: %q", s)
	}
	return Duration(td), nil
}

// Client represents a trusted source IP or CIDR on an ingress network.
type Client struct {
	CIDR string `yaml:"cidr"`
	Note string `yaml:"note,omitempty"`
}

// Profile bundles a TCP port with wake and idle policies.
type Profile struct {
	Port        int      `yaml:"port"`
	Wake        string   `yaml:"wake"`
	IdleTimeout Duration `yaml:"idle_timeout,omitempty"`
	IdleBytes   int64    `yaml:"idle_bytes,omitempty"`
	Note        string   `yaml:"note,omitempty"`
}

// Target represents a LAN host managed by wolproxy.
type Target struct {
	Name     string   `yaml:"name"`
	Note     string   `yaml:"note,omitempty"`
	IP       string   `yaml:"ip"`
	Alias    string   `yaml:"alias,omitempty"`
	MAC      string   `yaml:"mac"`
	Profiles []string `yaml:"profiles"`
	Allow    []string `yaml:"allow"`
}

// Config represents the entire /etc/wolproxy/config.yaml structure.
type Config struct {
	LANInterface      string             `yaml:"lan_interface"`
	IngressInterfaces []string           `yaml:"ingress_interfaces"`
	ProxyPort         int                `yaml:"proxy_port"`
	WakeTimeout       Duration           `yaml:"wake_timeout"`
	WakeCooldown      Duration           `yaml:"wake_cooldown"`
	PollInterval      Duration           `yaml:"poll_interval"`
	Clients           map[string]Client  `yaml:"clients"`
	Profiles          map[string]Profile `yaml:"profiles"`
	Targets           []Target           `yaml:"targets"`
}

// LoadMeta captures file-level metadata needed by the TUI when saving.
type LoadMeta struct {
	ModTime         time.Time
	Exists          bool
	HasUserComments bool
}

// Preset describes a built-in profile template.
type Preset struct {
	Name    string
	Label   string
	Profile Profile
}

// BuiltinPresets returns the built-in presets (copied into default config / TUI, never implicitly applied).
func BuiltinPresets() []Preset {
	return []Preset{
		{
			Name:  "rdp",
			Label: "rdp (3389 / auto)",
			Profile: Profile{
				Port: 3389,
				Wake: WakeAuto,
			},
		},
		{
			Name:  "ssh",
			Label: "ssh (22 / auto)",
			Profile: Profile{
				Port: 22,
				Wake: WakeAuto,
			},
		},
	}
}

// DefaultConfig returns a starter configuration containing the built-in presets.
func DefaultConfig() *Config {
	cfg := &Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         DefaultProxyPort,
		WakeTimeout:       Duration(DefaultWakeTimeout),
		WakeCooldown:      Duration(DefaultWakeCooldown),
		PollInterval:      Duration(DefaultPollInterval),
		Clients:           map[string]Client{},
		Profiles:          map[string]Profile{},
		Targets:           []Target{},
	}
	for _, p := range BuiltinPresets() {
		cfg.Profiles[p.Name] = p.Profile
	}
	return cfg
}

// Clone returns a deep copy of Config so forms and diffs never alias slices or maps.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}
	out := &Config{
		LANInterface:      c.LANInterface,
		IngressInterfaces: append([]string(nil), c.IngressInterfaces...),
		ProxyPort:         c.ProxyPort,
		WakeTimeout:       c.WakeTimeout,
		WakeCooldown:      c.WakeCooldown,
		PollInterval:      c.PollInterval,
		Clients:           make(map[string]Client, len(c.Clients)),
		Profiles:          make(map[string]Profile, len(c.Profiles)),
		Targets:           make([]Target, len(c.Targets)),
	}
	for k, v := range c.Clients {
		out.Clients[k] = v
	}
	for k, v := range c.Profiles {
		out.Profiles[k] = v
	}
	for i, t := range c.Targets {
		tCopy := t
		tCopy.Profiles = append([]string(nil), t.Profiles...)
		tCopy.Allow = append([]string(nil), t.Allow...)
		out.Targets[i] = tCopy
	}
	return out
}

// ParseBytes parses YAML bytes into Config (applying proxy_port and timing defaults when omitted)
// and detects whether any non-header user comments were present.
func ParseBytes(data []byte) (*Config, bool, error) {
	var docNode yaml.Node
	if err := yaml.Unmarshal(data, &docNode); err != nil {
		return nil, false, fmt.Errorf("YAML 파싱 실패: %w", err)
	}
	hasComments := detectNonHeaderComments(&docNode)

	cfg := &Config{
		ProxyPort:    DefaultProxyPort,
		WakeTimeout:  Duration(DefaultWakeTimeout),
		WakeCooldown: Duration(DefaultWakeCooldown),
		PollInterval: Duration(DefaultPollInterval),
		Clients:      map[string]Client{},
		Profiles:     map[string]Profile{},
		Targets:      []Target{},
	}

	if len(bytes.TrimSpace(data)) == 0 || len(docNode.Content) == 0 {
		return cfg, hasComments, nil
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, hasComments, fmt.Errorf("설정 디코딩 실패: %w", err)
	}
	if cfg.Clients == nil {
		cfg.Clients = map[string]Client{}
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]Profile{}
	}
	if cfg.Targets == nil {
		cfg.Targets = []Target{}
	}
	for i := range cfg.Targets {
		if cfg.Targets[i].Profiles == nil {
			cfg.Targets[i].Profiles = []string{}
		}
		if cfg.Targets[i].Allow == nil {
			cfg.Targets[i].Allow = []string{}
		}
	}
	return cfg, hasComments, nil
}

// Load reads and parses a YAML configuration file along with file metadata.
func Load(path string) (*Config, LoadMeta, error) {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, LoadMeta{Exists: false}, err
		}
		return nil, LoadMeta{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, LoadMeta{}, err
	}
	cfg, hasComments, err := ParseBytes(data)
	if err != nil {
		return nil, LoadMeta{ModTime: st.ModTime(), Exists: true, HasUserComments: hasComments}, err
	}
	return cfg, LoadMeta{
		ModTime:         st.ModTime(),
		Exists:          true,
		HasUserComments: hasComments,
	}, nil
}

func detectNonHeaderComments(root *yaml.Node) bool {
	if root == nil {
		return false
	}
	managedTrimmed := strings.TrimSpace(ManagedHeader)
	firstHeaderSkipped := false

	var walk func(n *yaml.Node, isTopFirst bool) bool
	walk = func(n *yaml.Node, isTopFirst bool) bool {
		if n == nil {
			return false
		}
		if n.HeadComment != "" {
			lines := strings.Split(n.HeadComment, "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				if isTopFirst && !firstHeaderSkipped && trimmed == managedTrimmed {
					firstHeaderSkipped = true
					continue
				}
				return true
			}
		}
		if strings.TrimSpace(n.LineComment) != "" || strings.TrimSpace(n.FootComment) != "" {
			return true
		}
		for idx, child := range n.Content {
			if walk(child, isTopFirst && idx == 0) {
				return true
			}
		}
		return false
	}
	return walk(root, true)
}

// Marshal formats the Config into canonical YAML with the managed header comment.
func Marshal(cfg *Config) ([]byte, error) {
	if cfg == nil {
		return nil, errors.New("설정이 비어 있습니다")
	}

	root := &yaml.Node{Kind: yaml.MappingNode}
	appendScalarKV := func(key string, val string, tag string) {
		root.Content = append(root.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: val},
		)
	}

	appendScalarKV("lan_interface", cfg.LANInterface, "!!str")

	ingSeq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
	for _, iface := range cfg.IngressInterfaces {
		ingSeq.Content = append(ingSeq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: iface})
	}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ingress_interfaces"},
		ingSeq,
	)

	appendScalarKV("proxy_port", strconv.Itoa(cfg.ProxyPort), "!!int")
	appendScalarKV("wake_timeout", cfg.WakeTimeout.String(), "!!str")
	appendScalarKV("wake_cooldown", cfg.WakeCooldown.String(), "!!str")
	appendScalarKV("poll_interval", cfg.PollInterval.String(), "!!str")

	// clients (sorted by name, flow style matching spec example)
	clientsMap := &yaml.Node{Kind: yaml.MappingNode}
	clientNames := SortedKeys(cfg.Clients)
	for _, name := range clientNames {
		c := cfg.Clients[name]
		cNode := &yaml.Node{Kind: yaml.MappingNode, Style: yaml.FlowStyle}
		cNode.Content = append(cNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "cidr"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: c.CIDR},
		)
		if c.Note != "" {
			cNode.Content = append(cNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "note"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Style: yaml.DoubleQuotedStyle, Value: c.Note},
			)
		}
		clientsMap.Content = append(clientsMap.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
			cNode,
		)
	}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "clients"},
		clientsMap,
	)

	// profiles (sorted by name, flow style matching spec example)
	profilesMap := &yaml.Node{Kind: yaml.MappingNode}
	profileNames := SortedKeys(cfg.Profiles)
	for _, name := range profileNames {
		p := cfg.Profiles[name]
		pNode := &yaml.Node{Kind: yaml.MappingNode, Style: yaml.FlowStyle}
		pNode.Content = append(pNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "port"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.Itoa(p.Port)},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "wake"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p.Wake},
		)
		if p.IdleTimeout > 0 {
			pNode.Content = append(pNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "idle_timeout"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: p.IdleTimeout.String()},
			)
		}
		if p.IdleBytes > 0 {
			pNode.Content = append(pNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "idle_bytes"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: strconv.FormatInt(p.IdleBytes, 10)},
			)
		}
		if p.Note != "" {
			pNode.Content = append(pNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "note"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Style: yaml.DoubleQuotedStyle, Value: p.Note},
			)
		}
		profilesMap.Content = append(profilesMap.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
			pNode,
		)
	}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "profiles"},
		profilesMap,
	)

	// targets (sequence in order)
	targetsSeq := &yaml.Node{Kind: yaml.SequenceNode}
	for _, t := range cfg.Targets {
		tNode := &yaml.Node{Kind: yaml.MappingNode}
		tNode.Content = append(tNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "name"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t.Name},
		)
		if t.Note != "" {
			tNode.Content = append(tNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "note"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Style: yaml.DoubleQuotedStyle, Value: t.Note},
			)
		}
		tNode.Content = append(tNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "ip"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t.IP},
		)
		if t.Alias != "" {
			tNode.Content = append(tNode.Content,
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "alias"},
				&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t.Alias},
			)
		}
		tNode.Content = append(tNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "mac"},
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Style: yaml.DoubleQuotedStyle, Value: t.MAC},
		)

		profSeq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, pn := range t.Profiles {
			profSeq.Content = append(profSeq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: pn})
		}
		tNode.Content = append(tNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "profiles"},
			profSeq,
		)

		allowSeq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle}
		for _, cn := range t.Allow {
			allowSeq.Content = append(allowSeq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: cn})
		}
		tNode.Content = append(tNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "allow"},
			allowSeq,
		)
		targetsSeq.Content = append(targetsSeq.Content, tNode)
	}
	root.Content = append(root.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "targets"},
		targetsSeq,
	)

	var buf bytes.Buffer
	buf.WriteString(ManagedHeader)
	buf.WriteByte('\n')

	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

var ErrExternalModification = errors.New("설정 파일이 외부에서 수정되었습니다")

// CheckExternalModification reports whether path's ModTime differs from expected.
func CheckExternalModification(path string, meta LoadMeta) (bool, error) {
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return meta.Exists, nil
		}
		return false, err
	}
	if !meta.Exists {
		// File was created externally since TUI opened.
		return true, nil
	}
	return !st.ModTime().Equal(meta.ModTime), nil
}

var syncDirFn = syncDir

func isIgnorableDirSyncError(err error) bool {
	return errors.Is(err, syscall.EINVAL) ||
		errors.Is(err, syscall.ENOTSUP) ||
		errors.Is(err, syscall.EOPNOTSUPP) ||
		errors.Is(err, syscall.EBADF)
}

// SaveAtomic backs up any existing config file to path+".bak", writes the managed
// YAML to a sibling temporary file with mode 0644 (readable by wolproxy user),
// renames it into place, and fsyncs the parent directory.
func SaveAtomic(path string, cfg *Config) (time.Time, error) {
	return SaveAtomicChecked(path, cfg, nil)
}

// SaveAtomicChecked performs SaveAtomic while verifying expected LoadMeta (when non-nil)
// immediately before backing up and renaming, preventing silent overwrite races.
func SaveAtomicChecked(path string, cfg *Config, expected *LoadMeta) (time.Time, error) {
	modTime, _, err := SaveAtomicCheckedWithWarning(path, cfg, expected)
	return modTime, err
}

// SaveAtomicCheckedWithWarning performs SaveAtomicChecked and additionally surfaces any
// non-ignorable directory fsync I/O failure after os.Rename succeeds as a warning rather
// than a fatal save error (since the target file has already been atomically replaced).
// Filesystem-unsupported directory fsync errors (EINVAL, ENOTSUP, EOPNOTSUPP, EBADF) are ignored.
func SaveAtomicCheckedWithWarning(path string, cfg *Config, expected *LoadMeta) (time.Time, error, error) {
	encoded, err := Marshal(cfg)
	if err != nil {
		return time.Time{}, nil, err
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return time.Time{}, nil, fmt.Errorf("설정 디렉터리 생성 실패: %w", err)
	}

	if expected != nil {
		changed, err := CheckExternalModification(path, *expected)
		if err != nil {
			return time.Time{}, nil, err
		}
		if changed {
			return time.Time{}, nil, ErrExternalModification
		}
	}

	var perm os.FileMode = 0o644
	var prevData []byte
	var hadPrev bool
	if data, err := os.ReadFile(path); err == nil {
		prevData = data
		hadPrev = true
		if st, statErr := os.Stat(path); statErr == nil && st.Mode().Perm() != 0 {
			perm = st.Mode().Perm()
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return time.Time{}, nil, fmt.Errorf("기존 설정 파일 읽기 실패: %w", err)
	}

	tmpFile, err := os.CreateTemp(dir, ".config.yaml.tmp-*")
	if err != nil {
		return time.Time{}, nil, fmt.Errorf("임시 파일 생성 실패: %w", err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(encoded); err != nil {
		_ = tmpFile.Close()
		return time.Time{}, nil, fmt.Errorf("임시 파일 쓰기 실패: %w", err)
	}
	if err := tmpFile.Chmod(perm); err != nil {
		_ = tmpFile.Close()
		return time.Time{}, nil, fmt.Errorf("파일 권한 설정 실패: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return time.Time{}, nil, fmt.Errorf("파일 동기화 실패: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return time.Time{}, nil, fmt.Errorf("임시 파일 닫기 실패: %w", err)
	}

	// Re-verify mtime right before backup + atomic rename to narrow the TOCTOU window.
	if expected != nil {
		changed, err := CheckExternalModification(path, *expected)
		if err != nil {
			return time.Time{}, nil, err
		}
		if changed {
			return time.Time{}, nil, ErrExternalModification
		}
	}

	if hadPrev {
		bakPath := path + ".bak"
		if err := writeFileSynced(bakPath, prevData, perm); err != nil {
			return time.Time{}, nil, fmt.Errorf("백업 파일(%s) 저장 실패: %w", bakPath, err)
		}
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return time.Time{}, nil, fmt.Errorf("설정 파일 교체 실패: %w", err)
	}
	cleanup = false

	var syncWarn error
	if dErr := syncDirFn(dir); dErr != nil && !isIgnorableDirSyncError(dErr) {
		syncWarn = fmt.Errorf("설정 디렉터리 동기화(fsync) 실패: %w", dErr)
	}

	st, err := os.Stat(path)
	if err != nil {
		return time.Time{}, syncWarn, nil
	}
	return st.ModTime(), syncWarn, nil
}

func writeFileSynced(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// SortedKeys returns sorted keys of map m.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TargetsUsingClient returns names of all targets referencing clientName in Allow.
func (c *Config) TargetsUsingClient(clientName string) []string {
	var out []string
	for _, t := range c.Targets {
		for _, a := range t.Allow {
			if a == clientName {
				out = append(out, t.Name)
				break
			}
		}
	}
	return out
}

// TargetsUsingProfile returns names of all targets referencing profileName in Profiles.
func (c *Config) TargetsUsingProfile(profileName string) []string {
	var out []string
	for _, t := range c.Targets {
		for _, p := range t.Profiles {
			if p == profileName {
				out = append(out, t.Name)
				break
			}
		}
	}
	return out
}

// RenameClient renames oldName to newName and updates all target Allow references.
func (c *Config) RenameClient(oldName, newName string) {
	if oldName == newName {
		return
	}
	cl, ok := c.Clients[oldName]
	if !ok {
		return
	}
	delete(c.Clients, oldName)
	c.Clients[newName] = cl
	for i := range c.Targets {
		for j, a := range c.Targets[i].Allow {
			if a == oldName {
				c.Targets[i].Allow[j] = newName
			}
		}
	}
}

// RenameProfile renames oldName to newName and updates all target Profiles references.
func (c *Config) RenameProfile(oldName, newName string) {
	if oldName == newName {
		return
	}
	pr, ok := c.Profiles[oldName]
	if !ok {
		return
	}
	delete(c.Profiles, oldName)
	c.Profiles[newName] = pr
	for i := range c.Targets {
		for j, p := range c.Targets[i].Profiles {
			if p == oldName {
				c.Targets[i].Profiles[j] = newName
			}
		}
	}
}
