package config

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// ChangeKind represents added, modified, or deleted items in a config diff.
type ChangeKind string

const (
	ChangeAdded    ChangeKind = "추가"
	ChangeModified ChangeKind = "수정"
	ChangeDeleted  ChangeKind = "삭제"
)

// ChangeEntry describes a single human-readable configuration change.
type ChangeEntry struct {
	Kind    ChangeKind
	Section string
	Name    string
	Detail  string
}

func (e ChangeEntry) String() string {
	if e.Detail != "" {
		return fmt.Sprintf("[%s] %s %s (%s)", e.Kind, e.Section, e.Name, e.Detail)
	}
	return fmt.Sprintf("[%s] %s %s", e.Kind, e.Section, e.Name)
}

// DiffResult summarizes differences between two Config snapshots.
type DiffResult struct {
	Entries         []ChangeEntry
	RequiresRestart bool
	RestartReasons  []string
}

func (d DiffResult) HasChanges() bool {
	return len(d.Entries) > 0
}

// Diff computes a structured summary of changes from before to after.
func Diff(before, after *Config) DiffResult {
	var res DiffResult
	if before == nil && after == nil {
		return res
	}
	if before == nil {
		before = &Config{
			Clients:  map[string]Client{},
			Profiles: map[string]Profile{},
		}
	}
	if after == nil {
		after = &Config{
			Clients:  map[string]Client{},
			Profiles: map[string]Profile{},
		}
	}

	// Global settings
	if before.LANInterface != after.LANInterface {
		res.Entries = append(res.Entries, ChangeEntry{
			Kind:    ChangeModified,
			Section: "전역 설정",
			Name:    "lan_interface",
			Detail:  fmt.Sprintf("%s -> %s", before.LANInterface, after.LANInterface),
		})
		res.RequiresRestart = true
		res.RestartReasons = append(res.RestartReasons, "lan_interface")
	}
	if !slices.Equal(before.IngressInterfaces, after.IngressInterfaces) {
		res.Entries = append(res.Entries, ChangeEntry{
			Kind:    ChangeModified,
			Section: "전역 설정",
			Name:    "ingress_interfaces",
			Detail:  fmt.Sprintf("[%s] -> [%s]", strings.Join(before.IngressInterfaces, ", "), strings.Join(after.IngressInterfaces, ", ")),
		})
		res.RequiresRestart = true
		res.RestartReasons = append(res.RestartReasons, "ingress_interfaces")
	}
	if before.ProxyPort != after.ProxyPort {
		res.Entries = append(res.Entries, ChangeEntry{
			Kind:    ChangeModified,
			Section: "전역 설정",
			Name:    "proxy_port",
			Detail:  fmt.Sprintf("%d -> %d", before.ProxyPort, after.ProxyPort),
		})
		res.RequiresRestart = true
		res.RestartReasons = append(res.RestartReasons, "proxy_port")
	}
	if before.WakeTimeout != after.WakeTimeout {
		res.Entries = append(res.Entries, ChangeEntry{
			Kind:    ChangeModified,
			Section: "전역 설정",
			Name:    "wake_timeout",
			Detail:  fmt.Sprintf("%s -> %s", before.WakeTimeout, after.WakeTimeout),
		})
	}
	if before.WakeCooldown != after.WakeCooldown {
		res.Entries = append(res.Entries, ChangeEntry{
			Kind:    ChangeModified,
			Section: "전역 설정",
			Name:    "wake_cooldown",
			Detail:  fmt.Sprintf("%s -> %s", before.WakeCooldown, after.WakeCooldown),
		})
	}
	if before.PollInterval != after.PollInterval {
		res.Entries = append(res.Entries, ChangeEntry{
			Kind:    ChangeModified,
			Section: "전역 설정",
			Name:    "poll_interval",
			Detail:  fmt.Sprintf("%s -> %s", before.PollInterval, after.PollInterval),
		})
	}

	// Clients
	for _, name := range SortedKeys(after.Clients) {
		ac := after.Clients[name]
		bc, ok := before.Clients[name]
		if !ok {
			res.Entries = append(res.Entries, ChangeEntry{
				Kind:    ChangeAdded,
				Section: "클라이언트",
				Name:    name,
				Detail:  ac.CIDR,
			})
		} else if bc != ac {
			res.Entries = append(res.Entries, ChangeEntry{
				Kind:    ChangeModified,
				Section: "클라이언트",
				Name:    name,
				Detail:  fmt.Sprintf("%s -> %s", bc.CIDR, ac.CIDR),
			})
		}
	}
	for _, name := range SortedKeys(before.Clients) {
		if _, ok := after.Clients[name]; !ok {
			res.Entries = append(res.Entries, ChangeEntry{
				Kind:    ChangeDeleted,
				Section: "클라이언트",
				Name:    name,
				Detail:  before.Clients[name].CIDR,
			})
		}
	}

	// Profiles
	for _, name := range SortedKeys(after.Profiles) {
		ap := after.Profiles[name]
		bp, ok := before.Profiles[name]
		if !ok {
			res.Entries = append(res.Entries, ChangeEntry{
				Kind:    ChangeAdded,
				Section: "프로파일",
				Name:    name,
				Detail:  fmt.Sprintf("port=%d, wake=%s", ap.Port, ap.Wake),
			})
		} else if bp != ap {
			res.Entries = append(res.Entries, ChangeEntry{
				Kind:    ChangeModified,
				Section: "프로파일",
				Name:    name,
				Detail:  fmt.Sprintf("port=%d, wake=%s", ap.Port, ap.Wake),
			})
		}
	}
	for _, name := range SortedKeys(before.Profiles) {
		if _, ok := after.Profiles[name]; !ok {
			bp := before.Profiles[name]
			res.Entries = append(res.Entries, ChangeEntry{
				Kind:    ChangeDeleted,
				Section: "프로파일",
				Name:    name,
				Detail:  fmt.Sprintf("port=%d", bp.Port),
			})
		}
	}

	// Targets (indexed by name)
	beforeTargets := make(map[string]Target, len(before.Targets))
	for _, t := range before.Targets {
		beforeTargets[t.Name] = t
	}
	afterTargets := make(map[string]Target, len(after.Targets))
	for _, t := range after.Targets {
		afterTargets[t.Name] = t
		bt, ok := beforeTargets[t.Name]
		if !ok {
			res.Entries = append(res.Entries, ChangeEntry{
				Kind:    ChangeAdded,
				Section: "타깃",
				Name:    t.Name,
				Detail:  t.IP,
			})
		} else if !reflect.DeepEqual(bt, t) {
			res.Entries = append(res.Entries, ChangeEntry{
				Kind:    ChangeModified,
				Section: "타깃",
				Name:    t.Name,
				Detail:  t.IP,
			})
		}
	}
	for _, t := range before.Targets {
		if _, ok := afterTargets[t.Name]; !ok {
			res.Entries = append(res.Entries, ChangeEntry{
				Kind:    ChangeDeleted,
				Section: "타깃",
				Name:    t.Name,
				Detail:  t.IP,
			})
		}
	}

	return res
}
