package nft

import (
	"strings"
	"testing"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
)

func TestBuildRulesetMatchesSpec(t *testing.T) {
	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         13389,
		Profiles: map[string]config.Profile{
			"rdp":        {Port: 3389, Wake: "auto"},
			"ssh":        {Port: 22, Wake: "auto"},
			"ssh-manual": {Port: 22, Wake: "never"},
		},
		Targets: []config.Target{
			{
				Name:     "pc1",
				IP:       "192.168.0.21",
				MAC:      "aa:bb:cc:dd:ee:01",
				Profiles: []string{"rdp", "ssh-manual"},
			},
			{
				Name:     "pc2",
				IP:       "192.168.0.22",
				Alias:    "10.66.1.12",
				MAC:      "aa:bb:cc:dd:ee:02",
				Profiles: []string{"ssh"},
			},
		},
	}

	got, err := BuildRuleset(cfg.IngressInterfaces, cfg.ProxyPort, cfg)
	if err != nil {
		t.Fatalf("BuildRuleset error: %v", err)
	}

	wantSubstrings := []string{
		"table inet wolproxy\ndelete table inet wolproxy\ntable inet wolproxy {",
		`set ingress { type ifname; elements = { "wg0" } }`,
		`elements = { 192.168.0.21 . 3389, 192.168.0.21 . 22, 192.168.0.22 . 22, 10.66.1.12 . 22 }`,
		`iifname @ingress ip daddr . tcp dport @capture redirect to :13389`,
	}
	for _, sub := range wantSubstrings {
		if !strings.Contains(got, sub) {
			t.Errorf("generated ruleset missing %q:\n%s", sub, got)
		}
	}
}

func TestBuildRulesetEmptyCaptureOmitsElements(t *testing.T) {
	cfg := &config.Config{
		LANInterface:      "eth0",
		IngressInterfaces: []string{"wg0"},
		ProxyPort:         13389,
		Profiles:          map[string]config.Profile{},
		Targets:           []config.Target{},
	}
	got, err := BuildRuleset(cfg.IngressInterfaces, cfg.ProxyPort, cfg)
	if err != nil {
		t.Fatalf("BuildRuleset error: %v", err)
	}
	if strings.Contains(got, "elements = {  }") {
		t.Fatalf("empty capture set must omit elements clause, got:\n%s", got)
	}
}
