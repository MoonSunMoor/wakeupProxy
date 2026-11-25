package config

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
)

// SectionKind identifies which TUI tab/section owns a ValidationError.
type SectionKind string

const (
	SectionGlobal  SectionKind = "global"
	SectionTarget  SectionKind = "target"
	SectionClient  SectionKind = "client"
	SectionProfile SectionKind = "profile"
)

// ValidationError describes a single configuration error with enough metadata
// for the TUI to jump directly to the offending item's edit form.
type ValidationError struct {
	Section  SectionKind
	ItemName string
	Field    string
	Message  string
}

func (e ValidationError) Error() string {
	switch e.Section {
	case SectionGlobal:
		if e.Field != "" {
			return fmt.Sprintf("[전역 설정 / %s] %s", e.Field, e.Message)
		}
		return fmt.Sprintf("[전역 설정] %s", e.Message)
	case SectionTarget:
		name := e.ItemName
		if name == "" {
			name = "(이름 없음)"
		}
		return fmt.Sprintf("[타깃 %s / %s] %s", name, e.Field, e.Message)
	case SectionClient:
		name := e.ItemName
		if name == "" {
			name = "(이름 없음)"
		}
		return fmt.Sprintf("[클라이언트 %s / %s] %s", name, e.Field, e.Message)
	case SectionProfile:
		name := e.ItemName
		if name == "" {
			name = "(이름 없음)"
		}
		return fmt.Sprintf("[프로파일 %s / %s] %s", name, e.Field, e.Message)
	default:
		return e.Message
	}
}

// ValidationErrorList aggregates multiple ValidationError items as a standard error.
type ValidationErrorList []ValidationError

func (list ValidationErrorList) Error() string {
	if len(list) == 0 {
		return ""
	}
	msgs := make([]string, len(list))
	for i, e := range list {
		msgs[i] = e.Error()
	}
	return strings.Join(msgs, "\n")
}

// ValidateOptions controls context-sensitive validation rules.
type ValidateOptions struct {
	// StrictInterfaces treats missing or unaddressed LAN/ingress interfaces as errors
	// (used on `wolproxy serve` startup). When false (`check`, reload, TUI save),
	// missing or unaddressed interfaces are reported in Warnings instead of Errors.
	StrictInterfaces bool
}

// ValidationReport separates blocking configuration errors from non-blocking warnings.
type ValidationReport struct {
	Errors   ValidationErrorList
	Warnings ValidationErrorList
}

// Validate checks the entire configuration with StrictInterfaces enabled (`serve` startup rules).
func Validate(cfg *Config, ifaces netutil.Provider) ValidationErrorList {
	return ValidateWithOptions(cfg, ifaces, ValidateOptions{StrictInterfaces: true}).Errors
}

// ValidateWithOptions checks the configuration according to opts and returns both Errors and Warnings.
func ValidateWithOptions(cfg *Config, ifaces netutil.Provider, opts ValidateOptions) ValidationReport {
	var errs ValidationErrorList
	var warns ValidationErrorList
	addIfaceIssue := func(ve ValidationError) {
		if opts.StrictInterfaces {
			errs = append(errs, ve)
		} else {
			warns = append(warns, ve)
		}
	}

	if cfg == nil {
		errs = append(errs, ValidationError{
			Section: SectionGlobal,
			Message: "설정이 비어 있습니다",
		})
		return ValidationReport{Errors: errs}
	}
	if ifaces == nil {
		ifaces = netutil.SystemProvider{}
	}

	// 1. Global settings
	lanName := strings.TrimSpace(cfg.LANInterface)
	var lanInfo netutil.InterfaceInfo
	var hasLANInfo bool
	if lanName == "" {
		errs = append(errs, ValidationError{
			Section: SectionGlobal,
			Field:   "lan_interface",
			Message: "LAN 인터페이스를 지정해야 합니다",
		})
	} else {
		info, err := ifaces.InterfaceByName(lanName)
		if err != nil {
			addIfaceIssue(ValidationError{
				Section: SectionGlobal,
				Field:   "lan_interface",
				Message: fmt.Sprintf("존재하지 않는 LAN 인터페이스입니다: %s", lanName),
			})
		} else if len(info.Prefixes) == 0 {
			addIfaceIssue(ValidationError{
				Section: SectionGlobal,
				Field:   "lan_interface",
				Message: fmt.Sprintf("LAN 인터페이스(%s)에 IPv4 주소가 없습니다", lanName),
			})
		} else {
			lanInfo = info
			hasLANInfo = true
		}
	}

	if len(cfg.IngressInterfaces) == 0 {
		errs = append(errs, ValidationError{
			Section: SectionGlobal,
			Field:   "ingress_interfaces",
			Message: "유입 인터페이스를 하나 이상 지정해야 합니다",
		})
	} else {
		seenIface := make(map[string]bool, len(cfg.IngressInterfaces))
		for _, rawName := range cfg.IngressInterfaces {
			name := strings.TrimSpace(rawName)
			if name == "" {
				errs = append(errs, ValidationError{
					Section: SectionGlobal,
					Field:   "ingress_interfaces",
					Message: "빈 유입 인터페이스 이름이 포함되어 있습니다",
				})
				continue
			}
			if seenIface[name] {
				errs = append(errs, ValidationError{
					Section: SectionGlobal,
					Field:   "ingress_interfaces",
					Message: fmt.Sprintf("중복된 유입 인터페이스입니다: %s", name),
				})
				continue
			}
			seenIface[name] = true
			if lanName != "" && name == lanName {
				errs = append(errs, ValidationError{
					Section: SectionGlobal,
					Field:   "ingress_interfaces",
					Message: fmt.Sprintf("유입 인터페이스(%s)는 LAN 인터페이스와 같을 수 없습니다", name),
				})
				continue
			}
			ingInfo, err := ifaces.InterfaceByName(name)
			if err != nil {
				addIfaceIssue(ValidationError{
					Section: SectionGlobal,
					Field:   "ingress_interfaces",
					Message: fmt.Sprintf("존재하지 않는 유입 인터페이스입니다: %s", name),
				})
			} else if len(ingInfo.Prefixes) == 0 {
				addIfaceIssue(ValidationError{
					Section: SectionGlobal,
					Field:   "ingress_interfaces",
					Message: fmt.Sprintf("유입 인터페이스(%s)에 IPv4 주소가 없습니다", name),
				})
			}
		}
	}

	if cfg.ProxyPort < MinProxyPort || cfg.ProxyPort > MaxPort {
		errs = append(errs, ValidationError{
			Section: SectionGlobal,
			Field:   "proxy_port",
			Message: fmt.Sprintf("proxy_port는 %d~%d 범위여야 합니다: %d", MinProxyPort, MaxPort, cfg.ProxyPort),
		})
	}
	if cfg.WakeTimeout <= 0 {
		errs = append(errs, ValidationError{
			Section: SectionGlobal,
			Field:   "wake_timeout",
			Message: "wake_timeout은 0보다 커야 합니다",
		})
	}
	if cfg.WakeCooldown <= 0 {
		errs = append(errs, ValidationError{
			Section: SectionGlobal,
			Field:   "wake_cooldown",
			Message: "wake_cooldown은 0보다 커야 합니다",
		})
	}
	if cfg.PollInterval <= 0 {
		errs = append(errs, ValidationError{
			Section: SectionGlobal,
			Field:   "poll_interval",
			Message: "poll_interval은 0보다 커야 합니다",
		})
	}
	if cfg.PollInterval > 0 && cfg.WakeTimeout > 0 && cfg.PollInterval > cfg.WakeTimeout {
		errs = append(errs, ValidationError{
			Section: SectionGlobal,
			Field:   "poll_interval",
			Message: "poll_interval은 wake_timeout보다 클 수 없습니다",
		})
	}

	// 2. Clients
	for _, name := range SortedKeys(cfg.Clients) {
		cl := cfg.Clients[name]
		if strings.TrimSpace(name) == "" {
			errs = append(errs, ValidationError{
				Section: SectionClient,
				Field:   "name",
				Message: "클라이언트 이름이 비어 있습니다",
			})
		}
		if _, err := netutil.ParseIPv4OrCIDR(cl.CIDR); err != nil {
			errs = append(errs, ValidationError{
				Section:  SectionClient,
				ItemName: name,
				Field:    "cidr",
				Message:  err.Error(),
			})
		}
	}

	// 3. Profiles
	for _, name := range SortedKeys(cfg.Profiles) {
		pr := cfg.Profiles[name]
		if strings.TrimSpace(name) == "" {
			errs = append(errs, ValidationError{
				Section: SectionProfile,
				Field:   "name",
				Message: "프로파일 이름이 비어 있습니다",
			})
		}
		if pr.Port < 1 || pr.Port > 65535 {
			errs = append(errs, ValidationError{
				Section:  SectionProfile,
				ItemName: name,
				Field:    "port",
				Message:  fmt.Sprintf("포트는 1~65535 범위여야 합니다: %d", pr.Port),
			})
		}
		if pr.Wake != WakeAuto && pr.Wake != WakeNever {
			errs = append(errs, ValidationError{
				Section:  SectionProfile,
				ItemName: name,
				Field:    "wake",
				Message:  fmt.Sprintf("wake 값은 auto 또는 never여야 합니다: %q", pr.Wake),
			})
		}
		if pr.IdleTimeout < 0 {
			errs = append(errs, ValidationError{
				Section:  SectionProfile,
				ItemName: name,
				Field:    "idle_timeout",
				Message:  "idle_timeout은 음수일 수 없습니다",
			})
		}
		if pr.IdleBytes < 0 {
			errs = append(errs, ValidationError{
				Section:  SectionProfile,
				ItemName: name,
				Field:    "idle_bytes",
				Message:  "idle_bytes는 음수일 수 없습니다",
			})
		}
	}

	// Collect local host IPv4 addresses across interfaces to prevent self-loop / address collisions.
	localIPs := make(map[netip.Addr]string)
	if allIfaces, err := ifaces.Interfaces(); err == nil {
		for _, info := range allIfaces {
			for _, addr := range info.IPv4Addrs() {
				if _, exists := localIPs[addr]; !exists {
					localIPs[addr] = info.Name
				}
			}
		}
	}
	if hasLANInfo {
		for _, addr := range lanInfo.IPv4Addrs() {
			if _, exists := localIPs[addr]; !exists {
				localIPs[addr] = lanInfo.Name
			}
		}
	}

	// 4. Targets
	seenTargetNames := make(map[string]bool, len(cfg.Targets))
	type addrOwner struct {
		targetName string
		kind       string // "IP" or "별칭"
	}
	seenAddrs := make(map[netip.Addr]addrOwner, len(cfg.Targets)*2)

	for _, t := range cfg.Targets {
		tName := strings.TrimSpace(t.Name)
		if tName == "" {
			errs = append(errs, ValidationError{
				Section: SectionTarget,
				Field:   "name",
				Message: "타깃 이름이 비어 있습니다",
			})
		} else if seenTargetNames[tName] {
			errs = append(errs, ValidationError{
				Section:  SectionTarget,
				ItemName: tName,
				Field:    "name",
				Message:  fmt.Sprintf("중복된 타깃 이름입니다: %s", tName),
			})
		} else {
			seenTargetNames[tName] = true
		}

		if ipAddr, err := netutil.ParseIPv4Host(t.IP); err != nil {
			errs = append(errs, ValidationError{
				Section:  SectionTarget,
				ItemName: tName,
				Field:    "ip",
				Message:  err.Error(),
			})
		} else {
			if prev, exists := seenAddrs[ipAddr]; exists {
				errs = append(errs, ValidationError{
					Section:  SectionTarget,
					ItemName: tName,
					Field:    "ip",
					Message:  fmt.Sprintf("타깃 %s의 %s(%s)와 주소가 중복됩니다", prev.targetName, prev.kind, ipAddr),
				})
			} else {
				seenAddrs[ipAddr] = addrOwner{targetName: tName, kind: "IP"}
			}
			if ownerIf, isLocal := localIPs[ipAddr]; isLocal {
				errs = append(errs, ValidationError{
					Section:  SectionTarget,
					ItemName: tName,
					Field:    "ip",
					Message:  fmt.Sprintf("타깃 IP(%s)가 호스트 인터페이스(%s)의 로컬 주소와 충돌합니다", ipAddr, ownerIf),
				})
			} else if hasLANInfo {
				if !lanInfo.ContainsIPv4(ipAddr) {
					errs = append(errs, ValidationError{
						Section:  SectionTarget,
						ItemName: tName,
						Field:    "ip",
						Message:  fmt.Sprintf("타깃 IP(%s)가 LAN 인터페이스(%s) 서브넷 대역에 속하지 않습니다", ipAddr, cfg.LANInterface),
					})
				} else if reservedDesc, reserved := isLANReservedAddr(lanInfo, ipAddr); reserved {
					errs = append(errs, ValidationError{
						Section:  SectionTarget,
						ItemName: tName,
						Field:    "ip",
						Message:  fmt.Sprintf("타깃 IP(%s)는 LAN 인터페이스(%s)의 %s이므로 사용할 수 없습니다", ipAddr, cfg.LANInterface, reservedDesc),
					})
				}
			}
		}

		if strings.TrimSpace(t.Alias) != "" {
			aliasAddr, err := netutil.ParseIPv4Host(t.Alias)
			if err != nil {
				errs = append(errs, ValidationError{
					Section:  SectionTarget,
					ItemName: tName,
					Field:    "alias",
					Message:  err.Error(),
				})
			} else {
				if prev, exists := seenAddrs[aliasAddr]; exists {
					errs = append(errs, ValidationError{
						Section:  SectionTarget,
						ItemName: tName,
						Field:    "alias",
						Message:  fmt.Sprintf("타깃 %s의 %s(%s)와 별칭 주소가 중복됩니다", prev.targetName, prev.kind, aliasAddr),
					})
				} else {
					seenAddrs[aliasAddr] = addrOwner{targetName: tName, kind: "별칭"}
				}
				if ownerIf, isLocal := localIPs[aliasAddr]; isLocal {
					errs = append(errs, ValidationError{
						Section:  SectionTarget,
						ItemName: tName,
						Field:    "alias",
						Message:  fmt.Sprintf("별칭(%s)이 호스트 인터페이스(%s)의 로컬 주소와 충돌합니다", aliasAddr, ownerIf),
					})
				} else if hasLANInfo && lanInfo.ContainsIPv4(aliasAddr) {
					errs = append(errs, ValidationError{
						Section:  SectionTarget,
						ItemName: tName,
						Field:    "alias",
						Message:  fmt.Sprintf("별칭(%s)이 LAN 인터페이스(%s) 대역과 겹칩니다", aliasAddr, cfg.LANInterface),
					})
				}
			}
		}

		if _, _, err := netutil.NormalizeMAC(t.MAC); err != nil {
			errs = append(errs, ValidationError{
				Section:  SectionTarget,
				ItemName: tName,
				Field:    "mac",
				Message:  err.Error(),
			})
		}

		// Profile references & per-target port uniqueness
		seenProfNames := make(map[string]bool, len(t.Profiles))
		seenPorts := make(map[int]string, len(t.Profiles))
		for _, pn := range t.Profiles {
			if seenProfNames[pn] {
				errs = append(errs, ValidationError{
					Section:  SectionTarget,
					ItemName: tName,
					Field:    "profiles",
					Message:  fmt.Sprintf("중복 지정된 프로파일입니다: %s", pn),
				})
				continue
			}
			seenProfNames[pn] = true
			pr, ok := cfg.Profiles[pn]
			if !ok {
				errs = append(errs, ValidationError{
					Section:  SectionTarget,
					ItemName: tName,
					Field:    "profiles",
					Message:  fmt.Sprintf("존재하지 않는 프로파일입니다: %s", pn),
				})
				continue
			}
			if prevProf, dup := seenPorts[pr.Port]; dup {
				errs = append(errs, ValidationError{
					Section:  SectionTarget,
					ItemName: tName,
					Field:    "profiles",
					Message:  fmt.Sprintf("한 타깃 안에서 같은 포트(%d)를 사용하는 프로파일(%s, %s)을 함께 쓸 수 없습니다", pr.Port, prevProf, pn),
				})
			} else if pr.Port >= 1 && pr.Port <= 65535 {
				seenPorts[pr.Port] = pn
			}
		}

		// Allowed clients
		seenClients := make(map[string]bool, len(t.Allow))
		for _, cn := range t.Allow {
			if seenClients[cn] {
				errs = append(errs, ValidationError{
					Section:  SectionTarget,
					ItemName: tName,
					Field:    "allow",
					Message:  fmt.Sprintf("중복 지정된 허용 클라이언트입니다: %s", cn),
				})
				continue
			}
			seenClients[cn] = true
			if _, ok := cfg.Clients[cn]; !ok {
				errs = append(errs, ValidationError{
					Section:  SectionTarget,
					ItemName: tName,
					Field:    "allow",
					Message:  fmt.Sprintf("존재하지 않는 클라이언트입니다: %s", cn),
				})
			}
		}
		if len(t.Profiles) > 0 && len(t.Allow) == 0 {
			warns = append(warns, ValidationError{
				Section:  SectionTarget,
				ItemName: tName,
				Field:    "allow",
				Message:  "프로파일이 지정되어 있으나 허용 클라이언트(allow)가 비어 있어 가로채는 모든 연결이 거부됩니다",
			})
		}
	}

	return ValidationReport{
		Errors:   errs,
		Warnings: warns,
	}
}

func isLANReservedAddr(lanInfo netutil.InterfaceInfo, ip netip.Addr) (string, bool) {
	for _, p := range lanInfo.Prefixes {
		if !p.Addr().Is4() || p.Bits() >= 31 {
			continue
		}
		if ip == p.Masked().Addr() {
			return "서브넷 네트워크 주소", true
		}
		if bcast, err := netutil.BroadcastAddr(p); err == nil && ip == bcast {
			return "서브넷 브로드캐스트 주소", true
		}
	}
	return "", false
}
