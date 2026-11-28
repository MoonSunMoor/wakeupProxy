package tui

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/MoonSunMoor/wakeupProxy/internal/config"
	"github.com/MoonSunMoor/wakeupProxy/internal/netutil"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

type targetDraft struct {
	origIdx  int // -1 when adding new target
	name     string
	ip       string
	mac      string
	alias    string
	profiles []string
	allow    []string
	note     string
}

type clientDraft struct {
	isNew    bool
	origName string
	name     string
	cidr     string
	note     string
}

type profileDraft struct {
	isNew       bool
	origName    string
	name        string
	port        string
	wake        string
	idleTimeout string
	idleBytes   string
	note        string
}

type globalDraft struct {
	lanInterface      string
	ingressInterfaces []string
	proxyPort         string
	wakeTimeout       string
	wakeCooldown      string
	pollInterval      string
}

func newFormTheme() *huh.Theme {
	t := huh.ThemeCharm()

	t.Focused.Base = t.Focused.Base.BorderForeground(lipgloss.Color("62"))
	t.Focused.Card = t.Focused.Base
	t.Focused.Title = lipgloss.NewStyle().Foreground(lipgloss.Color("111")).Bold(true)
	t.Focused.NoteTitle = lipgloss.NewStyle().Foreground(lipgloss.Color("111")).Bold(true).MarginBottom(1)
	t.Focused.Description = lipgloss.NewStyle().Foreground(lipgloss.Color("243"))
	t.Focused.ErrorIndicator = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).SetString(" *")
	t.Focused.ErrorMessage = lipgloss.NewStyle().Foreground(lipgloss.Color("203")).SetString(" *")

	t.Focused.SelectSelector = lipgloss.NewStyle()
	t.Focused.MultiSelectSelector = lipgloss.NewStyle()
	t.Focused.SelectedPrefix = lipgloss.NewStyle()
	t.Focused.UnselectedPrefix = lipgloss.NewStyle()
	t.Focused.Option = normalOptionStyle
	t.Focused.SelectedOption = okStyle
	t.Focused.UnselectedOption = normalOptionStyle

	t.Focused.TextInput.Cursor = lipgloss.NewStyle().Foreground(lipgloss.Color("78"))
	t.Focused.TextInput.Placeholder = lipgloss.NewStyle().Foreground(lipgloss.Color("242"))
	t.Focused.TextInput.Prompt = lipgloss.NewStyle()
	t.Focused.TextInput.Text = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))

	t.Blurred = t.Focused
	t.Blurred.Base = t.Focused.Base.BorderStyle(lipgloss.HiddenBorder())
	t.Blurred.Card = t.Blurred.Base
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()

	t.Group.Title = t.Focused.Title
	t.Group.Description = t.Focused.Description
	return t
}

func newTextInput() *huh.Input {
	return huh.NewInput().Prompt("")
}

func newStyledForm(termWidth, maxWidth int, fields ...huh.Field) *huh.Form {
	w := maxWidth
	if termWidth > 10 {
		w = min(termWidth-6, maxWidth)
	}
	return huh.NewForm(huh.NewGroup(fields...)).
		WithTheme(newFormTheme()).
		WithKeyMap(newFormKeyMap()).
		WithShowHelp(false).
		WithWidth(w)
}

func clampScrollOffset(yOffset, cursorIdx, totalOpts, vpHeight int) int {
	if totalOpts <= 0 || vpHeight <= 0 || totalOpts <= vpHeight {
		return 0
	}
	if cursorIdx < yOffset {
		yOffset = cursorIdx
	}
	if cursorIdx >= yOffset+vpHeight {
		yOffset = cursorIdx - vpHeight + 1
	}
	maxOff := totalOpts - vpHeight
	if yOffset > maxOff {
		yOffset = maxOff
	}
	if yOffset < 0 {
		yOffset = 0
	}
	return yOffset
}

func maxOptionWidth(options []huh.Option[string], availWidth int) int {
	maxW := 0
	for _, opt := range options {
		w := lipgloss.Width(opt.Key)
		if availWidth > 0 && w > availWidth {
			w = availWidth
		}
		if w > maxW {
			maxW = w
		}
	}
	return maxW
}

// selectField wraps *huh.Select[string] to preserve all key handling and validation
// while rendering 0-column aligned options with orthogonal cursor/selected styling.
type selectField struct {
	inner       *huh.Select[string]
	title       string
	description string
	options     []huh.Option[string]
	focused     bool
	width       int
	height      int
	yOffset     int
	theme       *huh.Theme
}

var _ huh.Field = (*selectField)(nil)

func newSelectField(fieldKey, title string, options []huh.Option[string], val *string) *selectField {
	optsCopy := append([]huh.Option[string](nil), options...)
	inner := huh.NewSelect[string]().
		Key(fieldKey).
		Title(title).
		Options(optsCopy...).
		Filtering(false).
		Value(val)
	inner.WithKeyMap(newFormKeyMap())
	return &selectField{
		inner:   inner,
		title:   title,
		options: optsCopy,
	}
}

func (f *selectField) Description(desc string) *selectField {
	f.description = desc
	f.inner.Description(desc)
	return f
}

func (f *selectField) Validate(validate func(string) error) *selectField {
	if validate != nil {
		f.inner.Validate(validate)
	}
	return f
}

func (f *selectField) Height(h int) *selectField {
	f.height = h
	f.inner.Height(h)
	f.syncViewport()
	return f
}

func (f *selectField) Init() tea.Cmd { return f.inner.Init() }

func (f *selectField) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := f.inner.Update(msg)
	if s, ok := next.(*huh.Select[string]); ok {
		f.inner = s
	}
	f.syncViewport()
	return f, cmd
}

func (f *selectField) Focus() tea.Cmd {
	f.focused = true
	cmd := f.inner.Focus()
	f.syncViewport()
	return cmd
}

func (f *selectField) Blur() tea.Cmd {
	f.focused = false
	return f.inner.Blur()
}

func (f *selectField) Error() error { return f.inner.Error() }
func (f *selectField) Run() error   { return f.inner.Run() }
func (f *selectField) RunAccessible(w io.Writer, r io.Reader) error {
	return f.inner.RunAccessible(w, r)
}
func (f *selectField) Skip() bool              { return f.inner.Skip() }
func (f *selectField) Zoom() bool              { return f.inner.Zoom() }
func (f *selectField) KeyBinds() []key.Binding { return f.inner.KeyBinds() }
func (f *selectField) GetKey() string          { return f.inner.GetKey() }
func (f *selectField) GetValue() any           { return f.inner.GetValue() }

func (f *selectField) WithTheme(t *huh.Theme) huh.Field {
	f.theme = t
	f.inner.WithTheme(t)
	return f
}

func (f *selectField) WithAccessible(a bool) huh.Field {
	f.inner.WithAccessible(a)
	return f
}

func (f *selectField) WithKeyMap(k *huh.KeyMap) huh.Field {
	f.inner.WithKeyMap(k)
	return f
}

func (f *selectField) WithWidth(w int) huh.Field {
	f.width = w
	f.inner.WithWidth(w)
	return f
}

func (f *selectField) WithHeight(h int) huh.Field {
	f.height = h
	f.inner.WithHeight(h)
	f.syncViewport()
	return f
}

func (f *selectField) WithPosition(p huh.FieldPosition) huh.Field {
	f.inner.WithPosition(p)
	return f
}

func (f *selectField) activeStyles() *huh.FieldStyles {
	t := f.theme
	if t == nil {
		t = newFormTheme()
	}
	if f.focused {
		return &t.Focused
	}
	return &t.Blurred
}

func (f *selectField) cursorIndex() int {
	if len(f.options) == 0 {
		return 0
	}
	if hovered, ok := f.inner.Hovered(); ok {
		for i, opt := range f.options {
			if opt.Value == hovered {
				return i
			}
		}
	}
	if val, ok := f.inner.GetValue().(string); ok {
		for i, opt := range f.options {
			if opt.Value == val {
				return i
			}
		}
	}
	return 0
}

func (f *selectField) headerLineCount() int {
	n := 0
	if f.title != "" {
		n++
	}
	if f.description != "" {
		n++
	}
	return n
}

func (f *selectField) syncViewport() {
	if f.height <= 0 {
		f.yOffset = 0
		return
	}
	vpHeight := max(1, f.height-f.headerLineCount())
	f.yOffset = clampScrollOffset(f.yOffset, f.cursorIndex(), len(f.options), vpHeight)
}

func (f *selectField) View() string {
	styles := f.activeStyles()
	availWidth := 0
	if f.width > 0 {
		availWidth = max(1, f.width-styles.Base.GetHorizontalFrameSize())
	}

	var parts []string
	if f.title != "" {
		titleLine := styles.Title.Render(f.title)
		if f.inner.Error() != nil {
			titleLine += styles.ErrorIndicator.String()
		}
		parts = append(parts, titleLine)
	}
	if f.description != "" {
		parts = append(parts, styles.Description.Render(f.description))
	}

	selIdx := f.cursorIndex()
	start, end := 0, len(f.options)
	if f.height > 0 && len(f.options) > 0 {
		vpHeight := max(1, f.height-f.headerLineCount())
		f.yOffset = clampScrollOffset(f.yOffset, selIdx, len(f.options), vpHeight)
		start = f.yOffset
		end = min(len(f.options), start+vpHeight)
	}

	ascii := isASCIIProfile()
	maxW := maxOptionWidth(f.options, availWidth)
	optLines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		opt := f.options[i]
		isSel := i == selIdx
		if ascii {
			suffix := ""
			if isSel {
				suffix += " [선택됨]"
			}
			if f.focused && isSel {
				suffix += " ←"
			}
			label := opt.Key
			if availWidth > lipgloss.Width(suffix)+1 {
				label = truncateDisplay(label, availWidth-lipgloss.Width(suffix))
			}
			optLines = append(optLines, label+suffix)
			continue
		}

		label := opt.Key
		if availWidth > 0 {
			label = truncateDisplay(label, availWidth)
		}
		padded := padRight(label, maxW)
		switch {
		case f.focused && isSel:
			optLines = append(optLines, selectedOptionCursorStyle.Render(padded))
		case f.focused && !isSel:
			optLines = append(optLines, normalOptionStyle.Render(padded))
		case !f.focused && isSel:
			optLines = append(optLines, okStyle.Render(padded))
		default:
			optLines = append(optLines, blurredUnselectedSelectStyle.Render(padded))
		}
	}
	if len(optLines) > 0 {
		parts = append(parts, strings.Join(optLines, "\n"))
	}

	base := styles.Base
	if f.width > 0 {
		base = base.Width(f.width)
	}
	if f.height > 0 {
		base = base.Height(f.height)
	}
	return base.Render(strings.Join(parts, "\n"))
}

// multiSelectField wraps *huh.MultiSelect[string] to preserve all key handling and validation
// while rendering 0-column aligned options with orthogonal cursor/selected styling.
type multiSelectField struct {
	inner       *huh.MultiSelect[string]
	title       string
	description string
	options     []huh.Option[string]
	focused     bool
	width       int
	height      int
	yOffset     int
	theme       *huh.Theme
}

var _ huh.Field = (*multiSelectField)(nil)

func newMultiSelectField(fieldKey, title string, options []huh.Option[string], val *[]string) *multiSelectField {
	optsCopy := append([]huh.Option[string](nil), options...)
	inner := huh.NewMultiSelect[string]().
		Key(fieldKey).
		Title(title).
		Options(optsCopy...).
		Filterable(false).
		Value(val)
	inner.WithKeyMap(newFormKeyMap())
	return &multiSelectField{
		inner:   inner,
		title:   title,
		options: optsCopy,
	}
}

func (f *multiSelectField) Description(desc string) *multiSelectField {
	f.description = desc
	f.inner.Description(desc)
	return f
}

func (f *multiSelectField) Validate(validate func([]string) error) *multiSelectField {
	if validate != nil {
		f.inner.Validate(validate)
	}
	return f
}

func (f *multiSelectField) Height(h int) *multiSelectField {
	f.height = h
	f.inner.Height(h)
	f.syncViewport()
	return f
}

func (f *multiSelectField) Init() tea.Cmd { return f.inner.Init() }

func (f *multiSelectField) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := f.inner.Update(msg)
	if ms, ok := next.(*huh.MultiSelect[string]); ok {
		f.inner = ms
	}
	f.syncViewport()
	return f, cmd
}

func (f *multiSelectField) Focus() tea.Cmd {
	f.focused = true
	cmd := f.inner.Focus()
	f.syncViewport()
	return cmd
}

func (f *multiSelectField) Blur() tea.Cmd {
	f.focused = false
	return f.inner.Blur()
}

func (f *multiSelectField) Error() error { return f.inner.Error() }
func (f *multiSelectField) Run() error   { return f.inner.Run() }
func (f *multiSelectField) RunAccessible(w io.Writer, r io.Reader) error {
	return f.inner.RunAccessible(w, r)
}
func (f *multiSelectField) Skip() bool              { return f.inner.Skip() }
func (f *multiSelectField) Zoom() bool              { return f.inner.Zoom() }
func (f *multiSelectField) KeyBinds() []key.Binding { return f.inner.KeyBinds() }
func (f *multiSelectField) GetKey() string          { return f.inner.GetKey() }
func (f *multiSelectField) GetValue() any           { return f.inner.GetValue() }

func (f *multiSelectField) WithTheme(t *huh.Theme) huh.Field {
	f.theme = t
	f.inner.WithTheme(t)
	return f
}

func (f *multiSelectField) WithAccessible(a bool) huh.Field {
	f.inner.WithAccessible(a)
	return f
}

func (f *multiSelectField) WithKeyMap(k *huh.KeyMap) huh.Field {
	f.inner.WithKeyMap(k)
	return f
}

func (f *multiSelectField) WithWidth(w int) huh.Field {
	f.width = w
	f.inner.WithWidth(w)
	return f
}

func (f *multiSelectField) WithHeight(h int) huh.Field {
	f.height = h
	f.inner.WithHeight(h)
	f.syncViewport()
	return f
}

func (f *multiSelectField) WithPosition(p huh.FieldPosition) huh.Field {
	f.inner.WithPosition(p)
	return f
}

func (f *multiSelectField) activeStyles() *huh.FieldStyles {
	t := f.theme
	if t == nil {
		t = newFormTheme()
	}
	if f.focused {
		return &t.Focused
	}
	return &t.Blurred
}

func (f *multiSelectField) cursorIndex() int {
	if len(f.options) == 0 {
		return 0
	}
	if hovered, ok := f.inner.Hovered(); ok {
		for i, opt := range f.options {
			if opt.Value == hovered {
				return i
			}
		}
	}
	return 0
}

func (f *multiSelectField) headerLineCount() int {
	n := 0
	if f.title != "" {
		n++
	}
	if f.description != "" {
		n++
	}
	return n
}

func (f *multiSelectField) syncViewport() {
	if f.height <= 0 {
		f.yOffset = 0
		return
	}
	vpHeight := max(1, f.height-f.headerLineCount())
	f.yOffset = clampScrollOffset(f.yOffset, f.cursorIndex(), len(f.options), vpHeight)
}

func (f *multiSelectField) View() string {
	styles := f.activeStyles()
	availWidth := 0
	if f.width > 0 {
		availWidth = max(1, f.width-styles.Base.GetHorizontalFrameSize())
	}

	var parts []string
	if f.title != "" {
		titleLine := styles.Title.Render(f.title)
		if f.inner.Error() != nil {
			titleLine += styles.ErrorIndicator.String()
		}
		parts = append(parts, titleLine)
	}
	if f.description != "" {
		parts = append(parts, styles.Description.Render(f.description))
	}

	cursorIdx := f.cursorIndex()
	selectedVals, _ := f.inner.GetValue().([]string)

	start, end := 0, len(f.options)
	if f.height > 0 && len(f.options) > 0 {
		vpHeight := max(1, f.height-f.headerLineCount())
		f.yOffset = clampScrollOffset(f.yOffset, cursorIdx, len(f.options), vpHeight)
		start = f.yOffset
		end = min(len(f.options), start+vpHeight)
	}

	ascii := isASCIIProfile()
	maxW := maxOptionWidth(f.options, availWidth)
	optLines := make([]string, 0, end-start)
	for i := start; i < end; i++ {
		opt := f.options[i]
		isCursor := f.focused && i == cursorIdx
		isSel := slices.Contains(selectedVals, opt.Value)
		if ascii {
			suffix := ""
			if isSel {
				suffix += " [선택됨]"
			}
			if isCursor {
				suffix += " ←"
			}
			label := opt.Key
			if availWidth > lipgloss.Width(suffix)+1 {
				label = truncateDisplay(label, availWidth-lipgloss.Width(suffix))
			}
			optLines = append(optLines, label+suffix)
			continue
		}

		label := opt.Key
		if availWidth > 0 {
			label = truncateDisplay(label, availWidth)
		}
		padded := padRight(label, maxW)
		switch {
		case isSel && isCursor:
			optLines = append(optLines, selectedOptionCursorStyle.Render(padded))
		case isSel && !isCursor:
			optLines = append(optLines, okStyle.Render(padded))
		case !isSel && isCursor:
			optLines = append(optLines, selectedRowStyle.Render(padded))
		default:
			optLines = append(optLines, normalOptionStyle.Render(padded))
		}
	}
	if len(optLines) > 0 {
		parts = append(parts, strings.Join(optLines, "\n"))
	}

	base := styles.Base
	if f.width > 0 {
		base = base.Width(f.width)
	}
	if f.height > 0 {
		base = base.Height(f.height)
	}
	return base.Render(strings.Join(parts, "\n"))
}

func newFormKeyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	// Esc is handled by our outer TUI model so it cleanly cancels the form without quitting tea.Program.
	km.Quit = key.NewBinding(key.WithDisabled())
	// Ensure Tab / Shift+Tab move between fields uniformly across Input, Select, and MultiSelect.
	km.Input.Next = key.NewBinding(key.WithKeys("enter", "tab"))
	km.Input.Prev = key.NewBinding(key.WithKeys("shift+tab"))
	km.Select.Next = key.NewBinding(key.WithKeys("enter", "tab"))
	km.Select.Prev = key.NewBinding(key.WithKeys("shift+tab"))
	km.MultiSelect.Next = key.NewBinding(key.WithKeys("enter", "tab"))
	km.MultiSelect.Prev = key.NewBinding(key.WithKeys("shift+tab"))
	return km
}

func validateRequiredName(label string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s 이름을 입력해 주세요", label)
		}
		return nil
	}
}

func validatePortStr(s string) error {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > config.MaxPort {
		return fmt.Errorf("포트는 1~%d 사이의 숫자여야 합니다", config.MaxPort)
	}
	return nil
}

func validateProxyPortStr(s string) error {
	s = strings.TrimSpace(s)
	n, err := strconv.Atoi(s)
	if err != nil || n < config.MinProxyPort || n > config.MaxPort {
		return fmt.Errorf("proxy_port는 %d~%d 사이의 숫자여야 합니다", config.MinProxyPort, config.MaxPort)
	}
	return nil
}

func validatePositiveDurationStr(s string) error {
	d, err := config.ParseDurationInput(s)
	if err != nil {
		return err
	}
	if d <= 0 {
		return errors.New("0보다 큰 시간을 입력해 주세요 (예: 10s, 120s)")
	}
	return nil
}

func validateOptionalDurationStr(s string) error {
	d, err := config.ParseDurationInput(s)
	if err != nil {
		return err
	}
	if d < 0 {
		return errors.New("시간은 음수일 수 없습니다")
	}
	return nil
}

func validateOptionalNonNegIntStr(s string) error {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return errors.New("0 이상의 정수를 입력해 주세요")
	}
	return nil
}

func (m *Model) buildTargetForm() *huh.Form {
	profNames := config.SortedKeys(m.cfg.Profiles)
	profOpts := make([]huh.Option[string], 0, len(profNames))
	for _, pn := range profNames {
		pr := m.cfg.Profiles[pn]
		label := fmt.Sprintf("%s (port %d, wake=%s)", pn, pr.Port, pr.Wake)
		profOpts = append(profOpts, huh.NewOption(label, pn))
	}

	clientNames := config.SortedKeys(m.cfg.Clients)
	clientOpts := make([]huh.Option[string], 0, len(clientNames))
	for _, cn := range clientNames {
		cl := m.cfg.Clients[cn]
		label := fmt.Sprintf("%s (%s)", cn, cl.CIDR)
		clientOpts = append(clientOpts, huh.NewOption(label, cn))
	}

	scanHint := "Ctrl+L: LAN 검색"
	if !m.deps.IsRoot {
		scanHint = "Ctrl+L: LAN 검색 (비활성 - root 필요)"
	}

	fields := []huh.Field{
		newTextInput().
			Key("name").
			Title("타깃 이름").
			Placeholder("pc1").
			Value(&m.tDraft.name).
			Validate(validateRequiredName("타깃")),
		newTextInput().
			Key("ip").
			Title("IP 주소 (" + scanHint + ")").
			Placeholder("192.168.0.21").
			Value(&m.tDraft.ip).
			Validate(func(s string) error {
				_, err := netutil.ParseIPv4Host(s)
				return err
			}),
		newTextInput().
			Key("mac").
			Title("MAC 주소").
			Placeholder("aa:bb:cc:dd:ee:01").
			DescriptionFunc(func() string {
				if m.macAutoNote != "" {
					return m.macAutoNote
				}
				return "IP 입력 후 이동하면 시스템 ARP 기록에서 자동으로 채웁니다"
			}, &m.macAutoNote).
			Value(&m.tDraft.mac).
			Validate(func(s string) error {
				_, _, err := netutil.NormalizeMAC(s)
				return err
			}),
		newTextInput().
			Key("alias").
			Title("별칭 IP (선택)").
			Placeholder("10.66.1.12").
			Value(&m.tDraft.alias).
			Validate(func(s string) error {
				if strings.TrimSpace(s) == "" {
					return nil
				}
				_, err := netutil.ParseIPv4Host(s)
				return err
			}),
	}

	if len(profOpts) > 0 {
		fields = append(fields,
			newMultiSelectField("profiles", "프로파일 (스페이스로 선택/해제)", profOpts, &m.tDraft.profiles),
		)
	} else {
		fields = append(fields,
			huh.NewNote().
				Title("프로파일").
				Description("등록된 프로파일이 없어 선택할 수 없습니다. '3. 프로파일' 탭에서 먼저 추가해 주세요."),
		)
	}
	if len(clientOpts) > 0 {
		fields = append(fields,
			newMultiSelectField("allow", "허용 클라이언트 (스페이스로 선택/해제)", clientOpts, &m.tDraft.allow),
		)
	} else {
		fields = append(fields,
			huh.NewNote().
				Title("허용 클라이언트").
				Description("등록된 클라이언트가 없어 허용 클라이언트를 선택할 수 없습니다. '2. 클라이언트' 탭에서 먼저 추가해 주세요."),
		)
	}

	fields = append(fields,
		newTextInput().
			Key("note").
			Title("메모 (note, 선택)").
			Placeholder("optional").
			Value(&m.tDraft.note),
	)

	return newStyledForm(m.width, 90, fields...)
}

func (m *Model) commitTargetDraft() error {
	normMAC, _, err := netutil.NormalizeMAC(m.tDraft.mac)
	if err != nil {
		return err
	}
	ipAddr, err := netutil.ParseIPv4Host(m.tDraft.ip)
	if err != nil {
		return err
	}
	var aliasStr string
	if strings.TrimSpace(m.tDraft.alias) != "" {
		aliasAddr, err := netutil.ParseIPv4Host(m.tDraft.alias)
		if err != nil {
			return err
		}
		aliasStr = aliasAddr.String()
	}

	t := config.Target{
		Name:     strings.TrimSpace(m.tDraft.name),
		Note:     strings.TrimSpace(m.tDraft.note),
		IP:       ipAddr.String(),
		Alias:    aliasStr,
		MAC:      normMAC,
		Profiles: append([]string(nil), m.tDraft.profiles...),
		Allow:    append([]string(nil), m.tDraft.allow...),
	}

	if m.tDraft.origIdx >= 0 && m.tDraft.origIdx < len(m.cfg.Targets) {
		m.cfg.Targets[m.tDraft.origIdx] = t
		m.targetCursor = m.tDraft.origIdx
	} else {
		m.cfg.Targets = append(m.cfg.Targets, t)
		m.targetCursor = len(m.cfg.Targets) - 1
	}
	return nil
}

func (m *Model) buildClientForm() *huh.Form {
	fields := []huh.Field{
		newTextInput().
			Key("name").
			Title("클라이언트 이름").
			Placeholder("laptop").
			Value(&m.cDraft.name).
			Validate(func(s string) error {
				name := strings.TrimSpace(s)
				if name == "" {
					return errors.New("클라이언트 이름을 입력해 주세요")
				}
				if (m.cDraft.isNew || name != m.cDraft.origName) && m.hasClient(name) {
					return fmt.Errorf("이미 존재하는 클라이언트 이름입니다: %s", name)
				}
				return nil
			}),
		newTextInput().
			Key("cidr").
			Title("IP/CIDR").
			Placeholder("10.66.0.2/32").
			Value(&m.cDraft.cidr).
			Validate(func(s string) error {
				_, err := netutil.ParseIPv4OrCIDR(s)
				return err
			}),
		newTextInput().
			Key("note").
			Title("메모 (note, 선택)").
			Placeholder("optional").
			Value(&m.cDraft.note),
	}

	return newStyledForm(m.width, 80, fields...)
}

func (m *Model) hasClient(name string) bool {
	_, ok := m.cfg.Clients[name]
	return ok
}

func (m *Model) commitClientDraft() error {
	name := strings.TrimSpace(m.cDraft.name)
	pfx, err := netutil.ParseIPv4OrCIDR(m.cDraft.cidr)
	if err != nil {
		return err
	}
	cl := config.Client{
		CIDR: pfx.String(),
		Note: strings.TrimSpace(m.cDraft.note),
	}
	if !m.cDraft.isNew && m.cDraft.origName != name {
		m.cfg.RenameClient(m.cDraft.origName, name)
	}
	m.cfg.Clients[name] = cl

	keys := config.SortedKeys(m.cfg.Clients)
	if idx := slices.Index(keys, name); idx >= 0 {
		m.clientCursor = idx
	}
	return nil
}

func (m *Model) buildProfileForm() *huh.Form {
	wakeOpts := []huh.Option[string]{
		huh.NewOption("auto (연결 시 자동으로 매직 패킷 송신)", config.WakeAuto),
		huh.NewOption("never (깨어 있을 때만 연결)", config.WakeNever),
	}
	fields := []huh.Field{
		newTextInput().
			Key("name").
			Title("프로파일 이름").
			Placeholder("rdp").
			Value(&m.pDraft.name).
			Validate(func(s string) error {
				name := strings.TrimSpace(s)
				if name == "" {
					return errors.New("프로파일 이름을 입력해 주세요")
				}
				if (m.pDraft.isNew || name != m.pDraft.origName) && m.hasProfile(name) {
					return fmt.Errorf("이미 존재하는 프로파일 이름입니다: %s", name)
				}
				return nil
			}),
		newTextInput().
			Key("port").
			Title("포트 (1~65535)").
			Placeholder("3389").
			Value(&m.pDraft.port).
			Validate(validatePortStr),
		newSelectField("wake", "깨우기 정책 (wake)", wakeOpts, &m.pDraft.wake),
		newTextInput().
			Key("idle_timeout").
			Title("유휴 제한 시간 (idle_timeout, 0=사용 안 함)").
			Placeholder("0").
			Value(&m.pDraft.idleTimeout).
			Validate(validateOptionalDurationStr),
		newTextInput().
			Key("idle_bytes").
			Title("유휴 판정 전송량 이하 기준 바이트 (idle_bytes)").
			Placeholder("0").
			Value(&m.pDraft.idleBytes).
			Validate(validateOptionalNonNegIntStr),
		newTextInput().
			Key("note").
			Title("메모 (note, 선택)").
			Placeholder("optional").
			Value(&m.pDraft.note),
	}

	return newStyledForm(m.width, 80, fields...)
}

func (m *Model) hasProfile(name string) bool {
	_, ok := m.cfg.Profiles[name]
	return ok
}

func (m *Model) commitProfileDraft() error {
	name := strings.TrimSpace(m.pDraft.name)
	port, err := strconv.Atoi(strings.TrimSpace(m.pDraft.port))
	if err != nil {
		return err
	}
	idleTimeout, err := config.ParseDurationInput(m.pDraft.idleTimeout)
	if err != nil {
		return err
	}
	var idleBytes int64
	if strings.TrimSpace(m.pDraft.idleBytes) != "" {
		idleBytes, err = strconv.ParseInt(strings.TrimSpace(m.pDraft.idleBytes), 10, 64)
		if err != nil {
			return err
		}
	}

	pr := config.Profile{
		Port:        port,
		Wake:        m.pDraft.wake,
		IdleTimeout: idleTimeout,
		IdleBytes:   idleBytes,
		Note:        strings.TrimSpace(m.pDraft.note),
	}
	if !m.pDraft.isNew && m.pDraft.origName != name {
		m.cfg.RenameProfile(m.pDraft.origName, name)
	}
	m.cfg.Profiles[name] = pr

	keys := config.SortedKeys(m.cfg.Profiles)
	if idx := slices.Index(keys, name); idx >= 0 {
		m.profileCursor = idx
	}
	return nil
}

func (m *Model) buildGlobalForm() *huh.Form {
	ifaces, _ := m.deps.Interfaces.Interfaces()
	seenNames := make(map[string]bool)
	var lanOpts []huh.Option[string]
	var ingOpts []huh.Option[string]

	addOption := func(name, desc string) {
		if name == "" || seenNames[name] {
			return
		}
		seenNames[name] = true
		label := name
		if desc != "" {
			label = fmt.Sprintf("%s (%s)", name, desc)
		}
		lanOpts = append(lanOpts, huh.NewOption(label, name))
		ingOpts = append(ingOpts, huh.NewOption(label, name))
	}

	for _, info := range ifaces {
		if info.Loopback {
			continue
		}
		var pfxStrs []string
		for _, p := range info.Prefixes {
			pfxStrs = append(pfxStrs, p.String())
		}
		addOption(info.Name, strings.Join(pfxStrs, ", "))
	}
	// Preserve currently configured interface names in options if absent on host so user can see/replace them.
	if m.gDraft.lanInterface != "" && !seenNames[m.gDraft.lanInterface] {
		addOption(m.gDraft.lanInterface, "시스템에 없음")
	}
	for _, ing := range m.gDraft.ingressInterfaces {
		if !seenNames[ing] {
			addOption(ing, "시스템에 없음")
		}
	}
	if len(lanOpts) == 0 {
		addOption("eth0", "기본값")
		addOption("wg0", "기본값")
	}

	fields := []huh.Field{
		newSelectField("lan_interface", "LAN 인터페이스", lanOpts, &m.gDraft.lanInterface),
		newMultiSelectField("ingress_interfaces", "유입 인터페이스 (스페이스로 다중 선택)", ingOpts, &m.gDraft.ingressInterfaces).
			Validate(func(sel []string) error {
				if len(sel) == 0 {
					return errors.New("유입 인터페이스를 하나 이상 선택해 주세요")
				}
				lanName := strings.TrimSpace(m.gDraft.lanInterface)
				for _, s := range sel {
					if lanName != "" && strings.TrimSpace(s) == lanName {
						return fmt.Errorf("유입 인터페이스(%s)는 LAN 인터페이스와 같을 수 없습니다", lanName)
					}
				}
				return nil
			}),
		newTextInput().
			Key("proxy_port").
			Title("프록시 리슨 포트 (proxy_port, 1024~65535)").
			Placeholder("13389").
			Value(&m.gDraft.proxyPort).
			Validate(validateProxyPortStr),
		newTextInput().
			Key("wake_timeout").
			Title("깨우기 대기 제한 시간 (wake_timeout)").
			Placeholder("120s").
			Value(&m.gDraft.wakeTimeout).
			Validate(validatePositiveDurationStr),
		newTextInput().
			Key("wake_cooldown").
			Title("매직 패킷 재송신 간격 (wake_cooldown)").
			Placeholder("10s").
			Value(&m.gDraft.wakeCooldown).
			Validate(validatePositiveDurationStr),
		newTextInput().
			Key("poll_interval").
			Title("포트 확인 간격 (poll_interval)").
			Placeholder("2s").
			Value(&m.gDraft.pollInterval).
			Validate(validatePositiveDurationStr),
	}

	return newStyledForm(m.width, 85, fields...)
}

func (m *Model) commitGlobalDraft() error {
	port, err := strconv.Atoi(strings.TrimSpace(m.gDraft.proxyPort))
	if err != nil {
		return err
	}
	wt, err := config.ParseDurationInput(m.gDraft.wakeTimeout)
	if err != nil {
		return err
	}
	wc, err := config.ParseDurationInput(m.gDraft.wakeCooldown)
	if err != nil {
		return err
	}
	pi, err := config.ParseDurationInput(m.gDraft.pollInterval)
	if err != nil {
		return err
	}

	m.cfg.LANInterface = m.gDraft.lanInterface
	m.cfg.IngressInterfaces = append([]string(nil), m.gDraft.ingressInterfaces...)
	m.cfg.ProxyPort = port
	m.cfg.WakeTimeout = wt
	m.cfg.WakeCooldown = wc
	m.cfg.PollInterval = pi
	return nil
}
