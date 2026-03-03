package quests

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/tui/components/core"
	"github.com/charmbracelet/crush/internal/tui/components/dialogs"
	"github.com/charmbracelet/crush/internal/tui/exp/list"
	"github.com/charmbracelet/crush/internal/tui/styles"
	"github.com/charmbracelet/crush/internal/tui/util"
)

const QuestsDialogID dialogs.DialogID = "quests"

type QuestsDialog interface {
	dialogs.DialogModel
}

type issue struct {
	Number      int             `json:"number"`
	Title       string          `json:"title"`
	HTMLURL     string          `json:"html_url"`
	PullRequest json.RawMessage `json:"pull_request"`
}

type questsDialogCmp struct {
	width   int
	wWidth  int
	wHeight int

	repo  string
	token string

	items []issue

	list    list.FilterableList[list.CompletionItem[issue]]
	keyMap  KeyMap
	help    help.Model
	loading bool
	err     error

	dup        map[int]bool
	dupSummary string
}

type issuesMsg struct {
	items []issue
	err   error
}

type setActiveMsg struct {
	item issue
	err  error
}

type clearMsg struct {
	err error
}

func NewQuestsDialogCmp() QuestsDialog {
	keyMap := DefaultKeyMap()
	listKeyMap := list.DefaultKeyMap()
	listKeyMap.Down.SetEnabled(false)
	listKeyMap.Up.SetEnabled(false)
	listKeyMap.DownOneItem = keyMap.Next
	listKeyMap.UpOneItem = keyMap.Previous

	t := styles.CurrentTheme()
	inputStyle := t.S().Base.PaddingLeft(1).PaddingBottom(1)
	l := list.NewFilterableList(
		[]list.CompletionItem[issue]{},
		list.WithFilterInputStyle(inputStyle),
		list.WithFilterPlaceholder("Find quests"),
		list.WithFilterListOptions(
			list.WithKeyMap(listKeyMap),
			list.WithWrapNavigation(),
			list.WithResizeByList(),
		),
	)

	h := help.New()
	h.Styles = t.S().Help

	cfg := config.Get()
	repo := ""
	token := ""
	if cfg.Options != nil && cfg.Options.TUI != nil && cfg.Options.TUI.Quests != nil {
		repo = strings.TrimSpace(cfg.Options.TUI.Quests.Repo)
		token = strings.TrimSpace(cfg.Options.TUI.Quests.Token)
	}

	return &questsDialogCmp{
		width:  100,
		list:   l,
		keyMap: keyMap,
		help:   h,
		repo:   repo,
		token:  token,
	}
}

func (q *questsDialogCmp) Init() tea.Cmd {
	return tea.Sequence(
		q.list.Init(),
		q.refresh(),
	)
}

func (q *questsDialogCmp) Update(msg tea.Msg) (util.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		q.wWidth = msg.Width
		q.wHeight = msg.Height
		q.width = min(140, q.wWidth-8)
		q.help.SetWidth(q.width - 2)
		return q, q.list.SetSize(q.listWidth(), q.listHeight())
	case issuesMsg:
		q.loading = false
		q.err = msg.err
		q.items = msg.items
		q.dup, q.dupSummary = detectDuplicateIssues(q.items)
		return q, q.setItems()
	case setActiveMsg:
		q.loading = false
		if msg.err != nil {
			return q, util.ReportError(msg.err)
		}
		return q, tea.Batch(
			util.CmdHandler(dialogs.CloseDialogMsg{}),
			util.ReportInfo(fmt.Sprintf("Active quest: #%d", msg.item.Number)),
		)
	case clearMsg:
		q.loading = false
		if msg.err != nil {
			return q, util.ReportError(msg.err)
		}
		return q, tea.Batch(
			util.CmdHandler(dialogs.CloseDialogMsg{}),
			util.ReportInfo("Quest cleared"),
		)
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, q.keyMap.Close):
			return q, util.CmdHandler(dialogs.CloseDialogMsg{})
		case key.Matches(msg, q.keyMap.Refresh):
			return q, q.refresh()
		case key.Matches(msg, q.keyMap.Clear):
			return q, q.clearActive()
		case key.Matches(msg, q.keyMap.Select):
			selected := q.list.SelectedItem()
			if selected == nil {
				return q, nil
			}
			it := (*selected).Value()
			if it.Number <= 0 {
				return q, nil
			}
			return q, q.setActive(it)
		default:
			u, cmd := q.list.Update(msg)
			q.list = u.(list.FilterableList[list.CompletionItem[issue]])
			return q, cmd
		}
	}
	u, cmd := q.list.Update(msg)
	q.list = u.(list.FilterableList[list.CompletionItem[issue]])
	return q, cmd
}

func (q *questsDialogCmp) View() string {
	t := styles.CurrentTheme()
	title := core.Title("GitHub Quests", q.width-4)
	header := t.S().Base.Padding(0, 1, 1, 1).Render(title)

	status := ""
	if strings.TrimSpace(q.repo) == "" {
		status = t.S().Error.Padding(0, 1).Render("No repo configured")
	} else if q.loading {
		status = t.S().Muted.Padding(0, 1).Render("Loading...")
	} else if q.err != nil {
		status = t.S().Error.Padding(0, 1).Render(q.err.Error())
	} else if len(q.items) == 0 {
		status = t.S().Muted.Padding(0, 1).Render("No open issues")
	} else {
		status = t.S().Muted.Padding(0, 1).Render(fmt.Sprintf("%s • %d issues", q.repo, len(q.items)))
	}

	dupLine := ""
	if strings.TrimSpace(q.dupSummary) != "" && q.err == nil && !q.loading {
		dupLine = t.S().Warning.Padding(0, 1).Render(q.dupSummary)
	}

	helpLine := t.S().Base.Padding(0, 1).Width(q.width - 2).Render(q.help.View(q.keyMap))

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		status,
		dupLine,
		q.list.View(),
		"",
		helpLine,
	)
	return q.style().Render(content)
}

func (q *questsDialogCmp) Cursor() *tea.Cursor {
	if cursor, ok := q.list.(util.Cursor); ok {
		return cursor.Cursor()
	}
	return nil
}

func (q *questsDialogCmp) Position() (int, int) {
	row := q.wHeight/4 - 2
	col := q.wWidth/2 - q.width/2
	return row, col
}

func (q *questsDialogCmp) ID() dialogs.DialogID {
	return QuestsDialogID
}

func (q *questsDialogCmp) style() lipgloss.Style {
	t := styles.CurrentTheme()
	return t.S().Base.
		Width(q.width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(t.BorderFocus)
}

func (q *questsDialogCmp) listWidth() int {
	return q.width - 2
}

func (q *questsDialogCmp) listHeight() int {
	base := 12
	if q.wHeight > 0 {
		base = min(q.wHeight/2, max(12, len(q.items)+6))
	}
	return max(12, base-6)
}

func (q *questsDialogCmp) refresh() tea.Cmd {
	q.loading = true
	q.err = nil
	return func() tea.Msg {
		repo := strings.TrimSpace(q.repo)
		if repo == "" {
			return issuesMsg{err: errors.New("repo required")}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		items, err := fetchIssues(ctx, repo, q.token)
		if err != nil {
			return issuesMsg{err: err}
		}
		slices.SortFunc(items, func(a, b issue) int {
			return cmpIssue(a, b)
		})
		return issuesMsg{items: items}
	}
}

func (q *questsDialogCmp) setItems() tea.Cmd {
	items := make([]list.CompletionItem[issue], 0, len(q.items))
	for _, it := range q.items {
		title := strings.TrimSpace(it.Title)
		if title == "" {
			title = fmt.Sprintf("#%d", it.Number)
		}
		if q.dup != nil && q.dup[it.Number] {
			title = title + " (dup)"
		}
		item := list.NewCompletionItem(
			title,
			it,
			list.WithCompletionID(strconv.Itoa(it.Number)),
			list.WithCompletionShortcut(fmt.Sprintf("#%d", it.Number)),
		)
		items = append(items, item)
	}
	return q.list.SetItems(items)
}

func (q *questsDialogCmp) setActive(it issue) tea.Cmd {
	q.loading = true
	q.err = nil
	return func() tea.Msg {
		if err := setActiveQuest(it); err != nil {
			return setActiveMsg{err: err}
		}
		return setActiveMsg{item: it}
	}
}

func (q *questsDialogCmp) clearActive() tea.Cmd {
	q.loading = true
	q.err = nil
	return func() tea.Msg {
		if err := clearActiveQuest(); err != nil {
			return clearMsg{err: err}
		}
		return clearMsg{}
	}
}

func setActiveQuest(it issue) error {
	cfg := config.Get()
	if cfg.Options == nil {
		cfg.Options = &config.Options{}
	}
	if cfg.Options.TUI == nil {
		cfg.Options.TUI = &config.TUIOptions{}
	}
	if cfg.Options.TUI.Quests == nil {
		cfg.Options.TUI.Quests = &config.QuestOptions{}
	}
	cfg.Options.TUI.Quests.Enabled = true
	cfg.Options.TUI.Quests.ActiveIssue = it.Number
	cfg.Options.TUI.Quests.ActiveTitle = it.Title
	cfg.Options.TUI.Quests.ActiveURL = it.HTMLURL
	if err := cfg.SetConfigField("options.tui.quests.enabled", true); err != nil {
		return err
	}
	if err := cfg.SetConfigField("options.tui.quests.active_issue", it.Number); err != nil {
		return err
	}
	if err := cfg.SetConfigField("options.tui.quests.active_title", it.Title); err != nil {
		return err
	}
	if err := cfg.SetConfigField("options.tui.quests.active_url", it.HTMLURL); err != nil {
		return err
	}
	return nil
}

func clearActiveQuest() error {
	cfg := config.Get()
	if cfg.Options != nil && cfg.Options.TUI != nil && cfg.Options.TUI.Quests != nil {
		cfg.Options.TUI.Quests.ActiveIssue = 0
		cfg.Options.TUI.Quests.ActiveTitle = ""
		cfg.Options.TUI.Quests.ActiveURL = ""
	}
	if err := cfg.RemoveConfigField("options.tui.quests.active_issue"); err != nil {
		return err
	}
	_ = cfg.RemoveConfigField("options.tui.quests.active_title")
	_ = cfg.RemoveConfigField("options.tui.quests.active_url")
	return nil
}

func fetchIssues(ctx context.Context, repo string, token string) ([]issue, error) {
	if strings.Count(repo, "/") != 1 {
		return nil, errors.New("repo must be owner/name")
	}

	u := url.URL{
		Scheme: "https",
		Host:   "api.github.com",
		Path:   "/repos/" + repo + "/issues",
	}
	q := u.Query()
	q.Set("state", "open")
	q.Set("per_page", "50")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "synapseide")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var items []issue
	if err := json.Unmarshal(b, &items); err != nil {
		return nil, err
	}
	out := make([]issue, 0, len(items))
	for _, it := range items {
		if it.Number <= 0 || strings.TrimSpace(it.Title) == "" {
			continue
		}
		if len(it.PullRequest) > 0 {
			continue
		}
		out = append(out, it)
	}
	return out, nil
}

func cmpIssue(a, b issue) int {
	if a.Number == b.Number {
		return strings.Compare(a.Title, b.Title)
	}
	if a.Number < b.Number {
		return -1
	}
	return 1
}

func detectDuplicateIssues(items []issue) (map[int]bool, string) {
	type group struct {
		key   string
		nums  []int
		count int
	}

	titleKey := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.NewReplacer(
			":", " ",
			"-", " ",
			"_", " ",
			".", " ",
			",", " ",
			";", " ",
			"(", " ",
			")", " ",
			"[", " ",
			"]", " ",
			"{", " ",
			"}", " ",
			"!", " ",
			"?", " ",
			"#", " ",
			"/", " ",
			"\\", " ",
			"\"", " ",
			"'", " ",
		).Replace(s)
		s = strings.Join(strings.Fields(s), " ")
		if len(s) < 10 {
			return ""
		}
		return s
	}

	buckets := map[string][]int{}
	for _, it := range items {
		k := titleKey(it.Title)
		if k == "" || it.Number <= 0 {
			continue
		}
		buckets[k] = append(buckets[k], it.Number)
	}

	var groups []group
	dup := map[int]bool{}
	for k, nums := range buckets {
		if len(nums) < 2 {
			continue
		}
		slices.Sort(nums)
		for _, n := range nums {
			dup[n] = true
		}
		groups = append(groups, group{key: k, nums: nums, count: len(nums)})
	}
	if len(groups) == 0 {
		return nil, ""
	}
	slices.SortFunc(groups, func(a, b group) int {
		if a.count != b.count {
			return b.count - a.count
		}
		return strings.Compare(a.key, b.key)
	})

	limit := min(3, len(groups))
	out := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		nums := groups[i].nums
		parts := make([]string, 0, min(3, len(nums)))
		for j := 0; j < len(nums) && j < 3; j++ {
			parts = append(parts, fmt.Sprintf("#%d", nums[j]))
		}
		if len(nums) > 3 {
			parts = append(parts, fmt.Sprintf("+%d", len(nums)-3))
		}
		out = append(out, strings.Join(parts, "/"))
	}

	return dup, "Possible duplicates: " + strings.Join(out, ", ")
}
