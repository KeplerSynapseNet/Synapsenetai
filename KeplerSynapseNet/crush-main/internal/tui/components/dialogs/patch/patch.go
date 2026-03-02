package patch

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/aymanbagabas/go-udiff"
	"github.com/charmbracelet/crush/internal/app"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/fsext"
	"github.com/charmbracelet/crush/internal/lsp"
	"github.com/charmbracelet/crush/internal/patch"
	"github.com/charmbracelet/crush/internal/tui/components/core"
	"github.com/charmbracelet/crush/internal/tui/components/dialogs"
	"github.com/charmbracelet/crush/internal/tui/components/dialogs/commands"
	"github.com/charmbracelet/crush/internal/tui/styles"
	"github.com/charmbracelet/crush/internal/tui/util"
)

const PatchDialogID dialogs.DialogID = "patch"

type PatchDialog interface {
	dialogs.DialogModel
}

type fileChange struct {
	relPath    string
	absPath    string
	oldContent string
	newContent string
	isCRLF     bool
	isNew      bool
	isDelete   bool
	applied    bool
	skipped    bool
	err        error
}

type patchDialogCmp struct {
	wWidth  int
	wHeight int
	width   int
	height  int

	app       *app.App
	sessionID string

	changes []fileChange
	index   int

	keyMap KeyMap
	help   help.Model

	defaultDiffSplitMode bool
	diffSplitMode        *bool
	diffXOffset          int
	diffYOffset          int
}

type applyAllResultMsg struct {
	err error
}

func New(app *app.App, sessionID string, patches []patch.FilePatch) PatchDialog {
	t := styles.CurrentTheme()
	h := help.New()
	h.Styles = t.S().Help

	d := &patchDialogCmp{
		app:       app,
		sessionID: sessionID,
		keyMap:    DefaultKeyMap(),
		help:      h,
	}
	d.changes = d.buildChanges(patches)
	return d
}

func (p *patchDialogCmp) Init() tea.Cmd {
	return nil
}

func (p *patchDialogCmp) Update(msg tea.Msg) (util.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		p.wWidth = msg.Width
		p.wHeight = msg.Height
		p.width = min(140, p.wWidth-8)
		p.height = min(p.wHeight-8, max(18, p.wHeight-10))
		return p, nil
	case applyAllResultMsg:
		if msg.err != nil {
			return p, util.ReportError(msg.err)
		}
		return p, tea.Batch(
			util.CmdHandler(dialogs.CloseDialogMsg{}),
			util.ReportInfo("Patch applied"),
		)
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, p.keyMap.Close):
			return p, util.CmdHandler(dialogs.CloseDialogMsg{})
		case key.Matches(msg, p.keyMap.Left):
			p.prev()
			return p, nil
		case key.Matches(msg, p.keyMap.Right):
			p.next()
			return p, nil
		case key.Matches(msg, p.keyMap.ToggleDiffMode):
			if p.diffSplitMode == nil {
				mode := !p.defaultDiffSplitMode
				p.diffSplitMode = &mode
			} else {
				*p.diffSplitMode = !*p.diffSplitMode
			}
			return p, nil
		case key.Matches(msg, p.keyMap.ScrollDown):
			p.diffYOffset++
			return p, nil
		case key.Matches(msg, p.keyMap.ScrollUp):
			p.diffYOffset = max(0, p.diffYOffset-1)
			return p, nil
		case key.Matches(msg, p.keyMap.ScrollLeft):
			p.diffXOffset = max(0, p.diffXOffset-1)
			return p, nil
		case key.Matches(msg, p.keyMap.ScrollRight):
			p.diffXOffset++
			return p, nil
		case key.Matches(msg, p.keyMap.Skip):
			p.skipCurrent()
			return p, p.maybeClose()
		case key.Matches(msg, p.keyMap.Submit):
			return p, p.openSubmitDialog()
		case key.Matches(msg, p.keyMap.ApplyAll):
			return p, p.applyAll()
		case key.Matches(msg, p.keyMap.Apply):
			return p, tea.Sequence(p.applyCurrent(), p.maybeClose())
		}
	}
	return p, nil
}

func (p *patchDialogCmp) View() string {
	t := styles.CurrentTheme()

	if len(p.changes) == 0 {
		content := t.S().Base.Padding(1, 2).Render("No patch changes")
		return p.style().Render(content)
	}

	cur := p.changes[p.index]
	title := fmt.Sprintf("Apply Patch (%d/%d)", p.index+1, len(p.changes))
	fileLine := cur.relPath
	if cur.isDelete {
		fileLine = cur.relPath + " (delete)"
	}

	header := lipgloss.JoinVertical(
		lipgloss.Left,
		t.S().Base.Padding(0, 1, 0, 1).Render(core.Title(title, p.width-4)),
		"",
		t.S().Muted.Padding(0, 2).Width(p.width-4).Render(fileLine),
	)

	diff := p.renderDiff(cur)
	helpLine := t.S().Base.Padding(0, 2).Width(p.width - 4).Render(p.help.View(p.keyMap))

	body := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		"",
		diff,
		"",
		helpLine,
	)
	return p.style().Render(body)
}

func (p *patchDialogCmp) Cursor() *tea.Cursor {
	return nil
}

func (p *patchDialogCmp) Position() (int, int) {
	row := p.wHeight/4 - 2
	col := p.wWidth/2 - p.width/2
	return row, col
}

func (p *patchDialogCmp) ID() dialogs.DialogID {
	return PatchDialogID
}

func (p *patchDialogCmp) style() lipgloss.Style {
	t := styles.CurrentTheme()
	return t.S().Base.
		Width(p.width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(t.BorderFocus)
}

func (p *patchDialogCmp) renderDiff(ch fileChange) string {
	t := styles.CurrentTheme()

	if ch.err != nil {
		return t.S().Error.Padding(0, 2).Width(p.width - 4).Render(ch.err.Error())
	}

	formatter := core.DiffFormatter().
		Before(fsext.PrettyPath(ch.relPath), ch.oldContent).
		After(fsext.PrettyPath(ch.relPath), ch.newContent).
		Height(p.height - 8).
		Width(p.width - 4).
		XOffset(p.diffXOffset).
		YOffset(p.diffYOffset)

	if p.useDiffSplitMode() {
		formatter = formatter.Split()
	} else {
		formatter = formatter.Unified()
	}

	return formatter.String()
}

func (p *patchDialogCmp) useDiffSplitMode() bool {
	if p.diffSplitMode != nil {
		return *p.diffSplitMode
	}
	return p.defaultDiffSplitMode
}

func (p *patchDialogCmp) prev() {
	if p.index <= 0 {
		return
	}
	p.index--
	p.diffXOffset = 0
	p.diffYOffset = 0
}

func (p *patchDialogCmp) next() {
	if p.index >= len(p.changes)-1 {
		return
	}
	p.index++
	p.diffXOffset = 0
	p.diffYOffset = 0
}

func (p *patchDialogCmp) skipCurrent() {
	if len(p.changes) == 0 {
		return
	}
	p.changes[p.index].skipped = true
	p.next()
}

func (p *patchDialogCmp) applyAll() tea.Cmd {
	return func() tea.Msg {
		err := p.applyAllNow(context.Background())
		return applyAllResultMsg{err: err}
	}
}

func (p *patchDialogCmp) applyAllNow(ctx context.Context) error {
	for i := range p.changes {
		ch := &p.changes[i]
		if ch.applied || ch.skipped {
			continue
		}
		if ch.err != nil {
			p.index = i
			return ch.err
		}
		if err := p.applyChange(ctx, ch); err != nil {
			ch.err = err
			p.index = i
			return err
		}
		ch.applied = true
	}
	return nil
}

func (p *patchDialogCmp) applyCurrent() tea.Cmd {
	return func() tea.Msg {
		if len(p.changes) == 0 {
			return nil
		}
		ch := &p.changes[p.index]
		if ch.err != nil {
			return util.InfoMsg{Type: util.InfoTypeError, Msg: ch.err.Error()}
		}
		if ch.applied || ch.skipped {
			return nil
		}
		if err := p.applyChange(context.Background(), ch); err != nil {
			ch.err = err
			return util.InfoMsg{Type: util.InfoTypeError, Msg: err.Error()}
		}
		ch.applied = true
		p.next()
		return util.InfoMsg{Type: util.InfoTypeSuccess, Msg: "Patch applied"}
	}
}

func (p *patchDialogCmp) maybeClose() tea.Cmd {
	return func() tea.Msg {
		for _, ch := range p.changes {
			if !ch.applied && !ch.skipped && ch.err == nil {
				return nil
			}
		}
		return dialogs.CloseDialogMsg{}
	}
}

func (p *patchDialogCmp) applyChange(ctx context.Context, ch *fileChange) error {
	if ch.relPath == "" || ch.absPath == "" {
		return errors.New("invalid file path")
	}

	if ch.isDelete {
		if err := os.Remove(ch.absPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return p.recordHistory(ctx, ch.absPath, ch.oldContent, "")
	}

	if err := os.MkdirAll(filepath.Dir(ch.absPath), 0o755); err != nil {
		return err
	}

	writeContent := ch.newContent
	if ch.isCRLF {
		wc, _ := fsext.ToWindowsLineEndings(writeContent)
		writeContent = wc
	}
	if err := os.WriteFile(ch.absPath, []byte(writeContent), 0o644); err != nil {
		return err
	}

	p.notifyLSPs(ctx, ch.absPath)
	return p.recordHistory(ctx, ch.absPath, ch.oldContent, writeContent)
}

func (p *patchDialogCmp) recordHistory(ctx context.Context, absPath, oldContent, newContent string) error {
	h := p.app.History
	_, err := h.GetByPathAndSession(ctx, absPath, p.sessionID)
	if err != nil {
		_, err = h.Create(ctx, p.sessionID, absPath, oldContent)
		if err != nil {
			return err
		}
	}
	_, err = h.CreateVersion(ctx, p.sessionID, absPath, newContent)
	return err
}

func (p *patchDialogCmp) notifyLSPs(ctx context.Context, path string) {
	if path == "" {
		return
	}
	var lsps *csync.Map[string, *lsp.Client]
	lsps = p.app.LSPClients
	for client := range lsps.Seq() {
		if !client.HandlesFile(path) {
			continue
		}
		_ = client.OpenFileOnDemand(ctx, path)
		_ = client.NotifyChange(ctx, path)
		client.WaitForDiagnostics(ctx, 5*time.Second)
	}
}

func (p *patchDialogCmp) buildChanges(patches []patch.FilePatch) []fileChange {
	workingDir := p.app.Config().WorkingDir()
	out := make([]fileChange, 0, len(patches))

	for _, fp := range patches {
		relPath := fp.NewPath
		if relPath == "" || relPath == "/dev/null" {
			relPath = fp.OldPath
		}
		relPath = strings.TrimPrefix(relPath, "./")

		absPath, err := safeJoin(workingDir, relPath)
		ch := fileChange{
			relPath:  relPath,
			absPath:  absPath,
			isDelete: fp.NewPath == "/dev/null",
			isNew:    fp.OldPath == "/dev/null" && fp.NewPath != "/dev/null",
			err:      err,
		}

		if ch.err == nil && !ch.isDelete && (fp.OldPath == "/dev/null") {
			ch.oldContent = ""
			newContent, applyErr := patch.Apply("", fp)
			ch.newContent = newContent
			ch.err = applyErr
			out = append(out, ch)
			continue
		}

		if ch.err == nil && (fp.OldPath != "/dev/null") {
			content, readErr := os.ReadFile(absPath)
			if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
				ch.err = readErr
			} else {
				old, isCrlf := fsext.ToUnixLineEndings(string(content))
				ch.oldContent = old
				ch.isCRLF = isCrlf
				newContent, applyErr := patch.Apply(old, fp)
				ch.newContent = newContent
				ch.err = applyErr
			}
		}

		if ch.err == nil && ch.isDelete {
			ch.newContent = ""
		}

		out = append(out, ch)
	}
	return out
}

func safeJoin(root, rel string) (string, error) {
	if rel == "" {
		return "", errors.New("empty path")
	}
	if filepath.IsAbs(rel) {
		return "", errors.New("absolute paths are not allowed")
	}
	clean := filepath.Clean(rel)
	abs := filepath.Join(root, clean)
	r, err := filepath.Rel(root, abs)
	if err != nil {
		return "", err
	}
	if r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return "", errors.New("path escapes working directory")
	}
	return abs, nil
}

func (p *patchDialogCmp) openSubmitDialog() tea.Cmd {
	if len(p.changes) == 0 {
		return util.ReportError(errors.New("no patch changes"))
	}

	return util.CmdHandler(dialogs.OpenDialogMsg{
		Model: commands.NewCommandArgumentsDialog(
			"poe.submit_code",
			"Submit PoE CODE",
			"poe.submit_code",
			"Publish patch as PoE CODE entry",
			[]commands.Argument{
				{Name: "title", Title: "Title", Description: "Entry title", Required: true},
				{Name: "citations", Title: "Citations", Description: "Comma/space separated PoE IDs (optional)", Required: false},
				{Name: "auto_finalize", Title: "Auto Finalize", Description: "true/false (default true)", Required: false},
			},
			func(args map[string]string) tea.Cmd {
				return func() tea.Msg {
					title := strings.TrimSpace(args["title"])
					if title == "" {
						return util.InfoMsg{Type: util.InfoTypeError, Msg: "Title is required"}
					}

					patchText, err := p.buildPatchForSubmit()
					if err != nil {
						return util.InfoMsg{Type: util.InfoTypeError, Msg: err.Error()}
					}

					params := map[string]any{
						"title": title,
						"patch": patchText,
					}

					if citations := parseCitations(args["citations"]); len(citations) > 0 {
						params["citations"] = citations
					}
					if af, ok := parseOptionalBool(args["auto_finalize"]); ok {
						params["auto_finalize"] = af
					}

					baseURL := "http://127.0.0.1:8332"
					if pc, ok := p.app.Config().Providers.Get("synapsenet"); ok && strings.TrimSpace(pc.BaseURL) != "" {
						baseURL = strings.TrimSpace(pc.BaseURL)
					}

					ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
					defer cancel()

					res, err := poeSubmitCodeRPC(ctx, baseURL, params)
					if err != nil {
						return util.InfoMsg{Type: util.InfoTypeError, Msg: err.Error()}
					}

					return tea.Sequence(
						util.CmdHandler(dialogs.CloseDialogMsg{}),
						util.ReportInfo(fmt.Sprintf("PoE CODE submitted: %s", res.SubmitID)),
					)()
				}
			},
		),
	})
}

func (p *patchDialogCmp) buildPatchForSubmit() (string, error) {
	var selected []fileChange
	for _, ch := range p.changes {
		if ch.applied && !ch.skipped && ch.err == nil {
			selected = append(selected, ch)
		}
	}
	if len(selected) == 0 {
		for _, ch := range p.changes {
			if !ch.skipped && ch.err == nil {
				selected = append(selected, ch)
			}
		}
	}
	if len(selected) == 0 {
		return "", errors.New("no changes to submit")
	}

	var parts []string
	for _, ch := range selected {
		rel := strings.TrimPrefix(ch.relPath, "/")
		if rel == "" {
			continue
		}

		oldName := "a/" + rel
		newName := "b/" + rel
		if ch.isDelete {
			newName = "/dev/null"
		} else if ch.isNew {
			oldName = "/dev/null"
		}

		diffText := udiff.Unified(oldName, newName, ch.oldContent, ch.newContent)
		if strings.TrimSpace(diffText) == "" {
			continue
		}
		parts = append(parts, strings.TrimRight(diffText, "\n"))
	}
	if len(parts) == 0 {
		return "", errors.New("empty patch")
	}
	return strings.Join(parts, "\n") + "\n", nil
}

func parseCitations(input string) []string {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return nil
	}
	raw = strings.ReplaceAll(raw, "\n", " ")
	raw = strings.ReplaceAll(raw, ",", " ")
	raw = strings.ReplaceAll(raw, "\t", " ")
	fields := strings.Fields(raw)
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		v := strings.TrimSpace(f)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}

func parseOptionalBool(input string) (bool, bool) {
	v := strings.ToLower(strings.TrimSpace(input))
	if v == "" {
		return false, false
	}
	switch v {
	case "1", "true", "yes", "y", "on":
		return true, true
	case "0", "false", "no", "n", "off":
		return false, true
	default:
		return false, false
	}
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

type poeSubmitCodeResult struct {
	Status   string `json:"status"`
	SubmitID string `json:"submitId"`
}

func poeSubmitCodeRPC(ctx context.Context, baseURL string, params map[string]any) (poeSubmitCodeResult, error) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "poe.submit_code",
		"params":  params,
	})
	if err != nil {
		return poeSubmitCodeResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(body))
	if err != nil {
		return poeSubmitCodeResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return poeSubmitCodeResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return poeSubmitCodeResult{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return poeSubmitCodeResult{}, fmt.Errorf("rpc http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var rr rpcResponse
	if err := json.Unmarshal(b, &rr); err != nil {
		return poeSubmitCodeResult{}, err
	}
	if rr.Error != nil {
		return poeSubmitCodeResult{}, fmt.Errorf("rpc error %d: %s", rr.Error.Code, rr.Error.Message)
	}

	var out poeSubmitCodeResult
	if err := json.Unmarshal(rr.Result, &out); err != nil {
		return poeSubmitCodeResult{}, err
	}
	if strings.TrimSpace(out.SubmitID) == "" {
		return poeSubmitCodeResult{}, errors.New("rpc: empty submitId")
	}
	return out, nil
}
