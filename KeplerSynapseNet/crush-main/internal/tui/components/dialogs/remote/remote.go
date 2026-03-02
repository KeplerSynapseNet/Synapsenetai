package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
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

const RemoteDialogID dialogs.DialogID = "remote"

type RemoteDialog interface {
	dialogs.DialogModel
}

type remoteOffer struct {
	OfferID         string `json:"offerId"`
	PeerID          string `json:"peerId"`
	ReceivedAt      uint64 `json:"receivedAt"`
	ModelID         string `json:"modelId"`
	ProviderAddress string `json:"providerAddress"`
	PricePerRequest uint64 `json:"pricePerRequestAtoms"`
	MaxSlots        uint32 `json:"maxSlots"`
	UsedSlots       uint32 `json:"usedSlots"`
	ExpiresAt       uint64 `json:"expiresAt"`
}

type remoteDialogCmp struct {
	width   int
	wWidth  int
	wHeight int

	offers []remoteOffer

	list   list.FilterableList[list.CompletionItem[remoteOffer]]
	keyMap KeyMap
	help   help.Model

	loading bool
	err     error
}

type offersMsg struct {
	offers []remoteOffer
	err    error
}

type rentMsg struct {
	offerID   string
	sessionID string
	err       error
}

type disableMsg struct {
	err error
}

func NewRemoteDialogCmp() RemoteDialog {
	keyMap := DefaultKeyMap()
	listKeyMap := list.DefaultKeyMap()
	listKeyMap.Down.SetEnabled(false)
	listKeyMap.Up.SetEnabled(false)
	listKeyMap.DownOneItem = keyMap.Next
	listKeyMap.UpOneItem = keyMap.Previous

	t := styles.CurrentTheme()
	inputStyle := t.S().Base.PaddingLeft(1).PaddingBottom(1)
	l := list.NewFilterableList(
		[]list.CompletionItem[remoteOffer]{},
		list.WithFilterInputStyle(inputStyle),
		list.WithFilterPlaceholder("Find remote offers"),
		list.WithFilterListOptions(
			list.WithKeyMap(listKeyMap),
			list.WithWrapNavigation(),
			list.WithResizeByList(),
		),
	)

	h := help.New()
	h.Styles = t.S().Help

	return &remoteDialogCmp{
		width:  90,
		list:   l,
		keyMap: keyMap,
		help:   h,
	}
}

func (r *remoteDialogCmp) Init() tea.Cmd {
	return tea.Sequence(
		r.list.Init(),
		r.refresh(),
	)
}

func (r *remoteDialogCmp) Update(msg tea.Msg) (util.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		r.wWidth = msg.Width
		r.wHeight = msg.Height
		r.width = min(120, r.wWidth-8)
		r.help.SetWidth(r.width - 2)
		return r, r.list.SetSize(r.listWidth(), r.listHeight())
	case offersMsg:
		r.loading = false
		r.err = msg.err
		r.offers = msg.offers
		return r, r.setItems()
	case rentMsg:
		r.loading = false
		if msg.err != nil {
			return r, util.ReportError(msg.err)
		}
		if err := enableRemoteSession(msg.sessionID); err != nil {
			return r, util.ReportError(err)
		}
		return r, tea.Batch(
			util.CmdHandler(dialogs.CloseDialogMsg{}),
			util.ReportInfo(fmt.Sprintf("Remote session enabled: %s", shortenID(msg.sessionID))),
		)
	case disableMsg:
		r.loading = false
		if msg.err != nil {
			return r, util.ReportError(msg.err)
		}
		return r, tea.Batch(
			util.CmdHandler(dialogs.CloseDialogMsg{}),
			util.ReportInfo("Remote inference disabled"),
		)
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, r.keyMap.Close):
			return r, util.CmdHandler(dialogs.CloseDialogMsg{})
		case key.Matches(msg, r.keyMap.Refresh):
			return r, r.refresh()
		case key.Matches(msg, r.keyMap.Disable):
			return r, r.disableRemote()
		case key.Matches(msg, r.keyMap.Select):
			selected := r.list.SelectedItem()
			if selected == nil {
				return r, nil
			}
			offer := (*selected).Value()
			if strings.TrimSpace(offer.OfferID) == "" {
				return r, nil
			}
			return r, r.rentOffer(offer.OfferID)
		default:
			u, cmd := r.list.Update(msg)
			r.list = u.(list.FilterableList[list.CompletionItem[remoteOffer]])
			return r, cmd
		}
	}
	u, cmd := r.list.Update(msg)
	r.list = u.(list.FilterableList[list.CompletionItem[remoteOffer]])
	return r, cmd
}

func (r *remoteDialogCmp) View() string {
	t := styles.CurrentTheme()
	title := core.Title("Remote Rentals", r.width-4)

	header := t.S().Base.Padding(0, 1, 1, 1).Render(title)

	status := ""
	if r.loading {
		status = t.S().Muted.Padding(0, 1).Render("Loading...")
	} else if r.err != nil {
		status = t.S().Error.Padding(0, 1).Render(r.err.Error())
	} else if len(r.offers) == 0 {
		status = t.S().Muted.Padding(0, 1).Render("No offers discovered")
	} else {
		status = t.S().Muted.Padding(0, 1).Render(fmt.Sprintf("%d offers", len(r.offers)))
	}

	helpLine := t.S().Base.Padding(0, 1).Width(r.width - 2).Render(r.help.View(r.keyMap))

	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		status,
		r.list.View(),
		"",
		helpLine,
	)
	return r.style().Render(content)
}

func (r *remoteDialogCmp) Cursor() *tea.Cursor {
	if cursor, ok := r.list.(util.Cursor); ok {
		return cursor.Cursor()
	}
	return nil
}

func (r *remoteDialogCmp) Position() (int, int) {
	row := r.wHeight/4 - 2
	col := r.wWidth/2 - r.width/2
	return row, col
}

func (r *remoteDialogCmp) ID() dialogs.DialogID {
	return RemoteDialogID
}

func (r *remoteDialogCmp) style() lipgloss.Style {
	t := styles.CurrentTheme()
	return t.S().Base.
		Width(r.width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(t.BorderFocus)
}

func (r *remoteDialogCmp) listWidth() int {
	return r.width - 2
}

func (r *remoteDialogCmp) listHeight() int {
	base := 10
	if r.wHeight > 0 {
		base = min(r.wHeight/2, max(10, len(r.offers)+6))
	}
	return max(10, base-6)
}

func (r *remoteDialogCmp) refresh() tea.Cmd {
	r.loading = true
	r.err = nil
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		var out []remoteOffer
		err := synapsedRPC(ctx, "model.remote.list", map[string]any{}, &out)
		if err != nil {
			return offersMsg{err: err}
		}
		slices.SortFunc(out, func(a, b remoteOffer) int {
			return strings.Compare(a.ModelID+a.OfferID, b.ModelID+b.OfferID)
		})
		return offersMsg{offers: out}
	}
}

func (r *remoteDialogCmp) rentOffer(offerID string) tea.Cmd {
	r.loading = true
	r.err = nil
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()

		var out struct {
			OK        bool   `json:"ok"`
			OfferID   string `json:"offerId"`
			SessionID string `json:"sessionId"`
		}
		err := synapsedRPC(ctx, "model.remote.rent", map[string]any{
			"offerId": offerID,
		}, &out)
		if err != nil {
			return rentMsg{offerID: offerID, err: err}
		}
		if !out.OK || strings.TrimSpace(out.SessionID) == "" {
			return rentMsg{offerID: offerID, err: errors.New("rent failed")}
		}
		return rentMsg{offerID: offerID, sessionID: out.SessionID}
	}
}

func (r *remoteDialogCmp) disableRemote() tea.Cmd {
	r.loading = true
	r.err = nil
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := disableRemoteSession(ctx); err != nil {
			return disableMsg{err: err}
		}
		return disableMsg{}
	}
}

func (r *remoteDialogCmp) setItems() tea.Cmd {
	items := make([]list.CompletionItem[remoteOffer], 0, len(r.offers))
	for _, o := range r.offers {
		title := strings.TrimSpace(o.ModelID)
		if title == "" {
			title = shortenID(o.OfferID)
		}
		shortcut := fmt.Sprintf("%d/%d", o.UsedSlots, o.MaxSlots)
		if o.PricePerRequest > 0 {
			shortcut = fmt.Sprintf("%s  %d", shortcut, o.PricePerRequest)
		}
		item := list.NewCompletionItem(
			title,
			o,
			list.WithCompletionID(o.OfferID),
			list.WithCompletionShortcut(shortcut),
		)
		items = append(items, item)
	}
	return r.list.SetItems(items)
}

func shortenID(id string) string {
	id = strings.TrimSpace(id)
	if len(id) <= 10 {
		return id
	}
	return id[:10]
}

func enableRemoteSession(sessionID string) error {
	cfg := config.Get()
	if cfg.Options == nil {
		cfg.Options = &config.Options{}
	}
	if cfg.Options.TUI == nil {
		cfg.Options.TUI = &config.TUIOptions{}
	}
	if cfg.Options.TUI.Remote == nil {
		cfg.Options.TUI.Remote = &config.RemoteOptions{}
	}
	cfg.Options.TUI.Remote.Enabled = true
	cfg.Options.TUI.Remote.SessionID = sessionID
	if err := cfg.SetConfigField("options.tui.remote.enabled", true); err != nil {
		return err
	}
	if err := cfg.SetConfigField("options.tui.remote.session_id", sessionID); err != nil {
		return err
	}
	return nil
}

func disableRemoteSession(ctx context.Context) error {
	cfg := config.Get()
	var sessionID string
	if cfg.Options != nil && cfg.Options.TUI != nil && cfg.Options.TUI.Remote != nil {
		sessionID = strings.TrimSpace(cfg.Options.TUI.Remote.SessionID)
		cfg.Options.TUI.Remote.Enabled = false
		cfg.Options.TUI.Remote.SessionID = ""
	}
	if err := cfg.SetConfigField("options.tui.remote.enabled", false); err != nil {
		return err
	}
	_ = cfg.RemoveConfigField("options.tui.remote.session_id")

	if sessionID != "" {
		var out struct {
			OK bool `json:"ok"`
		}
		_ = synapsedRPC(ctx, "model.remote.end", map[string]any{"sessionId": sessionID}, &out)
	}
	return nil
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func synapseBaseURL() string {
	cfg := config.Get()
	if cfg != nil {
		if pc, ok := cfg.Providers.Get("synapsenet"); ok {
			if v := strings.TrimSpace(pc.BaseURL); v != "" {
				return v
			}
		}
	}
	return "http://127.0.0.1:8332"
}

func synapsedRPC(ctx context.Context, method string, params any, out any) error {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, synapseBaseURL(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 50 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("rpc http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var rr rpcResponse
	if err := json.Unmarshal(b, &rr); err != nil {
		return err
	}
	if rr.Error != nil {
		return fmt.Errorf("rpc error %d: %s", rr.Error.Code, rr.Error.Message)
	}
	if out == nil {
		return nil
	}
	if len(rr.Result) == 0 {
		return errors.New("rpc: empty result")
	}
	return json.Unmarshal(rr.Result, out)
}
