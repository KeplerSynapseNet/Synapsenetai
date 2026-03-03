package models

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/tui/exp/list"
	"github.com/charmbracelet/crush/internal/tui/styles"
	"github.com/charmbracelet/crush/internal/tui/util"
)

type listModel = list.FilterableGroupList[list.CompletionItem[ModelOption]]

type ModelListComponent struct {
	list        listModel
	modelType   int
	localModels []catwalk.Model
}

func modelKey(providerID, modelID string) string {
	if providerID == "" || modelID == "" {
		return ""
	}
	return providerID + ":" + modelID
}

func NewModelListComponent(keyMap list.KeyMap, inputPlaceholder string, shouldResize bool) *ModelListComponent {
	t := styles.CurrentTheme()
	inputStyle := t.S().Base.PaddingLeft(1).PaddingBottom(1)
	options := []list.ListOption{
		list.WithKeyMap(keyMap),
		list.WithWrapNavigation(),
	}
	if shouldResize {
		options = append(options, list.WithResizeByList())
	}
	modelList := list.NewFilterableGroupedList(
		[]list.Group[list.CompletionItem[ModelOption]]{},
		list.WithFilterInputStyle(inputStyle),
		list.WithFilterPlaceholder(inputPlaceholder),
		list.WithFilterListOptions(
			options...,
		),
	)

	return &ModelListComponent{
		list:      modelList,
		modelType: LargeModelType,
	}
}

type localModelsMsg struct {
	models []catwalk.Model
}

func (m *ModelListComponent) Init() tea.Cmd {
	return tea.Batch(
		m.list.Init(),
		m.SetModelType(m.modelType),
		m.refreshLocalModelsCmd(),
	)
}

func (m *ModelListComponent) Update(msg tea.Msg) (*ModelListComponent, tea.Cmd) {
	switch msg := msg.(type) {
	case localModelsMsg:
		m.localModels = msg.models
		return m, m.SetModelType(m.modelType)
	}
	u, cmd := m.list.Update(msg)
	m.list = u.(listModel)
	return m, cmd
}

func (m *ModelListComponent) View() string {
	return m.list.View()
}

func (m *ModelListComponent) Cursor() *tea.Cursor {
	return m.list.Cursor()
}

func (m *ModelListComponent) SetSize(width, height int) tea.Cmd {
	return m.list.SetSize(width, height)
}

func (m *ModelListComponent) SelectedModel() *ModelOption {
	s := m.list.SelectedItem()
	if s == nil {
		return nil
	}
	sv := *s
	model := sv.Value()
	return &model
}

func (m *ModelListComponent) SetModelType(modelType int) tea.Cmd {
	t := styles.CurrentTheme()
	m.modelType = modelType

	var groups []list.Group[list.CompletionItem[ModelOption]]
	selectedItemID := ""
	itemsByKey := make(map[string]list.CompletionItem[ModelOption])

	cfg := config.Get()
	var currentModel config.SelectedModel
	selectedType := config.SelectedModelTypeLarge
	if m.modelType == LargeModelType {
		currentModel = cfg.Models[config.SelectedModelTypeLarge]
		selectedType = config.SelectedModelTypeLarge
	} else {
		currentModel = cfg.Models[config.SelectedModelTypeSmall]
		selectedType = config.SelectedModelTypeSmall
	}
	recentItems := cfg.RecentModels[selectedType]

	configuredIcon := t.S().Base.Foreground(t.Success).Render(styles.CheckIcon)
	configured := fmt.Sprintf("%s %s", configuredIcon, t.S().Subtle.Render("Configured"))

	providerIDs := []string{}
	for providerID, providerConfig := range cfg.Providers.Seq2() {
		if providerID != "synapsenet" {
			continue
		}
		if providerConfig.Disable {
			continue
		}
		providerIDs = append(providerIDs, providerID)
	}
	slices.Sort(providerIDs)

	for _, providerID := range providerIDs {
		providerConfig, ok := cfg.Providers.Get(providerID)
		if !ok || providerConfig.Disable {
			continue
		}
		provider := providerConfig.ToProvider()
		name := provider.Name
		if name == "" {
			name = providerID
		}
		section := list.NewItemSection(name)
		section.SetInfo(configured)
		group := list.Group[list.CompletionItem[ModelOption]]{
			Section: section,
		}

		models := provider.Models
		if providerID == "synapsenet" {
			models = mergeModels(models, m.localModels)
		}

		for _, model := range models {
			modelOption := ModelOption{
				Provider: provider,
				Model:    model,
			}
			key := modelKey(providerID, model.ID)
			item := list.NewCompletionItem(
				model.Name,
				modelOption,
				list.WithCompletionID(key),
			)
			itemsByKey[key] = item
			group.Items = append(group.Items, item)
			if model.ID == currentModel.Model && providerID == currentModel.Provider {
				selectedItemID = item.ID()
			}
		}
		groups = append(groups, group)
	}

	if len(recentItems) > 0 {
		recentSection := list.NewItemSection("Recently used")
		recentGroup := list.Group[list.CompletionItem[ModelOption]]{
			Section: recentSection,
		}
		var validRecentItems []config.SelectedModel
		for _, recent := range recentItems {
			key := modelKey(recent.Provider, recent.Model)
			option, ok := itemsByKey[key]
			if !ok {
				continue
			}
			validRecentItems = append(validRecentItems, recent)
			recentID := fmt.Sprintf("recent::%s", key)
			modelOption := option.Value()
			providerName := modelOption.Provider.Name
			if providerName == "" {
				providerName = string(modelOption.Provider.ID)
			}
			item := list.NewCompletionItem(
				modelOption.Model.Name,
				option.Value(),
				list.WithCompletionID(recentID),
				list.WithCompletionShortcut(providerName),
			)
			recentGroup.Items = append(recentGroup.Items, item)
			if recent.Model == currentModel.Model && recent.Provider == currentModel.Provider {
				selectedItemID = recentID
			}
		}

		if len(validRecentItems) != len(recentItems) {
			if err := cfg.SetConfigField(fmt.Sprintf("recent_models.%s", selectedType), validRecentItems); err != nil {
				return util.ReportError(err)
			}
		}

		if len(recentGroup.Items) > 0 {
			groups = append([]list.Group[list.CompletionItem[ModelOption]]{recentGroup}, groups...)
		}
	}

	var cmds []tea.Cmd

	cmd := m.list.SetGroups(groups)

	if cmd != nil {
		cmds = append(cmds, cmd)
	}
	cmd = m.list.SetSelected(selectedItemID)
	if cmd != nil {
		cmds = append(cmds, cmd)
	}

	return tea.Sequence(cmds...)
}

func (m *ModelListComponent) refreshLocalModelsCmd() tea.Cmd {
	return func() tea.Msg {
		cfg := config.Get()
		pc, ok := cfg.Providers.Get("synapsenet")
		baseURL := "http://127.0.0.1:8332"
		if ok && pc.BaseURL != "" {
			baseURL = pc.BaseURL
		}

		models, err := listModelsRPC(baseURL)
		if err == nil && len(models) > 0 {
			return localModelsMsg{models: models}
		}
		return localModelsMsg{models: listModelsFS()}
	}
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func listModelsRPC(baseURL string) ([]catwalk.Model, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "model.list",
		"params":  map[string]any{},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 3 * time.Second}
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
		return nil, fmt.Errorf("rpc http %d", resp.StatusCode)
	}

	var rr rpcResponse
	if err := json.Unmarshal(b, &rr); err != nil {
		return nil, err
	}
	if rr.Error != nil {
		return nil, fmt.Errorf("rpc error %d: %s", rr.Error.Code, rr.Error.Message)
	}

	var items []struct {
		Name      string `json:"name"`
		Path      string `json:"path"`
		SizeBytes uint64 `json:"sizeBytes"`
	}
	if err := json.Unmarshal(rr.Result, &items); err != nil {
		return nil, err
	}

	models := make([]catwalk.Model, 0, len(items))
	for _, it := range items {
		id := strings.TrimSpace(it.Name)
		if id == "" {
			continue
		}
		if it.SizeBytes < 50*1024*1024 {
			continue
		}
		if strings.HasPrefix(strings.ToLower(id), "ggml-vocab-") {
			continue
		}
		models = append(models, catwalk.Model{
			ID:               id,
			Name:             id,
			ContextWindow:    8192,
			DefaultMaxTokens: 512,
		})
	}
	return models, nil
}

func listModelsFS() []catwalk.Model {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		return nil
	}
	dir := filepath.Join(homeDir, ".synapsenet", "models")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	models := []catwalk.Model{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".gguf") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(name), "ggml-vocab-") {
			continue
		}
		fi, err := e.Info()
		if err != nil {
			continue
		}
		if fi.Size() < 50*1024*1024 {
			continue
		}
		models = append(models, catwalk.Model{
			ID:               name,
			Name:             name,
			ContextWindow:    8192,
			DefaultMaxTokens: 512,
		})
	}
	slices.SortFunc(models, func(a, b catwalk.Model) int { return strings.Compare(a.Name, b.Name) })
	return models
}

func mergeModels(base []catwalk.Model, extra []catwalk.Model) []catwalk.Model {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]bool, len(base))
	out := make([]catwalk.Model, 0, len(base)+len(extra))
	for _, m := range base {
		if m.ID == "" {
			continue
		}
		seen[m.ID] = true
		out = append(out, m)
	}
	for _, m := range extra {
		if m.ID == "" || seen[m.ID] {
			continue
		}
		seen[m.ID] = true
		out = append(out, m)
	}
	return out
}

// GetModelType returns the current model type
func (m *ModelListComponent) GetModelType() int {
	return m.modelType
}

func (m *ModelListComponent) SetInputPlaceholder(placeholder string) {
	m.list.SetInputPlaceholder(placeholder)
}
