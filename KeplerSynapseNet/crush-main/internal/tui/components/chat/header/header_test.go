package header

import (
	"strings"
	"testing"

	"github.com/charmbracelet/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/lsp"
	"github.com/charmbracelet/crush/internal/session"
	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/require"
)

func TestHeaderShowsWeb4StatusAndChangesOnToggle(t *testing.T) {
	wd := t.TempDir()
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	cfg, err := config.Init(wd, "", false)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	// Ensure config has enough fields so header.details() won't crash.
	if cfg.Options == nil {
		cfg.Options = &config.Options{}
	}
	if cfg.Options.TUI == nil {
		cfg.Options.TUI = &config.TUIOptions{}
	}
	cfg.Options.TUI.Web4 = &config.Web4Options{
		InjectEnabled: false,
		OnionEnabled:  true,
		TorClearnet:   true,
	}

	if cfg.Providers == nil {
		cfg.Providers = csync.NewMap[string, config.ProviderConfig]()
	}
	cfg.Providers = csync.NewMapFrom(map[string]config.ProviderConfig{
		"synapsenet": {
			ID:   "synapsenet",
			Name: "SynapseNet",
			Models: []catwalk.Model{
				{ID: "test", Name: "test", ContextWindow: 1000},
			},
		},
	})
	cfg.Models = map[config.SelectedModelType]config.SelectedModel{
		config.SelectedModelTypeSmall: {Provider: "synapsenet", Model: "test"},
	}
	cfg.Agents = map[string]config.Agent{
		config.AgentCoder: {ID: config.AgentCoder, Model: config.SelectedModelTypeSmall},
	}

	h := New(csync.NewMap[string, *lsp.Client]())
	_ = h.SetSession(session.Session{ID: "s1", PromptTokens: 10, CompletionTokens: 20})
	_ = h.SetWidth(200)

	off := h.View()
	plainOff := ansi.Strip(off)
	require.True(t, strings.Contains(plainOff, "WEB"))
	require.True(t, strings.Contains(plainOff, "ONION"))
	require.True(t, strings.Contains(plainOff, "TOR"))

	// Toggle on: should change the rendered output (style changes).
	cfg.Options.TUI.Web4.InjectEnabled = true
	on := h.View()
	require.NotEqual(t, off, on)
}

