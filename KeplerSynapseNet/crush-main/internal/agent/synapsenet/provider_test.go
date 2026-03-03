package synapsenet

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"charm.land/fantasy"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/stretchr/testify/require"
)

type rpcState struct {
	mu         sync.Mutex
	params     map[string]any
	handlerErr error
}

func (s *rpcState) setParams(params map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := make(map[string]any, len(params))
	for k, v := range params {
		cloned[k] = v
	}
	s.params = cloned
}

func (s *rpcState) setError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handlerErr == nil {
		s.handlerErr = err
	}
}

func (s *rpcState) snapshot() (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]any, len(s.params))
	for k, v := range s.params {
		out[k] = v
	}
	return out, s.handlerErr
}

func newTestRPCServer() (*httptest.Server, *rpcState) {
	state := &rpcState{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()

		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			state.setError(err)
			http.Error(w, "bad_request", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "ai.complete":
			state.setParams(req.Params)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "1",
				"result": map[string]any{
					"model": "stub",
					"text":  "ok",
				},
			})
		case "model.status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "1",
				"result": map[string]any{
					"loaded": true,
					"name":   "active",
					"path":   "active",
					"state":  "loaded",
				},
			})
		case "model.load":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "1",
				"result": map[string]any{
					"ok":    true,
					"state": "loaded",
				},
			})
		default:
			state.setError(fmt.Errorf("unexpected method: %s", req.Method))
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      "1",
				"error": map[string]any{
					"code":    -32601,
					"message": "method not found",
				},
			})
		}
	}))
	return server, state
}

func initTestConfig(t *testing.T, web4 *config.Web4Options) {
	t.Helper()

	t.Setenv("SYNAPSEIDE_GLOBAL_CONFIG", t.TempDir())
	t.Setenv("XDG_DATA_HOME", t.TempDir())

	cfg, err := config.Init(t.TempDir(), "", false)
	require.NoError(t, err)
	require.NotNil(t, cfg)

	if cfg.Options == nil {
		cfg.Options = &config.Options{}
	}
	if cfg.Options.TUI == nil {
		cfg.Options.TUI = &config.TUIOptions{}
	}
	cfg.Options.TUI.Web4 = web4
}

func runGenerate(t *testing.T, baseURL string, client *http.Client) {
	t.Helper()

	provider, err := New(WithBaseURL(baseURL), WithHTTPClient(client))
	require.NoError(t, err)

	model, err := provider.LanguageModel(context.Background(), "active")
	require.NoError(t, err)

	_, err = model.Generate(context.Background(), fantasy.Call{
		Prompt: fantasy.Prompt{
			fantasy.NewUserMessage("Collect darknet and clearnet intelligence"),
		},
	})
	require.NoError(t, err)
}

func TestGenerateIncludesWeb4ParamsWhenEnabled(t *testing.T) {
	initTestConfig(t, &config.Web4Options{
		InjectEnabled: true,
		OnionEnabled:  true,
		TorClearnet:   true,
		Query:         "custom query",
	})

	server, state := newTestRPCServer()
	defer server.Close()

	runGenerate(t, server.URL, server.Client())

	params, handlerErr := state.snapshot()
	require.NoError(t, handlerErr)
	require.Equal(t, true, params["webInject"])
	require.Equal(t, true, params["webOnion"])
	require.Equal(t, true, params["webTor"])
	require.Equal(t, "custom query", params["webQuery"])
}

func TestGenerateOmitsWeb4ParamsWhenDisabled(t *testing.T) {
	initTestConfig(t, &config.Web4Options{
		InjectEnabled: false,
		OnionEnabled:  true,
		TorClearnet:   true,
		Query:         "unused query",
	})

	server, state := newTestRPCServer()
	defer server.Close()

	runGenerate(t, server.URL, server.Client())

	params, handlerErr := state.snapshot()
	require.NoError(t, handlerErr)
	_, hasWebInject := params["webInject"]
	_, hasWebOnion := params["webOnion"]
	_, hasWebTor := params["webTor"]
	_, hasWebQuery := params["webQuery"]
	require.False(t, hasWebInject)
	require.False(t, hasWebOnion)
	require.False(t, hasWebTor)
	require.False(t, hasWebQuery)
}
