package config

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/charmbracelet/catwalk/pkg/catwalk"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/env"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	exitVal := m.Run()
	os.Exit(exitVal)
}

func TestConfig_LoadFromBytes(t *testing.T) {
	data1 := []byte(`{"providers": {"openai": {"api_key": "key1", "base_url": "https://api.openai.com/v1"}}}`)
	data2 := []byte(`{"providers": {"openai": {"api_key": "key2", "base_url": "https://api.openai.com/v2"}}}`)
	data3 := []byte(`{"providers": {"openai": {}}}`)

	loadedConfig, err := loadFromBytes([][]byte{data1, data2, data3})

	require.NoError(t, err)
	require.NotNil(t, loadedConfig)
	require.Equal(t, 1, loadedConfig.Providers.Len())
	pc, _ := loadedConfig.Providers.Get("openai")
	require.Equal(t, "key2", pc.APIKey)
	require.Equal(t, "https://api.openai.com/v2", pc.BaseURL)
}

func TestConfig_setDefaults(t *testing.T) {
	cfg := &Config{}

	cfg.setDefaults("/tmp", "")

	require.NotNil(t, cfg.Options)
	require.NotNil(t, cfg.Options.TUI)
	require.NotNil(t, cfg.Options.ContextPaths)
	require.NotNil(t, cfg.Providers)
	require.NotNil(t, cfg.Models)
	require.NotNil(t, cfg.LSP)
	require.NotNil(t, cfg.MCP)
	require.Equal(t, filepath.Join("/tmp", ".synapseide"), cfg.Options.DataDirectory)
	require.Equal(t, "AGENTS.md", cfg.Options.InitializeAs)
	for _, path := range defaultContextPaths {
		require.Contains(t, cfg.Options.ContextPaths, path)
	}
	require.Equal(t, "/tmp", cfg.workingDir)
}

func TestConfig_configureProviders(t *testing.T) {
	cfg := &Config{}
	cfg.setDefaults("/tmp", "")
	env := env.NewFromMap(map[string]string{})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
	require.NoError(t, err)
	require.Equal(t, 1, cfg.Providers.Len())
	pc, ok := cfg.Providers.Get("synapsenet")
	require.True(t, ok)
	require.Equal(t, "synapsenet", pc.ID)
	require.NotEmpty(t, pc.BaseURL)
	require.NotEmpty(t, pc.Models)
}

func TestConfig_configureProvidersWithOverride(t *testing.T) {
	cfg := &Config{Providers: csync.NewMap[string, ProviderConfig]()}
	cfg.Providers.Set("synapsenet", ProviderConfig{
		BaseURL: "http://127.0.0.1:9999",
		Models: []catwalk.Model{
			{ID: "m1", Name: "Model One", DefaultMaxTokens: 100},
			{ID: "m2", Name: "Model Two", DefaultMaxTokens: 100},
		},
	})
	cfg.Providers.Set("openai", ProviderConfig{
		APIKey:  "xyz",
		BaseURL: "https://api.openai.com/v1",
		Models:  []catwalk.Model{{ID: "test-model"}},
	})
	cfg.setDefaults("/tmp", "")

	env := env.NewFromMap(map[string]string{})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
	require.NoError(t, err)
	require.Equal(t, 1, cfg.Providers.Len())

	_, ok := cfg.Providers.Get("openai")
	require.False(t, ok)
	pc, ok := cfg.Providers.Get("synapsenet")
	require.True(t, ok)
	require.Equal(t, "synapsenet", pc.ID)
	require.Equal(t, catwalk.Type("synapsenet"), pc.Type)
	require.Equal(t, "http://127.0.0.1:9999", pc.BaseURL)
	require.Empty(t, pc.APIKey)
	require.Len(t, pc.Models, 2)
}

func TestConfig_configureProvidersWithNewProvider(t *testing.T) {
	cfg := &Config{
		Providers: csync.NewMapFrom(map[string]ProviderConfig{
			"custom": {
				APIKey:  "xyz",
				BaseURL: "https://api.someendpoint.com/v2",
				Models: []catwalk.Model{
					{
						ID: "test-model",
					},
				},
			},
		}),
	}
	cfg.setDefaults("/tmp", "")
	env := env.NewFromMap(map[string]string{})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
	require.NoError(t, err)
	require.Equal(t, 1, cfg.Providers.Len())

	_, ok := cfg.Providers.Get("custom")
	require.False(t, ok)
	_, ok = cfg.Providers.Get("synapsenet")
	require.True(t, ok)
}

func TestConfig_configureProvidersBedrockWithCredentials(t *testing.T) {
	t.Skip("skipping remote providers in local-only SynapseIDE build")

	knownProviders := []catwalk.Provider{
		{
			ID:          catwalk.InferenceProviderBedrock,
			APIKey:      "",
			APIEndpoint: "",
			Models: []catwalk.Model{{
				ID: "anthropic.claude-sonnet-4-20250514-v1:0",
			}},
		},
	}

	cfg := &Config{}
	cfg.setDefaults("/tmp", "")
	env := env.NewFromMap(map[string]string{
		"AWS_ACCESS_KEY_ID":     "test-key-id",
		"AWS_SECRET_ACCESS_KEY": "test-secret-key",
	})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, knownProviders)
	require.NoError(t, err)
	require.Equal(t, cfg.Providers.Len(), 1)

	bedrockProvider, ok := cfg.Providers.Get("bedrock")
	require.True(t, ok, "Bedrock provider should be present")
	require.Len(t, bedrockProvider.Models, 1)
	require.Equal(t, "anthropic.claude-sonnet-4-20250514-v1:0", bedrockProvider.Models[0].ID)
}

func TestConfig_configureProvidersBedrockWithoutCredentials(t *testing.T) {
	t.Skip("skipping remote providers in local-only SynapseIDE build")

	knownProviders := []catwalk.Provider{
		{
			ID:          catwalk.InferenceProviderBedrock,
			APIKey:      "",
			APIEndpoint: "",
			Models: []catwalk.Model{{
				ID: "anthropic.claude-sonnet-4-20250514-v1:0",
			}},
		},
	}

	cfg := &Config{}
	cfg.setDefaults("/tmp", "")
	env := env.NewFromMap(map[string]string{})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, knownProviders)
	require.NoError(t, err)
	// Provider should not be configured without credentials
	require.Equal(t, cfg.Providers.Len(), 0)
}

func TestConfig_configureProvidersBedrockWithoutUnsupportedModel(t *testing.T) {
	t.Skip("skipping remote providers in local-only SynapseIDE build")

	knownProviders := []catwalk.Provider{
		{
			ID:          catwalk.InferenceProviderBedrock,
			APIKey:      "",
			APIEndpoint: "",
			Models: []catwalk.Model{{
				ID: "some-random-model",
			}},
		},
	}

	cfg := &Config{}
	cfg.setDefaults("/tmp", "")
	env := env.NewFromMap(map[string]string{
		"AWS_ACCESS_KEY_ID":     "test-key-id",
		"AWS_SECRET_ACCESS_KEY": "test-secret-key",
	})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, knownProviders)
	require.Error(t, err)
}

func TestConfig_configureProvidersVertexAIWithCredentials(t *testing.T) {
	t.Skip("skipping remote providers in local-only SynapseIDE build")

	knownProviders := []catwalk.Provider{
		{
			ID:          catwalk.InferenceProviderVertexAI,
			APIKey:      "",
			APIEndpoint: "",
			Models: []catwalk.Model{{
				ID: "gemini-pro",
			}},
		},
	}

	cfg := &Config{}
	cfg.setDefaults("/tmp", "")
	env := env.NewFromMap(map[string]string{
		"VERTEXAI_PROJECT":  "test-project",
		"VERTEXAI_LOCATION": "us-central1",
	})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, knownProviders)
	require.NoError(t, err)
	require.Equal(t, cfg.Providers.Len(), 1)

	vertexProvider, ok := cfg.Providers.Get("vertexai")
	require.True(t, ok, "VertexAI provider should be present")
	require.Len(t, vertexProvider.Models, 1)
	require.Equal(t, "gemini-pro", vertexProvider.Models[0].ID)
	require.Equal(t, "test-project", vertexProvider.ExtraParams["project"])
	require.Equal(t, "us-central1", vertexProvider.ExtraParams["location"])
}

func TestConfig_configureProvidersVertexAIWithoutCredentials(t *testing.T) {
	t.Skip("skipping remote providers in local-only SynapseIDE build")

	knownProviders := []catwalk.Provider{
		{
			ID:          catwalk.InferenceProviderVertexAI,
			APIKey:      "",
			APIEndpoint: "",
			Models: []catwalk.Model{{
				ID: "gemini-pro",
			}},
		},
	}

	cfg := &Config{}
	cfg.setDefaults("/tmp", "")
	env := env.NewFromMap(map[string]string{
		"GOOGLE_GENAI_USE_VERTEXAI": "false",
		"GOOGLE_CLOUD_PROJECT":      "test-project",
		"GOOGLE_CLOUD_LOCATION":     "us-central1",
	})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, knownProviders)
	require.NoError(t, err)
	// Provider should not be configured without proper credentials
	require.Equal(t, cfg.Providers.Len(), 0)
}

func TestConfig_configureProvidersVertexAIMissingProject(t *testing.T) {
	t.Skip("skipping remote providers in local-only SynapseIDE build")

	knownProviders := []catwalk.Provider{
		{
			ID:          catwalk.InferenceProviderVertexAI,
			APIKey:      "",
			APIEndpoint: "",
			Models: []catwalk.Model{{
				ID: "gemini-pro",
			}},
		},
	}

	cfg := &Config{}
	cfg.setDefaults("/tmp", "")
	env := env.NewFromMap(map[string]string{
		"GOOGLE_GENAI_USE_VERTEXAI": "true",
		"GOOGLE_CLOUD_LOCATION":     "us-central1",
	})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, knownProviders)
	require.NoError(t, err)
	// Provider should not be configured without project
	require.Equal(t, cfg.Providers.Len(), 0)
}

func TestConfig_configureProvidersSetProviderID(t *testing.T) {
	cfg := &Config{
		Providers: csync.NewMapFrom(map[string]ProviderConfig{
			"synapsenet": {
				BaseURL: "http://127.0.0.1:8332",
				Models: []catwalk.Model{
					{ID: "test-model", Name: "Test Model", DefaultMaxTokens: 100},
				},
			},
		}),
	}
	cfg.setDefaults("/tmp", "")
	env := env.NewFromMap(map[string]string{})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
	require.NoError(t, err)
	require.Equal(t, 1, cfg.Providers.Len())

	pc, _ := cfg.Providers.Get("synapsenet")
	require.Equal(t, "synapsenet", pc.ID)
}

func TestConfig_EnabledProviders(t *testing.T) {
	t.Run("all providers enabled", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"openai": {
					ID:      "openai",
					APIKey:  "key1",
					Disable: false,
				},
				"anthropic": {
					ID:      "anthropic",
					APIKey:  "key2",
					Disable: false,
				},
			}),
		}

		enabled := cfg.EnabledProviders()
		require.Len(t, enabled, 2)
	})

	t.Run("some providers disabled", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"openai": {
					ID:      "openai",
					APIKey:  "key1",
					Disable: false,
				},
				"anthropic": {
					ID:      "anthropic",
					APIKey:  "key2",
					Disable: true,
				},
			}),
		}

		enabled := cfg.EnabledProviders()
		require.Len(t, enabled, 1)
		require.Equal(t, "openai", enabled[0].ID)
	})

	t.Run("empty providers map", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMap[string, ProviderConfig](),
		}

		enabled := cfg.EnabledProviders()
		require.Len(t, enabled, 0)
	})
}

func TestConfig_IsConfigured(t *testing.T) {
	t.Run("returns true when at least one provider is enabled", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"openai": {
					ID:      "openai",
					APIKey:  "key1",
					Disable: false,
				},
			}),
		}

		require.True(t, cfg.IsConfigured())
	})

	t.Run("returns false when no providers are configured", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMap[string, ProviderConfig](),
		}

		require.False(t, cfg.IsConfigured())
	})

	t.Run("returns false when all providers are disabled", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"openai": {
					ID:      "openai",
					APIKey:  "key1",
					Disable: true,
				},
				"anthropic": {
					ID:      "anthropic",
					APIKey:  "key2",
					Disable: true,
				},
			}),
		}

		require.False(t, cfg.IsConfigured())
	})
}

func TestConfig_setupAgentsWithNoDisabledTools(t *testing.T) {
	cfg := &Config{
		Options: &Options{
			DisabledTools: []string{},
		},
	}

	cfg.SetupAgents()
	coderAgent, ok := cfg.Agents[AgentCoder]
	require.True(t, ok)
	assert.Equal(t, allToolNames(), coderAgent.AllowedTools)

	taskAgent, ok := cfg.Agents[AgentTask]
	require.True(t, ok)
	assert.Equal(t, []string{"glob", "grep", "ls", "sourcegraph", "view"}, taskAgent.AllowedTools)
}

func TestConfig_setupAgentsWithDisabledTools(t *testing.T) {
	cfg := &Config{
		Options: &Options{
			DisabledTools: []string{
				"edit",
				"download",
				"grep",
			},
		},
	}

	cfg.SetupAgents()
	coderAgent, ok := cfg.Agents[AgentCoder]
	require.True(t, ok)

	assert.Equal(t, []string{"agent", "bash", "job_output", "job_kill", "multiedit", "lsp_diagnostics", "lsp_references", "fetch", "agentic_fetch", "glob", "ls", "sourcegraph", "todos", "view", "write"}, coderAgent.AllowedTools)

	taskAgent, ok := cfg.Agents[AgentTask]
	require.True(t, ok)
	assert.Equal(t, []string{"glob", "ls", "sourcegraph", "view"}, taskAgent.AllowedTools)
}

func TestConfig_setupAgentsWithEveryReadOnlyToolDisabled(t *testing.T) {
	cfg := &Config{
		Options: &Options{
			DisabledTools: []string{
				"glob",
				"grep",
				"ls",
				"sourcegraph",
				"view",
			},
		},
	}

	cfg.SetupAgents()
	coderAgent, ok := cfg.Agents[AgentCoder]
	require.True(t, ok)
	assert.Equal(t, []string{"agent", "bash", "job_output", "job_kill", "download", "edit", "multiedit", "lsp_diagnostics", "lsp_references", "fetch", "agentic_fetch", "todos", "write"}, coderAgent.AllowedTools)

	taskAgent, ok := cfg.Agents[AgentTask]
	require.True(t, ok)
	assert.Equal(t, []string{}, taskAgent.AllowedTools)
}

func TestConfig_configureProvidersWithDisabledProvider(t *testing.T) {
	cfg := &Config{
		Providers: csync.NewMapFrom(map[string]ProviderConfig{
			"openai": {
				Disable: true,
			},
		}),
	}
	cfg.setDefaults("/tmp", "")

	env := env.NewFromMap(map[string]string{})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
	require.NoError(t, err)

	require.Equal(t, 1, cfg.Providers.Len())
	_, exists := cfg.Providers.Get("openai")
	require.False(t, exists)
	_, exists = cfg.Providers.Get("synapsenet")
	require.True(t, exists)
}

func TestConfig_configureProvidersCustomProviderValidation(t *testing.T) {
	t.Run("prunes non-synapsenet providers", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"custom": {
					APIKey:  "test-key",
					BaseURL: "https://api.custom.com/v1",
					Models: []catwalk.Model{{
						ID: "test-model",
					}},
				},
				"openai": {
					APIKey:  "test-key",
					BaseURL: "https://api.openai.com/v1",
					Models: []catwalk.Model{{
						ID: "gpt",
					}},
				},
			}),
		}
		cfg.setDefaults("/tmp", "")

		env := env.NewFromMap(map[string]string{})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
		require.NoError(t, err)

		require.Equal(t, 1, cfg.Providers.Len())
		_, exists := cfg.Providers.Get("custom")
		require.False(t, exists)
		_, exists = cfg.Providers.Get("openai")
		require.False(t, exists)
		_, exists = cfg.Providers.Get("synapsenet")
		require.True(t, exists)
	})

	t.Run("normalizes synapsenet provider", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"synapsenet": {
					Type:   "openai",
					APIKey: "should_be_removed",
				},
			}),
		}
		cfg.setDefaults("/tmp", "")

		env := env.NewFromMap(map[string]string{})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
		require.NoError(t, err)

		require.Equal(t, 1, cfg.Providers.Len())
		pc, exists := cfg.Providers.Get("synapsenet")
		require.True(t, exists)
		require.Equal(t, "synapsenet", pc.ID)
		require.Equal(t, catwalk.Type("synapsenet"), pc.Type)
		require.NotEmpty(t, pc.BaseURL)
		require.NotEmpty(t, pc.Models)
		require.Empty(t, pc.APIKey)
	})
}

func TestConfig_configureProvidersEnhancedCredentialValidation(t *testing.T) {
	t.Skip("skipping remote providers in local-only SynapseIDE build")

	t.Run("VertexAI provider removed when credentials missing with existing config", func(t *testing.T) {
		knownProviders := []catwalk.Provider{
			{
				ID:          catwalk.InferenceProviderVertexAI,
				APIKey:      "",
				APIEndpoint: "",
				Models: []catwalk.Model{{
					ID: "gemini-pro",
				}},
			},
		}

		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"vertexai": {
					BaseURL: "custom-url",
				},
			}),
		}
		cfg.setDefaults("/tmp", "")

		env := env.NewFromMap(map[string]string{
			"GOOGLE_GENAI_USE_VERTEXAI": "false",
		})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, knownProviders)
		require.NoError(t, err)

		require.Equal(t, cfg.Providers.Len(), 0)
		_, exists := cfg.Providers.Get("vertexai")
		require.False(t, exists)
	})

	t.Run("Bedrock provider removed when AWS credentials missing with existing config", func(t *testing.T) {
		knownProviders := []catwalk.Provider{
			{
				ID:          catwalk.InferenceProviderBedrock,
				APIKey:      "",
				APIEndpoint: "",
				Models: []catwalk.Model{{
					ID: "anthropic.claude-sonnet-4-20250514-v1:0",
				}},
			},
		}

		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"bedrock": {
					BaseURL: "custom-url",
				},
			}),
		}
		cfg.setDefaults("/tmp", "")

		env := env.NewFromMap(map[string]string{})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, knownProviders)
		require.NoError(t, err)

		require.Equal(t, cfg.Providers.Len(), 0)
		_, exists := cfg.Providers.Get("bedrock")
		require.False(t, exists)
	})

	t.Run("provider removed when API key missing with existing config", func(t *testing.T) {
		knownProviders := []catwalk.Provider{
			{
				ID:          "openai",
				APIKey:      "$MISSING_API_KEY",
				APIEndpoint: "https://api.openai.com/v1",
				Models: []catwalk.Model{{
					ID: "test-model",
				}},
			},
		}

		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"openai": {
					BaseURL: "custom-url",
				},
			}),
		}
		cfg.setDefaults("/tmp", "")

		env := env.NewFromMap(map[string]string{})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, knownProviders)
		require.NoError(t, err)

		require.Equal(t, cfg.Providers.Len(), 0)
		_, exists := cfg.Providers.Get("openai")
		require.False(t, exists)
	})

	t.Run("known provider should still be added if the endpoint is missing the client will use default endpoints", func(t *testing.T) {
		knownProviders := []catwalk.Provider{
			{
				ID:          "openai",
				APIKey:      "$OPENAI_API_KEY",
				APIEndpoint: "$MISSING_ENDPOINT",
				Models: []catwalk.Model{{
					ID: "test-model",
				}},
			},
		}

		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"openai": {
					APIKey: "test-key",
				},
			}),
		}
		cfg.setDefaults("/tmp", "")

		env := env.NewFromMap(map[string]string{
			"OPENAI_API_KEY": "test-key",
		})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, knownProviders)
		require.NoError(t, err)

		require.Equal(t, cfg.Providers.Len(), 1)
		_, exists := cfg.Providers.Get("openai")
		require.True(t, exists)
	})
}

func TestConfig_defaultModelSelection(t *testing.T) {
	t.Run("defaults to deepseek on synapsenet", func(t *testing.T) {
		cfg := &Config{}
		cfg.setDefaults("/tmp", "")
		env := env.NewFromMap(map[string]string{})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
		require.NoError(t, err)

		large, small, err := cfg.defaultModelSelection([]catwalk.Provider{})
		require.NoError(t, err)
		require.Equal(t, "deepseek-coder-6.7b-instruct.Q4_K_M.gguf", large.Model)
		require.Equal(t, "synapsenet", large.Provider)
		require.Equal(t, int64(512), large.MaxTokens)
		require.Equal(t, "deepseek-coder-6.7b-instruct.Q4_K_M.gguf", small.Model)
		require.Equal(t, "synapsenet", small.Provider)
		require.Equal(t, int64(512), small.MaxTokens)
	})

	t.Run("prunes unknown providers and still selects defaults", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"openai": {
					APIKey:  "test-key",
					BaseURL: "https://api.openai.com/v1",
					Models:  []catwalk.Model{{ID: "gpt"}},
				},
			}),
		}
		cfg.setDefaults("/tmp", "")
		env := env.NewFromMap(map[string]string{})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
		require.NoError(t, err)

		large, small, err := cfg.defaultModelSelection([]catwalk.Provider{})
		require.NoError(t, err)
		require.Equal(t, "synapsenet", large.Provider)
		require.Equal(t, "synapsenet", small.Provider)
	})
}

func TestConfig_configureProvidersDisableDefaultProviders(t *testing.T) {
	cfg := &Config{
		Options: &Options{
			DisableDefaultProviders: true,
		},
		Providers: csync.NewMapFrom(map[string]ProviderConfig{
			"openai": {
				APIKey:  "test-key",
				BaseURL: "https://api.openai.com/v1",
				Models:  []catwalk.Model{{ID: "gpt"}},
			},
			"my-llm": {
				APIKey:  "test-key",
				BaseURL: "https://my-llm.example.com/v1",
				Models:  []catwalk.Model{{ID: "my-model"}},
			},
		}),
	}
	cfg.setDefaults("/tmp", "")

	env := env.NewFromMap(map[string]string{})
	resolver := NewEnvironmentVariableResolver(env)
	err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
	require.NoError(t, err)

	require.Equal(t, 1, cfg.Providers.Len())
	_, exists := cfg.Providers.Get("synapsenet")
	require.True(t, exists)
	_, exists = cfg.Providers.Get("openai")
	require.False(t, exists)
	_, exists = cfg.Providers.Get("my-llm")
	require.False(t, exists)
}

func TestConfig_setDefaultsDisableDefaultProvidersEnvVar(t *testing.T) {
	t.Run("sets option from environment variable", func(t *testing.T) {
		t.Setenv("SYNAPSEIDE_DISABLE_DEFAULT_PROVIDERS", "true")

		cfg := &Config{}
		cfg.setDefaults("/tmp", "")

		require.True(t, cfg.Options.DisableDefaultProviders)
	})

	t.Run("does not override when env var is not set", func(t *testing.T) {
		cfg := &Config{
			Options: &Options{
				DisableDefaultProviders: true,
			},
		}
		cfg.setDefaults("/tmp", "")

		require.True(t, cfg.Options.DisableDefaultProviders)
	})
}

func TestConfig_configureSelectedModels(t *testing.T) {
	t.Run("should override defaults", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"synapsenet": {
					BaseURL: "http://127.0.0.1:8332",
					Models: []catwalk.Model{
						{ID: "large-model", DefaultMaxTokens: 1000},
						{ID: "small-model", DefaultMaxTokens: 500},
						{ID: "larger-model", DefaultMaxTokens: 2000},
					},
				},
			}),
			Models: map[SelectedModelType]SelectedModel{
				"large": {
					Model: "larger-model",
				},
			},
		}
		cfg.dataConfigDir = filepath.Join(t.TempDir(), "synapseide.json")
		cfg.setDefaults("/tmp", "")
		env := env.NewFromMap(map[string]string{})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
		require.NoError(t, err)

		err = cfg.configureSelectedModels([]catwalk.Provider{})
		require.NoError(t, err)
		large := cfg.Models[SelectedModelTypeLarge]
		small := cfg.Models[SelectedModelTypeSmall]
		require.Equal(t, "larger-model", large.Model)
		require.Equal(t, "synapsenet", large.Provider)
		require.Equal(t, int64(2000), large.MaxTokens)
		require.Equal(t, "large-model", small.Model)
		require.Equal(t, "synapsenet", small.Provider)
		require.Equal(t, int64(1000), small.MaxTokens)
	})
	t.Run("should allow overriding the small model", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"synapsenet": {
					BaseURL: "http://127.0.0.1:8332",
					Models: []catwalk.Model{
						{ID: "large-model", DefaultMaxTokens: 1000},
						{ID: "small-model", DefaultMaxTokens: 500},
					},
				},
			}),
			Models: map[SelectedModelType]SelectedModel{
				"small": {
					Model:     "small-model",
					MaxTokens: 300,
				},
			},
		}
		cfg.dataConfigDir = filepath.Join(t.TempDir(), "synapseide.json")
		cfg.setDefaults("/tmp", "")
		env := env.NewFromMap(map[string]string{})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
		require.NoError(t, err)

		err = cfg.configureSelectedModels([]catwalk.Provider{})
		require.NoError(t, err)
		large := cfg.Models[SelectedModelTypeLarge]
		small := cfg.Models[SelectedModelTypeSmall]
		require.Equal(t, "large-model", large.Model)
		require.Equal(t, "synapsenet", large.Provider)
		require.Equal(t, int64(1000), large.MaxTokens)
		require.Equal(t, "small-model", small.Model)
		require.Equal(t, "synapsenet", small.Provider)
		require.Equal(t, int64(300), small.MaxTokens)
	})

	t.Run("should override the max tokens only", func(t *testing.T) {
		cfg := &Config{
			Providers: csync.NewMapFrom(map[string]ProviderConfig{
				"synapsenet": {
					BaseURL: "http://127.0.0.1:8332",
					Models: []catwalk.Model{
						{ID: "large-model", DefaultMaxTokens: 1000},
						{ID: "small-model", DefaultMaxTokens: 500},
					},
				},
			}),
			Models: map[SelectedModelType]SelectedModel{
				"large": {
					MaxTokens: 100,
				},
			},
		}
		cfg.dataConfigDir = filepath.Join(t.TempDir(), "synapseide.json")
		cfg.setDefaults("/tmp", "")
		env := env.NewFromMap(map[string]string{})
		resolver := NewEnvironmentVariableResolver(env)
		err := cfg.configureProviders(env, resolver, []catwalk.Provider{})
		require.NoError(t, err)

		err = cfg.configureSelectedModels([]catwalk.Provider{})
		require.NoError(t, err)
		large := cfg.Models[SelectedModelTypeLarge]
		require.Equal(t, "large-model", large.Model)
		require.Equal(t, "synapsenet", large.Provider)
		require.Equal(t, int64(100), large.MaxTokens)
	})
}
