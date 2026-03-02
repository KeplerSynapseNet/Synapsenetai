package commands

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/catwalk/pkg/catwalk"

	"github.com/charmbracelet/crush/internal/agent"
	"github.com/charmbracelet/crush/internal/agent/hyper"
	"github.com/charmbracelet/crush/internal/agent/synapsenet"
	"github.com/charmbracelet/crush/internal/agent/tools/mcp"
	"github.com/charmbracelet/crush/internal/config"
	"github.com/charmbracelet/crush/internal/csync"
	"github.com/charmbracelet/crush/internal/pubsub"
	"github.com/charmbracelet/crush/internal/shell"
	"github.com/charmbracelet/crush/internal/tui/components/chat"
	"github.com/charmbracelet/crush/internal/tui/components/core"
	"github.com/charmbracelet/crush/internal/tui/components/dialogs"
	"github.com/charmbracelet/crush/internal/tui/components/dialogs/quests"
	"github.com/charmbracelet/crush/internal/tui/components/dialogs/remote"
	"github.com/charmbracelet/crush/internal/tui/exp/list"
	"github.com/charmbracelet/crush/internal/tui/styles"
	"github.com/charmbracelet/crush/internal/tui/util"
	"github.com/charmbracelet/crush/internal/uicmd"
)

const (
	CommandsDialogID dialogs.DialogID = "commands"

	defaultWidth int = 70
)

func githubRepoFromRemote(remote string) string {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return ""
	}

	if strings.HasPrefix(remote, "git@github.com:") {
		return githubRepoFromPath(strings.TrimPrefix(remote, "git@github.com:"))
	}

	u, err := url.Parse(remote)
	if err == nil && strings.EqualFold(u.Hostname(), "github.com") {
		return githubRepoFromPath(strings.TrimPrefix(u.Path, "/"))
	}

	if strings.HasPrefix(remote, "github.com/") {
		return githubRepoFromPath(strings.TrimPrefix(remote, "github.com/"))
	}

	return ""
}

func githubRepoFromPath(path string) string {
	path = strings.TrimPrefix(strings.TrimSpace(path), "/")
	path = strings.TrimSuffix(path, ".git")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

type commandType = uicmd.CommandType

const (
	SystemCommands = uicmd.SystemCommands
	UserCommands   = uicmd.UserCommands
	MCPPrompts     = uicmd.MCPPrompts
)

type listModel = list.FilterableList[list.CompletionItem[Command]]

// Command represents a command that can be executed
type (
	Command                         = uicmd.Command
	CommandRunCustomMsg             = uicmd.CommandRunCustomMsg
	ShowMCPPromptArgumentsDialogMsg = uicmd.ShowMCPPromptArgumentsDialogMsg
)

// CommandsDialog represents the commands dialog.
type CommandsDialog interface {
	dialogs.DialogModel
}

type commandDialogCmp struct {
	width   int
	wWidth  int // Width of the terminal window
	wHeight int // Height of the terminal window

	commandList  listModel
	keyMap       CommandsDialogKeyMap
	help         help.Model
	selected     commandType           // Selected SystemCommands, UserCommands, or MCPPrompts
	userCommands []Command             // User-defined commands
	mcpPrompts   *csync.Slice[Command] // MCP prompts
	sessionID    string                // Current session ID
}

type (
	SwitchSessionsMsg      struct{}
	NewSessionsMsg         struct{}
	SwitchModelMsg         struct{}
	QuitMsg                struct{}
	OpenFilePickerMsg      struct{}
	ToggleHelpMsg          struct{}
	ToggleCompactModeMsg   struct{}
	ToggleThinkingMsg      struct{}
	ToggleWeb4Msg          struct{}
	ToggleWeb4OnionMsg     struct{}
	ToggleWeb4TorMsg       struct{}
	OpenReasoningDialogMsg struct{}
	OpenExternalEditorMsg  struct{}
	ToggleYoloModeMsg      struct{}
	CompactMsg             struct {
		SessionID string
	}
)

func NewCommandDialog(sessionID string) CommandsDialog {
	keyMap := DefaultCommandsDialogKeyMap()
	listKeyMap := list.DefaultKeyMap()
	listKeyMap.Down.SetEnabled(false)
	listKeyMap.Up.SetEnabled(false)
	listKeyMap.DownOneItem = keyMap.Next
	listKeyMap.UpOneItem = keyMap.Previous

	t := styles.CurrentTheme()
	inputStyle := t.S().Base.PaddingLeft(1).PaddingBottom(1)
	commandList := list.NewFilterableList(
		[]list.CompletionItem[Command]{},
		list.WithFilterInputStyle(inputStyle),
		list.WithFilterListOptions(
			list.WithKeyMap(listKeyMap),
			list.WithWrapNavigation(),
			list.WithResizeByList(),
		),
	)
	help := help.New()
	help.Styles = t.S().Help
	return &commandDialogCmp{
		commandList: commandList,
		width:       defaultWidth,
		keyMap:      DefaultCommandsDialogKeyMap(),
		help:        help,
		selected:    SystemCommands,
		sessionID:   sessionID,
		mcpPrompts:  csync.NewSlice[Command](),
	}
}

func (c *commandDialogCmp) Init() tea.Cmd {
	commands, err := uicmd.LoadCustomCommands()
	if err != nil {
		return util.ReportError(err)
	}
	c.userCommands = commands
	c.mcpPrompts.SetSlice(uicmd.LoadMCPPrompts())
	return c.setCommandType(c.selected)
}

func (c *commandDialogCmp) Update(msg tea.Msg) (util.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		c.wWidth = msg.Width
		c.wHeight = msg.Height
		return c, tea.Batch(
			c.setCommandType(c.selected),
			c.commandList.SetSize(c.listWidth(), c.listHeight()),
		)
	case pubsub.Event[mcp.Event]:
		// Reload MCP prompts when MCP state changes
		if msg.Type == pubsub.UpdatedEvent {
			c.mcpPrompts.SetSlice(uicmd.LoadMCPPrompts())
			// If we're currently viewing MCP prompts, refresh the list
			if c.selected == MCPPrompts {
				return c, c.setCommandType(MCPPrompts)
			}
			return c, nil
		}
	case tea.KeyPressMsg:
		switch {
		case key.Matches(msg, c.keyMap.Select):
			selectedItem := c.commandList.SelectedItem()
			if selectedItem == nil {
				return c, nil // No item selected, do nothing
			}
			command := (*selectedItem).Value()
			return c, tea.Sequence(
				util.CmdHandler(dialogs.CloseDialogMsg{}),
				command.Handler(command),
			)
		case key.Matches(msg, c.keyMap.Tab):
			if len(c.userCommands) == 0 && c.mcpPrompts.Len() == 0 {
				return c, nil
			}
			return c, c.setCommandType(c.next())
		case key.Matches(msg, c.keyMap.Close):
			return c, util.CmdHandler(dialogs.CloseDialogMsg{})
		default:
			u, cmd := c.commandList.Update(msg)
			c.commandList = u.(listModel)
			return c, cmd
		}
	}
	return c, nil
}

func (c *commandDialogCmp) next() commandType {
	switch c.selected {
	case SystemCommands:
		if len(c.userCommands) > 0 {
			return UserCommands
		}
		if c.mcpPrompts.Len() > 0 {
			return MCPPrompts
		}
		fallthrough
	case UserCommands:
		if c.mcpPrompts.Len() > 0 {
			return MCPPrompts
		}
		fallthrough
	case MCPPrompts:
		return SystemCommands
	default:
		return SystemCommands
	}
}

func (c *commandDialogCmp) View() string {
	t := styles.CurrentTheme()
	listView := c.commandList
	radio := c.commandTypeRadio()

	header := t.S().Base.Padding(0, 1, 1, 1).Render(core.Title("Commands", c.width-lipgloss.Width(radio)-5) + " " + radio)
	if len(c.userCommands) == 0 && c.mcpPrompts.Len() == 0 {
		header = t.S().Base.Padding(0, 1, 1, 1).Render(core.Title("Commands", c.width-4))
	}
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		listView.View(),
		"",
		t.S().Base.Width(c.width-2).PaddingLeft(1).AlignHorizontal(lipgloss.Left).Render(c.help.View(c.keyMap)),
	)
	return c.style().Render(content)
}

func (c *commandDialogCmp) Cursor() *tea.Cursor {
	if cursor, ok := c.commandList.(util.Cursor); ok {
		cursor := cursor.Cursor()
		if cursor != nil {
			cursor = c.moveCursor(cursor)
		}
		return cursor
	}
	return nil
}

func (c *commandDialogCmp) commandTypeRadio() string {
	t := styles.CurrentTheme()

	fn := func(i commandType) string {
		if i == c.selected {
			return "◉ " + i.String()
		}
		return "○ " + i.String()
	}

	parts := []string{
		fn(SystemCommands),
	}
	if len(c.userCommands) > 0 {
		parts = append(parts, fn(UserCommands))
	}
	if c.mcpPrompts.Len() > 0 {
		parts = append(parts, fn(MCPPrompts))
	}
	return t.S().Base.Foreground(t.FgHalfMuted).Render(strings.Join(parts, " "))
}

func (c *commandDialogCmp) listWidth() int {
	return defaultWidth - 2 // 4 for padding
}

func (c *commandDialogCmp) setCommandType(commandType commandType) tea.Cmd {
	c.selected = commandType

	var commands []Command
	switch c.selected {
	case SystemCommands:
		commands = c.defaultCommands()
	case UserCommands:
		commands = c.userCommands
	case MCPPrompts:
		commands = slices.Collect(c.mcpPrompts.Seq())
	}

	commandItems := []list.CompletionItem[Command]{}
	for _, cmd := range commands {
		opts := []list.CompletionItemOption{
			list.WithCompletionID(cmd.ID),
		}
		if cmd.Shortcut != "" {
			opts = append(
				opts,
				list.WithCompletionShortcut(cmd.Shortcut),
			)
		}
		commandItems = append(commandItems, list.NewCompletionItem(cmd.Title, cmd, opts...))
	}
	return c.commandList.SetItems(commandItems)
}

func (c *commandDialogCmp) listHeight() int {
	listHeigh := len(c.commandList.Items()) + 2 + 4 // height based on items + 2 for the input + 4 for the sections
	return min(listHeigh, c.wHeight/2)
}

func (c *commandDialogCmp) moveCursor(cursor *tea.Cursor) *tea.Cursor {
	row, col := c.Position()
	offset := row + 3
	cursor.Y += offset
	cursor.X = cursor.X + col + 2
	return cursor
}

func (c *commandDialogCmp) style() lipgloss.Style {
	t := styles.CurrentTheme()
	return t.S().Base.
		Width(c.width).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(t.BorderFocus)
}

func (c *commandDialogCmp) Position() (int, int) {
	row := c.wHeight/4 - 2 // just a bit above the center
	col := c.wWidth / 2
	col -= c.width / 2
	return row, col
}

func (c *commandDialogCmp) defaultCommands() []Command {
	commands := []Command{
		{
			ID:          "new_session",
			Title:       "New Session",
			Description: "start a new session",
			Shortcut:    "ctrl+n",
			Handler: func(cmd Command) tea.Cmd {
				return util.CmdHandler(NewSessionsMsg{})
			},
		},
		{
			ID:          "switch_session",
			Title:       "Switch Session",
			Description: "Switch to a different session",
			Shortcut:    "ctrl+s",
			Handler: func(cmd Command) tea.Cmd {
				return util.CmdHandler(SwitchSessionsMsg{})
			},
		},
		{
			ID:          "switch_model",
			Title:       "Switch Model",
			Description: "Switch to a different model",
			Shortcut:    "ctrl+l",
			Handler: func(cmd Command) tea.Cmd {
				return util.CmdHandler(SwitchModelMsg{})
			},
		},
	}

	// Only show compact command if there's an active session
	if c.sessionID != "" {
		commands = append(commands, Command{
			ID:          "Summarize",
			Title:       "Summarize Session",
			Description: "Summarize the current session and create a new one with the summary",
			Handler: func(cmd Command) tea.Cmd {
				return util.CmdHandler(CompactMsg{
					SessionID: c.sessionID,
				})
			},
		})
	}

	// Add reasoning toggle for models that support it
	cfg := config.Get()
	if agentCfg, ok := cfg.Agents[config.AgentCoder]; ok {
		providerCfg := cfg.GetProviderForModel(agentCfg.Model)
		model := cfg.GetModelByType(agentCfg.Model)
		if providerCfg != nil && model != nil && model.CanReason {
			selectedModel := cfg.Models[agentCfg.Model]

			// Anthropic models: thinking toggle
			if providerCfg.Type == catwalk.TypeAnthropic || providerCfg.Type == catwalk.Type(hyper.Name) {
				status := "Enable"
				if selectedModel.Think {
					status = "Disable"
				}
				commands = append(commands, Command{
					ID:          "toggle_thinking",
					Title:       status + " Thinking Mode",
					Description: "Toggle model thinking for reasoning-capable models",
					Handler: func(cmd Command) tea.Cmd {
						return util.CmdHandler(ToggleThinkingMsg{})
					},
				})
			}

			// OpenAI models: reasoning effort dialog
			if len(model.ReasoningLevels) > 0 {
				commands = append(commands, Command{
					ID:          "select_reasoning_effort",
					Title:       "Select Reasoning Effort",
					Description: "Choose reasoning effort level (low/medium/high)",
					Handler: func(cmd Command) tea.Cmd {
						return util.CmdHandler(OpenReasoningDialogMsg{})
					},
				})
			}
		}
	}

	// Add Web4 toggles for synapsenet provider
	if agentCfg, ok := cfg.Agents[config.AgentCoder]; ok {
		providerCfg := cfg.GetProviderForModel(agentCfg.Model)
		if providerCfg != nil && providerCfg.Type == synapsenet.Name {
			web4Enabled := false
			onionEnabled := false
			torEnabled := false
			if cfg.Options != nil && cfg.Options.TUI != nil && cfg.Options.TUI.Web4 != nil {
				web4 := cfg.Options.TUI.Web4
				web4Enabled = web4.InjectEnabled
				onionEnabled = web4.OnionEnabled
				torEnabled = web4.TorClearnet
			}

			// Toggle Web4 injection
			web4Status := "Enable"
			if web4Enabled {
				web4Status = "Disable"
			}
			commands = append(commands, Command{
				ID:          "toggle_web4",
				Title:       web4Status + " Web4 Injection",
				Description: "Toggle web context injection for AI responses",
				Handler: func(cmd Command) tea.Cmd {
					return util.CmdHandler(ToggleWeb4Msg{})
				},
			})

			// Toggle Onion sources (only if Web4 is enabled)
			if web4Enabled {
				onionStatus := "Disable"
				if !onionEnabled {
					onionStatus = "Enable"
				}
				commands = append(commands, Command{
					ID:          "toggle_web4_onion",
					Title:       onionStatus + " Onion Sources",
					Description: "Toggle onion sources in web searches",
					Handler: func(cmd Command) tea.Cmd {
						return util.CmdHandler(ToggleWeb4OnionMsg{})
					},
				})

				// Toggle Tor for clearnet (only if Web4 is enabled)
				torStatus := "Disable"
				if !torEnabled {
					torStatus = "Enable"
				}
				commands = append(commands, Command{
					ID:          "toggle_web4_tor",
					Title:       torStatus + " Tor for Clearnet",
					Description: "Toggle routing clearnet requests through Tor",
					Handler: func(cmd Command) tea.Cmd {
						return util.CmdHandler(ToggleWeb4TorMsg{})
					},
				})
			}
		}
	}

	commands = append(commands, Command{
		ID:          "github_quests",
		Title:       "GitHub Quests",
		Description: "Pick an active quest (GitHub issue) to keep visible while coding",
		Handler: func(cmd Command) tea.Cmd {
			cfg := config.Get()
			repo := ""
			if cfg.Options != nil && cfg.Options.TUI != nil && cfg.Options.TUI.Quests != nil {
				repo = strings.TrimSpace(cfg.Options.TUI.Quests.Repo)
			}
			if repo == "" {
				return util.CmdHandler(dialogs.OpenDialogMsg{
					Model: NewCommandArgumentsDialog(
						"github_quests_setup",
						"GitHub Quests",
						"GitHub Quests",
						"Configure repo and optional token",
						[]Argument{
							{Name: "repo", Title: "Repo", Description: "owner/name", Required: true},
							{Name: "token", Title: "Token", Description: "Optional GitHub token", Required: false},
						},
						func(args map[string]string) tea.Cmd {
							repo := strings.TrimSpace(args["repo"])
							token := strings.TrimSpace(args["token"])
							if repo == "" {
								return util.ReportError(fmt.Errorf("repo required"))
							}
							if strings.Count(repo, "/") != 1 {
								return util.ReportError(fmt.Errorf("repo must be owner/name"))
							}

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
							cfg.Options.TUI.Quests.Repo = repo
							cfg.Options.TUI.Quests.Token = token

							if err := cfg.SetConfigField("options.tui.quests.enabled", true); err != nil {
								return util.ReportError(err)
							}
							if err := cfg.SetConfigField("options.tui.quests.repo", repo); err != nil {
								return util.ReportError(err)
							}
							if token != "" {
								if err := cfg.SetConfigField("options.tui.quests.token", token); err != nil {
									return util.ReportError(err)
								}
							} else {
								_ = cfg.RemoveConfigField("options.tui.quests.token")
							}
							return util.CmdHandler(dialogs.OpenDialogMsg{
								Model: quests.NewQuestsDialogCmp(),
							})
						},
					),
				})
			}
			return util.CmdHandler(dialogs.OpenDialogMsg{
				Model: quests.NewQuestsDialogCmp(),
			})
		},
	})

	commands = append(commands, Command{
		ID:          "github_quest_checkout_branch",
		Title:       "Quest Checkout Branch",
		Description: "Create/switch to a quest branch for the active issue in the current repo",
		Handler: func(cmd Command) tea.Cmd {
			cfg := config.Get()
			if cfg.Options == nil || cfg.Options.TUI == nil || cfg.Options.TUI.Quests == nil || cfg.Options.TUI.Quests.ActiveIssue <= 0 {
				return util.ReportError(fmt.Errorf("no active quest selected"))
			}

			issue := cfg.Options.TUI.Quests.ActiveIssue
			repoCfg := strings.TrimSpace(cfg.Options.TUI.Quests.Repo)
			branch := fmt.Sprintf("quest-%d", issue)

			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()

			sh := shell.NewShell(&shell.Options{WorkingDir: cfg.WorkingDir()})
			_, _, err := sh.Exec(ctx, "git rev-parse --is-inside-work-tree 2>/dev/null")
			if err != nil {
				return util.ReportError(fmt.Errorf("not a git repo: %s", cfg.WorkingDir()))
			}

			remoteOut, _, _ := sh.Exec(ctx, "git remote get-url origin 2>/dev/null || true")
			remoteRepo := githubRepoFromRemote(remoteOut)

			var cmds []tea.Cmd
			if repoCfg != "" && remoteRepo != "" && !strings.EqualFold(repoCfg, remoteRepo) {
				cmds = append(cmds, util.ReportWarn(fmt.Sprintf("repo mismatch: %s (config) vs %s (origin)", repoCfg, remoteRepo)))
			}

			_, _, err = sh.Exec(ctx, fmt.Sprintf("git show-ref --verify --quiet refs/heads/%s", branch))
			checkoutCmd := fmt.Sprintf("git checkout -b %s", branch)
			if err == nil {
				checkoutCmd = fmt.Sprintf("git checkout %s", branch)
			}

			_, stderr, err := sh.Exec(ctx, checkoutCmd)
			if err != nil {
				msg := strings.TrimSpace(stderr)
				if msg == "" {
					msg = err.Error()
				}
				return util.ReportError(fmt.Errorf("git failed: %s", msg))
			}

			cmds = append(cmds, util.ReportInfo(fmt.Sprintf("Checked out %s for #%d", branch, issue)))
			return tea.Batch(cmds...)
		},
	})

	commands = append(commands, Command{
		ID:          "github_quest_clone_repo",
		Title:       "Quest Clone Repo",
		Description: "Clone the configured quest repo to a local directory",
		Handler: func(cmd Command) tea.Cmd {
			cfg := config.Get()
			if cfg.Options == nil || cfg.Options.TUI == nil || cfg.Options.TUI.Quests == nil {
				return util.ReportError(fmt.Errorf("github quests not configured"))
			}
			repo := strings.TrimSpace(cfg.Options.TUI.Quests.Repo)
			if repo == "" || strings.Count(repo, "/") != 1 {
				return util.ReportError(fmt.Errorf("repo must be owner/name"))
			}
			repoName := strings.Split(repo, "/")[1]

			return util.CmdHandler(dialogs.OpenDialogMsg{
				Model: NewCommandArgumentsDialog(
					"github_quest_clone",
					"GitHub Quests",
					"Quest Clone Repo",
					fmt.Sprintf("Clone repo (blank uses ./%s)", repoName),
					[]Argument{
						{Name: "dest", Title: "Destination", Description: "Directory path", Required: false},
					},
					func(args map[string]string) tea.Cmd {
						cfg := config.Get()
						dest := strings.TrimSpace(args["dest"])
						if dest == "" {
							dest = repoName
						}
						absDest := dest
						if !filepath.IsAbs(absDest) {
							absDest = filepath.Join(cfg.WorkingDir(), absDest)
						}
						if _, err := os.Stat(absDest); err == nil {
							return util.ReportError(fmt.Errorf("destination exists: %s", absDest))
						}

						issue := 0
						if cfg.Options != nil && cfg.Options.TUI != nil && cfg.Options.TUI.Quests != nil {
							issue = cfg.Options.TUI.Quests.ActiveIssue
						}

						return func() tea.Msg {
							ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
							defer cancel()

							cloneURL := fmt.Sprintf("https://github.com/%s.git", repo)
							sh := shell.NewShell(&shell.Options{WorkingDir: cfg.WorkingDir()})
							_, stderr, err := sh.Exec(ctx, fmt.Sprintf("git clone %q %q", cloneURL, absDest))
							if err != nil {
								msg := strings.TrimSpace(stderr)
								if msg == "" {
									msg = err.Error()
								}
								return util.InfoMsg{Type: util.InfoTypeError, Msg: "git clone failed: " + msg}
							}

							branch := ""
							if issue > 0 {
								branch = fmt.Sprintf("quest-%d", issue)
								sh2 := shell.NewShell(&shell.Options{WorkingDir: absDest})
								_, stderr, err = sh2.Exec(ctx, fmt.Sprintf("git checkout -b %s", branch))
								if err != nil {
									msg := strings.TrimSpace(stderr)
									if msg == "" {
										msg = err.Error()
									}
									return util.InfoMsg{Type: util.InfoTypeWarn, Msg: fmt.Sprintf("Cloned to %s but branch checkout failed: %s", absDest, msg)}
								}
							}

							msg := fmt.Sprintf("Cloned %s to %s", repo, absDest)
							if branch != "" {
								msg += " and checked out " + branch
							}
							return util.InfoMsg{Type: util.InfoTypeInfo, Msg: msg}
						}
					},
				),
			})
		},
	})

	commands = append(commands, Command{
		ID:          "github_quest_create_pr",
		Title:       "Quest Create PR",
		Description: "Create a pull request for the active quest and include a PoE submitId",
		Handler: func(cmd Command) tea.Cmd {
			cfg := config.Get()
			if cfg.Options == nil || cfg.Options.TUI == nil || cfg.Options.TUI.Quests == nil {
				return util.ReportError(fmt.Errorf("github quests not configured"))
			}

			repo := strings.TrimSpace(cfg.Options.TUI.Quests.Repo)
			token := strings.TrimSpace(cfg.Options.TUI.Quests.Token)
			issue := cfg.Options.TUI.Quests.ActiveIssue
			title := strings.TrimSpace(cfg.Options.TUI.Quests.ActiveTitle)
			issueURL := strings.TrimSpace(cfg.Options.TUI.Quests.ActiveURL)

			if repo == "" || strings.Count(repo, "/") != 1 {
				return util.ReportError(fmt.Errorf("repo must be owner/name"))
			}
			if token == "" {
				return util.ReportError(fmt.Errorf("token required"))
			}
			if issue <= 0 {
				return util.ReportError(fmt.Errorf("no active quest selected"))
			}

			return util.CmdHandler(dialogs.OpenDialogMsg{
				Model: NewCommandArgumentsDialog(
					"github_quest_pr",
					"GitHub Quests",
					"Quest Create PR",
					"Create PR (requires branch pushed to origin)",
					[]Argument{
						{Name: "submit_id", Title: "PoE submitId", Description: "PoE CODE submitId", Required: true},
						{Name: "draft", Title: "Draft", Description: "true/false (default false)", Required: false},
					},
					func(args map[string]string) tea.Cmd {
						submitID := strings.TrimSpace(args["submit_id"])
						if submitID == "" {
							return util.ReportError(fmt.Errorf("submit_id required"))
						}

						draft := false
						switch strings.ToLower(strings.TrimSpace(args["draft"])) {
						case "1", "true", "yes", "y", "on":
							draft = true
						}

						return func() tea.Msg {
							ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
							defer cancel()

							now := time.Now()
							if wait, err := quests.CheckQuestActionRateLimit("pr", now); err != nil {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: err.Error()}
							} else if wait > 0 {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: fmt.Sprintf("rate limited: wait %s", wait.Round(time.Second))}
							}

							baseURL := "http://127.0.0.1:8332"
							if pc, ok := cfg.Providers.Get("synapsenet"); ok && strings.TrimSpace(pc.BaseURL) != "" {
								baseURL = strings.TrimSpace(pc.BaseURL)
							}
							minPow := quests.DefaultMinSubmitPowBits
							if cfg.Options != nil && cfg.Options.TUI != nil && cfg.Options.TUI.Quests != nil && cfg.Options.TUI.Quests.MinSubmitPowBits > 0 {
								minPow = cfg.Options.TUI.Quests.MinSubmitPowBits
							}
							poeRes, err := quests.ValidateQuestSubmitID(ctx, baseURL, submitID, minPow)
							if err != nil {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: err.Error()}
							}

							sh := shell.NewShell(&shell.Options{WorkingDir: cfg.WorkingDir()})
							branchOut, _, err := sh.Exec(ctx, "git branch --show-current 2>/dev/null")
							if err != nil {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: "git branch failed"}
							}
							branch := strings.TrimSpace(branchOut)
							if branch == "" {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: "no current git branch"}
							}

							remoteOut, _, _ := sh.Exec(ctx, "git remote get-url origin 2>/dev/null || true")
							remoteRepo := githubRepoFromRemote(remoteOut)
							warn := ""
							head := branch
							if remoteRepo != "" && !strings.EqualFold(repo, remoteRepo) {
								warn = fmt.Sprintf("repo mismatch: %s (config) vs %s (origin)", repo, remoteRepo)
								if parts := strings.Split(remoteRepo, "/"); len(parts) == 2 && parts[0] != "" {
									head = parts[0] + ":" + branch
								}
							}
							if !poeRes.Finalized {
								if warn != "" {
									warn += " • "
								}
								warn += "PoE entry not finalized"
							}

							heads, _, _ := sh.Exec(ctx, fmt.Sprintf("git ls-remote --heads origin %q 2>/dev/null || true", branch))
							if strings.TrimSpace(heads) == "" {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: fmt.Sprintf("branch not found on origin: %s (push first)", branch)}
							}

							base, err := quests.FetchDefaultBranch(ctx, repo, token)
							if err != nil {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: err.Error()}
							}

							prTitle := title
							if prTitle == "" {
								prTitle = fmt.Sprintf("Quest #%d", issue)
							} else {
								prTitle = fmt.Sprintf("Quest #%d: %s", issue, prTitle)
							}

							bodyLines := []string{
								fmt.Sprintf("Quest: #%d", issue),
								fmt.Sprintf("PoE CODE submitId: %s", submitID),
							}
							if issueURL != "" {
								bodyLines = append(bodyLines, fmt.Sprintf("Quest URL: %s", issueURL))
							}
							body := strings.Join(bodyLines, "\n") + "\n"

							pr, err := quests.CreatePullRequest(ctx, repo, token, quests.CreatePullRequestParams{
								Title: prTitle,
								Head:  head,
								Base:  base,
								Body:  body,
								Draft: draft,
							})
							if err != nil {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: err.Error()}
							}

							if err := quests.RecordQuestAction("pr", now); err != nil {
								if warn != "" {
									warn += " • "
								}
								warn += "failed to record quest action"
							}

							if warn != "" {
								return util.InfoMsg{Type: util.InfoTypeWarn, Msg: warn + " • PR created: " + pr.HTMLURL}
							}
							return util.InfoMsg{Type: util.InfoTypeInfo, Msg: "PR created: " + pr.HTMLURL}
						}
					},
				),
			})
		},
	})

	commands = append(commands, Command{
		ID:          "github_quest_fork_repo",
		Title:       "Quest Fork Repo",
		Description: "Create a fork of the configured repo",
		Handler: func(cmd Command) tea.Cmd {
			cfg := config.Get()
			if cfg.Options == nil || cfg.Options.TUI == nil || cfg.Options.TUI.Quests == nil {
				return util.ReportError(fmt.Errorf("github quests not configured"))
			}

			repo := strings.TrimSpace(cfg.Options.TUI.Quests.Repo)
			token := strings.TrimSpace(cfg.Options.TUI.Quests.Token)
			if repo == "" || strings.Count(repo, "/") != 1 {
				return util.ReportError(fmt.Errorf("repo must be owner/name"))
			}
			if token == "" {
				return util.ReportError(fmt.Errorf("token required"))
			}

			return func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				now := time.Now()
				if wait, err := quests.CheckQuestActionRateLimit("fork", now); err != nil {
					return util.InfoMsg{Type: util.InfoTypeError, Msg: err.Error()}
				} else if wait > 0 {
					return util.InfoMsg{Type: util.InfoTypeError, Msg: fmt.Sprintf("rate limited: wait %s", wait.Round(time.Second))}
				}

				fork, err := quests.CreateFork(ctx, repo, token)
				if err != nil {
					return util.InfoMsg{Type: util.InfoTypeError, Msg: err.Error()}
				}
				recordErr := quests.RecordQuestAction("fork", now)

				remoteURL := strings.TrimSpace(fork.CloneURL)
				sh := shell.NewShell(&shell.Options{WorkingDir: cfg.WorkingDir()})
				originOut, _, _ := sh.Exec(ctx, "git remote get-url origin 2>/dev/null || true")
				originOut = strings.TrimSpace(originOut)
				if originOut != "" && (strings.HasPrefix(originOut, "git@") || strings.HasPrefix(originOut, "ssh://")) {
					if strings.TrimSpace(fork.SSHURL) != "" {
						remoteURL = strings.TrimSpace(fork.SSHURL)
					}
				}

				added := false
				if _, _, err := sh.Exec(ctx, "git rev-parse --is-inside-work-tree 2>/dev/null"); err == nil {
					existing, _, _ := sh.Exec(ctx, "git remote get-url fork 2>/dev/null || true")
					if strings.TrimSpace(existing) == "" && remoteURL != "" {
						_, stderr, err := sh.Exec(ctx, fmt.Sprintf("git remote add fork %q", remoteURL))
						if err != nil {
							msg := strings.TrimSpace(stderr)
							if msg == "" {
								msg = err.Error()
							}
							warnMsg := fmt.Sprintf("Fork created: %s • %s • failed to add git remote: %s", fork.FullName, fork.HTMLURL, msg)
							if recordErr != nil {
								warnMsg += " • failed to record quest action"
							}
							return util.InfoMsg{Type: util.InfoTypeWarn, Msg: warnMsg}
						}
						added = true
					}
				}

				msg := "Fork created: " + fork.FullName
				if strings.TrimSpace(fork.HTMLURL) != "" {
					msg += " • " + fork.HTMLURL
				}
				if added {
					msg += " • added git remote 'fork'"
				}
				if recordErr != nil {
					msg += " • failed to record quest action"
				}
				return util.InfoMsg{Type: util.InfoTypeInfo, Msg: msg}
			}
		},
	})

	commands = append(commands, Command{
		ID:          "github_quest_commit",
		Title:       "Quest Commit",
		Description: "Stage and commit changes for the active quest",
		Handler: func(cmd Command) tea.Cmd {
			cfg := config.Get()
			if cfg.Options == nil || cfg.Options.TUI == nil || cfg.Options.TUI.Quests == nil || cfg.Options.TUI.Quests.ActiveIssue <= 0 {
				return util.ReportError(fmt.Errorf("no active quest selected"))
			}

			issue := cfg.Options.TUI.Quests.ActiveIssue
			title := strings.TrimSpace(cfg.Options.TUI.Quests.ActiveTitle)
			issueURL := strings.TrimSpace(cfg.Options.TUI.Quests.ActiveURL)
			defaultSubject := fmt.Sprintf("Quest #%d", issue)
			if title != "" {
				defaultSubject = fmt.Sprintf("Quest #%d: %s", issue, title)
			}

			return util.CmdHandler(dialogs.OpenDialogMsg{
				Model: NewCommandArgumentsDialog(
					"github_quest_commit",
					"GitHub Quests",
					"Quest Commit",
					"Stage all changes and create a git commit",
					[]Argument{
						{Name: "subject", Title: "Subject", Description: "Commit subject (blank uses quest title)", Required: false},
						{Name: "submit_id", Title: "PoE submitId", Description: "Optional PoE CODE submitId to include in commit body", Required: false},
					},
					func(args map[string]string) tea.Cmd {
						subject := strings.TrimSpace(args["subject"])
						if subject == "" {
							subject = defaultSubject
						}
						submitID := strings.TrimSpace(args["submit_id"])

						return func() tea.Msg {
							ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
							defer cancel()

							sh := shell.NewShell(&shell.Options{WorkingDir: cfg.WorkingDir()})
							if _, _, err := sh.Exec(ctx, "git rev-parse --is-inside-work-tree 2>/dev/null"); err != nil {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: "not a git repo"}
							}

							status, _, err := sh.Exec(ctx, "git status --porcelain 2>/dev/null")
							if err != nil {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: "git status failed"}
							}
							if strings.TrimSpace(status) == "" {
								return util.InfoMsg{Type: util.InfoTypeError, Msg: "no changes to commit"}
							}

							_, stderr, err := sh.Exec(ctx, "git add -A")
							if err != nil {
								msg := strings.TrimSpace(stderr)
								if msg == "" {
									msg = err.Error()
								}
								return util.InfoMsg{Type: util.InfoTypeError, Msg: "git add failed: " + msg}
							}

							bodyLines := []string{
								fmt.Sprintf("Quest: #%d", issue),
							}
							if issueURL != "" {
								bodyLines = append(bodyLines, "Quest URL: "+issueURL)
							}
							if submitID != "" {
								bodyLines = append(bodyLines, "PoE CODE submitId: "+submitID)
							}
							body := strings.Join(bodyLines, "\n")

							commitCmd := fmt.Sprintf("git commit -m %q", subject)
							if strings.TrimSpace(body) != "" {
								commitCmd = fmt.Sprintf("git commit -m %q -m %q", subject, body)
							}
							_, stderr, err = sh.Exec(ctx, commitCmd)
							if err != nil {
								msg := strings.TrimSpace(stderr)
								if msg == "" {
									msg = err.Error()
								}
								return util.InfoMsg{Type: util.InfoTypeError, Msg: "git commit failed: " + msg}
							}

							return util.InfoMsg{Type: util.InfoTypeInfo, Msg: "Committed: " + subject}
						}
					},
				),
			})
		},
	})

	if agentCfg, ok := cfg.Agents[config.AgentCoder]; ok {
		providerCfg := cfg.GetProviderForModel(agentCfg.Model)
		if providerCfg != nil && providerCfg.Type == synapsenet.Name {
			commands = append(commands, Command{
				ID:          "remote_rentals",
				Title:       "Remote Rentals",
				Description: "Browse and rent a remote model slot (opt-in)",
				Handler: func(cmd Command) tea.Cmd {
					return util.CmdHandler(dialogs.OpenDialogMsg{
						Model: remote.NewRemoteDialogCmp(),
					})
				},
			})
		}
	}
	// Only show toggle compact mode command if window width is larger than compact breakpoint (90)
	if c.wWidth > 120 && c.sessionID != "" {
		commands = append(commands, Command{
			ID:          "toggle_sidebar",
			Title:       "Toggle Sidebar",
			Description: "Toggle between compact and normal layout",
			Handler: func(cmd Command) tea.Cmd {
				return util.CmdHandler(ToggleCompactModeMsg{})
			},
		})
	}
	if c.sessionID != "" {
		agentCfg := config.Get().Agents[config.AgentCoder]
		model := config.Get().GetModelByType(agentCfg.Model)
		if model.SupportsImages {
			commands = append(commands, Command{
				ID:          "file_picker",
				Title:       "Open File Picker",
				Shortcut:    "ctrl+f",
				Description: "Open file picker",
				Handler: func(cmd Command) tea.Cmd {
					return util.CmdHandler(OpenFilePickerMsg{})
				},
			})
		}
	}

	// Add external editor command if $EDITOR is available
	if os.Getenv("EDITOR") != "" {
		commands = append(commands, Command{
			ID:          "open_external_editor",
			Title:       "Open External Editor",
			Shortcut:    "ctrl+o",
			Description: "Open external editor to compose message",
			Handler: func(cmd Command) tea.Cmd {
				return util.CmdHandler(OpenExternalEditorMsg{})
			},
		})
	}

	return append(commands, []Command{
		{
			ID:          "toggle_yolo",
			Title:       "Toggle Yolo Mode",
			Description: "Toggle yolo mode",
			Handler: func(cmd Command) tea.Cmd {
				return util.CmdHandler(ToggleYoloModeMsg{})
			},
		},
		{
			ID:          "toggle_help",
			Title:       "Toggle Help",
			Shortcut:    "ctrl+g",
			Description: "Toggle help",
			Handler: func(cmd Command) tea.Cmd {
				return util.CmdHandler(ToggleHelpMsg{})
			},
		},
		{
			ID:          "init",
			Title:       "Initialize Project",
			Description: fmt.Sprintf("Create/Update the %s memory file", config.Get().Options.InitializeAs),
			Handler: func(cmd Command) tea.Cmd {
				initPrompt, err := agent.InitializePrompt(*config.Get())
				if err != nil {
					return util.ReportError(err)
				}
				return util.CmdHandler(chat.SendMsg{
					Text: initPrompt,
				})
			},
		},
		{
			ID:          "quit",
			Title:       "Quit",
			Description: "Quit",
			Shortcut:    "ctrl+c",
			Handler: func(cmd Command) tea.Cmd {
				return util.CmdHandler(QuitMsg{})
			},
		},
	}...)
}

func (c *commandDialogCmp) ID() dialogs.DialogID {
	return CommandsDialogID
}
