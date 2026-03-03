package chat

import (
	"charm.land/bubbles/v2/key"
)

type KeyMap struct {
	NewSession    key.Binding
	AddAttachment key.Binding
	Cancel        key.Binding
	Tab           key.Binding
	Details       key.Binding
	TogglePills   key.Binding
	PillLeft      key.Binding
	PillRight     key.Binding
	ToggleWeb4    key.Binding
	ToggleWeb4Onion key.Binding
	ToggleWeb4Tor  key.Binding
}

func DefaultKeyMap() KeyMap {
	return KeyMap{
		NewSession: key.NewBinding(
			key.WithKeys("ctrl+n"),
			key.WithHelp("ctrl+n", "new session"),
		),
		AddAttachment: key.NewBinding(
			key.WithKeys("ctrl+f"),
			key.WithHelp("ctrl+f", "add attachment"),
		),
		Cancel: key.NewBinding(
			key.WithKeys("esc", "alt+esc"),
			key.WithHelp("esc", "cancel"),
		),
		Tab: key.NewBinding(
			key.WithKeys("tab"),
			key.WithHelp("tab", "change focus"),
		),
		Details: key.NewBinding(
			key.WithKeys("ctrl+d"),
			key.WithHelp("ctrl+d", "toggle details"),
		),
		TogglePills: key.NewBinding(
			key.WithKeys("ctrl+space"),
			key.WithHelp("ctrl+space", "toggle tasks"),
		),
		PillLeft: key.NewBinding(
			key.WithKeys("left"),
			key.WithHelp("←/→", "switch section"),
		),
		PillRight: key.NewBinding(
			key.WithKeys("right"),
			key.WithHelp("←/→", "switch section"),
		),
		ToggleWeb4: key.NewBinding(
			key.WithKeys("f5", "ctrl+w"),
			key.WithHelp("f5", "toggle web4"),
		),
		ToggleWeb4Onion: key.NewBinding(
			key.WithKeys("f6", "ctrl+shift+o"),
			key.WithHelp("f6", "toggle onion"),
		),
		ToggleWeb4Tor: key.NewBinding(
			key.WithKeys("f7", "ctrl+shift+t"),
			key.WithHelp("f7", "toggle tor"),
		),
	}
}
