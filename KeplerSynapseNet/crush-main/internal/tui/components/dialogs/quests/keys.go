package quests

import (
	"charm.land/bubbles/v2/key"
)

type KeyMap struct {
	Select,
	Next,
	Previous,
	Refresh,
	Clear,
	Close key.Binding
}

func DefaultKeyMap() KeyMap {
	return KeyMap{
		Select: key.NewBinding(
			key.WithKeys("enter"),
			key.WithHelp("enter", "select"),
		),
		Next: key.NewBinding(
			key.WithKeys("down", "ctrl+n"),
			key.WithHelp("↓", "next"),
		),
		Previous: key.NewBinding(
			key.WithKeys("up", "ctrl+p"),
			key.WithHelp("↑", "prev"),
		),
		Refresh: key.NewBinding(
			key.WithKeys("r"),
			key.WithHelp("r", "refresh"),
		),
		Clear: key.NewBinding(
			key.WithKeys("c"),
			key.WithHelp("c", "clear"),
		),
		Close: key.NewBinding(
			key.WithKeys("esc", "alt+esc"),
			key.WithHelp("esc", "close"),
		),
	}
}

func (k KeyMap) KeyBindings() []key.Binding {
	return []key.Binding{
		k.Select,
		k.Next,
		k.Previous,
		k.Refresh,
		k.Clear,
		k.Close,
	}
}

func (k KeyMap) FullHelp() [][]key.Binding {
	m := [][]key.Binding{}
	slice := k.KeyBindings()
	for i := 0; i < len(slice); i += 4 {
		end := min(i+4, len(slice))
		m = append(m, slice[i:end])
	}
	return m
}

func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{
		key.NewBinding(
			key.WithKeys("down", "up"),
			key.WithHelp("↑↓", "choose"),
		),
		k.Select,
		k.Refresh,
		k.Clear,
		k.Close,
	}
}
