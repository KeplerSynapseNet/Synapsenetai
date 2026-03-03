package patch

import (
	"charm.land/bubbles/v2/key"
)

type KeyMap struct {
	Left,
	Right,
	Apply,
	ApplyAll,
	Submit,
	Skip,
	Close,
	ToggleDiffMode,
	ScrollDown,
	ScrollUp,
	ScrollLeft,
	ScrollRight key.Binding
}

func DefaultKeyMap() KeyMap {
	return KeyMap{
		Left: key.NewBinding(
			key.WithKeys("left", "h"),
			key.WithHelp("←", "previous"),
		),
		Right: key.NewBinding(
			key.WithKeys("right", "l"),
			key.WithHelp("→", "next"),
		),
		Apply: key.NewBinding(
			key.WithKeys("enter", "a"),
			key.WithHelp("enter", "apply"),
		),
		ApplyAll: key.NewBinding(
			key.WithKeys("A"),
			key.WithHelp("A", "apply all"),
		),
		Submit: key.NewBinding(
			key.WithKeys("p"),
			key.WithHelp("p", "submit"),
		),
		Skip: key.NewBinding(
			key.WithKeys("s"),
			key.WithHelp("s", "skip"),
		),
		Close: key.NewBinding(
			key.WithKeys("esc"),
			key.WithHelp("esc", "close"),
		),
		ToggleDiffMode: key.NewBinding(
			key.WithKeys("t"),
			key.WithHelp("t", "toggle diff"),
		),
		ScrollDown: key.NewBinding(
			key.WithKeys("shift+down", "J"),
			key.WithHelp("shift+↓", "scroll down"),
		),
		ScrollUp: key.NewBinding(
			key.WithKeys("shift+up", "K"),
			key.WithHelp("shift+↑", "scroll up"),
		),
		ScrollLeft: key.NewBinding(
			key.WithKeys("shift+left", "H"),
			key.WithHelp("shift+←", "scroll left"),
		),
		ScrollRight: key.NewBinding(
			key.WithKeys("shift+right", "L"),
			key.WithHelp("shift+→", "scroll right"),
		),
	}
}

func (k KeyMap) KeyBindings() []key.Binding {
	return []key.Binding{
		k.Left,
		k.Right,
		k.Apply,
		k.ApplyAll,
		k.Submit,
		k.Skip,
		k.Close,
		k.ToggleDiffMode,
		k.ScrollDown,
		k.ScrollUp,
		k.ScrollLeft,
		k.ScrollRight,
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
		k.Apply,
		k.Submit,
		k.Skip,
		k.ToggleDiffMode,
		key.NewBinding(
			key.WithKeys("shift+←↓↑→"),
			key.WithHelp("shift+←↓↑→", "scroll"),
		),
	}
}
