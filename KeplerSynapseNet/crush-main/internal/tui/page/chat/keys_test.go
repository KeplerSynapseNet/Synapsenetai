package chat

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWeb4KeyBindingsIncludeFunctionKeys(t *testing.T) {
	t.Parallel()

	km := DefaultKeyMap()

	require.Contains(t, km.ToggleWeb4.Keys(), "f5")
	require.Contains(t, km.ToggleWeb4Onion.Keys(), "f6")
	require.Contains(t, km.ToggleWeb4Tor.Keys(), "f7")
}

