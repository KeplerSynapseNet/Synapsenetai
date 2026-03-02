package patch_test

import (
	"testing"

	"github.com/charmbracelet/crush/internal/patch"
	"github.com/stretchr/testify/require"
)

func TestParseUnifiedDiff_ModifyFile(t *testing.T) {
	in := `diff --git a/foo.txt b/foo.txt
--- a/foo.txt
+++ b/foo.txt
@@ -1,3 +1,3 @@
 a
-b
+B
 c
`

	patches, err := patch.ParseUnifiedDiff(in)
	require.NoError(t, err)
	require.Len(t, patches, 1)
	require.Equal(t, "foo.txt", patches[0].OldPath)
	require.Equal(t, "foo.txt", patches[0].NewPath)
	require.Len(t, patches[0].Hunks, 1)
}

func TestApply_ModifyFile(t *testing.T) {
	oldContent := "a\nb\nc\n"
	fp := patch.FilePatch{
		OldPath: "foo.txt",
		NewPath: "foo.txt",
		Hunks: []patch.Hunk{
			{
				OldStart: 1,
				OldCount: 3,
				NewStart: 1,
				NewCount: 3,
				Lines: []patch.HunkLine{
					{Kind: patch.LineContext, Text: "a"},
					{Kind: patch.LineDelete, Text: "b"},
					{Kind: patch.LineAdd, Text: "B"},
					{Kind: patch.LineContext, Text: "c"},
				},
			},
		},
	}

	newContent, err := patch.Apply(oldContent, fp)
	require.NoError(t, err)
	require.Equal(t, "a\nB\nc\n", newContent)
}

func TestApply_NewFile(t *testing.T) {
	oldContent := ""
	fp := patch.FilePatch{
		OldPath: "/dev/null",
		NewPath: "new.txt",
		Hunks: []patch.Hunk{
			{
				OldStart: 0,
				OldCount: 0,
				NewStart: 1,
				NewCount: 2,
				Lines: []patch.HunkLine{
					{Kind: patch.LineAdd, Text: "hello"},
					{Kind: patch.LineAdd, Text: "world"},
				},
			},
		},
	}

	newContent, err := patch.Apply(oldContent, fp)
	require.NoError(t, err)
	require.Equal(t, "hello\nworld\n", newContent)
}

