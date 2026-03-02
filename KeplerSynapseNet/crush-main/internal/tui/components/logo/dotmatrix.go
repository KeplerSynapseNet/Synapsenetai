package logo

import (
	"fmt"
	"image/color"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/crush/internal/tui/styles"
	"github.com/charmbracelet/x/ansi"
)

func DotMatrixRender(version string, compact bool, o Opts) string {
	if compact {
		return Render(version, compact, o)
	}

	const charm = " Kepler"
	const titlePlain = "SYNAPSENET"

	fg := func(c color.Color, s string) string {
		return lipgloss.NewStyle().Foreground(c).Render(s)
	}

	titleLines := dotMatrixLines(titlePlain)
	titleWidth := maxLineWidth(titleLines)

	styledTitleLines := make([]string, 0, len(titleLines))
	for _, line := range titleLines {
		styledTitleLines = append(styledTitleLines, styles.ApplyBoldForegroundGrad(line, o.TitleColorA, o.TitleColorB))
	}
	title := strings.Join(styledTitleLines, "\n")

	metaRowGap := 1
	maxVersionWidth := titleWidth - lipgloss.Width(charm) - metaRowGap
	maxVersionWidth = max(0, maxVersionWidth)
	version = ansi.Truncate(version, maxVersionWidth, "…")
	gap := max(0, titleWidth-lipgloss.Width(charm)-lipgloss.Width(version))
	metaRow := fg(o.CharmColor, charm) + strings.Repeat(" ", gap) + fg(o.VersionColor, version)

	wordmark := strings.TrimSpace(metaRow + "\n" + title)
	wordmarkWidth := titleWidth

	fieldHeight := lipgloss.Height(wordmark)

	const leftWidth = 6
	leftFieldRow := fg(o.FieldColor, strings.Repeat(diag, leftWidth))
	leftField := new(strings.Builder)
	for range fieldHeight {
		fmt.Fprintln(leftField, leftFieldRow)
	}

	rightWidth := max(15, o.Width-wordmarkWidth-leftWidth-2)
	const stepDownAt = 0
	rightField := new(strings.Builder)
	for i := range fieldHeight {
		width := rightWidth
		if i >= stepDownAt {
			width = rightWidth - (i - stepDownAt)
		}
		fmt.Fprint(rightField, fg(o.FieldColor, strings.Repeat(diag, width)), "\n")
	}

	logo := lipgloss.JoinHorizontal(lipgloss.Top, leftField.String(), " ", wordmark, " ", rightField.String())
	if o.Width > 0 {
		lines := strings.Split(logo, "\n")
		for i, line := range lines {
			lines[i] = ansi.Truncate(line, o.Width, "")
		}
		logo = strings.Join(lines, "\n")
	}
	return logo
}

func maxLineWidth(lines []string) int {
	w := 0
	for _, line := range lines {
		w = max(w, lipgloss.Width(line))
	}
	return w
}

func dotMatrixLines(text string) []string {
	const h = 5
	rows := make([]string, h)
	for i := range h {
		parts := make([]string, 0, len(text))
		for _, r := range text {
			g, ok := dotFont[r]
			if !ok {
				g = dotFont[' ']
			}
			parts = append(parts, g[i])
		}
		rows[i] = strings.Join(parts, " ")
	}
	return rows
}

var dotFont = map[rune][5]string{
	' ': {"     ", "     ", "     ", "     ", "     "},
	'A': {" ███ ", "█   █", "█████", "█   █", "█   █"},
	'E': {"█████", "█    ", "████ ", "█    ", "█████"},
	'N': {"█   █", "██  █", "█ █ █", "█  ██", "█   █"},
	'P': {"████ ", "█   █", "████ ", "█    ", "█    "},
	'S': {"█████", "█    ", "█████", "    █", "█████"},
	'T': {"█████", "  █  ", "  █  ", "  █  ", "  █  "},
	'Y': {"█   █", " █ █ ", "  █  ", "  █  ", "  █  "},
}
