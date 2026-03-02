package patch

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type LineKind int

const (
	LineContext LineKind = iota
	LineAdd
	LineDelete
)

type HunkLine struct {
	Kind LineKind
	Text string
}

type Hunk struct {
	OldStart int
	OldCount int
	NewStart int
	NewCount int
	Lines    []HunkLine
}

type FilePatch struct {
	OldPath string
	NewPath string
	Hunks   []Hunk
}

func ParseUnifiedDiff(input string) ([]FilePatch, error) {
	diffText := extractDiffBlock(input)
	lines := splitLines(diffText)

	var patches []FilePatch
	var cur *FilePatch
	var curHunk *Hunk

	flushHunk := func() {
		if cur == nil || curHunk == nil {
			return
		}
		cur.Hunks = append(cur.Hunks, *curHunk)
		curHunk = nil
	}
	flushFile := func() {
		if cur == nil {
			return
		}
		flushHunk()
		if cur.OldPath != "" || cur.NewPath != "" {
			patches = append(patches, *cur)
		}
		cur = nil
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if strings.HasPrefix(line, "diff --git ") {
			flushFile()
			oldPath, newPath := parseDiffGitLine(line)
			cur = &FilePatch{
				OldPath: oldPath,
				NewPath: newPath,
			}
			continue
		}

		if strings.HasPrefix(line, "--- ") {
			if cur == nil {
				cur = &FilePatch{}
			}
			cur.OldPath = normalizePath(strings.TrimSpace(strings.TrimPrefix(line, "--- ")))
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			if cur == nil {
				cur = &FilePatch{}
			}
			cur.NewPath = normalizePath(strings.TrimSpace(strings.TrimPrefix(line, "+++ ")))
			continue
		}

		if strings.HasPrefix(line, "@@ ") {
			if cur == nil {
				cur = &FilePatch{}
			}
			flushHunk()
			h, err := parseHunkHeader(line)
			if err != nil {
				return nil, err
			}
			curHunk = &h
			continue
		}

		if curHunk != nil {
			if line == "\\ No newline at end of file" {
				continue
			}
			if line == "" {
				curHunk.Lines = append(curHunk.Lines, HunkLine{Kind: LineContext, Text: ""})
				continue
			}
			switch line[0] {
			case ' ':
				curHunk.Lines = append(curHunk.Lines, HunkLine{Kind: LineContext, Text: line[1:]})
			case '+':
				if strings.HasPrefix(line, "+++") {
					continue
				}
				curHunk.Lines = append(curHunk.Lines, HunkLine{Kind: LineAdd, Text: line[1:]})
			case '-':
				if strings.HasPrefix(line, "---") {
					continue
				}
				curHunk.Lines = append(curHunk.Lines, HunkLine{Kind: LineDelete, Text: line[1:]})
			default:
				return nil, fmt.Errorf("invalid hunk line: %q", line)
			}
			continue
		}
	}

	flushFile()

	if len(patches) == 0 {
		return nil, errors.New("no file diffs found")
	}
	for _, p := range patches {
		if len(p.Hunks) == 0 && p.OldPath != "/dev/null" && p.NewPath != "/dev/null" {
			return nil, errors.New("no hunks found")
		}
	}

	return patches, nil
}

func Apply(oldContent string, p FilePatch) (string, error) {
	hasFinalNewline := strings.HasSuffix(oldContent, "\n")
	oldLines := splitContentLines(oldContent)

	out := make([]string, 0, len(oldLines))
	oldIdx := 0

	for _, h := range p.Hunks {
		target := h.OldStart - 1
		if target < 0 {
			target = 0
		}
		if target > len(oldLines) {
			return "", fmt.Errorf("hunk starts beyond end of file: %d", h.OldStart)
		}
		out = append(out, oldLines[oldIdx:target]...)
		oldIdx = target

		for _, hl := range h.Lines {
			switch hl.Kind {
			case LineContext:
				if oldIdx >= len(oldLines) {
					return "", errors.New("context exceeds file length")
				}
				if oldLines[oldIdx] != hl.Text {
					return "", fmt.Errorf("context mismatch at line %d", oldIdx+1)
				}
				out = append(out, hl.Text)
				oldIdx++
			case LineDelete:
				if oldIdx >= len(oldLines) {
					return "", errors.New("delete exceeds file length")
				}
				if oldLines[oldIdx] != hl.Text {
					return "", fmt.Errorf("delete mismatch at line %d", oldIdx+1)
				}
				oldIdx++
			case LineAdd:
				out = append(out, hl.Text)
			default:
				return "", errors.New("unknown line kind")
			}
		}
	}

	out = append(out, oldLines[oldIdx:]...)
	newContent := strings.Join(out, "\n")
	if hasFinalNewline || oldContent == "" {
		newContent += "\n"
	}
	return newContent, nil
}

func extractDiffBlock(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return ""
	}

	lines := splitLines(trimmed)
	best := ""

	inFence := false
	fenceStart := -1
	for i, line := range lines {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "```") {
			if !inFence {
				inFence = true
				fenceStart = i + 1
				continue
			}
			inFence = false
			if fenceStart >= 0 && fenceStart < i {
				block := strings.Join(lines[fenceStart:i], "\n")
				if strings.Contains(block, "diff --git ") || (strings.Contains(block, "--- ") && strings.Contains(block, "+++ ")) {
					return block
				}
				if best == "" {
					best = block
				}
			}
			fenceStart = -1
		}
	}

	if best != "" {
		return best
	}
	return trimmed
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func splitContentLines(content string) []string {
	if content == "" {
		return []string{}
	}
	c := strings.TrimSuffix(content, "\n")
	if c == "" {
		return []string{}
	}
	return strings.Split(c, "\n")
}

func parseDiffGitLine(line string) (string, string) {
	rest := strings.TrimSpace(strings.TrimPrefix(line, "diff --git "))
	parts := strings.Fields(rest)
	if len(parts) >= 2 {
		return normalizePath(parts[0]), normalizePath(parts[1])
	}
	return "", ""
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return p
	}
	if p == "/dev/null" {
		return p
	}
	p = strings.TrimPrefix(p, "a/")
	p = strings.TrimPrefix(p, "b/")
	return p
}

func parseHunkHeader(line string) (Hunk, error) {
	if !strings.HasPrefix(line, "@@") {
		return Hunk{}, fmt.Errorf("invalid hunk header: %q", line)
	}
	end := strings.Index(line[2:], "@@")
	if end == -1 {
		return Hunk{}, fmt.Errorf("invalid hunk header: %q", line)
	}
	body := strings.TrimSpace(line[2 : 2+end])
	fields := strings.Fields(body)
	if len(fields) < 2 {
		return Hunk{}, fmt.Errorf("invalid hunk header: %q", line)
	}
	oldStart, oldCount, err := parseRange(fields[0])
	if err != nil {
		return Hunk{}, err
	}
	newStart, newCount, err := parseRange(fields[1])
	if err != nil {
		return Hunk{}, err
	}
	return Hunk{
		OldStart: oldStart,
		OldCount: oldCount,
		NewStart: newStart,
		NewCount: newCount,
		Lines:    nil,
	}, nil
}

func parseRange(tok string) (int, int, error) {
	if tok == "" {
		return 0, 0, errors.New("empty range")
	}
	sign := tok[0]
	if sign != '-' && sign != '+' {
		return 0, 0, fmt.Errorf("invalid range token: %q", tok)
	}
	tok = tok[1:]
	if tok == "" {
		return 0, 0, fmt.Errorf("invalid range token: %q", tok)
	}
	startStr, countStr, hasCount := strings.Cut(tok, ",")
	start, err := strconv.Atoi(startStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid range start: %q", tok)
	}
	count := 1
	if hasCount {
		if countStr == "" {
			count = 0
		} else {
			count, err = strconv.Atoi(countStr)
			if err != nil {
				return 0, 0, fmt.Errorf("invalid range count: %q", tok)
			}
		}
	}
	return start, count, nil
}

