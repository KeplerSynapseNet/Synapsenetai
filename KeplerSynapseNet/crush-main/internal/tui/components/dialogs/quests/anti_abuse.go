package quests

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/charmbracelet/crush/internal/config"
)

const (
	DefaultMinSubmitPowBits = 16
	defaultForkCooldown     = 10 * time.Minute
	defaultPrCooldown       = 1 * time.Minute
)

type poeFetchCodeResult struct {
	SubmitID  string `json:"submitId"`
	Finalized bool   `json:"finalized"`
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func validatePoeSubmitID(ctx context.Context, baseURL string, submitID string) (poeFetchCodeResult, error) {
	params := map[string]any{
		"id": submitID,
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  "poe.fetch_code",
		"params":  params,
	})
	if err != nil {
		return poeFetchCodeResult{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL, bytes.NewReader(body))
	if err != nil {
		return poeFetchCodeResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return poeFetchCodeResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return poeFetchCodeResult{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return poeFetchCodeResult{}, fmt.Errorf("rpc http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var rr rpcResponse
	if err := json.Unmarshal(b, &rr); err != nil {
		return poeFetchCodeResult{}, err
	}
	if rr.Error != nil {
		return poeFetchCodeResult{}, fmt.Errorf("rpc error %d: %s", rr.Error.Code, rr.Error.Message)
	}

	var out poeFetchCodeResult
	if err := json.Unmarshal(rr.Result, &out); err != nil {
		return poeFetchCodeResult{}, err
	}
	if strings.TrimSpace(out.SubmitID) == "" {
		return poeFetchCodeResult{}, errors.New("rpc: empty submitId")
	}
	return out, nil
}

func leadingZeroBitsHex(hashHex string) (int, error) {
	h := strings.ToLower(strings.TrimSpace(hashHex))
	if h == "" {
		return 0, errors.New("empty hex")
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return 0, errors.New("invalid hex")
	}
	if len(b) != 32 {
		return 0, errors.New("expected 32-byte hash")
	}

	total := 0
	for _, v := range b {
		if v == 0 {
			total += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if (v>>uint(i))&1 == 0 {
				total++
				continue
			}
			return total, nil
		}
	}
	return total, nil
}

func ValidateQuestSubmitID(ctx context.Context, baseURL string, submitID string, minPowBits int) (poeFetchCodeResult, error) {
	if minPowBits <= 0 {
		minPowBits = DefaultMinSubmitPowBits
	}
	z, err := leadingZeroBitsHex(submitID)
	if err != nil {
		return poeFetchCodeResult{}, err
	}
	if z < minPowBits {
		return poeFetchCodeResult{}, fmt.Errorf("submitId PoW too low: %d < %d leading-zero bits", z, minPowBits)
	}
	return validatePoeSubmitID(ctx, baseURL, submitID)
}

func CheckQuestActionRateLimit(action string, now time.Time) (time.Duration, error) {
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

	var last int64
	var cooldown time.Duration
	switch action {
	case "fork":
		last = cfg.Options.TUI.Quests.LastForkAt
		cooldown = defaultForkCooldown
	case "pr":
		last = cfg.Options.TUI.Quests.LastPRAt
		cooldown = defaultPrCooldown
	default:
		return 0, errors.New("unknown quest action")
	}
	if last <= 0 {
		return 0, nil
	}

	elapsed := now.Sub(time.Unix(last, 0))
	if elapsed >= cooldown {
		return 0, nil
	}
	return cooldown - elapsed, nil
}

func RecordQuestAction(action string, now time.Time) error {
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

	ts := now.Unix()
	switch action {
	case "fork":
		cfg.Options.TUI.Quests.LastForkAt = ts
		return cfg.SetConfigField("options.tui.quests.last_fork_at", ts)
	case "pr":
		cfg.Options.TUI.Quests.LastPRAt = ts
		return cfg.SetConfigField("options.tui.quests.last_pr_at", ts)
	default:
		return errors.New("unknown quest action")
	}
}
