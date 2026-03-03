package synapsenet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"charm.land/fantasy"
	"charm.land/fantasy/object"
	"github.com/charmbracelet/crush/internal/config"
)

const Name = "synapsenet"

const defaultBaseURL = "http://127.0.0.1:8332"

type options struct {
	baseURL  string
	provider string
	client   *http.Client
}

type Option func(*options)

func WithBaseURL(url string) Option { return func(o *options) { o.baseURL = url } }

func WithHTTPClient(c *http.Client) Option { return func(o *options) { o.client = c } }

func New(opts ...Option) (fantasy.Provider, error) {
	o := options{
		baseURL:  defaultBaseURL,
		provider: Name,
		client:   &http.Client{Timeout: 0},
	}
	for _, opt := range opts {
		opt(&o)
	}
	if o.baseURL == "" {
		return nil, errors.New("synapsenet: missing base URL")
	}
	return &provider{options: o}, nil
}

type provider struct{ options options }

func (p *provider) Name() string { return p.options.provider }

func (p *provider) LanguageModel(_ context.Context, modelID string) (fantasy.LanguageModel, error) {
	if modelID == "" {
		return nil, errors.New("synapsenet: missing model id")
	}
	return &languageModel{provider: p.options.provider, modelID: modelID, opts: p.options}, nil
}

type languageModel struct {
	provider string
	modelID  string
	opts     options
}

func (m *languageModel) GenerateObject(ctx context.Context, call fantasy.ObjectCall) (*fantasy.ObjectResponse, error) {
	return object.GenerateWithTool(ctx, m, call)
}

func (m *languageModel) StreamObject(ctx context.Context, call fantasy.ObjectCall) (fantasy.ObjectStreamResponse, error) {
	return object.StreamWithTool(ctx, m, call)
}

func (m *languageModel) Provider() string { return m.provider }

func (m *languageModel) Model() string { return m.modelID }

func (m *languageModel) Generate(ctx context.Context, call fantasy.Call) (*fantasy.Response, error) {
	res, finishReason, err := m.complete(ctx, call)
	if err != nil {
		return nil, err
	}
	return &fantasy.Response{
		Content:      res,
		FinishReason: finishReason,
		Usage:        fantasy.Usage{},
		Warnings:     nil,
	}, nil
}

func (m *languageModel) Stream(ctx context.Context, call fantasy.Call) (fantasy.StreamResponse, error) {
	content, finishReason, err := m.complete(ctx, call)
	if err != nil {
		return nil, err
	}

	id := fmt.Sprintf("syn-%d", time.Now().UnixNano())
	return func(yield func(fantasy.StreamPart) bool) {
		for _, c := range content {
			switch c.GetType() {
			case fantasy.ContentTypeText:
				text, ok := fantasy.AsContentType[fantasy.TextContent](c)
				if !ok {
					continue
				}
				if !yield(fantasy.StreamPart{Type: fantasy.StreamPartTypeTextStart, ID: id}) {
					return
				}
				for _, chunk := range splitForStream(text.Text, 256) {
					if !yield(fantasy.StreamPart{Type: fantasy.StreamPartTypeTextDelta, ID: id, Delta: chunk}) {
						return
					}
				}
				if !yield(fantasy.StreamPart{Type: fantasy.StreamPartTypeTextEnd, ID: id}) {
					return
				}
			case fantasy.ContentTypeToolCall:
				tc, ok := fantasy.AsContentType[fantasy.ToolCallContent](c)
				if !ok {
					continue
				}
				if !yield(fantasy.StreamPart{
					Type:          fantasy.StreamPartTypeToolCall,
					ID:            tc.ToolCallID,
					ToolCallName:  tc.ToolName,
					ToolCallInput: tc.Input,
				}) {
					return
				}
			}
		}
		_ = yield(fantasy.StreamPart{
			Type:         fantasy.StreamPartTypeFinish,
			FinishReason: finishReason,
			Usage:        fantasy.Usage{},
		})
	}, nil
}

type rpcResponse struct {
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (m *languageModel) rpc(ctx context.Context, method string, params any, out any) error {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      "1",
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.opts.baseURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.opts.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("synapsenet rpc http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var rr rpcResponse
	if err := json.Unmarshal(b, &rr); err != nil {
		return err
	}
	if rr.Error != nil {
		return fmt.Errorf("synapsenet rpc error %d: %s", rr.Error.Code, rr.Error.Message)
	}
	if out == nil {
		return nil
	}
	if len(rr.Result) == 0 {
		return errors.New("synapsenet rpc: empty result")
	}
	return json.Unmarshal(rr.Result, out)
}

func (m *languageModel) ensureModelLoaded(ctx context.Context) error {
	modelID := strings.TrimSpace(m.modelID)
	if modelID == "" || strings.EqualFold(modelID, "active") {
		return nil
	}
	var st struct {
		Loaded bool   `json:"loaded"`
		Name   string `json:"name"`
		Path   string `json:"path"`
		State  string `json:"state"`
	}
	if err := m.rpc(ctx, "model.status", map[string]any{}, &st); err != nil {
		return err
	}
	if st.Loaded {
		if st.Name == modelID {
			return nil
		}
		if st.Path == modelID {
			return nil
		}
		if filepath.Base(st.Path) == modelID {
			return nil
		}
	}

	params := map[string]any{}
	if strings.Contains(modelID, "/") || strings.Contains(modelID, "\\") {
		params["path"] = modelID
	} else {
		params["name"] = modelID
	}
	var lr struct {
		OK    bool   `json:"ok"`
		State string `json:"state"`
		Error string `json:"error"`
	}
	if err := m.rpc(ctx, "model.load", params, &lr); err != nil {
		return err
	}
	if !lr.OK {
		if lr.Error != "" {
			return errors.New(lr.Error)
		}
		return errors.New("model load failed")
	}
	return nil
}

func (m *languageModel) complete(ctx context.Context, call fantasy.Call) ([]fantasy.Content, fantasy.FinishReason, error) {
	cfg := config.Get()
	remoteEnabled := false
	remoteSessionID := ""
	if cfg.Options != nil && cfg.Options.TUI != nil && cfg.Options.TUI.Remote != nil {
		remote := cfg.Options.TUI.Remote
		if remote.Enabled && strings.TrimSpace(remote.SessionID) != "" {
			remoteEnabled = true
			remoteSessionID = strings.TrimSpace(remote.SessionID)
		}
	}
	if !remoteEnabled {
		if err := m.ensureModelLoaded(ctx); err != nil {
			return nil, fantasy.FinishReasonError, err
		}
	}

	finalPrompt := promptToText(call.Prompt, call.Tools, call.ToolChoice)

	params := map[string]any{
		"prompt": finalPrompt,
	}
	if call.MaxOutputTokens != nil {
		params["maxTokens"] = *call.MaxOutputTokens
	}
	if call.Temperature != nil {
		params["temperature"] = *call.Temperature
	}
	if call.TopP != nil {
		params["topP"] = *call.TopP
	}
	if call.TopK != nil {
		params["topK"] = *call.TopK
	}
	if len(call.Tools) > 0 && call.ToolChoice != nil && *call.ToolChoice != fantasy.ToolChoiceNone {
		params["jsonMode"] = true
	}

	// Add Web4 parameters from config
	if cfg.Options != nil && cfg.Options.TUI != nil && cfg.Options.TUI.Web4 != nil {
		web4 := cfg.Options.TUI.Web4
		if web4.InjectEnabled {
			params["webInject"] = true
			params["webOnion"] = web4.OnionEnabled
			params["webTor"] = web4.TorClearnet
			if web4.Query != "" {
				params["webQuery"] = web4.Query
			}
		}
	}

	// Optional remote inference (opt-in). Requires a rental session id.
	if remoteEnabled {
		params["remote"] = true
		params["remoteSessionId"] = remoteSessionID
	}

	var out struct {
		Model string `json:"model"`
		Text  string `json:"text"`
	}
	if err := m.rpc(ctx, "ai.complete", params, &out); err != nil {
		return nil, fantasy.FinishReasonError, err
	}

	tc, ok := parseToolCall(out.Text)
	if ok && len(call.Tools) > 0 && call.ToolChoice != nil && *call.ToolChoice != fantasy.ToolChoiceNone {
		return []fantasy.Content{tc}, fantasy.FinishReasonToolCalls, nil
	}
	return []fantasy.Content{fantasy.TextContent{Text: out.Text}}, fantasy.FinishReasonStop, nil
}

func promptToText(prompt fantasy.Prompt, tools []fantasy.Tool, toolChoice *fantasy.ToolChoice) string {
	var b strings.Builder
	for _, msg := range prompt {
		role := strings.ToUpper(string(msg.Role))
		if role == "" {
			role = "USER"
		}
		b.WriteString(role)
		b.WriteString(":\n")
		for _, part := range msg.Content {
			switch part.GetType() {
			case fantasy.ContentTypeText:
				t, ok := fantasy.AsMessagePart[fantasy.TextPart](part)
				if ok && t.Text != "" {
					b.WriteString(t.Text)
					if !strings.HasSuffix(t.Text, "\n") {
						b.WriteString("\n")
					}
				}
			case fantasy.ContentTypeReasoning:
				r, ok := fantasy.AsMessagePart[fantasy.ReasoningPart](part)
				if ok && r.Text != "" {
					b.WriteString(r.Text)
					if !strings.HasSuffix(r.Text, "\n") {
						b.WriteString("\n")
					}
				}
			case fantasy.ContentTypeToolCall:
				tc, ok := fantasy.AsMessagePart[fantasy.ToolCallPart](part)
				if ok {
					b.WriteString("TOOL_CALL ")
					b.WriteString(tc.ToolName)
					b.WriteString(" ")
					b.WriteString(tc.Input)
					b.WriteString("\n")
				}
			case fantasy.ContentTypeToolResult:
				tr, ok := fantasy.AsMessagePart[fantasy.ToolResultPart](part)
				if ok {
					raw, _ := json.Marshal(tr.Output)
					b.WriteString("TOOL_RESULT ")
					b.WriteString(tr.ToolCallID)
					b.WriteString(" ")
					b.WriteString(string(raw))
					b.WriteString("\n")
				}
			}
		}
		b.WriteString("\n")
	}

	if len(tools) > 0 && toolChoice != nil && *toolChoice != fantasy.ToolChoiceNone {
		b.WriteString("TOOLS:\n")
		for _, t := range tools {
			ft, ok := t.(fantasy.FunctionTool)
			if !ok {
				continue
			}
			schemaBytes, _ := json.Marshal(ft.InputSchema)
			b.WriteString("- ")
			b.WriteString(ft.Name)
			b.WriteString(": ")
			b.WriteString(ft.Description)
			b.WriteString("\n  schema: ")
			b.WriteString(string(schemaBytes))
			b.WriteString("\n")
		}
		b.WriteString("\n")
		if *toolChoice == fantasy.ToolChoiceRequired {
			b.WriteString("You must call a tool. Reply ONLY with JSON: {\"tool_call\":{\"name\":\"...\",\"input\":{...}}}\n")
		} else if *toolChoice != fantasy.ToolChoiceAuto {
			b.WriteString("If you need a tool, reply ONLY with JSON: {\"tool_call\":{\"name\":\"...\",\"input\":{...}}}\n")
		} else {
			b.WriteString("If a tool is needed, reply ONLY with JSON: {\"tool_call\":{\"name\":\"...\",\"input\":{...}}}\n")
		}
	}
	return b.String()
}

func parseToolCall(text string) (fantasy.ToolCallContent, bool) {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "{") {
		return fantasy.ToolCallContent{}, false
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(t), &obj); err != nil {
		return fantasy.ToolCallContent{}, false
	}
	tcRaw, ok := obj["tool_call"]
	if !ok {
		return fantasy.ToolCallContent{}, false
	}
	tcObj, ok := tcRaw.(map[string]any)
	if !ok {
		return fantasy.ToolCallContent{}, false
	}
	name, _ := tcObj["name"].(string)
	if name == "" {
		return fantasy.ToolCallContent{}, false
	}
	inputObj := tcObj["input"]
	inputBytes, err := json.Marshal(inputObj)
	if err != nil {
		return fantasy.ToolCallContent{}, false
	}
	return fantasy.ToolCallContent{
		ToolCallID: fmt.Sprintf("call_%d", time.Now().UnixNano()),
		ToolName:   name,
		Input:      string(inputBytes),
	}, true
}

func splitForStream(s string, chunkSize int) []string {
	if chunkSize <= 0 {
		return []string{s}
	}
	var out []string
	for len(s) > 0 {
		if len(s) <= chunkSize {
			out = append(out, s)
			break
		}
		out = append(out, s[:chunkSize])
		s = s[chunkSize:]
	}
	return out
}
