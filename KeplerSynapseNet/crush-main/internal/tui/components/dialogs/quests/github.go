package quests

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type githubRepoInfo struct {
	DefaultBranch string `json:"default_branch"`
}

func FetchDefaultBranch(ctx context.Context, repo string, token string) (string, error) {
	repo = strings.TrimSpace(repo)
	if strings.Count(repo, "/") != 1 {
		return "", errors.New("repo must be owner/name")
	}

	u := url.URL{
		Scheme: "https",
		Host:   "api.github.com",
		Path:   "/repos/" + repo,
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "synapseide")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if strings.TrimSpace(token) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(token))
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out githubRepoInfo
	if err := json.Unmarshal(b, &out); err != nil {
		return "", err
	}
	if strings.TrimSpace(out.DefaultBranch) == "" {
		return "", errors.New("github: empty default_branch")
	}
	return out.DefaultBranch, nil
}

type CreatePullRequestParams struct {
	Title string
	Head  string
	Base  string
	Body  string
	Draft bool
}

type PullRequest struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
}

func CreatePullRequest(ctx context.Context, repo string, token string, params CreatePullRequestParams) (PullRequest, error) {
	repo = strings.TrimSpace(repo)
	token = strings.TrimSpace(token)
	if strings.Count(repo, "/") != 1 {
		return PullRequest{}, errors.New("repo must be owner/name")
	}
	if token == "" {
		return PullRequest{}, errors.New("token required")
	}
	if strings.TrimSpace(params.Title) == "" {
		return PullRequest{}, errors.New("title required")
	}
	if strings.TrimSpace(params.Head) == "" {
		return PullRequest{}, errors.New("head required")
	}
	if strings.TrimSpace(params.Base) == "" {
		return PullRequest{}, errors.New("base required")
	}

	u := url.URL{
		Scheme: "https",
		Host:   "api.github.com",
		Path:   "/repos/" + repo + "/pulls",
	}

	body, err := json.Marshal(map[string]any{
		"title": params.Title,
		"head":  params.Head,
		"base":  params.Base,
		"body":  params.Body,
		"draft": params.Draft,
	})
	if err != nil {
		return PullRequest{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return PullRequest{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "synapseide")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return PullRequest{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return PullRequest{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return PullRequest{}, fmt.Errorf("github http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out PullRequest
	if err := json.Unmarshal(b, &out); err != nil {
		return PullRequest{}, err
	}
	if strings.TrimSpace(out.HTMLURL) == "" {
		return PullRequest{}, errors.New("github: empty pr url")
	}
	return out, nil
}

type ForkRepo struct {
	FullName string `json:"full_name"`
	HTMLURL  string `json:"html_url"`
	CloneURL string `json:"clone_url"`
	SSHURL   string `json:"ssh_url"`
}

func CreateFork(ctx context.Context, repo string, token string) (ForkRepo, error) {
	repo = strings.TrimSpace(repo)
	token = strings.TrimSpace(token)
	if strings.Count(repo, "/") != 1 {
		return ForkRepo{}, errors.New("repo must be owner/name")
	}
	if token == "" {
		return ForkRepo{}, errors.New("token required")
	}

	u := url.URL{
		Scheme: "https",
		Host:   "api.github.com",
		Path:   "/repos/" + repo + "/forks",
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
	if err != nil {
		return ForkRepo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "synapseide")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return ForkRepo{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return ForkRepo{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ForkRepo{}, fmt.Errorf("github http %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var out ForkRepo
	if err := json.Unmarshal(b, &out); err != nil {
		return ForkRepo{}, err
	}
	if strings.TrimSpace(out.FullName) == "" {
		return ForkRepo{}, errors.New("github: empty fork full_name")
	}
	if strings.TrimSpace(out.CloneURL) == "" && strings.TrimSpace(out.SSHURL) == "" {
		return ForkRepo{}, errors.New("github: empty fork clone url")
	}
	return out, nil
}
