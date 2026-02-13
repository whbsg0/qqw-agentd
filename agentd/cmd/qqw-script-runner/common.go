package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

type fridaMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

type eventPoster struct {
	url    string
	client *http.Client
}

func newEventPoster(url string) *eventPoster {
	return &eventPoster{
		url:    strings.TrimSpace(url),
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

func (p *eventPoster) post(body json.RawMessage) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = resp.Status
		}
		return errors.New(msg)
	}
	return nil
}

func handleFridaMessageJSONLine(poster *eventPoster, line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	if !strings.HasPrefix(line, "{") {
		if i := strings.IndexByte(line, '{'); i >= 0 {
			line = strings.TrimSpace(line[i:])
		}
	}
	var msg fridaMessage
	if err := json.Unmarshal([]byte(line), &msg); err != nil {
		return
	}
	if msg.Type != "send" || len(bytes.TrimSpace(msg.Payload)) == 0 {
		return
	}
	_ = poster.post(msg.Payload)
}

