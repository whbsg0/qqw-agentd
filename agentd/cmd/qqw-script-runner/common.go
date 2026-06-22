package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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

// summarizeFridaPayload 提取 Frida send payload 中的最小诊断字段，便于回传失败时快速定位是哪条正式链路卡住。
// 参数：body 为脚本 send(...) 回来的 JSON payload。
// 返回：eventType 为事件类型；opID 为操作 ID；jid 为目标 JID；缺失时返回空字符串。
func summarizeFridaPayload(body json.RawMessage) (eventType string, opID string, jid string) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return "", "", ""
	}
	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", "", ""
	}
	eventType = strings.TrimSpace(valueOrString(payload["type"]))
	opID = strings.TrimSpace(valueOrString(payload["opId"]))
	if opID == "" {
		opID = strings.TrimSpace(valueOrString(payload["op_id"]))
	}
	jid = strings.TrimSpace(valueOrString(payload["jid"]))
	return eventType, opID, jid
}

// valueOrString 将任意 JSON 字段安全转成字符串，供最小诊断日志使用。
// 参数：v 为待转换的字段值。
// 返回：字符串形式的字段值；无法转换时返回空字符串。
func valueOrString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		return fmt.Sprintf("%v", x)
	case bool:
		if x {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

// handleFridaMessageJSONLine 解析 Frida 输出的单行 JSON，并把脚本 send(...) 的 payload 转发到本地事件入口。
// 参数：poster 为本地事件上报器；line 为 Frida 输出的一行文本。
// 返回：无；解析失败或非 send 消息时直接忽略。
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
	if err := poster.post(msg.Payload); err != nil {
		eventType, opID, jid := summarizeFridaPayload(msg.Payload)
		summary := strings.TrimSpace(fmt.Sprintf("runner_event_post_failed type=%s opId=%s jid=%s err=%v", eventType, opID, jid, err))
		setRunnerLastHealthErr(summary)
		log.Printf("%s", summary)
		return
	}
	setRunnerLastHealthErr("")
}
