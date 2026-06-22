package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type EventQueue struct {
	mu              sync.Mutex
	path            string
	offsetPath      string
	offset          int64
	lastEnqueueAtMs int64
	lastFlushAtMs   int64
	lastFlushErr    string
	wake            chan struct{}
}

type EventQueueSnapshot struct {
	OffsetBytes     int64
	FileSizeBytes   int64
	PendingBytes    int64
	LastEnqueueAtMs int64
	LastFlushAtMs   int64
	LastFlushErr    string
}

func NewEventQueue(dir string) *EventQueue {
	dir = strings.TrimSpace(dir)
	_ = os.MkdirAll(dir, 0o755)
	q := &EventQueue{
		path:       filepath.Join(dir, "events_queue.jsonl"),
		offsetPath: filepath.Join(dir, "events_queue.offset"),
		wake:       make(chan struct{}, 1),
	}
	q.offset = q.readOffset()
	return q
}

func (q *EventQueue) Enqueue(body []byte) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	f, err := os.OpenFile(q.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = f.Write(body)
	_, _ = f.Write([]byte("\n"))
	_ = f.Close()
	q.lastEnqueueAtMs = time.Now().UnixMilli()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

func (q *EventQueue) Run(ctx context.Context, deviceID string, getCfg func() Config) {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return
	}
	backoff := 250 * time.Millisecond
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := q.flushOnce(ctx, deviceID, getCfg)
		if err != nil {
			q.noteFlushResult(err)
		} else if n > 0 {
			q.noteFlushResult(nil)
		}
		if err == nil && n > 0 {
			backoff = 250 * time.Millisecond
			continue
		}
		if err != nil {
			backoff = minDuration(backoff*2, 10*time.Second)
		} else {
			backoff = minDuration(backoff, 2*time.Second)
		}
		select {
		case <-ctx.Done():
			return
		case <-q.wake:
		case <-time.After(backoff):
		}
	}
}

func (q *EventQueue) noteFlushResult(err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.lastFlushAtMs = time.Now().UnixMilli()
	if err != nil {
		q.lastFlushErr = strings.TrimSpace(err.Error())
		return
	}
	q.lastFlushErr = ""
}

func minDuration(a, b time.Duration) time.Duration {
	if a <= b {
		return a
	}
	return b
}

func (q *EventQueue) flushOnce(ctx context.Context, deviceID string, getCfg func() Config) (int, error) {
	cfg := getCfg()
	base := serverHTTPBase(cfg.ServerURL)
	if base == "" {
		return 0, errors.New("serverUrl invalid")
	}
	secret := strings.TrimSpace(cfg.DeviceSecret)
	if secret == "" {
		return 0, errors.New("deviceSecret missing")
	}
	target := base + "/api/device/" + url.PathEscape(deviceID) + "/events"

	q.mu.Lock()
	offset := q.offset
	q.mu.Unlock()

	f, err := os.Open(q.path)
	if err != nil {
		return 0, nil
	}
	defer f.Close()
	if offset > 0 {
		_, _ = f.Seek(offset, io.SeekStart)
	}
	r := bufio.NewReaderSize(f, 256*1024)
	sent := 0
	const maxBatchEvents = 50
	const maxBatchBytes = 256 * 1024
	var pendingLine []byte
	var pendingRawLen int
	for {
		if ctx.Err() != nil {
			return sent, ctx.Err()
		}
		lines := make([][]byte, 0, maxBatchEvents)
		rawLens := make([]int, 0, maxBatchEvents)
		sumRawLen := 0
		sumBody := 0
		for len(lines) < maxBatchEvents && sumBody < maxBatchBytes {
			var (
				line   []byte
				rawLen int
				err    error
			)
			if len(pendingLine) > 0 {
				line = pendingLine
				rawLen = pendingRawLen
				pendingLine = nil
				pendingRawLen = 0
			} else {
				var raw []byte
				raw, err = r.ReadBytes('\n')
				rawLen = len(raw)
				if rawLen == 0 && err != nil {
					break
				}
				line = bytes.TrimSpace(raw)
			}
			if len(line) == 0 {
				offset += int64(rawLen)
				q.writeOffset(offset)
				if err != nil {
					break
				}
				continue
			}
			if len(lines) > 0 && (sumBody+len(line)+1) > maxBatchBytes {
				pendingLine = line
				pendingRawLen = rawLen
				break
			}
			lines = append(lines, line)
			rawLens = append(rawLens, rawLen)
			sumRawLen += rawLen
			sumBody += len(line) + 1
			if err != nil {
				break
			}
		}
		if len(lines) == 0 {
			break
		}
		batch := buildJSONArray(lines)
		ok, status, respBody, postErr := postEventsJSON(ctx, target, deviceID, secret, batch, true)
		if !ok && (status == http.StatusBadRequest || status == http.StatusUnsupportedMediaType) {
			ok = true
			for i := range lines {
				ok1, status1, body1, err1 := postEventJSON(ctx, target, deviceID, secret, lines[i])
				if !ok1 {
					ok = false
					postErr = explainEventPostFailure("single", status1, body1, err1, lines[i], i+1, len(lines))
					break
				}
				sent++
				offset += int64(rawLens[i])
				q.writeOffset(offset)
			}
			if !ok {
				if postErr == nil {
					postErr = explainBatchPostFailure("single", status, respBody, nil, lines)
				}
				return sent, postErr
			}
			continue
		}
		if !ok {
			if postErr == nil {
				postErr = explainBatchPostFailure("batch", status, respBody, nil, lines)
			} else {
				postErr = explainBatchPostFailure("batch", status, respBody, postErr, lines)
			}
			return sent, postErr
		}
		sent += len(lines)
		offset += int64(sumRawLen)
		q.writeOffset(offset)
		if sent > 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	return sent, nil
}

// summarizeQueuedEvent 返回队列单条事件的最小摘要，便于定位是哪类事件拖死了整批上传。
// 参数：body 为单条 JSON 事件内容。
// 返回：包含 type/opId/jid 的紧凑字符串；若无法解析则返回截断后的原文预览。
func summarizeQueuedEvent(body []byte) string {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return "empty"
	}
	var env struct {
		Type  string `json:"type"`
		OpID  string `json:"op_id"`
		OpID2 string `json:"opId"`
		JID   string `json:"jid"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return "raw=" + clipString(string(body), 160)
	}
	opID := strings.TrimSpace(env.OpID)
	if opID == "" {
		opID = strings.TrimSpace(env.OpID2)
	}
	return strings.TrimSpace(fmt.Sprintf("type=%s opId=%s jid=%s", strings.TrimSpace(env.Type), opID, strings.TrimSpace(env.JID)))
}

// clipString 截断调试字符串，避免把超长响应体或原始事件整体塞进健康状态。
// 参数：s 为原始文本；maxLen 为最大保留长度。
// 返回：截断后的字符串，必要时追加省略号。
func clipString(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if maxLen <= 0 || len(s) <= maxLen {
		return s
	}
	return strings.TrimSpace(s[:maxLen]) + "..."
}

// explainBatchPostFailure 统一生成批量上传失败摘要，用于判断批量链路本身是否正确。
// 参数：mode 为上传模式；status/body/err 为 HTTP 结果；lines 为本批事件。
// 返回：包含状态码、响应体与首尾事件摘要的错误对象。
func explainBatchPostFailure(mode string, status int, body string, err error, lines [][]byte) error {
	if err != nil {
		return fmt.Errorf("%s post failed err=%v count=%d first={%s} last={%s}", strings.TrimSpace(mode), err, len(lines), summarizeBatchEdge(lines, true), summarizeBatchEdge(lines, false))
	}
	if status > 0 {
		return fmt.Errorf("%s post failed status=%d body=%s count=%d first={%s} last={%s}", strings.TrimSpace(mode), status, clipString(body, 240), len(lines), summarizeBatchEdge(lines, true), summarizeBatchEdge(lines, false))
	}
	return fmt.Errorf("%s post failed count=%d first={%s} last={%s}", strings.TrimSpace(mode), len(lines), summarizeBatchEdge(lines, true), summarizeBatchEdge(lines, false))
}

// explainEventPostFailure 统一生成逐条上传失败摘要，便于判断是否为特定事件毒化整批队列。
// 参数：mode 为上传模式；status/body/err 为 HTTP 结果；line 为当前事件；index/total 为序号。
// 返回：包含状态码、响应体和当前事件摘要的错误对象。
func explainEventPostFailure(mode string, status int, body string, err error, line []byte, index, total int) error {
	eventSummary := summarizeQueuedEvent(line)
	if err != nil {
		return fmt.Errorf("%s post failed err=%v event=%d/%d {%s}", strings.TrimSpace(mode), err, index, total, eventSummary)
	}
	if status > 0 {
		return fmt.Errorf("%s post failed status=%d body=%s event=%d/%d {%s}", strings.TrimSpace(mode), status, clipString(body, 240), index, total, eventSummary)
	}
	return fmt.Errorf("%s post failed event=%d/%d {%s}", strings.TrimSpace(mode), index, total, eventSummary)
}

// summarizeBatchEdge 返回批量首条或末条事件的摘要，帮助判断是哪类事件与头像结果一起被卡住。
// 参数：lines 为本批事件；first 为 true 时取首条，否则取末条。
// 返回：单条事件摘要；若批次为空则返回 empty-batch。
func summarizeBatchEdge(lines [][]byte, first bool) string {
	if len(lines) == 0 {
		return "empty-batch"
	}
	if first {
		return summarizeQueuedEvent(lines[0])
	}
	return summarizeQueuedEvent(lines[len(lines)-1])
}

func (q *EventQueue) readOffset() int64 {
	b, err := os.ReadFile(q.offsetPath)
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0
	}
	n, _ := strconv.ParseInt(s, 10, 64)
	if n < 0 {
		n = 0
	}
	return n
}

func (q *EventQueue) writeOffset(n int64) {
	q.mu.Lock()
	if n < 0 {
		n = 0
	}
	q.offset = n
	q.mu.Unlock()
	_ = os.WriteFile(q.offsetPath, []byte(strconv.FormatInt(n, 10)+"\n"), 0o644)
}

func (q *EventQueue) Snapshot() EventQueueSnapshot {
	q.mu.Lock()
	offset := q.offset
	lastEnqueueAtMs := q.lastEnqueueAtMs
	lastFlushAtMs := q.lastFlushAtMs
	lastFlushErr := strings.TrimSpace(q.lastFlushErr)
	path := q.path
	q.mu.Unlock()
	fileSize := int64(0)
	if st, err := os.Stat(path); err == nil && st != nil {
		fileSize = st.Size()
	}
	pending := fileSize - offset
	if pending < 0 {
		pending = 0
	}
	return EventQueueSnapshot{
		OffsetBytes:     offset,
		FileSizeBytes:   fileSize,
		PendingBytes:    pending,
		LastEnqueueAtMs: lastEnqueueAtMs,
		LastFlushAtMs:   lastFlushAtMs,
		LastFlushErr:    lastFlushErr,
	}
}

// postEventJSON 以单条模式上传一条设备事件，并返回状态码与响应体摘要。
// 参数：ctx 为请求上下文；target 为目标 URL；deviceID/deviceSecret 为设备鉴权；body 为单条 JSON。
// 返回：ok 表示是否返回 200；status 为 HTTP 状态码；respBody 为响应体摘要；err 为网络层错误。
func postEventJSON(ctx context.Context, target, deviceID, deviceSecret string, body []byte) (ok bool, status int, respBody string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return false, 0, "", err
	}
	req.Header.Set("X-Device-Id", deviceID)
	req.Header.Set("X-Device-Secret", deviceSecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()
	bs, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return resp.StatusCode == http.StatusOK, resp.StatusCode, clipString(string(bs), 240), nil
}

// postEventsJSON 以批量模式上传设备事件数组，并返回状态码与响应体摘要。
// 参数：ctx 为请求上下文；target 为目标 URL；deviceID/deviceSecret 为设备鉴权；body 为 JSON 数组；gzipBody 表示是否 gzip 压缩。
// 返回：ok 表示是否返回 200；status 为 HTTP 状态码；respBody 为响应体摘要；err 为网络层错误。
func postEventsJSON(ctx context.Context, target, deviceID, deviceSecret string, body []byte, gzipBody bool) (ok bool, status int, respBody string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var reader io.Reader = bytes.NewReader(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return false, 0, "", err
	}
	req.Header.Set("X-Device-Id", deviceID)
	req.Header.Set("X-Device-Secret", deviceSecret)
	req.Header.Set("Content-Type", "application/json")
	if gzipBody {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(body)
		_ = zw.Close()
		reader = &buf
		req.Header.Set("Content-Encoding", "gzip")
	}
	req.Body = io.NopCloser(reader)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, 0, "", err
	}
	defer resp.Body.Close()
	bs, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	return resp.StatusCode == http.StatusOK, resp.StatusCode, clipString(string(bs), 240), nil
}

func buildJSONArray(lines [][]byte) []byte {
	if len(lines) == 0 {
		return []byte("[]")
	}
	var buf bytes.Buffer
	buf.Grow(2 + len(lines)*64)
	_ = buf.WriteByte('[')
	for i := range lines {
		if i > 0 {
			_ = buf.WriteByte(',')
		}
		_, _ = buf.Write(bytes.TrimSpace(lines[i]))
	}
	_ = buf.WriteByte(']')
	return buf.Bytes()
}
