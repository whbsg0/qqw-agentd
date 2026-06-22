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
	InspectReport   string
}

type EventQueueInspectIssue struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	Escape string `json:"escape,omitempty"`
	Detail string `json:"detail,omitempty"`
}

type EventQueueInspectEntry struct {
	Index         int                      `json:"index"`
	OffsetBytes   int64                    `json:"offsetBytes"`
	RawLen        int                      `json:"rawLen"`
	Summary       string                   `json:"summary"`
	RawPreview    string                   `json:"rawPreview"`
	IssueCount    int                      `json:"issueCount"`
	InspectIssues []EventQueueInspectIssue `json:"inspectIssues,omitempty"`
}

type EventQueueInspectReport struct {
	QueuePath        string                   `json:"queuePath"`
	OffsetPath       string                   `json:"offsetPath"`
	StartOffsetBytes int64                    `json:"startOffsetBytes"`
	Limit            int                      `json:"limit"`
	EntryCount       int                      `json:"entryCount"`
	BadEntryCount    int                      `json:"badEntryCount"`
	Entries          []EventQueueInspectEntry `json:"entries"`
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

// CurrentOffset 返回当前队列读取指针，供只读检查口复用。
// 参数：无。
// 返回：当前 offset 字节位置。
func (q *EventQueue) CurrentOffset() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.offset
}

// InspectBatchAtOffset 只读展开指定 offset 开始的一批队列事件，并定位非法 Unicode 转义。
// 参数：offset 为起始字节位置；limit 为最多读取的非空事件数。
// 返回：检查报告；若文件读取失败则返回错误。
func (q *EventQueue) InspectBatchAtOffset(offset int64, limit int) (EventQueueInspectReport, error) {
	if limit <= 0 {
		limit = 50
	}
	report := EventQueueInspectReport{
		QueuePath:        q.path,
		OffsetPath:       q.offsetPath,
		StartOffsetBytes: maxInt64(offset, 0),
		Limit:            limit,
		Entries:          make([]EventQueueInspectEntry, 0, limit),
	}
	f, err := os.Open(q.path)
	if err != nil {
		return report, err
	}
	defer f.Close()
	if report.StartOffsetBytes > 0 {
		if _, err := f.Seek(report.StartOffsetBytes, io.SeekStart); err != nil {
			return report, err
		}
	}
	r := bufio.NewReaderSize(f, 256*1024)
	curOffset := report.StartOffsetBytes
	for len(report.Entries) < limit {
		raw, err := r.ReadBytes('\n')
		rawLen := len(raw)
		if rawLen == 0 && err != nil {
			break
		}
		line := bytes.TrimSpace(raw)
		lineOffset := curOffset
		curOffset += int64(rawLen)
		if len(line) == 0 {
			if err != nil {
				break
			}
			continue
		}
		issues, inspectErr := inspectJSONUnicodeIssues(line)
		entry := EventQueueInspectEntry{
			Index:         len(report.Entries) + 1,
			OffsetBytes:   lineOffset,
			RawLen:        rawLen,
			Summary:       summarizeQueuedEvent(line),
			RawPreview:    clipString(string(line), 240),
			IssueCount:    len(issues),
			InspectIssues: issues,
		}
		if inspectErr != nil {
			entry.IssueCount++
			entry.InspectIssues = append(entry.InspectIssues, EventQueueInspectIssue{
				Path:   "$",
				Kind:   "inspect_error",
				Detail: strings.TrimSpace(inspectErr.Error()),
			})
		}
		if entry.IssueCount > 0 {
			report.BadEntryCount++
		}
		report.Entries = append(report.Entries, entry)
		if err != nil {
			break
		}
	}
	report.EntryCount = len(report.Entries)
	return report, nil
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

// maxInt64 返回两个 int64 中较大的一个。
// 参数：a、b 为待比较值。
// 返回：较大值。
func maxInt64(a, b int64) int64 {
	if a >= b {
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

// inspectJSONUnicodeIssues 递归扫描 JSON 文本中的字符串值，定位 PostgreSQL jsonb 不接受的代理项转义。
// 参数：body 为单条 JSON 事件文本。
// 返回：命中的问题列表；若 JSON 词法结构异常则返回错误。
func inspectJSONUnicodeIssues(body []byte) ([]EventQueueInspectIssue, error) {
	issues := make([]EventQueueInspectIssue, 0)
	pos, err := inspectJSONValue(body, 0, "$", &issues)
	if err != nil {
		return issues, err
	}
	pos = skipJSONSpaces(body, pos)
	if pos != len(body) {
		return issues, fmt.Errorf("unexpected trailing bytes at %d", pos)
	}
	return issues, nil
}

// inspectJSONValue 递归扫描单个 JSON 值。
// 参数：body 为完整 JSON 文本；pos 为当前起点；path 为当前 JSON 路径；issues 为收集目标。
// 返回：消费后的下一个位置；若结构异常则返回错误。
func inspectJSONValue(body []byte, pos int, path string, issues *[]EventQueueInspectIssue) (int, error) {
	pos = skipJSONSpaces(body, pos)
	if pos >= len(body) {
		return pos, io.ErrUnexpectedEOF
	}
	switch body[pos] {
	case '{':
		return inspectJSONObject(body, pos, path, issues)
	case '[':
		return inspectJSONArray(body, pos, path, issues)
	case '"':
		raw, next, err := scanJSONStringRaw(body, pos)
		if err != nil {
			return pos, err
		}
		*issues = append(*issues, inspectJSONStringUnicode(path, raw)...)
		return next, nil
	default:
		return scanJSONPrimitive(body, pos)
	}
}

// inspectJSONObject 扫描 JSON 对象中的每个键值对。
// 参数：body 为完整 JSON 文本；pos 指向 `{`；path 为当前路径；issues 为收集目标。
// 返回：消费后的下一个位置；若结构异常则返回错误。
func inspectJSONObject(body []byte, pos int, path string, issues *[]EventQueueInspectIssue) (int, error) {
	pos++
	pos = skipJSONSpaces(body, pos)
	if pos < len(body) && body[pos] == '}' {
		return pos + 1, nil
	}
	for {
		rawKey, next, err := scanJSONStringRaw(body, pos)
		if err != nil {
			return pos, err
		}
		key := decodeJSONKeyForPath(rawKey)
		pos = skipJSONSpaces(body, next)
		if pos >= len(body) || body[pos] != ':' {
			return pos, fmt.Errorf("object missing colon at %d", pos)
		}
		pos++
		childPath := joinJSONPath(path, key)
		pos, err = inspectJSONValue(body, pos, childPath, issues)
		if err != nil {
			return pos, err
		}
		pos = skipJSONSpaces(body, pos)
		if pos >= len(body) {
			return pos, io.ErrUnexpectedEOF
		}
		if body[pos] == '}' {
			return pos + 1, nil
		}
		if body[pos] != ',' {
			return pos, fmt.Errorf("object missing comma at %d", pos)
		}
		pos++
		pos = skipJSONSpaces(body, pos)
	}
}

// inspectJSONArray 扫描 JSON 数组中的每个元素。
// 参数：body 为完整 JSON 文本；pos 指向 `[`；path 为当前路径；issues 为收集目标。
// 返回：消费后的下一个位置；若结构异常则返回错误。
func inspectJSONArray(body []byte, pos int, path string, issues *[]EventQueueInspectIssue) (int, error) {
	pos++
	idx := 0
	pos = skipJSONSpaces(body, pos)
	if pos < len(body) && body[pos] == ']' {
		return pos + 1, nil
	}
	for {
		childPath := fmt.Sprintf("%s[%d]", path, idx)
		next, err := inspectJSONValue(body, pos, childPath, issues)
		if err != nil {
			return pos, err
		}
		pos = skipJSONSpaces(body, next)
		if pos >= len(body) {
			return pos, io.ErrUnexpectedEOF
		}
		if body[pos] == ']' {
			return pos + 1, nil
		}
		if body[pos] != ',' {
			return pos, fmt.Errorf("array missing comma at %d", pos)
		}
		pos++
		pos = skipJSONSpaces(body, pos)
		idx++
	}
}

// scanJSONStringRaw 词法扫描一个 JSON 字符串，返回不含首尾引号的原始字节片段。
// 参数：body 为完整 JSON 文本；pos 指向 `"`。
// 返回：原始字符串内容、结束后的下一个位置，以及结构错误。
func scanJSONStringRaw(body []byte, pos int) ([]byte, int, error) {
	if pos >= len(body) || body[pos] != '"' {
		return nil, pos, fmt.Errorf("string expected at %d", pos)
	}
	start := pos + 1
	i := start
	for i < len(body) {
		switch body[i] {
		case '\\':
			i += 2
			continue
		case '"':
			return body[start:i], i + 1, nil
		default:
			i++
		}
	}
	return nil, pos, io.ErrUnexpectedEOF
}

// inspectJSONStringUnicode 扫描单个 JSON 字符串中的 Unicode escape，定位孤立高低代理项。
// 参数：path 为当前 JSON 路径；raw 为不含首尾引号的原始字符串片段。
// 返回：命中的问题列表。
func inspectJSONStringUnicode(path string, raw []byte) []EventQueueInspectIssue {
	issues := make([]EventQueueInspectIssue, 0)
	for i := 0; i < len(raw); {
		if raw[i] != '\\' {
			i++
			continue
		}
		if i+1 >= len(raw) {
			issues = append(issues, EventQueueInspectIssue{Path: path, Kind: "dangling_escape", Detail: "string ends with backslash"})
			break
		}
		if raw[i+1] != 'u' {
			i += 2
			continue
		}
		if i+6 > len(raw) {
			issues = append(issues, EventQueueInspectIssue{Path: path, Kind: "short_unicode_escape", Escape: string(raw[i:])})
			break
		}
		cp, ok := parseHexRune4(raw[i+2 : i+6])
		esc := string(raw[i : i+6])
		if !ok {
			issues = append(issues, EventQueueInspectIssue{Path: path, Kind: "bad_unicode_escape", Escape: esc})
			i += 6
			continue
		}
		if cp >= 0xD800 && cp <= 0xDBFF {
			if i+12 <= len(raw) && raw[i+6] == '\\' && raw[i+7] == 'u' {
				low, lowOK := parseHexRune4(raw[i+8 : i+12])
				if lowOK && low >= 0xDC00 && low <= 0xDFFF {
					i += 12
					continue
				}
			}
			issues = append(issues, EventQueueInspectIssue{
				Path:   path,
				Kind:   "high_surrogate_without_low",
				Escape: esc,
				Detail: "high surrogate not followed by low surrogate pair",
			})
			i += 6
			continue
		}
		if cp >= 0xDC00 && cp <= 0xDFFF {
			issues = append(issues, EventQueueInspectIssue{
				Path:   path,
				Kind:   "low_surrogate_without_high",
				Escape: esc,
				Detail: "low surrogate appears without preceding high surrogate",
			})
			i += 6
			continue
		}
		i += 6
	}
	return issues
}

// parseHexRune4 解析四位十六进制 Unicode escape。
// 参数：hex4 为四位十六进制字符。
// 返回：解析后的码点以及是否成功。
func parseHexRune4(hex4 []byte) (int, bool) {
	if len(hex4) != 4 {
		return 0, false
	}
	n, err := strconv.ParseUint(string(hex4), 16, 16)
	if err != nil {
		return 0, false
	}
	return int(n), true
}

// decodeJSONKeyForPath 将 JSON key 的原始字符串解码成便于展示的路径段。
// 参数：raw 为不含首尾引号的 JSON 字符串片段。
// 返回：解码后的 key；若解码失败则返回截断预览。
func decodeJSONKeyForPath(raw []byte) string {
	s, err := strconv.Unquote(`"` + string(raw) + `"`)
	if err != nil {
		return clipString(string(raw), 40)
	}
	return s
}

// joinJSONPath 拼接对象子字段路径。
// 参数：base 为父路径；key 为字段名。
// 返回：人类可读的 JSON 路径。
func joinJSONPath(base, key string) string {
	if base == "" {
		base = "$"
	}
	if key == "" {
		return base + `[""]`
	}
	if isSimpleJSONKey(key) {
		return base + "." + key
	}
	return base + `["` + strings.ReplaceAll(key, `"`, `\"`) + `"]`
}

// isSimpleJSONKey 判断字段名是否适合直接以 `.field` 形式展示。
// 参数：key 为字段名。
// 返回：true 表示可直接拼接；false 表示应使用 bracket 形式。
func isSimpleJSONKey(key string) bool {
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		return false
	}
	return true
}

// skipJSONSpaces 跳过 JSON 中的空白字符。
// 参数：body 为完整 JSON 文本；pos 为起点。
// 返回：跳过空白后的新位置。
func skipJSONSpaces(body []byte, pos int) int {
	for pos < len(body) {
		switch body[pos] {
		case ' ', '\t', '\r', '\n':
			pos++
		default:
			return pos
		}
	}
	return pos
}

// scanJSONPrimitive 扫描 number/true/false/null 等非容器、非字符串值。
// 参数：body 为完整 JSON 文本；pos 为起点。
// 返回：消费后的下一个位置；若未读到任何内容则返回错误。
func scanJSONPrimitive(body []byte, pos int) (int, error) {
	start := pos
	for pos < len(body) {
		switch body[pos] {
		case ' ', '\t', '\r', '\n', ',', '}', ']':
			if pos == start {
				return pos, fmt.Errorf("invalid primitive at %d", pos)
			}
			return pos, nil
		default:
			pos++
		}
	}
	if pos == start {
		return pos, io.ErrUnexpectedEOF
	}
	return pos, nil
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
	inspectReport := ""
	if pending > 0 {
		inspectReport = q.BuildInspectReportAtOffset(offset, 50)
	}
	return EventQueueSnapshot{
		OffsetBytes:     offset,
		FileSizeBytes:   fileSize,
		PendingBytes:    pending,
		LastEnqueueAtMs: lastEnqueueAtMs,
		LastFlushAtMs:   lastFlushAtMs,
		LastFlushErr:    lastFlushErr,
		InspectReport:   inspectReport,
	}
}

// BuildInspectReportAtOffset 生成指定 offset 队头批次的紧凑检查报告，供状态链透传导出。
// 参数：offset 为起始字节位置；limit 为最多导出的事件条数。
// 返回：紧凑 JSON 字符串；若读取失败则返回错误摘要。
func (q *EventQueue) BuildInspectReportAtOffset(offset int64, limit int) string {
	report, err := q.InspectBatchAtOffset(offset, limit)
	if err != nil {
		return strings.TrimSpace(fmt.Sprintf(`{"ok":false,"offsetBytes":%d,"error":%q}`, maxInt64(offset, 0), clipString(err.Error(), 240)))
	}
	type compactEntry struct {
		Index         int                      `json:"index"`
		OffsetBytes   int64                    `json:"offsetBytes"`
		RawLen        int                      `json:"rawLen"`
		Summary       string                   `json:"summary"`
		RawPreview    string                   `json:"rawPreview"`
		IssueCount    int                      `json:"issueCount"`
		InspectIssues []EventQueueInspectIssue `json:"inspectIssues,omitempty"`
	}
	type compactReport struct {
		OK               bool           `json:"ok"`
		StartOffsetBytes int64          `json:"startOffsetBytes"`
		EntryCount       int            `json:"entryCount"`
		BadEntryCount    int            `json:"badEntryCount"`
		Entries          []compactEntry `json:"entries"`
	}
	out := compactReport{
		OK:               true,
		StartOffsetBytes: report.StartOffsetBytes,
		EntryCount:       report.EntryCount,
		BadEntryCount:    report.BadEntryCount,
		Entries:          make([]compactEntry, 0, len(report.Entries)),
	}
	for _, entry := range report.Entries {
		out.Entries = append(out.Entries, compactEntry{
			Index:         entry.Index,
			OffsetBytes:   entry.OffsetBytes,
			RawLen:        entry.RawLen,
			Summary:       entry.Summary,
			RawPreview:    entry.RawPreview,
			IssueCount:    entry.IssueCount,
			InspectIssues: entry.InspectIssues,
		})
	}
	bs, err := json.Marshal(out)
	if err != nil {
		return strings.TrimSpace(fmt.Sprintf(`{"ok":false,"offsetBytes":%d,"error":%q}`, report.StartOffsetBytes, clipString(err.Error(), 240)))
	}
	return clipString(string(bs), 60000)
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
