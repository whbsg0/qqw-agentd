package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
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
	mu         sync.Mutex
	path       string
	offsetPath string
	offset     int64
	wake       chan struct{}
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
		ok, status, postErr := postEventsJSON(ctx, target, deviceID, secret, batch, true)
		if !ok && (status == http.StatusBadRequest || status == http.StatusUnsupportedMediaType) {
			ok = true
			for i := range lines {
				ok1, err1 := postEventJSON(ctx, target, deviceID, secret, lines[i])
				if !ok1 {
					ok = false
					postErr = err1
					break
				}
				sent++
				offset += int64(rawLens[i])
				q.writeOffset(offset)
			}
			if !ok {
				if postErr == nil {
					postErr = errors.New("post failed")
				}
				return sent, postErr
			}
			continue
		}
		if !ok {
			if postErr == nil {
				postErr = errors.New("post failed")
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

func postEventJSON(ctx context.Context, target, deviceID, deviceSecret string, body []byte) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("X-Device-Id", deviceID)
	req.Header.Set("X-Device-Secret", deviceSecret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 1024))
	return resp.StatusCode == http.StatusOK, nil
}

func postEventsJSON(ctx context.Context, target, deviceID, deviceSecret string, body []byte, gzipBody bool) (ok bool, status int, err error) {
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	var reader io.Reader = bytes.NewReader(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
	if err != nil {
		return false, 0, err
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
		return false, 0, err
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(io.LimitReader(resp.Body, 1024))
	return resp.StatusCode == http.StatusOK, resp.StatusCode, nil
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
