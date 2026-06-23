package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	runnerModeScript         = "runner"
	runnerModeFrontmostProbe = "frontmost-probe"
)

// frontmostProbeSnapshot 表示 frontmost-probe 最近一次采样的结构化结果。
// 字段用途：通过 `/rpc/frontmost/status` 暴露给 agentd，供 guard 映射为前台/后台/查询失败。
type frontmostProbeSnapshot struct {
	Ok           bool   `json:"ok"`
	Source       string `json:"source"`
	SampleAtMs   int64  `json:"sampleAtMs"`
	BundleID     string `json:"bundleId"`
	DisplayName  string `json:"displayName"`
	Visibility   string `json:"visibility"`
	TaskState    string `json:"taskState"`
	Retryable    bool   `json:"retryable"`
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

var (
	serviceMode = runnerModeScript

	frontmostProbeStateMu sync.RWMutex
	frontmostProbeState   frontmostProbeSnapshot
)

const debugFrontmostProbeServerURL = "http://192.168.1.4:7777/event"
const debugFrontmostProbeSessionID = "guard-fuse-errors"
const debugFrontmostProbeLocalLogPath = "/var/mobile/Library/QQwAgent/trae-debug-log-guard-fuse-errors.ndjson"
const debugFrontmostProbeAFCLocalLogPath = "/var/mobile/Media/QQwAgent/trae-debug-log-guard-fuse-errors.ndjson"

// appendDebugFrontmostProbeLogFile 将调试事件追加写入指定设备本地 ndjson。
// 参数：filePath 为目标日志路径；body 为已编码的单条 JSON 调试事件。
// 返回：写入失败时返回错误。
func appendDebugFrontmostProbeLogFile(filePath string, body []byte) error {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return err
	}
	if _, err := f.Write([]byte("\n")); err != nil {
		return err
	}
	return nil
}

// appendDebugFrontmostProbeLocalLog 同时写入设备私有路径与 AFC 可读取路径，便于本机终端直接拉取。
// 参数：body 为已编码的单条 JSON 调试事件。
// 返回：至少一个路径写入成功则返回 nil；全部失败时返回最后一个错误。
func appendDebugFrontmostProbeLocalLog(body []byte) error {
	var lastErr error
	wrote := false
	for _, filePath := range []string{debugFrontmostProbeLocalLogPath, debugFrontmostProbeAFCLocalLogPath} {
		if err := appendDebugFrontmostProbeLogFile(filePath, body); err != nil {
			lastErr = err
			continue
		}
		wrote = true
	}
	if wrote {
		return nil
	}
	return lastErr
}

// #region debug-point H1-H2:frontmost-probe-debug-report
// debugFrontmostProbeReport 将 frontmost-probe 调试事件上报到本轮调试服务器。
// 参数：runID 为运行阶段；hypothesisID 为假设编号；location 为调用位置；msg 为摘要；data 为结构化上下文。
// 返回：无。
func debugFrontmostProbeReport(runID string, hypothesisID string, location string, msg string, data map[string]any) {
	go func() {
		body, err := json.Marshal(map[string]any{
			"sessionId":    debugFrontmostProbeSessionID,
			"runId":        strings.TrimSpace(runID),
			"hypothesisId": strings.TrimSpace(hypothesisID),
			"location":     strings.TrimSpace(location),
			"msg":          "[DEBUG] " + strings.TrimSpace(msg),
			"data":         data,
			"ts":           time.Now().UnixMilli(),
		})
		if err != nil {
			return
		}
		_ = appendDebugFrontmostProbeLocalLog(body)
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, debugFrontmostProbeServerURL, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}

// #endregion

// normalizeRunnerMode 归一化 runner 运行模式。
// 参数：mode 为命令行传入模式。
// 返回：支持的模式字符串；未知值回退为 `runner`。
func normalizeRunnerMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", runnerModeScript:
		return runnerModeScript
	case runnerModeFrontmostProbe:
		return runnerModeFrontmostProbe
	default:
		return runnerModeScript
	}
}

// setFrontmostProbeStatus 原子更新 frontmost-probe 最近一次采样结果。
// 参数：snapshot 为新的采样结果。
// 返回：无。
func setFrontmostProbeStatus(snapshot frontmostProbeSnapshot) {
	frontmostProbeStateMu.Lock()
	frontmostProbeState = snapshot
	frontmostProbeStateMu.Unlock()
}

// getFrontmostProbeStatus 读取 frontmost-probe 最近一次采样结果。
// 参数：无。
// 返回：最近一次 frontmost 采样结果副本。
func getFrontmostProbeStatus() frontmostProbeSnapshot {
	frontmostProbeStateMu.RLock()
	defer frontmostProbeStateMu.RUnlock()
	return frontmostProbeState
}

// frontmostProbeReady 判断 frontmost-probe 是否至少完成过一次采样。
// 参数：无。
// 返回：有有效采样时间时返回 true。
func frontmostProbeReady() bool {
	return getFrontmostProbeStatus().SampleAtMs > 0
}

// runFrontmostProbeService 以独立模式循环执行前台探测并把结果缓存到本地 RPC 状态。
// 参数：fridaHost 为 frida 远端主机；fridaPort 为 frida 端口；intervalMs 为采样周期；timeoutMs 为单次查询超时。
// 返回：正常情况下不会返回；若循环意外退出则返回错误。
func runFrontmostProbeService(fridaHost string, fridaPort int, intervalMs int, timeoutMs int) error {
	if intervalMs <= 0 {
		intervalMs = 3000
	}
	if timeoutMs <= 0 {
		timeoutMs = 3000
	}
	setFrontmostProbeStatus(frontmostProbeSnapshot{
		Ok:           false,
		Source:       "springboard.runningApplications",
		SampleAtMs:   0,
		Retryable:    true,
		ErrorCode:    "not_ready",
		ErrorMessage: "frontmost probe not sampled yet",
	})
	setRunnerLastHealthErr("not_ready frontmost probe not sampled yet")
	debugFrontmostProbeReport("pre-fix", "H1", "frontmost_probe.go:runFrontmostProbeService", "frontmost probe service started", map[string]any{
		"fridaHost":       strings.TrimSpace(fridaHost),
		"fridaPort":       fridaPort,
		"probeIntervalMs": intervalMs,
		"probeTimeoutMs":  timeoutMs,
	})
	for {
		snapshot := queryFrontmostProbeOnce(fridaHost, fridaPort, timeoutMs)
		if snapshot.SampleAtMs <= 0 {
			snapshot.SampleAtMs = time.Now().UnixMilli()
		}
		setFrontmostProbeStatus(snapshot)
		if snapshot.Ok {
			setRunnerLastHealthErr("")
		} else {
			setRunnerLastHealthErr(strings.TrimSpace(fmt.Sprintf("%s %s", snapshot.ErrorCode, snapshot.ErrorMessage)))
			debugFrontmostProbeReport("pre-fix", "H2", "frontmost_probe.go:runFrontmostProbeService", "frontmost probe snapshot not ok", map[string]any{
				"source":       strings.TrimSpace(snapshot.Source),
				"sampleAtMs":   snapshot.SampleAtMs,
				"retryable":    snapshot.Retryable,
				"errorCode":    strings.TrimSpace(snapshot.ErrorCode),
				"errorMessage": strings.TrimSpace(snapshot.ErrorMessage),
				"bundleId":     strings.TrimSpace(snapshot.BundleID),
				"displayName":  strings.TrimSpace(snapshot.DisplayName),
				"visibility":   strings.TrimSpace(snapshot.Visibility),
				"taskState":    strings.TrimSpace(snapshot.TaskState),
			})
		}
		time.Sleep(time.Duration(intervalMs) * time.Millisecond)
	}
}
