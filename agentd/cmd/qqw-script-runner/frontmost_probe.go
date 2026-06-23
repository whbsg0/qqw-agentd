package main

import (
	"fmt"
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
		}
		time.Sleep(time.Duration(intervalMs) * time.Millisecond)
	}
}
