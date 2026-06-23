package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const guardScriptPongIntervalMs = 15_000

var guardScriptBuildIDPattern = regexp.MustCompile(`\bSCRIPT_BUILD_ID\s*=\s*"([^"]+)"`)

// processProbeResult 表示 WhatsApp 进程探测的原始采样结果。
// 字段用途：供 guard supervisor 派生“进程存在 / 探测失败 / 缺失”真值。
type processProbeResult struct {
	Running    bool
	Err        string
	SampleAtMs int64
	Epoch      int64
}

// frontmostProbeResult 表示 WhatsApp 前台探测的原始采样结果。
// 字段用途：供 guard supervisor 派生前台、查询失败与 stale 状态。
type frontmostProbeResult struct {
	Running    bool
	Err        string
	SampleAtMs int64
	Fresh      bool
	Epoch      int64
}

// runnerProbeResult 表示 runner 与脚本健康面的原始采样结果。
// 字段用途：供 guard supervisor 派生 runner/script 健康、版本一致性与 freshness。
type runnerProbeResult struct {
	RunnerProcessAlive       bool
	RunnerPid                int64
	RunnerRPCOK              bool
	ScriptReady              bool
	ScriptBuild              string
	ScriptSha256             string
	StartedAtMs              int64
	LastHealthErr            string
	LastHealthErrAtMs        int64
	SampleAtMs               int64
	InstalledScriptPath      string
	InstalledScriptUpdatedAt int64
	InstalledScriptBuild     string
	InstalledScriptSha256    string
	ScriptLastEventTsMs      int64
	ScriptLastPongTsMs       int64
	ScriptEventFresh         bool
	ScriptPongFresh          bool
	ScriptBuildMatch         bool
	ScriptSha256Match        bool
	Epoch                    int64
}

// installedScriptInfo 表示 agentd 本地安装脚本的版本信息。
// 字段用途：与 runner 实际加载脚本做 build/sha256 对齐。
type installedScriptInfo struct {
	Path        string
	UpdatedAtMs int64
	Build       string
	Sha256      string
}

// guardProbeSnapshot 表示 guard 当前持有的三类 probe 快照。
// 字段用途：供 supervisor 原子读取，避免自行触发阻塞探测。
type guardProbeSnapshot struct {
	Process   processProbeResult
	Frontmost frontmostProbeResult
	Runner    runnerProbeResult
}

// startGuardWorkers 启动值守所需的 probe 与 recovery worker。
// 参数：ctx 为 worker 生命周期上下文。
// 返回：无。
func (a *Agent) startGuardWorkers(ctx context.Context) {
	a.guardWorkersOnce.Do(func() {
		go a.runProcessProbeWorker(ctx)
		go a.runRunnerProbeWorker(ctx)
		if guardFrontmostQueryEnabled() {
			go a.runFrontmostProbeWorker(ctx)
		}
		go a.runGuardRecoveryWorker(ctx)
	})
}

// nextGuardProbeEpoch 递增并返回新的 probe epoch。
// 参数：无。
// 返回：新的 probe epoch。
func (a *Agent) nextGuardProbeEpoch() int64 {
	return a.guardProbeEpoch.Add(1)
}

// currentGuardProbeEpoch 读取当前 probe epoch。
// 参数：无。
// 返回：当前 probe epoch。
func (a *Agent) currentGuardProbeEpoch() int64 {
	return a.guardProbeEpoch.Load()
}

// currentGuardRecoveryEpoch 读取当前 recovery epoch。
// 参数：无。
// 返回：当前 recovery epoch。
func (a *Agent) currentGuardRecoveryEpoch() int64 {
	return a.guardRecoveryEpoch.Load()
}

// bumpGuardProbeEpoch 递增 probe epoch 并唤醒 supervisor。
// 参数：reason 为触发 epoch 变更的原因。
// 返回：新的 probe epoch。
func (a *Agent) bumpGuardProbeEpoch(reason string) int64 {
	next := a.nextGuardProbeEpoch()
	debugGuardReport("guard-refactor", "P0", "whatsapp_guard_probes.go:bumpGuardProbeEpoch", "guard probe epoch bumped", map[string]any{
		"epoch":  next,
		"reason": strings.TrimSpace(reason),
	})
	a.wakeGuardLoop()
	return next
}

// setGuardProcessProbeResult 在 epoch 未过期时写入进程 probe 结果。
// 参数：result 为本轮进程 probe 结果。
// 返回：无。
func (a *Agent) setGuardProcessProbeResult(result processProbeResult) {
	if result.Epoch < a.currentGuardProbeEpoch() {
		return
	}
	a.guardProbeMu.Lock()
	a.guardProcessProbe = result
	a.guardProbeMu.Unlock()
	a.wakeGuardLoop()
}

// setGuardFrontmostProbeResult 在 epoch 未过期时写入前台 probe 结果。
// 参数：result 为本轮前台 probe 结果。
// 返回：无。
func (a *Agent) setGuardFrontmostProbeResult(result frontmostProbeResult) {
	if result.Epoch < a.currentGuardProbeEpoch() {
		return
	}
	a.guardProbeMu.Lock()
	a.guardFrontmostProbe = result
	a.guardProbeMu.Unlock()
	a.wakeGuardLoop()
}

// setGuardRunnerProbeResult 在 epoch 未过期时写入 runner probe 结果。
// 参数：result 为本轮 runner probe 结果。
// 返回：无。
func (a *Agent) setGuardRunnerProbeResult(result runnerProbeResult) {
	if result.Epoch < a.currentGuardProbeEpoch() {
		return
	}
	a.guardProbeMu.Lock()
	a.guardRunnerProbe = result
	a.guardProbeMu.Unlock()
	a.wakeGuardLoop()
}

// getGuardProbeSnapshot 读取当前三类 probe 的原子快照。
// 参数：无。
// 返回：当前 probe 快照副本。
func (a *Agent) getGuardProbeSnapshot() guardProbeSnapshot {
	a.guardProbeMu.RLock()
	defer a.guardProbeMu.RUnlock()
	return guardProbeSnapshot{
		Process:   a.guardProcessProbe,
		Frontmost: a.guardFrontmostProbe,
		Runner:    a.guardRunnerProbe,
	}
}

// runProcessProbeWorker 周期执行 WhatsApp 进程探测。
// 参数：ctx 为 worker 生命周期上下文。
// 返回：无。
func (a *Agent) runProcessProbeWorker(ctx context.Context) {
	for {
		epoch := a.currentGuardProbeEpoch()
		a.setGuardProcessProbeResult(a.sampleProcessProbe(epoch))
		if !waitGuardInterval(ctx, a.getCfg()) {
			return
		}
	}
}

// runFrontmostProbeWorker 周期执行单实例前台探测。
// 参数：ctx 为 worker 生命周期上下文。
// 返回：无。
func (a *Agent) runFrontmostProbeWorker(ctx context.Context) {
	for {
		epoch := a.currentGuardProbeEpoch()
		a.setGuardFrontmostProbeResult(a.sampleFrontmostProbe(epoch))
		if !waitGuardInterval(ctx, a.getCfg()) {
			return
		}
	}
}

// runRunnerProbeWorker 周期执行 runner 与脚本健康探测。
// 参数：ctx 为 worker 生命周期上下文。
// 返回：无。
func (a *Agent) runRunnerProbeWorker(ctx context.Context) {
	for {
		epoch := a.currentGuardProbeEpoch()
		a.setGuardRunnerProbeResult(a.sampleRunnerProbe(epoch))
		if !waitGuardInterval(ctx, a.getCfg()) {
			return
		}
	}
}

// sampleProcessProbe 执行单次进程探测。
// 参数：epoch 为本轮采样绑定的 probe epoch。
// 返回：进程 probe 结果。
func (a *Agent) sampleProcessProbe(epoch int64) processProbeResult {
	now := time.Now().UnixMilli()
	running, err := a.detectWhatsAppProcess()
	result := processProbeResult{
		Running:    running,
		SampleAtMs: now,
		Epoch:      epoch,
	}
	if err != nil {
		result.Err = strings.TrimSpace(err.Error())
	}
	return result
}

// sampleFrontmostProbe 执行单次前台探测。
// 参数：epoch 为本轮采样绑定的 probe epoch。
// 返回：前台 probe 结果。
func (a *Agent) sampleFrontmostProbe(epoch int64) frontmostProbeResult {
	now := time.Now().UnixMilli()
	process := a.getGuardProbeSnapshot().Process
	if !process.Running {
		return frontmostProbeResult{
			Running:    false,
			Err:        "",
			SampleAtMs: now,
			Fresh:      true,
			Epoch:      epoch,
		}
	}
	running, err := a.detectWhatsAppFrontmost()
	result := frontmostProbeResult{
		Running:    running,
		SampleAtMs: now,
		Fresh:      true,
		Epoch:      epoch,
	}
	if err != nil {
		result.Err = strings.TrimSpace(err.Error())
	}
	return result
}

// sampleRunnerProbe 执行单次 runner 与脚本健康探测。
// 参数：epoch 为本轮采样绑定的 probe epoch。
// 返回：runner probe 结果。
func (a *Agent) sampleRunnerProbe(epoch int64) runnerProbeResult {
	now := time.Now().UnixMilli()
	installed := a.readInstalledScriptInfo()
	result := runnerProbeResult{
		RunnerPid:                a.runnerPid.Load(),
		RunnerProcessAlive:       a.runnerPid.Load() > 0,
		SampleAtMs:               now,
		InstalledScriptPath:      strings.TrimSpace(installed.Path),
		InstalledScriptUpdatedAt: installed.UpdatedAtMs,
		InstalledScriptBuild:     strings.TrimSpace(installed.Build),
		InstalledScriptSha256:    strings.TrimSpace(installed.Sha256),
		ScriptLastEventTsMs:      a.scriptLastEventTS.Load(),
		ScriptLastPongTsMs:       a.scriptLastPongTS.Load(),
		Epoch:                    epoch,
	}
	result.ScriptEventFresh = guardTimestampFresh(result.ScriptLastEventTsMs, guardScriptEventFreshnessThresholdMs(a.getCfg()), now)
	result.ScriptPongFresh = guardTimestampFresh(result.ScriptLastPongTsMs, guardScriptPongFreshnessThresholdMs(), now)
	if !result.RunnerProcessAlive {
		return result
	}
	health, err := a.getRunnerRPCHealth()
	if err != nil {
		result.LastHealthErr = strings.TrimSpace(err.Error())
		result.LastHealthErrAtMs = now
		return result
	}
	result.RunnerRPCOK = true
	result.ScriptReady = health.ScriptReady
	result.ScriptBuild = strings.TrimSpace(health.ScriptBuild)
	result.ScriptSha256 = strings.TrimSpace(health.ScriptSha256)
	result.StartedAtMs = health.StartedAtMs
	result.LastHealthErr = strings.TrimSpace(health.LastHealthErr)
	if result.LastHealthErr != "" {
		result.LastHealthErrAtMs = now
	}
	result.ScriptBuildMatch = result.ScriptBuild != "" && result.InstalledScriptBuild != "" && result.ScriptBuild == result.InstalledScriptBuild
	result.ScriptSha256Match = result.ScriptSha256 != "" && result.InstalledScriptSha256 != "" && result.ScriptSha256 == result.InstalledScriptSha256
	return result
}

// readInstalledScriptInfo 读取当前安装脚本的 build / sha256 / 更新时间。
// 参数：无。
// 返回：本地安装脚本信息；读取失败时返回零值信息。
func (a *Agent) readInstalledScriptInfo() installedScriptInfo {
	path := strings.TrimSpace(a.scriptPath)
	if path == "" {
		return installedScriptInfo{}
	}
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return installedScriptInfo{Path: path}
	}
	bs, err := os.ReadFile(path)
	if err != nil || len(bs) == 0 {
		return installedScriptInfo{
			Path:        path,
			UpdatedAtMs: st.ModTime().UnixMilli(),
		}
	}
	sum := sha256.Sum256(bs)
	updatedAtMs := a.scriptUpdatedAtTS.Load()
	if updatedAtMs <= 0 {
		updatedAtMs = st.ModTime().UnixMilli()
	}
	return installedScriptInfo{
		Path:        path,
		UpdatedAtMs: updatedAtMs,
		Build:       extractInstalledScriptBuildID(bs),
		Sha256:      hex.EncodeToString(sum[:]),
	}
}

// extractInstalledScriptBuildID 从脚本文本中提取 `SCRIPT_BUILD_ID`。
// 参数：scriptBytes 为脚本原始字节。
// 返回：提取到的 build id；不存在时返回空字符串。
func extractInstalledScriptBuildID(scriptBytes []byte) string {
	if len(scriptBytes) == 0 {
		return ""
	}
	m := guardScriptBuildIDPattern.FindSubmatch(scriptBytes)
	if len(m) != 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// guardFrontmostFreshnessThresholdMs 返回前台 probe 的 freshness 阈值。
// 参数：cfg 为当前配置。
// 返回：frontmost freshness 阈值毫秒数。
func guardFrontmostFreshnessThresholdMs(cfg Config) int64 {
	return int64(maxInt(cfg.WhatsApp.HealthCheckMs*2, 5000))
}

// guardScriptPongFreshnessThresholdMs 返回脚本 pong 的 freshness 阈值。
// 参数：无。
// 返回：script pong freshness 阈值毫秒数。
func guardScriptPongFreshnessThresholdMs() int64 {
	return int64(maxInt(guardScriptPongIntervalMs*3, 45_000))
}

// guardScriptEventFreshnessThresholdMs 返回脚本事件的诊断 freshness 阈值。
// 参数：cfg 为当前配置。
// 返回：script event freshness 阈值毫秒数。
func guardScriptEventFreshnessThresholdMs(cfg Config) int64 {
	return int64(maxInt(cfg.WhatsApp.HealthCheckMs*30, 90_000))
}

// guardRunnerStartingGraceMs 返回 runner 从启动到判定为 not ready 的宽限时间。
// 参数：cfg 为当前配置。
// 返回：runner 启动宽限毫秒数。
func guardRunnerStartingGraceMs(cfg Config) int64 {
	return int64(maxInt(cfg.WhatsApp.ForegroundStableMs, cfg.WhatsApp.HealthCheckMs*2))
}

// guardTimestampFresh 判断某个毫秒时间戳是否仍处于 freshness 窗口。
// 参数：tsMs 为目标时间戳；thresholdMs 为 freshness 阈值；nowMs 为当前毫秒时间。
// 返回：在 freshness 窗口内返回 true，否则返回 false。
func guardTimestampFresh(tsMs int64, thresholdMs int64, nowMs int64) bool {
	if tsMs <= 0 || thresholdMs <= 0 || nowMs <= 0 {
		return false
	}
	return nowMs-tsMs <= thresholdMs
}

// waitGuardInterval 按当前配置等待下一轮 probe 周期。
// 参数：ctx 为 worker 生命周期上下文；cfg 为当前配置。
// 返回：正常等待返回 true；ctx 结束返回 false。
func waitGuardInterval(ctx context.Context, cfg Config) bool {
	delay := time.Duration(maxInt(cfg.WhatsApp.HealthCheckMs, 1000)) * time.Millisecond
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

var _ sync.Locker
