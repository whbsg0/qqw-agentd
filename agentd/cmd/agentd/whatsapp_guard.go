package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os/exec"
	"strings"
	"time"
)

const debugGuardServerURL = "http://192.168.1.4:7777/event"
const debugGuardSessionID = "multi-device-guard-drift"

// #region debug-point H1-H5:guard-debug-report
func debugGuardReport(runID string, hypothesisID string, location string, msg string, data map[string]any) {
	go func() {
		body, err := json.Marshal(map[string]any{
			"sessionId":    debugGuardSessionID,
			"runId":        runID,
			"hypothesisId": hypothesisID,
			"location":     location,
			"msg":          "[DEBUG] " + strings.TrimSpace(msg),
			"data":         data,
			"ts":           time.Now().UnixMilli(),
		})
		if err != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, debugGuardServerURL, bytes.NewReader(body))
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

func debugGuardSamplePS(output string) []string {
	src := strings.Split(output, "\n")
	out := make([]string, 0, 4)
	for _, line := range src {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(strings.ToLower(line), "whatsapp") || len(out) == 0 {
			out = append(out, line)
		}
		if len(out) >= 4 {
			break
		}
	}
	return out
}

// #endregion

// guardRuntimeSnapshot 表示当前守护循环的运行态快照。
// 字段用途：用于 `/status`、`/guard/status` 和手机端守护状态展示。
type guardRuntimeSnapshot struct {
	GuardEnabled   bool
	State          string
	GuardState     string
	RunnerState    string
	ReasonCode     string
	ListeningReady bool

	ProcessRunning    bool
	ProcessProbeErr   string
	ProcessSampleAtMs int64

	Frontmost           bool
	FrontmostErr        string
	FrontmostSampleAtMs int64
	FrontmostFresh      bool

	RunnerProcessAlive      bool
	RunnerPid               int64
	RunnerRPCOK             bool
	ScriptReady             bool
	RunnerScriptBuild       string
	RunnerScriptSha256      string
	RunnerSampleAtMs        int64
	RunnerLastHealthErr     string
	RunnerLastHealthErrAtMs int64

	ScriptInstalledPath        string
	ScriptInstalledUpdatedAtMs int64
	ScriptInstalledBuild       string
	ScriptInstalledSha256      string
	ScriptLastEventTsMs        int64
	ScriptLastPongTsMs         int64
	ScriptEventFresh           bool
	ScriptPongFresh            bool
	ScriptBuildMatch           bool
	ScriptSha256Match          bool

	ProbeEpoch    int64
	RecoveryEpoch int64

	LastRecoveryAtMs        int64
	RecoveryAttempts        int
	MaxRecoveryAttempts     int
	RemainingRetryCount     int
	NextRetryAtMs           int64
	RecoveryInFlight        bool
	RecoveryPending         bool
	RecoveryAction          string
	RecoveryRequestedState  string
	RecoveryRequestedReason string

	FrontmostQueryEnabled bool
}

// defaultGuardRuntimeSnapshot 按当前配置构造默认守护快照。
// 参数：cfg 为当前配置。
// 返回：适合作为守护状态默认值的快照。
func defaultGuardRuntimeSnapshot(cfg Config) guardRuntimeSnapshot {
	state := "guard_off"
	reason := "guard_switch_off"
	if cfg.WhatsApp.AutoGuardEnabled {
		state = "wa_process_probe_failed"
		reason = "probe_not_sampled_yet"
	}
	return guardRuntimeSnapshot{
		GuardEnabled:          cfg.WhatsApp.AutoGuardEnabled,
		State:                 state,
		GuardState:            state,
		RunnerState:           "runner_down",
		ReasonCode:            reason,
		ListeningReady:        false,
		ProcessRunning:        false,
		FrontmostFresh:        !guardFrontmostQueryEnabled(),
		LastRecoveryAtMs:      0,
		RecoveryAttempts:      0,
		MaxRecoveryAttempts:   cfg.WhatsApp.MaxRecoveryAttempts,
		RemainingRetryCount:   cfg.WhatsApp.MaxRecoveryAttempts,
		NextRetryAtMs:         0,
		FrontmostQueryEnabled: guardFrontmostQueryEnabled(),
	}
}

// getGuardRuntimeSnapshot 读取当前守护运行态快照。
// 参数：cfg 为当前配置，用于补齐默认值。
// 返回：当前守护快照。
func (a *Agent) getGuardRuntimeSnapshot(cfg Config) guardRuntimeSnapshot {
	a.guardStateMu.RLock()
	snapshot := a.guardState
	a.guardStateMu.RUnlock()
	if strings.TrimSpace(snapshot.State) == "" {
		snapshot = defaultGuardRuntimeSnapshot(cfg)
	}
	snapshot.MaxRecoveryAttempts = cfg.WhatsApp.MaxRecoveryAttempts
	if snapshot.RemainingRetryCount < 0 {
		snapshot.RemainingRetryCount = 0
	}
	return snapshot
}

// setGuardRuntimeSnapshot 原子更新守护运行态快照。
// 参数：snapshot 为新的快照。
// 返回：无。
func (a *Agent) setGuardRuntimeSnapshot(snapshot guardRuntimeSnapshot) {
	a.guardStateMu.Lock()
	a.guardState = snapshot
	a.guardStateMu.Unlock()
	// #region debug-point H4:guard-snapshot
	debugGuardReport("pre-fix", "H4", "whatsapp_guard.go:setGuardRuntimeSnapshot", "guard snapshot updated", map[string]any{
		"state":            snapshot.State,
		"runnerState":      snapshot.RunnerState,
		"reasonCode":       snapshot.ReasonCode,
		"listeningReady":   snapshot.ListeningReady,
		"processRunning":   snapshot.ProcessRunning,
		"frontmostFresh":   snapshot.FrontmostFresh,
		"runnerRpcOk":      snapshot.RunnerRPCOK,
		"scriptReady":      snapshot.ScriptReady,
		"recoveryAttempts": snapshot.RecoveryAttempts,
		"nextRetryAtMs":    snapshot.NextRetryAtMs,
	})
	// #endregion
}

// wakeGuardLoop 唤醒守护循环，使配置切换和手工动作能尽快生效。
// 参数：无。
// 返回：无。
func (a *Agent) wakeGuardLoop() {
	if a.guardWake == nil {
		return
	}
	select {
	case a.guardWake <- struct{}{}:
	default:
	}
}

// runGuardLoop 常驻执行第二阶段第一版守护主循环。
// 参数：ctx 为循环上下文。
// 返回：无。
func (a *Agent) runGuardLoop(ctx context.Context) {
	cfg := a.getCfg()
	var confirmStartedAt time.Time
	a.setGuardRuntimeSnapshot(defaultGuardRuntimeSnapshot(cfg))
	a.startGuardWorkers(ctx)
	a.bumpGuardProbeEpoch("guard_loop_start")
	for {
		if ctx.Err() != nil {
			return
		}
		cfg = a.getCfg()
		now := time.Now()
		trimmedAttempts, blocked, err := a.trimGuardRecoveryAttemptsPersisted(now.UnixMilli(), cfg.WhatsApp.RecoveryWindowMs)
		if err != nil {
			a.recordGuardAction("guard_store_trim", err)
		}
		if blocked && trimmedAttempts == 0 {
			if err := a.clearGuardRecoveryState(); err == nil {
				blocked = false
			}
		}
		manualRecover := a.consumeGuardForceRecoverRequest()
		recoveryStatus := a.getGuardRecoveryStatus()
		snapshot := deriveGuardRuntimeSnapshot(
			cfg,
			a.getGuardProbeSnapshot(),
			trimmedAttempts,
			blocked,
			recoveryStatus,
			now,
			&confirmStartedAt,
		)
		if blocked && guardBlockedAutoClearEligible(snapshot) {
			if err := a.clearGuardRecoveryState(); err == nil {
				blocked = false
				trimmedAttempts = 0
				a.clearGuardRecoverySchedule()
				snapshot = deriveGuardRuntimeSnapshot(
					cfg,
					a.getGuardProbeSnapshot(),
					trimmedAttempts,
					blocked,
					a.getGuardRecoveryStatus(),
					now,
					&confirmStartedAt,
				)
			}
		}
		a.setGuardRuntimeSnapshot(snapshot)
		if !snapshot.RecoveryInFlight && !snapshot.RecoveryPending {
			_ = a.maybeScheduleGuardRecovery(cfg, snapshot, manualRecover)
		}
		waitFor := time.Duration(maxInt(cfg.WhatsApp.HealthCheckMs, 1000)) * time.Millisecond
		select {
		case <-ctx.Done():
			return
		case <-a.guardWake:
		case <-time.After(waitFor):
		}
	}
}

// guardBlockedAutoClearEligible 判断熔断状态是否已具备自动解封条件。
// 参数：snapshot 为当前基于实时 probe 派生的 guard 快照。
// 返回：实时 probe 已恢复到可继续判定状态时返回 true。
func guardBlockedAutoClearEligible(snapshot guardRuntimeSnapshot) bool {
	if !snapshot.GuardEnabled {
		return false
	}
	if snapshot.ProcessProbeErr != "" || !snapshot.ProcessRunning {
		return false
	}
	if snapshot.FrontmostQueryEnabled {
		if !snapshot.FrontmostFresh {
			return false
		}
		if strings.TrimSpace(snapshot.FrontmostErr) != "" {
			return false
		}
	}
	return true
}

// detectWhatsAppProcess 检查当前设备上是否存在 WhatsApp 进程。
// 参数：无。
// 返回：存在返回 true；若检测工具不可用则返回错误。
func (a *Agent) detectWhatsAppProcess() (bool, error) {
	type psCommand struct {
		path string
		args []string
	}
	commands := []psCommand{
		{path: "/bin/ps", args: []string{"-A", "-o", "comm="}},
		{path: "/usr/bin/ps", args: []string{"-A", "-o", "comm="}},
		{path: "/bin/ps", args: []string{"ax", "-o", "command="}},
		{path: "/usr/bin/ps", args: []string{"ax", "-o", "command="}},
	}
	var lastErr error
	for _, command := range commands {
		if firstExistingFile(command.path) == "" {
			continue
		}
		cmd := exec.Command(command.path, command.args...)
		cmd.Env = append(cmd.Env, "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin")
		out, err := cmd.CombinedOutput()
		if err != nil {
			msg := strings.TrimSpace(string(out))
			if msg != "" {
				lastErr = errors.New(msg)
			} else {
				lastErr = err
			}
			// #region debug-point H1:ps-command-error
			debugGuardReport("pre-fix", "H1", "whatsapp_guard.go:detectWhatsAppProcess", "ps command failed", map[string]any{
				"path":  command.path,
				"args":  command.args,
				"error": lastErr.Error(),
			})
			// #endregion
			continue
		}
		matched := parsePSContainsWhatsApp(string(out))
		// #region debug-point H1:ps-command-result
		debugGuardReport("pre-fix", "H1", "whatsapp_guard.go:detectWhatsAppProcess", "ps command parsed", map[string]any{
			"path":    command.path,
			"args":    command.args,
			"matched": matched,
			"sample":  debugGuardSamplePS(string(out)),
		})
		// #endregion
		return matched, nil
	}
	if lastErr == nil {
		lastErr = errors.New("ps not available")
	}
	// #region debug-point H1:ps-unavailable
	debugGuardReport("pre-fix", "H1", "whatsapp_guard.go:detectWhatsAppProcess", "all ps commands unavailable", map[string]any{
		"error": lastErr.Error(),
	})
	// #endregion
	return false, lastErr
}

// parsePSContainsWhatsApp 从 ps 输出中判断是否存在 WhatsApp 进程。
// 参数：output 为 ps 命令原始输出。
// 返回：命中 WhatsApp 进程返回 true，否则返回 false。
func parsePSContainsWhatsApp(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		base := line
		if idx := strings.LastIndex(base, "/"); idx >= 0 {
			base = base[idx+1:]
		}
		fields := strings.Fields(base)
		if len(fields) > 0 {
			base = fields[0]
		}
		if strings.EqualFold(strings.TrimSpace(base), "WhatsApp") {
			return true
		}
	}
	return false
}

// waitGuardDuration 在可被唤醒的前提下等待指定时长。
// 参数：ctx 为等待上下文；wake 为唤醒信号通道；d 为目标等待时长。
// 返回：正常等待结束返回 true；上下文取消返回 false。
func waitGuardDuration(ctx context.Context, wake <-chan struct{}, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-wake:
		return true
	case <-timer.C:
		return true
	}
}

// trimGuardRecoveryAttempts 裁剪恢复窗口之外的历史恢复记录。
// 参数：nowMs 为当前毫秒时间；windowMs 为恢复统计窗口；attempts 为恢复时间戳数组指针。
// 返回：裁剪后的记录数量。
func trimGuardRecoveryAttempts(nowMs int64, windowMs int, attempts *[]int64) int {
	if attempts == nil {
		return 0
	}
	if windowMs <= 0 {
		windowMs = 10 * 60 * 1000
	}
	windowStart := nowMs - int64(windowMs)
	src := *attempts
	dst := src[:0]
	for _, ts := range src {
		if ts >= windowStart {
			dst = append(dst, ts)
		}
	}
	*attempts = dst
	return len(dst)
}

// appendGuardRecoveryAttempt 记录一次新的恢复尝试并判断是否触发熔断。
// 参数：nowMs 为当前毫秒时间；windowMs 为恢复统计窗口；maxAttempts 为窗口内最大允许次数；attempts 为恢复时间戳数组指针。
// 返回：本轮尝试序号、是否已熔断、窗口内总次数。
func appendGuardRecoveryAttempt(nowMs int64, windowMs int, maxAttempts int, attempts *[]int64) (int, bool, int) {
	count := trimGuardRecoveryAttempts(nowMs, windowMs, attempts)
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if count >= maxAttempts {
		return count, true, count
	}
	*attempts = append(*attempts, nowMs)
	count = len(*attempts)
	return count, false, count
}

// guardRecoveryBackoff 返回当前恢复次数对应的退避时长。
// 参数：attemptNo 为当前窗口内第几次恢复。
// 返回：固定退避时长。
func guardRecoveryBackoff(attemptNo int) time.Duration {
	switch attemptNo {
	case 1:
		return 0
	case 2:
		return 3 * time.Second
	case 3:
		return 8 * time.Second
	case 4:
		return 15 * time.Second
	default:
		return 30 * time.Second
	}
}

// clampRemainingRetries 计算剩余可重试次数，避免出现负值。
// 参数：maxAttempts 为最大允许次数；used 为窗口内已使用次数。
// 返回：剩余次数。
func clampRemainingRetries(maxAttempts int, used int) int {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	remaining := maxAttempts - used
	if remaining < 0 {
		return 0
	}
	return remaining
}

// maxInt 返回两个整数中的较大值。
// 参数：a、b 为待比较值。
// 返回：较大值。
func maxInt(a int, b int) int {
	if a >= b {
		return a
	}
	return b
}

// firstNonEmpty 返回第一个非空字符串。
// 参数：values 为待选择的字符串列表。
// 返回：第一个非空字符串；若全为空则返回空串。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}
