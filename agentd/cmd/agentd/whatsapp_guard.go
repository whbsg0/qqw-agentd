package main

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// guardRuntimeSnapshot 表示当前守护循环的运行态快照。
// 字段用途：用于 `/status`、`/guard/status` 和手机端守护状态展示。
type guardRuntimeSnapshot struct {
	State                 string
	RunnerState           string
	ReasonCode            string
	ListeningReady        bool
	ProcessRunning        bool
	LastRecoveryAtMs      int64
	RecoveryAttempts      int
	MaxRecoveryAttempts   int
	RemainingRetryCount   int
	NextRetryAtMs         int64
	FrontmostQueryEnabled bool
}

// defaultGuardRuntimeSnapshot 按当前配置构造默认守护快照。
// 参数：cfg 为当前配置。
// 返回：适合作为守护状态默认值的快照。
func defaultGuardRuntimeSnapshot(cfg Config) guardRuntimeSnapshot {
	state := "guard_off"
	reason := "guard_switch_off"
	if cfg.WhatsApp.AutoGuardEnabled {
		state = "wa_not_running"
		reason = ""
	}
	return guardRuntimeSnapshot{
		State:                 state,
		RunnerState:           "runner_down",
		ReasonCode:            reason,
		ListeningReady:        false,
		ProcessRunning:        false,
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
	var confirmStartedAt time.Time
	a.setGuardRuntimeSnapshot(defaultGuardRuntimeSnapshot(a.getCfg()))
	for {
		if ctx.Err() != nil {
			return
		}
		waitFor := a.runGuardIteration(ctx, &confirmStartedAt)
		if waitFor <= 0 {
			waitFor = time.Second
		}
		select {
		case <-ctx.Done():
			return
		case <-a.guardWake:
		case <-time.After(waitFor):
		}
	}
}

// runGuardIteration 执行一轮守护检查与恢复决策。
// 参数：ctx 为循环上下文；confirmStartedAt 用于跨轮记住确认窗口起点。
// 返回：下一轮建议等待时长。
func (a *Agent) runGuardIteration(ctx context.Context, confirmStartedAt *time.Time) time.Duration {
	cfg := a.getCfg()
	now := time.Now()
	frontmostEnabled := guardFrontmostQueryEnabled()
	trimmedAttempts, blocked, err := a.trimGuardRecoveryAttemptsPersisted(now.UnixMilli(), cfg.WhatsApp.RecoveryWindowMs)
	if !cfg.WhatsApp.AutoGuardEnabled {
		*confirmStartedAt = time.Time{}
		a.setGuardRuntimeSnapshot(defaultGuardRuntimeSnapshot(cfg))
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}
	if err != nil {
		a.recordGuardAction("guard_store_trim", err)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}
	if blocked {
		*confirmStartedAt = time.Time{}
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_crash_loop_blocked"
		snapshot.RunnerState = "runner_down"
		snapshot.ReasonCode = "recovery_retry_exhausted"
		snapshot.ListeningReady = false
		snapshot.RecoveryAttempts = trimmedAttempts
		snapshot.RemainingRetryCount = 0
		snapshot.NextRetryAtMs = 0
		snapshot.FrontmostQueryEnabled = frontmostEnabled
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}
	manualRecover := a.consumeGuardForceRecoverRequest()

	processRunning, processErr := a.detectWhatsAppProcess()
	runnerState, runnerReady, runnerReason := a.queryRunnerGuardState(cfg)
	frontmost := false
	var frontmostErr error
	if processErr != nil {
		if runnerReady {
			processRunning = true
		} else {
			snapshot := a.getGuardRuntimeSnapshot(cfg)
			snapshot.State = "wa_background"
			snapshot.RunnerState = runnerState
			snapshot.ReasonCode = "wa_process_probe_failed"
			snapshot.ListeningReady = false
			snapshot.ProcessRunning = false
			snapshot.RecoveryAttempts = trimmedAttempts
			snapshot.RemainingRetryCount = clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, trimmedAttempts)
			snapshot.NextRetryAtMs = 0
			snapshot.FrontmostQueryEnabled = frontmostEnabled
			a.setGuardRuntimeSnapshot(snapshot)
			return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
		}
	}

	if frontmostEnabled {
		if processRunning {
			frontmost, frontmostErr = a.detectWhatsAppFrontmost()
		}
		if processRunning && frontmostErr != nil {
			snapshot := a.getGuardRuntimeSnapshot(cfg)
			snapshot.State = "wa_background"
			snapshot.RunnerState = runnerState
			snapshot.ReasonCode = "wa_frontmost_query_failed"
			snapshot.ListeningReady = false
			snapshot.ProcessRunning = processRunning
			snapshot.RecoveryAttempts = trimmedAttempts
			snapshot.RemainingRetryCount = clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, trimmedAttempts)
			snapshot.NextRetryAtMs = 0
			snapshot.FrontmostQueryEnabled = true
			a.setGuardRuntimeSnapshot(snapshot)
			return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
		}
		if processRunning && frontmost && runnerReady {
			*confirmStartedAt = time.Time{}
			snapshot := a.getGuardRuntimeSnapshot(cfg)
			snapshot.State = "wa_foreground_ready"
			snapshot.RunnerState = "runner_ready"
			snapshot.ReasonCode = ""
			snapshot.ListeningReady = true
			snapshot.ProcessRunning = true
			snapshot.RecoveryAttempts = trimmedAttempts
			snapshot.RemainingRetryCount = clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, trimmedAttempts)
			snapshot.NextRetryAtMs = 0
			snapshot.FrontmostQueryEnabled = true
			a.setGuardRuntimeSnapshot(snapshot)
			return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
		}
		if processRunning && frontmost && runnerState == "runner_starting" {
			snapshot := a.getGuardRuntimeSnapshot(cfg)
			snapshot.State = "wa_wait_foreground_stable"
			snapshot.RunnerState = "runner_starting"
			snapshot.ReasonCode = ""
			snapshot.ListeningReady = false
			snapshot.ProcessRunning = true
			snapshot.RecoveryAttempts = trimmedAttempts
			snapshot.RemainingRetryCount = clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, trimmedAttempts)
			snapshot.FrontmostQueryEnabled = true
			a.setGuardRuntimeSnapshot(snapshot)
			return time.Duration(maxInt(cfg.WhatsApp.HealthCheckMs, 1000)) * time.Millisecond
		}
		if processRunning && frontmost {
			*confirmStartedAt = time.Time{}
			if manualRecover && runnerReady {
				return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
			}
			return a.runGuardRunnerRecovery(ctx, cfg, firstNonEmpty(runnerReason, "runner_detached"))
		}
	}

	if manualRecover {
		*confirmStartedAt = time.Time{}
		if !processRunning {
			return a.runGuardRecovery(ctx, cfg, "wa_process_missing", false)
		}
		if frontmostEnabled && frontmostErr == nil && !frontmost {
			return a.runGuardRecovery(ctx, cfg, firstNonEmpty(runnerReason, "wa_not_frontmost"), true)
		}
		if !frontmostEnabled && runnerReady {
			return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
		}
		return a.runGuardRecovery(ctx, cfg, firstNonEmpty(runnerReason, "wa_not_frontmost"), processRunning)
	}

	if processRunning && runnerReady {
		*confirmStartedAt = time.Time{}
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_foreground_ready"
		snapshot.RunnerState = "runner_ready"
		snapshot.ReasonCode = ""
		snapshot.ListeningReady = true
		snapshot.ProcessRunning = true
		snapshot.RecoveryAttempts = trimmedAttempts
		snapshot.RemainingRetryCount = clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, trimmedAttempts)
		snapshot.NextRetryAtMs = 0
		snapshot.FrontmostQueryEnabled = frontmostEnabled
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}

	if processRunning && runnerState == "runner_starting" {
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_wait_foreground_stable"
		snapshot.RunnerState = "runner_starting"
		snapshot.ReasonCode = ""
		snapshot.ListeningReady = false
		snapshot.ProcessRunning = true
		snapshot.RecoveryAttempts = trimmedAttempts
		snapshot.RemainingRetryCount = clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, trimmedAttempts)
		snapshot.FrontmostQueryEnabled = frontmostEnabled
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Duration(maxInt(cfg.WhatsApp.HealthCheckMs, 1000)) * time.Millisecond
	}

	if !processRunning {
		*confirmStartedAt = time.Time{}
		return a.runGuardRecovery(ctx, cfg, "wa_process_missing", false)
	}

	if confirmStartedAt.IsZero() {
		*confirmStartedAt = now
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_wait_foreground_confirm"
		snapshot.RunnerState = runnerState
		snapshot.ReasonCode = firstNonEmpty(runnerReason, "wa_not_frontmost")
		snapshot.ListeningReady = false
		snapshot.ProcessRunning = true
		snapshot.RecoveryAttempts = trimmedAttempts
		snapshot.RemainingRetryCount = clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, trimmedAttempts)
		snapshot.FrontmostQueryEnabled = frontmostEnabled
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Second
	}

	if now.Sub(*confirmStartedAt) < time.Duration(cfg.WhatsApp.ForegroundConfirmMs)*time.Millisecond {
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_wait_foreground_confirm"
		snapshot.RunnerState = runnerState
		snapshot.ReasonCode = firstNonEmpty(runnerReason, "wa_not_frontmost")
		snapshot.ListeningReady = false
		snapshot.ProcessRunning = true
		snapshot.RecoveryAttempts = trimmedAttempts
		snapshot.RemainingRetryCount = clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, trimmedAttempts)
		snapshot.FrontmostQueryEnabled = frontmostEnabled
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Second
	}

	*confirmStartedAt = time.Time{}
	return a.runGuardRecovery(ctx, cfg, firstNonEmpty(runnerReason, "wa_not_frontmost"), true)
}

// runGuardRecovery 执行一轮恢复流程。
// 参数：ctx 为循环上下文；cfg 为当前配置；reasonCode 为本轮恢复原因；processRunning 表示恢复前是否已有进程。
// 返回：下一轮建议等待时长。
func (a *Agent) runGuardRecovery(ctx context.Context, cfg Config, reasonCode string, processRunning bool) time.Duration {
	nowMs := time.Now().UnixMilli()
	attemptNo, blocked, attemptsCount, err := a.appendGuardRecoveryAttemptPersisted(nowMs, cfg.WhatsApp.RecoveryWindowMs, cfg.WhatsApp.MaxRecoveryAttempts)
	if err != nil {
		a.recordGuardAction("guard_store_append", err)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}
	remaining := clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, attemptsCount)
	if blocked {
		_ = a.stopRunnerIfRunning()
		a.recordGuardAction("guard_blocked", errors.New("recovery retry exhausted"))
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_crash_loop_blocked"
		snapshot.RunnerState = "runner_down"
		snapshot.ReasonCode = "recovery_retry_exhausted"
		snapshot.ListeningReady = false
		snapshot.ProcessRunning = processRunning
		snapshot.RecoveryAttempts = attemptsCount
		snapshot.RemainingRetryCount = 0
		snapshot.NextRetryAtMs = 0
		snapshot.FrontmostQueryEnabled = guardFrontmostQueryEnabled()
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}

	backoff := guardRecoveryBackoff(attemptNo)
	nextRetryAtMs := time.Now().Add(backoff).UnixMilli()
	snapshot := a.getGuardRuntimeSnapshot(cfg)
	snapshot.State = "wa_launching"
	snapshot.RunnerState = "runner_down"
	snapshot.ReasonCode = reasonCode
	snapshot.ListeningReady = false
	snapshot.ProcessRunning = processRunning
	snapshot.RecoveryAttempts = attemptsCount
	snapshot.RemainingRetryCount = remaining
	snapshot.NextRetryAtMs = nextRetryAtMs
	snapshot.FrontmostQueryEnabled = guardFrontmostQueryEnabled()
	a.setGuardRuntimeSnapshot(snapshot)

	if backoff > 0 {
		if !waitGuardDuration(ctx, a.guardWake, backoff) {
			return time.Second
		}
	}
	if !a.getCfg().WhatsApp.AutoGuardEnabled {
		return time.Second
	}

	_ = a.stopRunnerIfRunning()
	a.recordGuardAction("guard_recover_begin", nil)
	if err := a.launchWhatsApp(); err != nil {
		a.recordGuardAction("guard_recover_launch_failed", err)
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_not_running"
		snapshot.RunnerState = "runner_down"
		snapshot.ReasonCode = "wa_launch_failed"
		snapshot.ListeningReady = false
		snapshot.ProcessRunning = false
		snapshot.RecoveryAttempts = attemptsCount
		snapshot.RemainingRetryCount = remaining
		snapshot.NextRetryAtMs = 0
		snapshot.FrontmostQueryEnabled = guardFrontmostQueryEnabled()
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}

	snapshot = a.getGuardRuntimeSnapshot(cfg)
	snapshot.State = "wa_wait_foreground_stable"
	snapshot.RunnerState = "runner_starting"
	snapshot.ReasonCode = ""
	snapshot.ListeningReady = false
	snapshot.ProcessRunning = true
	snapshot.RecoveryAttempts = attemptsCount
	snapshot.RemainingRetryCount = remaining
	snapshot.NextRetryAtMs = 0
	a.setGuardRuntimeSnapshot(snapshot)

	if err := a.startRunner(); err != nil {
		a.recordGuardAction("guard_recover_runner_start_failed", err)
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_background"
		snapshot.RunnerState = "runner_broken"
		snapshot.ReasonCode = "runner_start_failed"
		snapshot.ListeningReady = false
		snapshot.ProcessRunning = true
		snapshot.RecoveryAttempts = attemptsCount
		snapshot.RemainingRetryCount = remaining
		snapshot.FrontmostQueryEnabled = guardFrontmostQueryEnabled()
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}

	if a.waitRunnerReadyAfterRecovery(ctx, cfg, attemptsCount, remaining) {
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}
	return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
}

// runGuardRunnerRecovery 在 WhatsApp 已前台时只恢复 runner，不重复拉起 app。
// 参数：ctx 为循环上下文；cfg 为当前配置；reasonCode 为本轮恢复原因。
// 返回：下一轮建议等待时长。
func (a *Agent) runGuardRunnerRecovery(ctx context.Context, cfg Config, reasonCode string) time.Duration {
	nowMs := time.Now().UnixMilli()
	attemptNo, blocked, attemptsCount, err := a.appendGuardRecoveryAttemptPersisted(nowMs, cfg.WhatsApp.RecoveryWindowMs, cfg.WhatsApp.MaxRecoveryAttempts)
	if err != nil {
		a.recordGuardAction("guard_store_append", err)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}
	remaining := clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, attemptsCount)
	if blocked {
		_ = a.stopRunnerIfRunning()
		a.recordGuardAction("guard_runner_blocked", errors.New("recovery retry exhausted"))
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_crash_loop_blocked"
		snapshot.RunnerState = "runner_down"
		snapshot.ReasonCode = "recovery_retry_exhausted"
		snapshot.ListeningReady = false
		snapshot.ProcessRunning = true
		snapshot.RecoveryAttempts = attemptsCount
		snapshot.RemainingRetryCount = 0
		snapshot.NextRetryAtMs = 0
		snapshot.FrontmostQueryEnabled = guardFrontmostQueryEnabled()
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}

	backoff := guardRecoveryBackoff(attemptNo)
	nextRetryAtMs := time.Now().Add(backoff).UnixMilli()
	snapshot := a.getGuardRuntimeSnapshot(cfg)
	snapshot.State = "wa_wait_foreground_stable"
	snapshot.RunnerState = "runner_down"
	snapshot.ReasonCode = reasonCode
	snapshot.ListeningReady = false
	snapshot.ProcessRunning = true
	snapshot.RecoveryAttempts = attemptsCount
	snapshot.RemainingRetryCount = remaining
	snapshot.NextRetryAtMs = nextRetryAtMs
	snapshot.FrontmostQueryEnabled = guardFrontmostQueryEnabled()
	a.setGuardRuntimeSnapshot(snapshot)

	if backoff > 0 {
		if !waitGuardDuration(ctx, a.guardWake, backoff) {
			return time.Second
		}
	}
	if !a.getCfg().WhatsApp.AutoGuardEnabled {
		return time.Second
	}

	_ = a.stopRunnerIfRunning()
	a.recordGuardAction("guard_runner_recover_begin", nil)
	if err := a.startRunner(); err != nil {
		a.recordGuardAction("guard_runner_recover_start_failed", err)
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		snapshot.State = "wa_foreground_ready"
		snapshot.RunnerState = "runner_broken"
		snapshot.ReasonCode = "runner_start_failed"
		snapshot.ListeningReady = false
		snapshot.ProcessRunning = true
		snapshot.RecoveryAttempts = attemptsCount
		snapshot.RemainingRetryCount = remaining
		snapshot.NextRetryAtMs = 0
		snapshot.FrontmostQueryEnabled = guardFrontmostQueryEnabled()
		a.setGuardRuntimeSnapshot(snapshot)
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}

	if a.waitRunnerReadyAfterRecovery(ctx, cfg, attemptsCount, remaining) {
		return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
	}
	return time.Duration(cfg.WhatsApp.HealthCheckMs) * time.Millisecond
}

// waitRunnerReadyAfterRecovery 在恢复启动后等待 runner 进入 ready。
// 参数：ctx 为循环上下文；cfg 为当前配置；attemptsCount 为当前窗口内恢复次数；remaining 为剩余可重试次数。
// 返回：进入 ready 返回 true，否则返回 false。
func (a *Agent) waitRunnerReadyAfterRecovery(ctx context.Context, cfg Config, attemptsCount int, remaining int) bool {
	waitMs := maxInt(cfg.WhatsApp.ForegroundStableMs, cfg.WhatsApp.HealthCheckMs*2)
	deadline := time.Now().Add(time.Duration(waitMs) * time.Millisecond)
	frontmostEnabled := guardFrontmostQueryEnabled()
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		if !a.getCfg().WhatsApp.AutoGuardEnabled {
			return false
		}
		processRunning, _ := a.detectWhatsAppProcess()
		frontmost := processRunning
		frontmostReason := ""
		if processRunning && frontmostEnabled {
			var err error
			frontmost, err = a.detectWhatsAppFrontmost()
			if err != nil {
				frontmostReason = "wa_frontmost_query_failed"
			}
		}
		runnerState, runnerReady, runnerReason := a.queryRunnerGuardState(cfg)
		if processRunning && frontmost && runnerReady {
			a.recordGuardAction("guard_recover_success", nil)
			snapshot := a.getGuardRuntimeSnapshot(cfg)
			snapshot.State = "wa_foreground_ready"
			snapshot.RunnerState = "runner_ready"
			snapshot.ReasonCode = ""
			snapshot.ListeningReady = true
			snapshot.ProcessRunning = true
			snapshot.LastRecoveryAtMs = time.Now().UnixMilli()
			snapshot.RecoveryAttempts = attemptsCount
			snapshot.RemainingRetryCount = remaining
			snapshot.NextRetryAtMs = 0
			snapshot.FrontmostQueryEnabled = frontmostEnabled
			a.setGuardRuntimeSnapshot(snapshot)
			return true
		}
		snapshot := a.getGuardRuntimeSnapshot(cfg)
		switch {
		case !processRunning:
			snapshot.State = "wa_not_running"
			snapshot.ReasonCode = "wa_process_missing"
		case frontmostReason != "":
			snapshot.State = "wa_background"
			snapshot.ReasonCode = frontmostReason
		case !frontmost:
			snapshot.State = "wa_background"
			snapshot.ReasonCode = "wa_not_frontmost"
		case runnerState == "runner_starting":
			snapshot.State = "wa_wait_foreground_stable"
			snapshot.ReasonCode = ""
		default:
			snapshot.State = "wa_foreground_ready"
			snapshot.ReasonCode = runnerReason
		}
		snapshot.RunnerState = runnerState
		snapshot.ListeningReady = false
		snapshot.ProcessRunning = processRunning
		snapshot.RecoveryAttempts = attemptsCount
		snapshot.RemainingRetryCount = remaining
		snapshot.FrontmostQueryEnabled = frontmostEnabled
		a.setGuardRuntimeSnapshot(snapshot)
		if !waitGuardDuration(ctx, a.guardWake, 500*time.Millisecond) {
			return false
		}
	}
	a.recordGuardAction("guard_recover_health_failed", errors.New("runner health wait timeout"))
	snapshot := a.getGuardRuntimeSnapshot(cfg)
	snapshot.State = "wa_background"
	snapshot.RunnerState = "runner_broken"
	snapshot.ReasonCode = "runner_health_failed"
	snapshot.ListeningReady = false
	snapshot.ProcessRunning = true
	snapshot.RecoveryAttempts = attemptsCount
	snapshot.RemainingRetryCount = remaining
	snapshot.FrontmostQueryEnabled = frontmostEnabled
	a.setGuardRuntimeSnapshot(snapshot)
	return false
}

// queryRunnerGuardState 查询当前 runner 是否可视为守护 ready。
// 参数：cfg 为当前配置。
// 返回：runner 状态、是否 ready、失败原因码。
func (a *Agent) queryRunnerGuardState(cfg Config) (string, bool, string) {
	if a.runnerPid.Load() <= 0 {
		return "runner_down", false, ""
	}
	health, err := a.getRunnerRPCHealth()
	if err != nil {
		return "runner_broken", false, "runner_health_failed"
	}
	if !health.ScriptReady {
		graceMs := int64(maxInt(cfg.WhatsApp.ForegroundStableMs, cfg.WhatsApp.HealthCheckMs*2))
		if graceMs <= 0 {
			graceMs = 3000
		}
		if health.StartedAtMs > 0 && time.Now().UnixMilli()-health.StartedAtMs < graceMs {
			return "runner_starting", false, ""
		}
		return "runner_broken", false, "runner_health_failed"
	}
	return "runner_ready", true, ""
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
			continue
		}
		return parsePSContainsWhatsApp(string(out)), nil
	}
	if lastErr == nil {
		lastErr = errors.New("ps not available")
	}
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
