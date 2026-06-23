package main

import (
	"strings"
	"time"
)

// deriveGuardRuntimeSnapshot 根据最新 probe 与恢复控制面派生统一 guard 真值。
// 参数：cfg 为当前配置；probes 为最新 probe 快照；attemptsCount 为窗口内恢复次数；blocked 表示是否熔断；recovery 为恢复执行状态；now 为当前时间；confirmStartedAt 为前台确认窗口起点。
// 返回：统一派生后的 guard 运行态快照。
func deriveGuardRuntimeSnapshot(
	cfg Config,
	probes guardProbeSnapshot,
	attemptsCount int,
	blocked bool,
	recovery guardRecoveryStatus,
	now time.Time,
	confirmStartedAt *time.Time,
) guardRuntimeSnapshot {
	nowMs := now.UnixMilli()
	frontmostEnabled := guardFrontmostQueryEnabled()
	snapshot := defaultGuardRuntimeSnapshot(cfg)
	snapshot.ProcessRunning = probes.Process.Running
	snapshot.ProcessProbeErr = strings.TrimSpace(probes.Process.Err)
	snapshot.ProcessSampleAtMs = probes.Process.SampleAtMs
	snapshot.Frontmost = probes.Frontmost.Running
	snapshot.FrontmostErr = strings.TrimSpace(probes.Frontmost.Err)
	snapshot.FrontmostSampleAtMs = probes.Frontmost.SampleAtMs
	snapshot.FrontmostFresh = !frontmostEnabled || !probes.Process.Running || guardTimestampFresh(probes.Frontmost.SampleAtMs, guardFrontmostFreshnessThresholdMs(cfg), nowMs)
	snapshot.FrontmostSource = strings.TrimSpace(probes.Frontmost.Source)
	snapshot.FrontmostObservedID = strings.TrimSpace(probes.Frontmost.ObservedBundleID)
	snapshot.FrontmostDetail = strings.TrimSpace(probes.Frontmost.Detail)
	snapshot.RunnerProcessAlive = probes.Runner.RunnerProcessAlive
	snapshot.RunnerPid = probes.Runner.RunnerPid
	snapshot.RunnerRPCOK = probes.Runner.RunnerRPCOK
	snapshot.ScriptReady = probes.Runner.ScriptReady
	snapshot.RunnerScriptBuild = strings.TrimSpace(probes.Runner.ScriptBuild)
	snapshot.RunnerScriptSha256 = strings.TrimSpace(probes.Runner.ScriptSha256)
	snapshot.RunnerSampleAtMs = probes.Runner.SampleAtMs
	snapshot.RunnerLastHealthErr = strings.TrimSpace(probes.Runner.LastHealthErr)
	snapshot.RunnerLastHealthErrAtMs = probes.Runner.LastHealthErrAtMs
	snapshot.ScriptInstalledPath = strings.TrimSpace(probes.Runner.InstalledScriptPath)
	snapshot.ScriptInstalledUpdatedAtMs = probes.Runner.InstalledScriptUpdatedAt
	snapshot.ScriptInstalledBuild = strings.TrimSpace(probes.Runner.InstalledScriptBuild)
	snapshot.ScriptInstalledSha256 = strings.TrimSpace(probes.Runner.InstalledScriptSha256)
	snapshot.ScriptLastEventTsMs = probes.Runner.ScriptLastEventTsMs
	snapshot.ScriptLastPongTsMs = probes.Runner.ScriptLastPongTsMs
	snapshot.ScriptEventFresh = probes.Runner.ScriptEventFresh
	snapshot.ScriptPongFresh = probes.Runner.ScriptPongFresh
	snapshot.ScriptBuildMatch = probes.Runner.ScriptBuildMatch
	snapshot.ScriptSha256Match = probes.Runner.ScriptSha256Match
	snapshot.ProbeEpoch = guardMaxInt64(probes.Process.Epoch, guardMaxInt64(probes.Frontmost.Epoch, probes.Runner.Epoch))
	snapshot.RecoveryEpoch = recovery.Epoch
	snapshot.RecoveryAttempts = attemptsCount
	snapshot.RemainingRetryCount = clampRemainingRetries(cfg.WhatsApp.MaxRecoveryAttempts, attemptsCount)
	snapshot.NextRetryAtMs = recovery.NextRetryAtMs
	snapshot.LastRecoveryAtMs = recovery.LastRecoveryAtMs
	snapshot.RecoveryInFlight = recovery.InFlight
	snapshot.RecoveryPending = recovery.Pending
	snapshot.RecoveryAction = strings.TrimSpace(recovery.Action)
	snapshot.RecoveryRequestedState = strings.TrimSpace(recovery.TargetState)
	snapshot.RecoveryRequestedReason = strings.TrimSpace(recovery.ReasonCode)
	snapshot.FrontmostQueryEnabled = frontmostEnabled
	snapshot.RunnerState = deriveRunnerState(cfg, probes.Runner, nowMs)

	if probes.Runner.RunnerProcessAlive && probes.Runner.ScriptForegroundKnown && probes.Runner.ScriptForegroundFresh {
		snapshot.Frontmost = probes.Runner.ScriptForegroundActive
		snapshot.FrontmostErr = ""
		snapshot.FrontmostSampleAtMs = guardMaxInt64(snapshot.FrontmostSampleAtMs, probes.Runner.ScriptForegroundSampleAt)
		snapshot.FrontmostFresh = true
		snapshot.FrontmostSource = firstNonEmpty(strings.TrimSpace(probes.Runner.ScriptForegroundSource), "runner.qqw_pong")
		if snapshot.Frontmost {
			snapshot.FrontmostObservedID = firstNonEmpty(strings.TrimSpace(cfg.WhatsApp.BundleID), "net.whatsapp.WhatsApp")
		} else {
			snapshot.FrontmostObservedID = ""
		}
		stateText := strings.TrimSpace(probes.Runner.ScriptForegroundState)
		if stateText == "" {
			stateText = "unknown"
		}
		snapshot.FrontmostDetail = strings.TrimSpace("source=" + snapshot.FrontmostSource + "; appState=" + stateText + "; foreground=" + strings.ToLower(firstNonEmpty(boolText(snapshot.Frontmost), "false")))
	}

	if !cfg.WhatsApp.AutoGuardEnabled {
		*confirmStartedAt = time.Time{}
		snapshot.GuardEnabled = false
		snapshot.State = "guard_off"
		snapshot.GuardState = "guard_off"
		snapshot.ReasonCode = "guard_switch_off"
		return snapshot
	}
	snapshot.GuardEnabled = true

	if blocked {
		*confirmStartedAt = time.Time{}
		snapshot.State = "wa_crash_loop_blocked"
		snapshot.GuardState = "wa_crash_loop_blocked"
		snapshot.ReasonCode = "recovery_retry_exhausted"
		snapshot.ListeningReady = false
		return snapshot
	}

	if probes.Process.SampleAtMs <= 0 {
		snapshot.State = "wa_process_probe_failed"
		snapshot.GuardState = "wa_process_probe_failed"
		snapshot.ReasonCode = "probe_not_sampled_yet"
		return snapshot
	}
	if snapshot.ProcessProbeErr != "" {
		*confirmStartedAt = time.Time{}
		snapshot.State = "wa_process_probe_failed"
		snapshot.GuardState = "wa_process_probe_failed"
		snapshot.ReasonCode = "wa_process_probe_failed"
		return snapshot
	}
	if !probes.Process.Running {
		*confirmStartedAt = time.Time{}
		snapshot.State = "wa_process_missing"
		snapshot.GuardState = "wa_process_missing"
		snapshot.ReasonCode = "wa_process_missing"
		return snapshot
	}

	if frontmostEnabled {
		if !snapshot.FrontmostFresh {
			*confirmStartedAt = time.Time{}
			snapshot.State = "wa_frontmost_stale"
			snapshot.GuardState = "wa_frontmost_stale"
			snapshot.ReasonCode = "wa_frontmost_stale"
			return snapshot
		}
		if snapshot.FrontmostErr != "" {
			*confirmStartedAt = time.Time{}
			snapshot.State = "wa_frontmost_query_failed"
			snapshot.GuardState = "wa_frontmost_query_failed"
			snapshot.ReasonCode = "wa_frontmost_query_failed"
			return snapshot
		}
		if !snapshot.Frontmost {
			if confirmStartedAt.IsZero() {
				*confirmStartedAt = now
				snapshot.State = "wa_wait_foreground_confirm"
				snapshot.GuardState = "wa_wait_foreground_confirm"
				snapshot.ReasonCode = "wa_not_frontmost"
				return snapshot
			}
			if now.Sub(*confirmStartedAt) < time.Duration(cfg.WhatsApp.ForegroundConfirmMs)*time.Millisecond {
				snapshot.State = "wa_wait_foreground_confirm"
				snapshot.GuardState = "wa_wait_foreground_confirm"
				snapshot.ReasonCode = "wa_not_frontmost"
				return snapshot
			}
			snapshot.State = "wa_background"
			snapshot.GuardState = "wa_background"
			snapshot.ReasonCode = "wa_not_frontmost"
			return snapshot
		}
	}
	*confirmStartedAt = time.Time{}

	switch snapshot.RunnerState {
	case "runner_starting":
		snapshot.State = "runner_starting"
		snapshot.GuardState = "runner_starting"
		snapshot.ReasonCode = ""
		return snapshot
	case "runner_down":
		snapshot.State = "runner_health_failed"
		snapshot.GuardState = "runner_health_failed"
		snapshot.ReasonCode = "runner_process_missing"
		return snapshot
	case "runner_broken":
		snapshot.State = "runner_health_failed"
		snapshot.GuardState = "runner_health_failed"
		snapshot.ReasonCode = firstNonEmpty(snapshot.RunnerLastHealthErr, "runner_health_failed")
		return snapshot
	case "runner_not_ready":
		snapshot.State = "runner_not_ready"
		snapshot.GuardState = "runner_not_ready"
		snapshot.ReasonCode = "runner_not_ready"
		return snapshot
	case "runner_script_mismatch":
		snapshot.State = "runner_script_mismatch"
		snapshot.GuardState = "runner_script_mismatch"
		snapshot.ReasonCode = "runner_script_mismatch"
		return snapshot
	case "runner_unresponsive":
		snapshot.State = "script_unresponsive"
		snapshot.GuardState = "script_unresponsive"
		snapshot.ReasonCode = "script_pong_stale"
		return snapshot
	default:
		snapshot.State = "wa_foreground_ready"
		snapshot.GuardState = "wa_foreground_ready"
		snapshot.ReasonCode = ""
		snapshot.ListeningReady = true
		return snapshot
	}
}

// deriveRunnerState 根据 runner probe 派生 runner 子状态。
// 参数：cfg 为当前配置；probe 为 runner probe 结果；nowMs 为当前毫秒时间。
// 返回：runner 子状态字符串。
func deriveRunnerState(cfg Config, probe runnerProbeResult, nowMs int64) string {
	if !probe.RunnerProcessAlive {
		return "runner_down"
	}
	if !probe.RunnerRPCOK {
		return "runner_broken"
	}
	if !probe.ScriptReady {
		if probe.StartedAtMs > 0 && nowMs-probe.StartedAtMs < guardRunnerStartingGraceMs(cfg) {
			return "runner_starting"
		}
		return "runner_not_ready"
	}
	if !probe.ScriptBuildMatch || !probe.ScriptSha256Match {
		return "runner_script_mismatch"
	}
	if !probe.ScriptPongFresh {
		return "runner_unresponsive"
	}
	return "runner_ready"
}

// boolText 将布尔值转为稳定文本，便于拼接 detail 摘要。
// 参数：v 为布尔值。
// 返回：true/false 文本。
func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

// guardMaxInt64 返回两个 int64 中的较大值。
// 参数：a、b 为待比较的两个值。
// 返回：较大值。
func guardMaxInt64(a, b int64) int64 {
	if a >= b {
		return a
	}
	return b
}
