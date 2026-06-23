package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"
)

// guardRecoveryTask 表示 supervisor 投递给 recovery worker 的一次恢复任务。
// 字段用途：将“恢复目标状态 / 原因 / 动作链”从派生层解耦给执行层。
type guardRecoveryTask struct {
	GuardState string
	ReasonCode string
	Manual     bool
	Actions    []string
}

// guardRecoveryStatus 表示 recovery worker 当前的控制面状态。
// 字段用途：供 supervisor 与 `/guard/status` 查询恢复是否排队、执行中与下一次可重试时间。
type guardRecoveryStatus struct {
	InFlight         bool
	Pending          bool
	Action           string
	TargetState      string
	ReasonCode       string
	NextRetryAtMs    int64
	LastRecoveryAtMs int64
	Epoch            int64
}

// getGuardRecoveryStatus 读取当前恢复控制面状态。
// 参数：无。
// 返回：恢复控制面状态副本。
func (a *Agent) getGuardRecoveryStatus() guardRecoveryStatus {
	a.guardRecoveryMu.RLock()
	defer a.guardRecoveryMu.RUnlock()
	return a.guardRecoveryState
}

// setGuardRecoveryStatus 原子更新恢复控制面状态。
// 参数：status 为新的恢复控制面状态。
// 返回：无。
func (a *Agent) setGuardRecoveryStatus(status guardRecoveryStatus) {
	a.guardRecoveryMu.Lock()
	a.guardRecoveryState = status
	a.guardRecoveryMu.Unlock()
	a.wakeGuardLoop()
}

// clearGuardRecoverySchedule 清理恢复排队与执行中的控制面状态。
// 参数：无。
// 返回：无。
func (a *Agent) clearGuardRecoverySchedule() {
	a.guardRecoveryMu.Lock()
	status := a.guardRecoveryState
	status.InFlight = false
	status.Pending = false
	status.Action = ""
	status.TargetState = ""
	status.ReasonCode = ""
	status.NextRetryAtMs = 0
	a.guardRecoveryState = status
	a.guardRecoveryMu.Unlock()
	a.wakeGuardLoop()
}

// maybeScheduleGuardRecovery 根据当前派生状态决定是否投递恢复任务。
// 参数：cfg 为当前配置；snapshot 为当前统一派生快照；manual 表示是否为人工恢复请求。
// 返回：成功投递返回 true，否则返回 false。
func (a *Agent) maybeScheduleGuardRecovery(cfg Config, snapshot guardRuntimeSnapshot, manual bool) bool {
	task, ok := buildGuardRecoveryTask(snapshot, manual)
	if !ok {
		return false
	}
	nowMs := time.Now().UnixMilli()
	a.guardRecoveryMu.Lock()
	status := a.guardRecoveryState
	if status.InFlight || status.Pending {
		a.guardRecoveryMu.Unlock()
		return false
	}
	if !manual && status.NextRetryAtMs > nowMs {
		a.guardRecoveryMu.Unlock()
		return false
	}
	status.Pending = true
	status.Action = joinGuardRecoveryActions(task.Actions)
	status.TargetState = strings.TrimSpace(task.GuardState)
	status.ReasonCode = strings.TrimSpace(task.ReasonCode)
	a.guardRecoveryState = status
	a.guardRecoveryMu.Unlock()
	select {
	case a.guardRecoveryQueue <- task:
		a.wakeGuardLoop()
		return true
	default:
		a.clearGuardRecoverySchedule()
		return false
	}
}

// runGuardRecoveryWorker 串行执行恢复动作，避免与 supervisor 共享阻塞调用。
// 参数：ctx 为 worker 生命周期上下文。
// 返回：无。
func (a *Agent) runGuardRecoveryWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-a.guardRecoveryQueue:
			a.executeGuardRecoveryTask(ctx, task)
		}
	}
}

// executeGuardRecoveryTask 执行一次完整恢复任务。
// 参数：ctx 为 worker 生命周期上下文；task 为待执行的恢复任务。
// 返回：无。
func (a *Agent) executeGuardRecoveryTask(ctx context.Context, task guardRecoveryTask) {
	cfg := a.getCfg()
	nowMs := time.Now().UnixMilli()
	attemptNo, blocked, _, err := a.appendGuardRecoveryAttemptPersisted(nowMs, cfg.WhatsApp.RecoveryWindowMs, cfg.WhatsApp.MaxRecoveryAttempts)
	status := a.getGuardRecoveryStatus()
	status.Pending = false
	status.InFlight = false
	status.TargetState = strings.TrimSpace(task.GuardState)
	status.ReasonCode = strings.TrimSpace(task.ReasonCode)
	status.Action = joinGuardRecoveryActions(task.Actions)
	if err != nil {
		a.recordGuardAction("guard_store_append", err)
		a.setGuardRecoveryStatus(status)
		return
	}
	if blocked {
		status.NextRetryAtMs = 0
		status.Epoch = a.guardRecoveryEpoch.Load()
		a.setGuardRecoveryStatus(status)
		return
	}
	backoff := guardRecoveryBackoff(attemptNo)
	status.InFlight = true
	status.Epoch = a.guardRecoveryEpoch.Add(1)
	if backoff > 0 {
		status.NextRetryAtMs = time.Now().Add(backoff).UnixMilli()
	} else {
		status.NextRetryAtMs = 0
	}
	a.setGuardRecoveryStatus(status)
	if backoff > 0 && !waitGuardDuration(ctx, a.guardWake, backoff) {
		a.clearGuardRecoverySchedule()
		return
	}
	if !a.getCfg().WhatsApp.AutoGuardEnabled {
		a.clearGuardRecoverySchedule()
		return
	}
	lastErr := a.executeGuardRecoveryActions(task)
	if lastErr != nil {
		a.recordGuardAction("guard_recovery_failed", lastErr)
	} else {
		a.recordGuardAction("guard_recovery_applied", nil)
	}
	status = a.getGuardRecoveryStatus()
	status.InFlight = false
	status.Pending = false
	status.NextRetryAtMs = 0
	status.LastRecoveryAtMs = time.Now().UnixMilli()
	a.setGuardRecoveryStatus(status)
	a.wakeGuardLoop()
}

// executeGuardRecoveryActions 顺序执行一条恢复动作链。
// 参数：task 为待执行的恢复任务。
// 返回：任一步失败时返回错误；全部成功返回 nil。
func (a *Agent) executeGuardRecoveryActions(task guardRecoveryTask) error {
	if len(task.Actions) == 0 {
		return nil
	}
	for idx, action := range task.Actions {
		if err := a.executeGuardRecoveryAction(action); err != nil {
			return err
		}
		if idx < len(task.Actions)-1 {
			time.Sleep(600 * time.Millisecond)
		}
	}
	return nil
}

// executeGuardRecoveryAction 执行单个恢复动作。
// 参数：action 为动作名。
// 返回：动作失败时返回错误。
func (a *Agent) executeGuardRecoveryAction(action string) error {
	cfg := a.getCfg()
	switch strings.TrimSpace(action) {
	case "open_whatsapp":
		return a.launchWhatsApp()
	case "restart_runner":
		if err := a.stopRunnerIfRunning(); err != nil {
			return err
		}
		return a.startRunner()
	case "restart_frontmost_probe":
		if err := a.stopFrontmostProbeIfRunning(); err != nil {
			return err
		}
		return a.startFrontmostProbe()
	case "restart_frida_server":
		return a.restartFridaService(cfg)
	case "restart_agentd":
		return a.restartAgentdService()
	case "open_whatsapp_after_recover":
		return a.launchWhatsApp()
	default:
		return errors.New("unsupported recovery action: " + action)
	}
}

// restartFridaService 优先通过 launchctl 重启 frida-server，并轮询端口 ready。
// 参数：cfg 为当前配置。
// 返回：服务未能在等待窗口内 ready 时返回错误。
func (a *Agent) restartFridaService(cfg Config) error {
	host := strings.TrimSpace(cfg.Frida.Host)
	port := cfg.Frida.Port
	if launchctlPath := guardLaunchctlPath(); launchctlPath != "" {
		cmd := exec.Command(launchctlPath, "kickstart", "-k", "system/re.frida.server")
		cmd.Env = append(os.Environ(), "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin")
		if out, err := cmd.CombinedOutput(); err == nil {
			if err := waitTCPReady(host, port, 8*time.Second, 250*time.Millisecond); err == nil {
				return nil
			}
		} else {
			msg := strings.TrimSpace(string(out))
			if msg != "" {
				err = errors.New(msg)
			}
			_ = err
		}
	}
	if err := ensureFridaUp(host, port, cfg.Frida.StartCmd); err != nil {
		return err
	}
	return waitTCPReady(host, port, 5*time.Second, 250*time.Millisecond)
}

// restartAgentdService 通过 launchctl 请求重启当前 agentd 服务。
// 参数：无。
// 返回：命令启动失败时返回错误。
func (a *Agent) restartAgentdService() error {
	launchctlPath := guardLaunchctlPath()
	if launchctlPath == "" {
		launchctlPath = "launchctl"
	}
	cmd := exec.Command(launchctlPath, "kickstart", "-k", "system/com.qqw.agentd")
	cmd.Env = append(os.Environ(), "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	return cmd.Start()
}

// guardLaunchctlPath 返回当前设备上可用的 launchctl 可执行路径。
// 参数：无。
// 返回：找到则返回绝对路径，否则返回空串。
func guardLaunchctlPath() string {
	for _, p := range []string{"/var/jb/usr/bin/launchctl", "/var/jb/bin/launchctl", "/usr/bin/launchctl", "/bin/launchctl"} {
		if firstExistingFile(p) != "" {
			return p
		}
	}
	return ""
}

// waitTCPReady 在限定窗口内轮询目标 TCP 地址是否已准备完成。
// 参数：host 为目标主机；port 为目标端口；timeout 为总等待时间；interval 为轮询间隔。
// 返回：连通返回 nil；超时返回最后一次拨号错误。
func waitTCPReady(host string, port int, timeout time.Duration, interval time.Duration) error {
	host = strings.TrimSpace(host)
	if host == "" || port <= 0 {
		return errors.New("frida host/port missing")
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if interval <= 0 {
		interval = 250 * time.Millisecond
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	deadline := time.Now().Add(timeout)
	var lastErr error
	for {
		conn, err := net.DialTimeout("tcp", addr, interval)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(interval)
	}
	if lastErr != nil {
		return lastErr
	}
	return errors.New("tcp ready wait timeout")
}

// buildGuardRecoveryTask 根据当前派生状态构造恢复任务。
// 参数：snapshot 为当前统一派生快照；manual 表示是否为人工恢复请求。
// 返回：恢复任务和是否需要调度。
func buildGuardRecoveryTask(snapshot guardRuntimeSnapshot, manual bool) (guardRecoveryTask, bool) {
	state := strings.TrimSpace(snapshot.GuardState)
	reason := strings.TrimSpace(snapshot.ReasonCode)
	switch state {
	case "wa_process_missing":
		return guardRecoveryTask{GuardState: state, ReasonCode: reason, Manual: manual, Actions: []string{"open_whatsapp"}}, true
	case "runner_not_ready", "runner_script_mismatch", "runner_health_failed":
		return guardRecoveryTask{GuardState: state, ReasonCode: reason, Manual: manual, Actions: []string{"restart_runner"}}, true
	case "script_unresponsive":
		actions := []string{"restart_runner"}
		if snapshot.RecoveryAttempts >= 2 {
			actions = []string{"restart_frida_server", "restart_agentd", "open_whatsapp_after_recover"}
		}
		return guardRecoveryTask{GuardState: state, ReasonCode: reason, Manual: manual, Actions: actions}, true
	case "wa_frontmost_query_failed", "wa_frontmost_stale":
		if shouldDeferFrontmostRecoveryWhileRunnerStarting(snapshot) {
			return guardRecoveryTask{}, false
		}
		if state == "wa_frontmost_query_failed" && !manual && !shouldAutoRecoverFrontmostQueryFailure(snapshot.FrontmostErr) {
			return guardRecoveryTask{}, false
		}
		actions := []string{"restart_frontmost_probe"}
		if manual || snapshot.RecoveryAttempts >= 2 {
			actions = []string{"restart_frida_server", "restart_frontmost_probe", "open_whatsapp_after_recover"}
		}
		return guardRecoveryTask{GuardState: state, ReasonCode: reason, Manual: manual, Actions: actions}, true
	case "wa_process_probe_failed":
		if snapshot.RecoveryAttempts >= 2 || manual {
			return guardRecoveryTask{GuardState: state, ReasonCode: reason, Manual: manual, Actions: []string{"restart_agentd"}}, true
		}
		return guardRecoveryTask{}, false
	default:
		return guardRecoveryTask{}, false
	}
}

// shouldDeferFrontmostRecoveryWhileRunnerStarting 判断当前是否应暂缓 frontmost 侧恢复。
// 参数：snapshot 为当前统一派生快照。
// 返回：true 表示 runner 仍处于启动窗口，不应让 frontmost 恢复链打断其启动；false 表示可按常规恢复。
func shouldDeferFrontmostRecoveryWhileRunnerStarting(snapshot guardRuntimeSnapshot) bool {
	return strings.TrimSpace(snapshot.RunnerState) == "runner_starting" && snapshot.RunnerProcessAlive
}

// shouldAutoRecoverFrontmostQueryFailure 判断 frontmost 查询失败是否仍值得自动触发重启链。
// 参数：frontmostErr 为当前 frontmost probe 错误详情。
// 返回：true 表示更像瞬时链路错误，可继续自动恢复；false 表示为稳定逻辑型错误，应避免进入重启循环。
func shouldAutoRecoverFrontmostQueryFailure(frontmostErr string) bool {
	errText := strings.ToLower(strings.TrimSpace(frontmostErr))
	if errText == "" {
		return true
	}
	nonRecoverableMarkers := []string{
		"invalid front identifier",
		"returned nil",
		"invalid identifier type",
		"invalid name type",
	}
	for _, marker := range nonRecoverableMarkers {
		if strings.Contains(errText, marker) {
			return false
		}
	}
	return true
}

// joinGuardRecoveryActions 把恢复动作链格式化为便于展示的字符串。
// 参数：actions 为动作名列表。
// 返回：`->` 拼接后的动作链描述。
func joinGuardRecoveryActions(actions []string) string {
	if len(actions) == 0 {
		return ""
	}
	out := make([]string, 0, len(actions))
	for _, action := range actions {
		action = strings.TrimSpace(action)
		if action != "" {
			out = append(out, action)
		}
	}
	return strings.Join(out, " -> ")
}
