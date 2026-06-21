package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// guardPersistentState 表示 guard crash loop 的本地持久化状态。
// 字段用途：保存恢复窗口时间戳和熔断标记，使 agentd 重启后仍能保持一致口径。
type guardPersistentState struct {
	RecoveryAttemptsMs []int64 `json:"recoveryAttemptsMs"`
	Blocked            bool    `json:"blocked"`
	UpdatedAtMs        int64   `json:"updatedAtMs"`
}

// defaultGuardStorePath 根据当前配置计算守护状态文件路径。
// 参数：cfg 为当前配置。
// 返回：守护状态文件绝对路径。
func defaultGuardStorePath(cfg Config) string {
	baseDir := filepath.Dir(stringsTrimSpaceOrFallback(cfg.DeviceIDPath, "."))
	return filepath.Join(baseDir, "guard_state.json")
}

// initGuardPersistentState 初始化 guard 本地持久化状态。
// 参数：cfg 为当前配置。
// 返回：初始化失败时返回错误。
func (a *Agent) initGuardPersistentState(cfg Config) error {
	path := defaultGuardStorePath(cfg)
	state, err := loadGuardPersistentState(path)
	if err != nil {
		return err
	}
	a.guardPersistMu.Lock()
	a.guardStorePath = path
	a.guardRecoveryAttempts = cloneGuardAttempts(state.RecoveryAttemptsMs)
	a.guardRecoveryBlocked = state.Blocked
	a.guardForceRecover = false
	a.guardPersistMu.Unlock()
	return nil
}

// loadGuardPersistentState 从磁盘加载 guard 持久化状态。
// 参数：path 为状态文件路径。
// 返回：持久化状态和加载错误。
func loadGuardPersistentState(path string) (guardPersistentState, error) {
	var state guardPersistentState
	if stringsTrimSpaceOrFallback(path, "") == "" {
		return state, errors.New("guard store path empty")
	}
	bs, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return state, nil
		}
		return state, err
	}
	if len(bs) == 0 {
		return state, nil
	}
	if err := json.Unmarshal(bs, &state); err != nil {
		return state, err
	}
	state.RecoveryAttemptsMs = sanitizeGuardAttempts(state.RecoveryAttemptsMs)
	return state, nil
}

// getGuardRecoveryState 读取当前内存态的 crash loop 计数和熔断标记。
// 参数：无。
// 返回：恢复时间戳切片副本和当前熔断标记。
func (a *Agent) getGuardRecoveryState() ([]int64, bool) {
	a.guardPersistMu.Lock()
	defer a.guardPersistMu.Unlock()
	return cloneGuardAttempts(a.guardRecoveryAttempts), a.guardRecoveryBlocked
}

// replaceGuardRecoveryState 原子更新内存和磁盘中的 crash loop 状态。
// 参数：attempts 为最新恢复时间戳；blocked 表示是否熔断。
// 返回：写盘失败时返回错误。
func (a *Agent) replaceGuardRecoveryState(attempts []int64, blocked bool) error {
	a.guardPersistMu.Lock()
	defer a.guardPersistMu.Unlock()
	return a.replaceGuardRecoveryStateLocked(attempts, blocked)
}

// clearGuardRecoveryState 清空 crash loop 计数和熔断标记。
// 参数：无。
// 返回：写盘失败时返回错误。
func (a *Agent) clearGuardRecoveryState() error {
	return a.replaceGuardRecoveryState(nil, false)
}

// isGuardRecoveryBlocked 返回当前是否处于 crash loop 熔断状态。
// 参数：无。
// 返回：已熔断返回 true，否则返回 false。
func (a *Agent) isGuardRecoveryBlocked() bool {
	_, blocked := a.getGuardRecoveryState()
	return blocked
}

// trimGuardRecoveryAttemptsPersisted 裁剪窗口外恢复记录并同步回磁盘。
// 参数：nowMs 为当前毫秒时间；windowMs 为恢复窗口毫秒数。
// 返回：裁剪后记录数、是否熔断和可能的写盘错误。
func (a *Agent) trimGuardRecoveryAttemptsPersisted(nowMs int64, windowMs int) (int, bool, error) {
	attempts, blocked := a.getGuardRecoveryState()
	before := len(attempts)
	count := trimGuardRecoveryAttempts(nowMs, windowMs, &attempts)
	if count != before {
		if err := a.replaceGuardRecoveryState(attempts, blocked); err != nil {
			return before, blocked, err
		}
	}
	return count, blocked, nil
}

// appendGuardRecoveryAttemptPersisted 追加一次恢复记录并把结果写回磁盘。
// 参数：nowMs 为当前毫秒时间；windowMs 为恢复窗口毫秒数；maxAttempts 为窗口内最大允许次数。
// 返回：本轮序号、是否已熔断、窗口内总次数和可能的写盘错误。
func (a *Agent) appendGuardRecoveryAttemptPersisted(nowMs int64, windowMs int, maxAttempts int) (int, bool, int, error) {
	attempts, blocked := a.getGuardRecoveryState()
	attemptNo, appendBlocked, count := appendGuardRecoveryAttempt(nowMs, windowMs, maxAttempts, &attempts)
	if blocked {
		appendBlocked = true
	}
	if err := a.replaceGuardRecoveryState(attempts, appendBlocked); err != nil {
		return attemptNo, appendBlocked, count, err
	}
	return attemptNo, appendBlocked, count, nil
}

// setGuardForceRecoverRequest 设置一次手工恢复请求。
// 参数：requested 表示是否请求手工恢复。
// 返回：无。
func (a *Agent) setGuardForceRecoverRequest(requested bool) {
	a.guardPersistMu.Lock()
	a.guardForceRecover = requested
	a.guardPersistMu.Unlock()
}

// consumeGuardForceRecoverRequest 读取并消费一次手工恢复请求。
// 参数：无。
// 返回：存在未消费请求时返回 true。
func (a *Agent) consumeGuardForceRecoverRequest() bool {
	a.guardPersistMu.Lock()
	defer a.guardPersistMu.Unlock()
	if !a.guardForceRecover {
		return false
	}
	a.guardForceRecover = false
	return true
}

// persistGuardRecoveryState 将当前 crash loop 状态写入磁盘。
// 参数：attempts 为恢复时间戳；blocked 表示是否熔断。
// 返回：写盘失败时返回错误。
func (a *Agent) persistGuardRecoveryState(attempts []int64, blocked bool) error {
	if stringsTrimSpaceOrFallback(a.guardStorePath, "") == "" {
		return errors.New("guard store path not initialized")
	}
	state := guardPersistentState{
		RecoveryAttemptsMs: cloneGuardAttempts(attempts),
		Blocked:            blocked,
		UpdatedAtMs:        time.Now().UnixMilli(),
	}
	bs, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	bs = append(bs, '\n')
	if err := os.MkdirAll(filepath.Dir(a.guardStorePath), 0o755); err != nil {
		return err
	}
	tmpPath := a.guardStorePath + ".tmp"
	if err := os.WriteFile(tmpPath, bs, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpPath, a.guardStorePath)
}

// replaceGuardRecoveryStateLocked 在 guardPersistMu 已持有时更新持久化状态。
// 参数：attempts 为最新恢复时间戳；blocked 表示是否熔断。
// 返回：写盘失败时返回错误。
func (a *Agent) replaceGuardRecoveryStateLocked(attempts []int64, blocked bool) error {
	attempts = sanitizeGuardAttempts(attempts)
	if err := a.persistGuardRecoveryState(attempts, blocked); err != nil {
		return err
	}
	a.guardRecoveryAttempts = cloneGuardAttempts(attempts)
	a.guardRecoveryBlocked = blocked
	return nil
}

// sanitizeGuardAttempts 过滤无效恢复时间戳，避免脏数据进入窗口计算。
// 参数：attempts 为原始恢复时间戳。
// 返回：过滤后的恢复时间戳切片。
func sanitizeGuardAttempts(attempts []int64) []int64 {
	if len(attempts) == 0 {
		return nil
	}
	dst := make([]int64, 0, len(attempts))
	for _, ts := range attempts {
		if ts > 0 {
			dst = append(dst, ts)
		}
	}
	return dst
}

// cloneGuardAttempts 复制恢复时间戳切片，避免外部直接改写内部状态。
// 参数：attempts 为原始恢复时间戳。
// 返回：恢复时间戳副本。
func cloneGuardAttempts(attempts []int64) []int64 {
	if len(attempts) == 0 {
		return nil
	}
	out := make([]int64, len(attempts))
	copy(out, attempts)
	return out
}

// stringsTrimSpaceOrFallback 返回去空白后的值；若为空则返回 fallback。
// 参数：value 为原始字符串；fallback 为空时的回退值。
// 返回：去空白后的字符串或 fallback。
func stringsTrimSpaceOrFallback(value string, fallback string) string {
	value = strings.TrimSpace(value)
	if value != "" {
		return value
	}
	return fallback
}
