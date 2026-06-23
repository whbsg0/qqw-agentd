//go:build !ios

package main

import "time"

// queryFrontmostProbeOnce 在非 iOS 构建下返回“平台不支持”的固定结果。
// 参数：fridaHost 为 frida 主机；fridaPort 为 frida 端口；timeoutMs 为单次探测超时。
// 返回：固定的失败快照，提示当前平台不支持 frontmost-probe。
func queryFrontmostProbeOnce(fridaHost string, fridaPort int, timeoutMs int) frontmostProbeSnapshot {
	return frontmostProbeSnapshot{
		Ok:           false,
		Source:       "frontmost-probe.unsupported",
		SampleAtMs:   time.Now().UnixMilli(),
		Retryable:    false,
		ErrorCode:    "unsupported_platform",
		ErrorMessage: "frontmost probe only supported on ios",
	}
}
