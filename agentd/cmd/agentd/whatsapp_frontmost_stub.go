//go:build !ios

package main

import "errors"

// guardFrontmostQueryEnabled 返回当前构建是否具备宿主直接 frontmost 真查询能力。
// 参数：无。
// 返回：非 iOS 编译桩返回 false。
func guardFrontmostQueryEnabled() bool {
	return false
}

// detectWhatsAppFrontmost 为非 iOS 本地编译提供占位实现。
// 参数：无。
// 返回：固定返回不可用错误，不作为正式守护路径。
func (a *Agent) detectWhatsAppFrontmost() (bool, error) {
	return false, errors.New("frontmost query unavailable on non-ios build")
}
