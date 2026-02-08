# agentd（iOS rootless）deb 打包

目标：把 `agentd` 以 rootless `.deb` 形式安装到手机，并通过 `LaunchDaemon(com.qqw.agentd)` 常驻运行。

## 目录结构
- `layout/`：deb 内容布局（rootless 路径以 `/var/jb` 为前缀）
- `build.sh`：把 `dist/agentd-ios-arm64` 填入 layout 并输出 deb

## 在手机上构建 deb（推荐）
```sh
cd /var/mobile/Library/QQwDev/QQw/agentd/ios-deb
chmod 755 build.sh layout/DEBIAN/postinst layout/DEBIAN/prerm
./build.sh ../dist/agentd-ios-arm64 0.1.0-1
```

生成 deb：
```sh
ls -la packages/*.deb
```

安装：
```sh
dpkg -i packages/com.qqw.agentd_*.deb
```

验证：
```sh
curl -sS http://127.0.0.1:17171/status || true
tail -n 200 /private/var/tmp/qqwagentd-postinst.log 2>/dev/null || true
tail -n 200 /var/mobile/Library/QQwAgent/agent.log 2>/dev/null || true
```

## 与 QQwApp Updater 配合（推荐）
若已安装 QQwApp（方案 1），系统会有 `com.qqw.updater` 常驻进程自动安装 agentd deb：
- 将 deb 放入：`/var/mobile/Library/QQwUpdates/`
  - `agentd.deb`
  - 或 `com.qqw.agentd_*.deb`
- 等待 60 秒内自动安装并尝试重启 agentd
- 查看状态与日志：
  - `/var/mobile/Library/QQwUpdates/status.json`
  - `/var/mobile/Library/QQwUpdates/updater.log`

## 配置文件
- `agent.json` 默认路径：`/var/mobile/Library/QQwAgent/agent.json`
- 包内只提供 `agent.json.sample`，postinst 会在 `agent.json` 缺失时复制生成，避免覆盖已有配置。
