# Go 反向 Frida Agent（MVP）

目标：在手机必须使用 Shadowrocket 的情况下，让手机保持出站连接到云端，云端通过反向通道访问手机本机 `127.0.0.1:27042` 的 frida-server。

## 组件
- agentd：部署到 iOS 越狱手机常驻运行，WSS 长连接 + frida TCP 转发
- broker：部署到 ECS-3（控制平面），接收 agent WSS，提供本地端口桥接（MVP）

## Broker（云端）
启动：
```bash
BROKER_ADDR=:8080 ./broker
```

WebSocket：
- `ws://<host>:8080/agent/ws`

HTTP API：
- `GET /api/devices`
- `POST /api/open?deviceId=<deviceId>` → 返回 `localPort`，本机连接 `127.0.0.1:<localPort>` 会被转发到该设备 frida

生产建议：
- 使用 Nginx/ALB 把 `wss://api.yourdomain.com/agent/ws` 反代到 `broker:8080/agent/ws`
- 仅对公网暴露 443

## Agent（手机端）
配置文件示例见 `examples/agent.json`。

启动：
```bash
./agentd /var/mobile/Library/QQwAgent/agent.json
```

要求：
- frida-server 监听在 `127.0.0.1:27042`

本地控制口（可选）：
- 在 `agent.json` 配置 `controlListen`（建议 `127.0.0.1:17171`）后，agentd 会额外监听一个本地 HTTP 控制口：
  - `GET /status`：返回 deviceId/serverUrl/connected/uptime 等
  - `GET /config`：返回当前配置文件内容
  - `POST /config`：写入配置文件（写入后通常需要 `POST /quit` 触发 launchd 拉起新进程生效）
  - `POST /quit`：优雅退出（用于配合 launchd 实现“重启”）

## 快速联调
1) 云端启动 broker（8080）
2) 手机启动 agentd，serverUrl 指向 `wss://.../agent/ws`（经反代）
3) 云端查询在线设备 `GET /api/devices`
4) 云端请求通道 `POST /api/open?deviceId=...`
5) 在 broker 机器本地连接 `127.0.0.1:<localPort>` 验证 frida 协议可通
