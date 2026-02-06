package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

type Config struct {
	ServerURL     string `json:"serverUrl"`
	RegisterToken string `json:"registerToken"`
	DeviceSecret  string `json:"deviceSecret"`
	DeviceIDPath  string `json:"deviceIdPath"`
	HeartbeatSec  int    `json:"heartbeatSec"`
	ControlListen string `json:"controlListen"`
	ControlToken  string `json:"controlToken"`
	Reconnect     struct {
		BaseMs   int `json:"baseMs"`
		MaxMs    int `json:"maxMs"`
		JitterMs int `json:"jitterMs"`
	} `json:"reconnect"`
	Frida struct {
		Host          string `json:"host"`
		Port          int    `json:"port"`
		EnsureRunning bool   `json:"ensureRunning"`
		StartCmd      string `json:"startCmd"`
	} `json:"frida"`
}

type Envelope struct {
	V        int             `json:"v"`
	Type     string          `json:"type"`
	DeviceID string          `json:"deviceId,omitempty"`
	Session  string          `json:"sessionId,omitempty"`
	TunnelID string          `json:"tunnelId,omitempty"`
	Seq      uint64          `json:"seq,omitempty"`
	TS       int64           `json:"ts,omitempty"`
	Payload  json.RawMessage `json:"payload,omitempty"`
}

type HelloPayload struct {
	RegisterToken    string                 `json:"registerToken,omitempty"`
	DeviceSecret     string                 `json:"deviceSecret,omitempty"`
	FridaServerVer   string                 `json:"fridaServerVersion,omitempty"`
	Capabilities     map[string]any         `json:"capabilities,omitempty"`
	AdditionalFields map[string]interface{} `json:"-"`
}

type HelloAckPayload struct {
	SessionID    string `json:"sessionId"`
	DeviceSecret string `json:"deviceSecret,omitempty"`
	HeartbeatSec int    `json:"heartbeatSec,omitempty"`
}

type OpenTunnelPayload struct {
	Target string `json:"target"`
}

type TunnelReadyPayload struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type TunnelDataPayload struct {
	B64 string `json:"b64"`
}

type Agent struct {
	cfg      Config
	deviceID string

	seq uint64

	wsMu sync.Mutex

	tunnelsMu sync.Mutex
	tunnels   map[string]*Tunnel

	startedAt       time.Time
	configPath      string
	connected       atomic.Bool
	lastConnectedTS atomic.Int64
}

type Tunnel struct {
	id     string
	conn   net.Conn
	cancel context.CancelFunc
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: agentd <config.json>")
		os.Exit(2)
	}

	cfgPath := os.Args[1]
	cfgBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read config:", err)
		os.Exit(1)
	}
	var cfg Config
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		fmt.Fprintln(os.Stderr, "parse config:", err)
		os.Exit(1)
	}

	if cfg.ServerURL == "" {
		fmt.Fprintln(os.Stderr, "config: serverUrl is required")
		os.Exit(1)
	}
	if cfg.DeviceIDPath == "" {
		cfg.DeviceIDPath = "/var/mobile/Library/QQwAgent/device_id"
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 20
	}
	if cfg.Reconnect.BaseMs <= 0 {
		cfg.Reconnect.BaseMs = 1000
	}
	if cfg.Reconnect.MaxMs <= 0 {
		cfg.Reconnect.MaxMs = 60000
	}
	if cfg.Reconnect.JitterMs <= 0 {
		cfg.Reconnect.JitterMs = 3000
	}
	if cfg.Frida.Host == "" {
		cfg.Frida.Host = "127.0.0.1"
	}
	if cfg.Frida.Port == 0 {
		cfg.Frida.Port = 27042
	}

	deviceID, err := loadOrCreateDeviceID(cfg.DeviceIDPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "device_id:", err)
		os.Exit(1)
	}

	a := &Agent{
		cfg:       cfg,
		deviceID:  deviceID,
		tunnels:   make(map[string]*Tunnel),
		startedAt: time.Now(),
	}

	a.startControlServer(cfgPath)
	a.runForever()
}

func (a *Agent) startControlServer(cfgPath string) {
	if a.cfg.ControlListen == "" {
		return
	}
	a.configPath = cfgPath

	mux := http.NewServeMux()

	authOK := func(r *http.Request) bool {
		if a.cfg.ControlToken == "" {
			return true
		}
		return r.Header.Get("X-QQw-Token") == a.cfg.ControlToken
	}

	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
	}

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"deviceId":        a.deviceID,
			"serverUrl":       a.cfg.ServerURL,
			"connected":       a.connected.Load(),
			"lastConnectedTs": a.lastConnectedTS.Load(),
			"pid":             os.Getpid(),
			"uptimeSec":       int64(time.Since(a.startedAt).Seconds()),
		})
	})

	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method {
		case http.MethodGet:
			b, err := os.ReadFile(a.configPath)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		case http.MethodPost:
			limited := io.LimitReader(r.Body, 256*1024)
			body, err := io.ReadAll(limited)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			var tmp any
			if err := json.Unmarshal(body, &tmp); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
				return
			}
			if err := os.WriteFile(a.configPath, body, 0o644); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/quit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		go func() {
			time.Sleep(200 * time.Millisecond)
			os.Exit(0)
		}()
	})

	srv := &http.Server{
		Addr:              a.cfg.ControlListen,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	go func() {
		ln, err := net.Listen("tcp", a.cfg.ControlListen)
		if err != nil {
			fmt.Fprintln(os.Stderr, "control server listen:", err)
			return
		}
		fmt.Fprintln(os.Stderr, "control server: listening on", ln.Addr().String())
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "control server serve:", err)
		}
	}()
}

func (a *Agent) runForever() {
	backoff := time.Duration(a.cfg.Reconnect.BaseMs) * time.Millisecond
	maxBackoff := time.Duration(a.cfg.Reconnect.MaxMs) * time.Millisecond
	jitter := time.Duration(a.cfg.Reconnect.JitterMs) * time.Millisecond

	for {
		err := a.runOnce()
		if err != nil {
			fmt.Fprintln(os.Stderr, "agent run error:", err)
		}
		sleep := backoff + time.Duration(randInt63n(int64(jitter)))
		if sleep < 0 {
			sleep = backoff
		}
		time.Sleep(sleep)
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (a *Agent) runOnce() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	a.connected.Store(false)
	ws, _, err := websocket.Dial(ctx, a.cfg.ServerURL, &websocket.DialOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return err
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	sessionID, err := a.hello(ctx, ws)
	if err != nil {
		return err
	}
	a.connected.Store(true)
	a.lastConnectedTS.Store(time.Now().UnixMilli())

	hb := time.Duration(a.cfg.HeartbeatSec) * time.Second
	if hb <= 0 {
		hb = 20 * time.Second
	}

	done := make(chan error, 1)
	go func() {
		done <- a.readLoop(ctx, ws, sessionID)
	}()

	ticker := time.NewTicker(hb)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := a.sendPing(ctx, ws, sessionID); err != nil {
				a.closeAllTunnels()
				a.connected.Store(false)
				return err
			}
		case err := <-done:
			a.closeAllTunnels()
			a.connected.Store(false)
			return err
		}
	}
}

func (a *Agent) hello(ctx context.Context, ws *websocket.Conn) (string, error) {
	payload := map[string]any{
		"capabilities": map[string]any{
			"fridaTcpForward": true,
		},
	}
	if a.cfg.DeviceSecret != "" {
		payload["deviceSecret"] = a.cfg.DeviceSecret
	} else if a.cfg.RegisterToken != "" {
		payload["registerToken"] = a.cfg.RegisterToken
	}

	env := Envelope{
		V:        1,
		Type:     "hello",
		DeviceID: a.deviceID,
		Seq:      atomic.AddUint64(&a.seq, 1),
		TS:       time.Now().UnixMilli(),
	}
	b, _ := json.Marshal(payload)
	env.Payload = b
	if err := a.sendJSON(ctx, ws, env); err != nil {
		return "", err
	}

	readCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	for {
		_, data, err := ws.Read(readCtx)
		if err != nil {
			return "", err
		}
		var in Envelope
		if err := json.Unmarshal(data, &in); err != nil {
			continue
		}
		if in.Type != "hello_ack" {
			continue
		}
		var ack HelloAckPayload
		if err := json.Unmarshal(in.Payload, &ack); err != nil {
			return "", err
		}
		if ack.DeviceSecret != "" && a.cfg.DeviceSecret == "" {
			a.cfg.DeviceSecret = ack.DeviceSecret
		}
		if ack.HeartbeatSec > 0 {
			a.cfg.HeartbeatSec = ack.HeartbeatSec
		}
		return ack.SessionID, nil
	}
}

func (a *Agent) sendPing(ctx context.Context, ws *websocket.Conn, sessionID string) error {
	env := Envelope{
		V:        1,
		Type:     "ping",
		DeviceID: a.deviceID,
		Session:  sessionID,
		Seq:      atomic.AddUint64(&a.seq, 1),
		TS:       time.Now().UnixMilli(),
	}
	return a.sendJSON(ctx, ws, env)
}

func (a *Agent) readLoop(ctx context.Context, ws *websocket.Conn, sessionID string) error {
	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		var in Envelope
		if err := json.Unmarshal(data, &in); err != nil {
			continue
		}
		switch in.Type {
		case "pong":
		case "open_tunnel":
			a.handleOpenTunnel(ctx, ws, sessionID, in)
		case "close_tunnel":
			a.handleCloseTunnel(in.TunnelID)
		case "tunnel_data":
			a.handleTunnelData(ws, in)
		}
	}
}

func (a *Agent) handleOpenTunnel(ctx context.Context, ws *websocket.Conn, sessionID string, in Envelope) {
	var p OpenTunnelPayload
	_ = json.Unmarshal(in.Payload, &p)
	if p.Target == "" {
		p.Target = "frida"
	}
	if p.Target != "frida" {
		a.sendTunnelReady(ctx, ws, sessionID, in.TunnelID, false, "UNSUPPORTED_TARGET")
		return
	}

	if a.cfg.Frida.EnsureRunning {
		_ = ensureFridaUp(a.cfg.Frida.Host, a.cfg.Frida.Port, a.cfg.Frida.StartCmd)
	}

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(a.cfg.Frida.Host, fmt.Sprintf("%d", a.cfg.Frida.Port)))
	if err != nil {
		a.sendTunnelReady(ctx, ws, sessionID, in.TunnelID, false, "FRIDA_CONNECT_FAILED")
		return
	}

	tCtx, tCancel := context.WithCancel(context.Background())
	t := &Tunnel{
		id:     in.TunnelID,
		conn:   conn,
		cancel: tCancel,
	}
	a.tunnelsMu.Lock()
	a.tunnels[in.TunnelID] = t
	a.tunnelsMu.Unlock()

	a.sendTunnelReady(ctx, ws, sessionID, in.TunnelID, true, "")

	go a.tunnelReadPump(tCtx, ws, sessionID, t)
}

func (a *Agent) tunnelReadPump(ctx context.Context, ws *websocket.Conn, sessionID string, t *Tunnel) {
	buf := make([]byte, 16*1024)
	for {
		_ = t.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, err := t.conn.Read(buf)
		if n > 0 {
			b64 := base64.StdEncoding.EncodeToString(buf[:n])
			payload, _ := json.Marshal(TunnelDataPayload{B64: b64})
			env := Envelope{
				V:        1,
				Type:     "tunnel_data",
				DeviceID: a.deviceID,
				Session:  sessionID,
				TunnelID: t.id,
				Seq:      atomic.AddUint64(&a.seq, 1),
				TS:       time.Now().UnixMilli(),
				Payload:  payload,
			}
			_ = a.sendJSON(context.Background(), ws, env)
		}
		if err != nil {
			a.handleCloseTunnel(t.id)
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

func (a *Agent) handleTunnelData(ws *websocket.Conn, in Envelope) {
	a.tunnelsMu.Lock()
	t := a.tunnels[in.TunnelID]
	a.tunnelsMu.Unlock()
	if t == nil {
		return
	}
	var p TunnelDataPayload
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		return
	}
	if p.B64 == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(p.B64)
	if err != nil {
		return
	}
	_, _ = t.conn.Write(raw)
	_ = ws
}

func (a *Agent) handleCloseTunnel(tunnelID string) {
	a.tunnelsMu.Lock()
	t := a.tunnels[tunnelID]
	if t != nil {
		delete(a.tunnels, tunnelID)
	}
	a.tunnelsMu.Unlock()
	if t == nil {
		return
	}
	t.cancel()
	_ = t.conn.Close()
}

func (a *Agent) closeAllTunnels() {
	a.tunnelsMu.Lock()
	ids := make([]string, 0, len(a.tunnels))
	for id := range a.tunnels {
		ids = append(ids, id)
	}
	a.tunnelsMu.Unlock()
	for _, id := range ids {
		a.handleCloseTunnel(id)
	}
}

func (a *Agent) sendTunnelReady(ctx context.Context, ws *websocket.Conn, sessionID, tunnelID string, ok bool, errCode string) {
	payload, _ := json.Marshal(TunnelReadyPayload{OK: ok, Error: errCode})
	env := Envelope{
		V:        1,
		Type:     "tunnel_ready",
		DeviceID: a.deviceID,
		Session:  sessionID,
		TunnelID: tunnelID,
		Seq:      atomic.AddUint64(&a.seq, 1),
		TS:       time.Now().UnixMilli(),
		Payload:  payload,
	}
	_ = a.sendJSON(ctx, ws, env)
}

func (a *Agent) sendJSON(ctx context.Context, ws *websocket.Conn, env Envelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	a.wsMu.Lock()
	defer a.wsMu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return ws.Write(wctx, websocket.MessageText, b)
}

func loadOrCreateDeviceID(path string) (string, error) {
	if b, err := os.ReadFile(path); err == nil {
		s := string(bytesTrimSpace(b))
		if s != "" {
			return s, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return "", err
	}
	id, err := uuidV4()
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(id+"\n"), 0644); err != nil {
		return "", err
	}
	return id, nil
}

func uuidV4() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	u1 := binary.BigEndian.Uint32(b[0:4])
	u2 := binary.BigEndian.Uint16(b[4:6])
	u3 := binary.BigEndian.Uint16(b[6:8])
	u4 := binary.BigEndian.Uint16(b[8:10])
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%02x%02x%02x%02x%02x%02x",
		u1, u2, u3, u4,
		b[10], b[11], b[12], b[13], b[14], b[15],
	), nil
}

func bytesTrimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}

func randInt63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	v := int64(b[0])<<56 | int64(b[1])<<48 | int64(b[2])<<40 | int64(b[3])<<32 | int64(b[4])<<24 | int64(b[5])<<16 | int64(b[6])<<8 | int64(b[7])
	if v < 0 {
		v = -v
	}
	return v % n
}

func ensureFridaUp(host string, port int, startCmd string) error {
	if startCmd == "" {
		return nil
	}
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	c, err := net.DialTimeout("tcp", addr, 300*time.Millisecond)
	if err == nil {
		_ = c.Close()
		return nil
	}
	cmd := exec.Command("sh", "-lc", startCmd)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	_ = cmd.Start()
	time.Sleep(300 * time.Millisecond)
	c2, err2 := net.DialTimeout("tcp", addr, 500*time.Millisecond)
	if err2 == nil {
		_ = c2.Close()
		return nil
	}
	if err2 != nil {
		return err2
	}
	return errors.New("frida not available")
}
