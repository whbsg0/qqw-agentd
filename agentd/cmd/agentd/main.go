package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"nhooyr.io/websocket"
)

var buildVersion = "dev"
var buildCommit = ""

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
	WhatsApp struct {
		ChatStoragePath string `json:"chatStoragePath"`
	} `json:"whatsApp"`
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

type limitedLineBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func newLimitedLineBuffer(max int) *limitedLineBuffer {
	if max <= 0 {
		max = 4096
	}
	return &limitedLineBuffer{max: max, buf: make([]byte, 0, max)}
}

func (b *limitedLineBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(p) >= b.max {
		b.buf = append(b.buf[:0], p[len(p)-b.max:]...)
		return len(p), nil
	}
	if len(b.buf)+len(p) > b.max {
		drop := (len(b.buf) + len(p)) - b.max
		if drop >= len(b.buf) {
			b.buf = b.buf[:0]
		} else {
			copy(b.buf, b.buf[drop:])
			b.buf = b.buf[:len(b.buf)-drop]
		}
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *limitedLineBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.buf))
}

type DbSyncStartPayload struct {
	JobID     string `json:"jobId"`
	UploadURL string `json:"uploadUrl"`
}

type SetDeviceSecretPayload struct {
	DeviceSecret string `json:"deviceSecret,omitempty"`
}

type TxSendPayload struct {
	OpID               string              `json:"opId"`
	Kind               string              `json:"kind"`
	JID                string              `json:"jid"`
	Text               string              `json:"text,omitempty"`
	QuoteStanzaID      string              `json:"quoteStanzaId,omitempty"`
	ParticipantJID     string              `json:"participantJid,omitempty"`
	MessageOrigin      int                 `json:"messageOrigin,omitempty"`
	CreationEntryPoint int                 `json:"creationEntryPoint,omitempty"`
	TimeoutMs          int                 `json:"timeoutMs,omitempty"`
	Media              *TxSendMediaPayload `json:"media,omitempty"`
}

type TxSendMediaPayload struct {
	Source      string `json:"source,omitempty"`
	URL         string `json:"url,omitempty"`
	Base64      string `json:"base64,omitempty"`
	DevicePath  string `json:"devicePath,omitempty"`
	Mime        string `json:"mime,omitempty"`
	Filename    string `json:"filename,omitempty"`
	Caption     string `json:"caption,omitempty"`
	SizeBytes   int64  `json:"sizeBytes,omitempty"`
	Sha256      string `json:"sha256,omitempty"`
	DurationSec int    `json:"durationSec,omitempty"`
}

type TxMsgActionPayload struct {
	OpID           string `json:"opId"`
	Action         string `json:"action"`
	JID            string `json:"jid"`
	StanzaID       string `json:"stanzaId"`
	Text           string `json:"text,omitempty"`
	ParticipantJID string `json:"participantJid,omitempty"`
	TimeoutMs      int    `json:"timeoutMs,omitempty"`
}

type TxAvatarURLPayload struct {
	OpID      string `json:"opId"`
	JID       string `json:"jid"`
	FullSize  bool   `json:"fullSize,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
}

type TxSelfCardPayload struct {
	OpID      string `json:"opId"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
}

type Agent struct {
	cfgMu sync.RWMutex
	cfg   Config

	deviceID   string
	scriptPath string

	seq uint64

	wsMu sync.Mutex

	tunnelsMu sync.Mutex
	tunnels   map[string]*Tunnel

	startedAt       time.Time
	configPath      string
	connected       atomic.Bool
	lastConnectedTS atomic.Int64

	runCancelMu  sync.Mutex
	runCancel    context.CancelFunc
	reconnectNow chan struct{}

	lastWhatsAppLocateTS  atomic.Int64
	lastWhatsAppLocateErr atomic.Value

	lastDbSyncTS        atomic.Int64
	lastDbSyncJobID     atomic.Value
	lastDbSyncUploadURL atomic.Value
	lastDbSyncState     atomic.Value
	lastDbSyncErr       atomic.Value

	scriptUpdatedAtTS atomic.Int64
	scriptLastError   atomic.Value
	scriptLastEventTS atomic.Int64
	scriptLastPongTS  atomic.Int64

	runnerMu  sync.Mutex
	runnerCmd *exec.Cmd
	runnerPid atomic.Int64

	eventQueue *EventQueue
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

	if err := normalizeConfig(&cfg); err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}

	deviceID, err := loadOrCreateDeviceID(cfg.DeviceIDPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "device_id:", err)
		os.Exit(1)
	}

	a := &Agent{
		cfg:          cfg,
		deviceID:     deviceID,
		scriptPath:   filepath.Join(filepath.Dir(cfg.DeviceIDPath), "scripts", "current.js"),
		tunnels:      make(map[string]*Tunnel),
		startedAt:    time.Now(),
		reconnectNow: make(chan struct{}, 1),
		eventQueue:   NewEventQueue(filepath.Join(filepath.Dir(cfg.DeviceIDPath), "events")),
	}

	a.startControlServer(cfgPath)
	go a.eventQueue.Run(context.Background(), deviceID, a.getCfg)
	a.runForever()
}

func (a *Agent) startControlServer(cfgPath string) {
	if a.getCfg().ControlListen == "" {
		return
	}
	a.configPath = cfgPath

	mux := http.NewServeMux()

	authOK := func(r *http.Request) bool {
		if a.getCfg().ControlToken == "" {
			return true
		}
		return r.Header.Get("X-QQw-Token") == a.getCfg().ControlToken
	}

	authOKEvents := func(r *http.Request) bool {
		if authOK(r) {
			return true
		}
		host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
		if err != nil {
			host = strings.TrimSpace(r.RemoteAddr)
		}
		ip := net.ParseIP(host)
		return ip != nil && ip.IsLoopback()
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
		cfg := a.getCfg()
		writeJSON(w, http.StatusOK, map[string]any{
			"version":         buildVersion,
			"commit":          buildCommit,
			"deviceId":        a.deviceID,
			"serverUrl":       cfg.ServerURL,
			"controlListen":   cfg.ControlListen,
			"connected":       a.connected.Load(),
			"lastConnectedTs": a.lastConnectedTS.Load(),
			"pid":             os.Getpid(),
			"uptimeSec":       int64(time.Since(a.startedAt).Seconds()),
			"dbsync": map[string]any{
				"ts":        a.lastDbSyncTS.Load(),
				"jobId":     strings.TrimSpace(valueOrEmptyString(a.lastDbSyncJobID.Load())),
				"uploadUrl": strings.TrimSpace(valueOrEmptyString(a.lastDbSyncUploadURL.Load())),
				"state":     strings.TrimSpace(valueOrEmptyString(a.lastDbSyncState.Load())),
				"error":     strings.TrimSpace(valueOrEmptyString(a.lastDbSyncErr.Load())),
			},
		})
	})

	mux.HandleFunc("/whatsapp/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		cfg := a.getCfg()
		path := cfg.WhatsApp.ChatStoragePath
		ok, size, modTS, errText := statReadableFile(path)
		locErr, _ := a.lastWhatsAppLocateErr.Load().(string)
		writeJSON(w, http.StatusOK, map[string]any{
			"chatStoragePath":     path,
			"existsReadable":      ok,
			"sizeBytes":           size,
			"modTs":               modTS,
			"uploadReady":         ok && size > 0,
			"lastLocateTs":        a.lastWhatsAppLocateTS.Load(),
			"lastLocateErr":       locErr,
			"chatStoragePathErr":  errText,
			"deviceSecretPresent": cfg.DeviceSecret != "",
		})
	})

	mux.HandleFunc("/whatsapp/locate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()

		found, candidates, err := locateChatStorage(ctx)
		a.lastWhatsAppLocateTS.Store(time.Now().UnixMilli())
		if err != nil {
			a.lastWhatsAppLocateErr.Store(err.Error())
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error(), "candidates": candidates})
			return
		}
		a.lastWhatsAppLocateErr.Store("")

		prev := a.getCfg()
		next := prev
		next.WhatsApp.ChatStoragePath = found
		_ = normalizeConfig(&next)
		if err := a.persistConfig(next); err != nil {
			a.setCfg(next)
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "chatStoragePath": found, "persisted": false, "persistErr": err.Error(), "candidates": candidates})
			return
		}
		a.setCfg(next)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "chatStoragePath": found, "persisted": true, "candidates": candidates})
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
			var nextCfg Config
			if err := json.Unmarshal(body, &nextCfg); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid json"})
				return
			}
			if err := normalizeConfig(&nextCfg); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": err.Error()})
				return
			}

			canonical, _ := json.MarshalIndent(nextCfg, "", "  ")
			canonical = append(canonical, '\n')
			if err := os.WriteFile(a.configPath, canonical, 0o644); err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": err.Error()})
				return
			}

			prev := a.getCfg()
			a.setCfg(nextCfg)
			if prev.ServerURL != nextCfg.ServerURL || prev.HeartbeatSec != nextCfg.HeartbeatSec || prev.DeviceSecret != nextCfg.DeviceSecret || prev.RegisterToken != nextCfg.RegisterToken {
				a.requestReconnect()
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
			_ = a.stopRunnerIfRunning()
			os.Exit(0)
		}()
	})

	mux.HandleFunc("/asset/snapshot", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		cfg := a.getCfg()
		base := serverHTTPBase(cfg.ServerURL)
		if base == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "serverUrl invalid"})
			return
		}
		if strings.TrimSpace(cfg.DeviceSecret) == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "deviceSecret missing"})
			return
		}
		target := fmt.Sprintf("%s/api/device/%s/asset-snapshot", base, url.PathEscape(a.deviceID))
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		req.Header.Set("X-Device-Id", a.deviceID)
		req.Header.Set("X-Device-Secret", cfg.DeviceSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			msg := strings.TrimSpace(string(body))
			if msg == "" {
				msg = resp.Status
			}
			writeJSON(w, resp.StatusCode, map[string]any{"ok": false, "error": msg})
			return
		}
		var out any
		if err := json.Unmarshal(body, &out); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "invalid json"})
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("/asset/egress-ip/fill", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		cfg := a.getCfg()
		base := serverHTTPBase(cfg.ServerURL)
		if base == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "serverUrl invalid"})
			return
		}
		if strings.TrimSpace(cfg.DeviceSecret) == "" {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "deviceSecret missing"})
			return
		}
		target := fmt.Sprintf("%s/api/device/%s/asset/egress-ip/fill", base, url.PathEscape(a.deviceID))
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, nil)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		req.Header.Set("X-Device-Id", a.deviceID)
		req.Header.Set("X-Device-Secret", cfg.DeviceSecret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != http.StatusOK {
			msg := strings.TrimSpace(string(body))
			if msg == "" {
				msg = resp.Status
			}
			writeJSON(w, resp.StatusCode, map[string]any{"ok": false, "error": msg})
			return
		}
		var out any
		if err := json.Unmarshal(body, &out); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": "invalid json"})
			return
		}
		writeJSON(w, http.StatusOK, out)
	})

	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOKEvents(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		cfg := a.getCfg()
		if strings.TrimSpace(cfg.DeviceSecret) == "" {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queued": true, "warning": "deviceSecret missing"})
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 16<<20))
		if err != nil || len(body) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid body"})
			return
		}
		now := time.Now().UnixMilli()
		a.scriptLastEventTS.Store(now)
		var m map[string]any
		if err := json.Unmarshal(body, &m); err == nil {
			if t, ok := m["type"].(string); ok && strings.TrimSpace(t) == "qqw.pong" {
				a.scriptLastPongTS.Store(now)
			}
		}
		a.eventQueue.Enqueue(body)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "queued": true})
	})

	mux.HandleFunc("/script/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		lastErr, _ := a.scriptLastError.Load().(string)
		running := false
		a.runnerMu.Lock()
		running = a.runnerCmd != nil && a.runnerCmd.Process != nil
		a.runnerMu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":            true,
			"running":       running,
			"scriptPath":    a.scriptPath,
			"updatedAtTsMs": a.scriptUpdatedAtTS.Load(),
			"lastError":     strings.TrimSpace(lastErr),
			"lastEventTsMs": a.scriptLastEventTS.Load(),
			"lastPongTsMs":  a.scriptLastPongTS.Load(),
		})
	})

	mux.HandleFunc("/script/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := a.startRunner(); err != nil {
			a.scriptLastError.Store(err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		a.scriptLastError.Store("")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/script/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if err := a.stopRunnerIfRunning(); err != nil {
			a.scriptLastError.Store(err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		a.scriptLastError.Store("")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})
	mux.HandleFunc("/script/uninstall", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = a.stopRunnerIfRunning()
		a.scriptLastError.Store("")
		a.scriptLastEventTS.Store(0)
		a.scriptLastPongTS.Store(0)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	mux.HandleFunc("/script/update", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		downloadURL, updatedAt, err := a.updateScriptAndRestart()
		if err != nil {
			a.scriptLastError.Store(err.Error())
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		a.scriptLastError.Store("")
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "downloadUrl": downloadURL, "updatedAtTsMs": updatedAt})
	})

	mux.HandleFunc("/updater/run", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !authOK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = os.WriteFile("/var/mobile/Library/QQwUpdates/force_run", []byte("1\n"), 0o644)
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		launchctlPath := ""
		for _, p := range []string{"/var/jb/usr/bin/launchctl", "/var/jb/bin/launchctl", "/usr/bin/launchctl", "/bin/launchctl"} {
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				launchctlPath = p
				break
			}
		}
		if launchctlPath == "" {
			launchctlPath = "launchctl"
		}
		cmd := exec.CommandContext(ctx, launchctlPath, "kickstart", "-k", "system/com.qqw.updater")
		out, err := cmd.CombinedOutput()
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "error": err.Error(), "output": strings.TrimSpace(string(out))})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})

	srv := &http.Server{
		Addr:              a.getCfg().ControlListen,
		Handler:           mux,
		ReadHeaderTimeout: 3 * time.Second,
	}
	go func() {
		ln, err := net.Listen("tcp", a.getCfg().ControlListen)
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

func serverHTTPBase(serverURL string) string {
	u, err := url.Parse(strings.TrimSpace(serverURL))
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme == "wss" {
		scheme = "https"
	} else if scheme == "ws" {
		scheme = "http"
	}
	if scheme != "http" && scheme != "https" {
		return ""
	}
	return scheme + "://" + u.Host
}

func (a *Agent) runnerBinaryPath() (string, error) {
	const fixed = "/var/jb/usr/local/bin/qqw-script-runner"
	if st, err := os.Stat(fixed); err == nil && !st.IsDir() {
		return fixed, nil
	}
	exe, err := os.Executable()
	if err != nil || strings.TrimSpace(exe) == "" {
		arg0 := strings.TrimSpace(os.Args[0])
		if arg0 != "" {
			return filepath.Join(filepath.Dir(arg0), "qqw-script-runner"), nil
		}
		return "", errors.New("executable path unavailable")
	}
	return filepath.Join(filepath.Dir(exe), "qqw-script-runner"), nil
}

func (a *Agent) startRunner() error {
	a.runnerMu.Lock()
	defer a.runnerMu.Unlock()

	if a.runnerCmd != nil && a.runnerCmd.Process != nil {
		return errors.New("runner already running")
	}
	cfg := a.getCfg()
	if strings.TrimSpace(cfg.ControlListen) == "" {
		return errors.New("controlListen missing")
	}
	runnerPath, err := a.runnerBinaryPath()
	if err != nil {
		return err
	}
	eventsURL := "http://" + strings.TrimSpace(cfg.ControlListen) + "/events"
	outBuf := newLimitedLineBuffer(16 * 1024)
	cmd := exec.Command(
		runnerPath,
		"-fridaHost", strings.TrimSpace(cfg.Frida.Host),
		"-fridaPort", strconv.Itoa(cfg.Frida.Port),
		"-processName", "WhatsApp",
		"-bundleId", "net.whatsapp.WhatsApp",
		"-requireForeground=false",
		"-waitForegroundMs=0",
		"-rpcAddr", "127.0.0.1:17172",
		"-scriptPath", a.scriptPath,
		"-eventsUrl", eventsURL,
	)
	cmd.Env = append(os.Environ(), "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin:/usr/sbin:/sbin")
	mw := io.MultiWriter(os.Stderr, outBuf)
	cmd.Stdout = mw
	cmd.Stderr = mw
	if err := cmd.Start(); err != nil {
		return err
	}
	a.runnerCmd = cmd
	a.runnerPid.Store(int64(cmd.Process.Pid))
	go func() {
		err := cmd.Wait()
		a.runnerMu.Lock()
		if a.runnerCmd == cmd {
			a.runnerCmd = nil
			a.runnerPid.Store(0)
		}
		a.runnerMu.Unlock()
		if err != nil {
			s := outBuf.String()
			if s != "" {
				a.scriptLastError.Store(s)
			} else {
				a.scriptLastError.Store(err.Error())
			}
		} else {
			a.scriptLastError.Store("")
		}
	}()
	return nil
}

func (a *Agent) stopRunner() error {
	a.runnerMu.Lock()
	defer a.runnerMu.Unlock()

	if a.runnerCmd == nil || a.runnerCmd.Process == nil {
		return errors.New("runner not running")
	}
	if err := a.runnerCmd.Process.Kill(); err != nil {
		return err
	}
	a.runnerCmd = nil
	a.runnerPid.Store(0)
	return nil
}

func (a *Agent) stopRunnerIfRunning() error {
	a.runnerMu.Lock()
	defer a.runnerMu.Unlock()

	if a.runnerCmd == nil || a.runnerCmd.Process == nil {
		return nil
	}
	if err := a.runnerCmd.Process.Kill(); err != nil {
		return err
	}
	a.runnerCmd = nil
	a.runnerPid.Store(0)
	return nil
}

func (a *Agent) persistConfig(nextCfg Config) error {
	if a.configPath == "" {
		return errors.New("configPath not set")
	}
	canonical, _ := json.MarshalIndent(nextCfg, "", "  ")
	canonical = append(canonical, '\n')
	return os.WriteFile(a.configPath, canonical, 0o644)
}

type locateCandidate struct {
	Path  string `json:"path"`
	Size  int64  `json:"sizeBytes"`
	ModTS int64  `json:"modTs"`
}

func statReadableFile(path string) (ok bool, size int64, modTS int64, errText string) {
	if strings.TrimSpace(path) == "" {
		return false, 0, 0, "empty path"
	}
	st, err := os.Stat(path)
	if err != nil {
		return false, 0, 0, err.Error()
	}
	if st.IsDir() {
		return false, 0, 0, "is a directory"
	}
	f, err := os.Open(path)
	if err != nil {
		return false, 0, 0, err.Error()
	}
	_ = f.Close()
	return true, st.Size(), st.ModTime().UnixMilli(), ""
}

func locateChatStorage(ctx context.Context) (string, []locateCandidate, error) {
	roots := []string{
		"/var/mobile/Containers/Shared/AppGroup",
		"/var/mobile/Containers/Data/Application",
		"/private/var/mobile/Containers/Shared/AppGroup",
		"/private/var/mobile/Containers/Data/Application",
	}
	name := "ChatStorage.sqlite"

	candidates := make([]locateCandidate, 0, 8)
	seen := make(map[string]struct{}, 32)
	var lastFindErr error
	for _, root := range roots {
		out, err := execFind(ctx, root, 10, name, 50)
		if err != nil {
			lastFindErr = err
			continue
		}
		for _, p := range out {
			if _, ok := seen[p]; ok {
				continue
			}
			seen[p] = struct{}{}
			st, err := os.Stat(p)
			if err != nil || st.IsDir() {
				continue
			}
			candidates = append(candidates, locateCandidate{Path: p, Size: st.Size(), ModTS: st.ModTime().UnixMilli()})
		}
	}

	if len(candidates) == 0 {
		if lastFindErr != nil {
			return "", candidates, fmt.Errorf("no candidates found (find err: %v)", lastFindErr)
		}
		return "", candidates, errors.New("no candidates found")
	}

	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Size != candidates[j].Size {
			return candidates[i].Size > candidates[j].Size
		}
		return candidates[i].ModTS > candidates[j].ModTS
	})

	return candidates[0].Path, candidates, nil
}

func execFind(ctx context.Context, root string, maxDepth int, name string, limit int) ([]string, error) {
	findBin := firstExistingFile("/var/jb/usr/bin/find", "/usr/bin/find")
	if findBin == "" {
		if p, err := exec.LookPath("find"); err == nil {
			findBin = p
		} else {
			findBin = "find"
		}
	}
	cmd := exec.CommandContext(ctx, findBin, root, "-maxdepth", strconv.Itoa(maxDepth), "-type", "f", "-name", name, "-print")
	b, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, err
		}
		if len(bytes.TrimSpace(b)) == 0 {
			return nil, err
		}
	}
	lines := strings.Split(string(b), "\n")
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		out = append(out, l)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func firstExistingFile(paths ...string) string {
	for _, p := range paths {
		if p == "" {
			continue
		}
		st, err := os.Stat(p)
		if err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func (a *Agent) runForever() {
	cfg := a.getCfg()
	backoff := time.Duration(cfg.Reconnect.BaseMs) * time.Millisecond
	maxBackoff := time.Duration(cfg.Reconnect.MaxMs) * time.Millisecond
	jitter := time.Duration(cfg.Reconnect.JitterMs) * time.Millisecond

	for {
		a.logf("ws: dialing serverUrl=%s", a.getCfg().ServerURL)
		err := a.runOnce()
		if err != nil {
			a.logf("ws: run error: %v", err)
		}

		cfg = a.getCfg()
		baseBackoff := time.Duration(cfg.Reconnect.BaseMs) * time.Millisecond
		maxBackoff = time.Duration(cfg.Reconnect.MaxMs) * time.Millisecond
		jitter = time.Duration(cfg.Reconnect.JitterMs) * time.Millisecond
		if baseBackoff <= 0 {
			baseBackoff = 1000 * time.Millisecond
		}
		if backoff < baseBackoff {
			backoff = baseBackoff
		}

		sleep := backoff + time.Duration(randInt63n(int64(jitter)))
		if sleep < 0 {
			sleep = backoff
		}
		a.logf("ws: reconnect sleep=%s", sleep)
		timer := time.NewTimer(sleep)
		select {
		case <-timer.C:
		case <-a.reconnectNow:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			backoff = baseBackoff
			continue
		}
		backoff *= 2
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

func (a *Agent) runOnce() error {
	ctx, cancel := context.WithCancel(context.Background())
	a.setRunCancel(cancel)
	defer func() {
		a.clearRunCancel()
		cancel()
	}()

	a.connected.Store(false)
	cfg := a.getCfg()
	ws, _, err := websocket.Dial(ctx, cfg.ServerURL, &websocket.DialOptions{
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
	a.logf("ws: connected")

	hb := time.Duration(a.getCfg().HeartbeatSec) * time.Second
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
	cfg := a.getCfg()
	payload := map[string]any{
		"capabilities": map[string]any{
			"fridaTcpForward": true,
		},
	}
	if cfg.DeviceSecret != "" {
		payload["deviceSecret"] = cfg.DeviceSecret
	} else if cfg.RegisterToken != "" {
		payload["registerToken"] = cfg.RegisterToken
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
		nextCfg := cfg
		if ack.DeviceSecret != "" && cfg.DeviceSecret == "" {
			nextCfg.DeviceSecret = ack.DeviceSecret
		}
		if ack.HeartbeatSec > 0 {
			nextCfg.HeartbeatSec = ack.HeartbeatSec
		}
		a.setCfg(nextCfg)
		if nextCfg.DeviceSecret != cfg.DeviceSecret && a.configPath != "" {
			_ = a.persistConfig(nextCfg)
		}
		return ack.SessionID, nil
	}
}

func (a *Agent) sendPing(ctx context.Context, ws *websocket.Conn, sessionID string) error {
	type runnerHealth struct {
		Pid           int64  `json:"pid"`
		RpcOk         bool   `json:"rpcOk"`
		ScriptReady   bool   `json:"scriptReady"`
		ScriptPath    string `json:"scriptPath,omitempty"`
		ScriptSha256  string `json:"scriptSha256,omitempty"`
		ScriptBuild   string `json:"scriptBuild,omitempty"`
		StartedAtMs   int64  `json:"startedAtMs,omitempty"`
		LastHealthAt  int64  `json:"lastHealthAtMs,omitempty"`
		LastHealthErr string `json:"lastHealthErr,omitempty"`
	}
	type scriptHealth struct {
		InstalledPath string `json:"installedPath,omitempty"`
		UpdatedAtMs   int64  `json:"updatedAtMs,omitempty"`
		LastEventTsMs int64  `json:"lastEventTsMs,omitempty"`
		LastPongTsMs  int64  `json:"lastPongTsMs,omitempty"`
		LastError     string `json:"lastError,omitempty"`
	}
	type pingPayload struct {
		Runner runnerHealth `json:"runner"`
		Script scriptHealth `json:"script"`
	}

	now := time.Now().UnixMilli()
	rh := runnerHealth{Pid: a.runnerPid.Load(), LastHealthAt: now}
	if rh.Pid > 0 {
		h, err := a.getRunnerRPCHealth()
		if err != nil {
			rh.RpcOk = false
			rh.LastHealthErr = err.Error()
		} else {
			rh.RpcOk = true
			rh.ScriptReady = h.ScriptReady
			rh.ScriptPath = strings.TrimSpace(h.ScriptPath)
			rh.ScriptSha256 = strings.TrimSpace(h.ScriptSha256)
			rh.ScriptBuild = strings.TrimSpace(h.ScriptBuild)
			rh.StartedAtMs = h.StartedAtMs
		}
	}
	lastErr, _ := a.scriptLastError.Load().(string)
	payload := pingPayload{
		Runner: rh,
		Script: scriptHealth{
			InstalledPath: strings.TrimSpace(a.scriptPath),
			UpdatedAtMs:   a.scriptUpdatedAtTS.Load(),
			LastEventTsMs: a.scriptLastEventTS.Load(),
			LastPongTsMs:  a.scriptLastPongTS.Load(),
			LastError:     strings.TrimSpace(lastErr),
		},
	}
	pb, _ := json.Marshal(payload)
	env := Envelope{
		V:        1,
		Type:     "ping",
		DeviceID: a.deviceID,
		Session:  sessionID,
		Seq:      atomic.AddUint64(&a.seq, 1),
		TS:       now,
		Payload:  pb,
	}
	return a.sendJSON(ctx, ws, env)
}

type runnerRPCHealthResp struct {
	Ok           bool   `json:"ok"`
	Ts           int64  `json:"ts"`
	StartedAtMs  int64  `json:"startedAtMs"`
	ScriptReady  bool   `json:"scriptReady"`
	ScriptPath   string `json:"scriptPath"`
	ScriptSha256 string `json:"scriptSha256"`
	ScriptBuild  string `json:"scriptBuild"`
}

func (a *Agent) getRunnerRPCHealth() (runnerRPCHealthResp, error) {
	var out runnerRPCHealthResp
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:17172/rpc/health", nil)
	if err != nil {
		return out, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bs, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(bs))
		if msg == "" {
			msg = resp.Status
		}
		return out, fmt.Errorf("runner rpc health status=%d err=%s", resp.StatusCode, msg)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return out, err
	}
	if !out.Ok {
		return out, fmt.Errorf("runner rpc health not ok")
	}
	return out, nil
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
		case "set_device_secret":
			var p SetDeviceSecretPayload
			_ = json.Unmarshal(in.Payload, &p)
			next := a.getCfg()
			next.DeviceSecret = strings.TrimSpace(p.DeviceSecret)
			a.setCfg(next)
			if a.configPath != "" {
				_ = a.persistConfig(next)
			}
			a.logf("deviceSecret updated")
		case "dbsync_start":
			go a.handleDbSyncStart(in)
		case "script_start":
			go a.handleScriptStart()
		case "script_stop":
			go a.handleScriptStop()
		case "script_update":
			go a.handleScriptUpdate()
		case "script_uninstall":
			go a.handleScriptUninstall()
		case "tx_send":
			go a.handleTxSend(in)
		case "tx_msg_action":
			go a.handleTxMsgAction(in)
		case "tx_avatar_url":
			go a.handleTxAvatarURL(in)
		case "tx_self_card":
			go a.handleTxSelfCard(in)
		}
	}
}

func (a *Agent) handleScriptStart() {
	if err := a.startRunner(); err != nil {
		a.scriptLastError.Store(err.Error())
		return
	}
	a.scriptLastError.Store("")
}

func (a *Agent) handleScriptStop() {
	if err := a.stopRunnerIfRunning(); err != nil {
		a.scriptLastError.Store(err.Error())
		return
	}
	a.scriptLastError.Store("")
}

func (a *Agent) handleScriptUpdate() {
	_, _, err := a.updateScriptAndRestart()
	if err != nil {
		a.scriptLastError.Store(err.Error())
		return
	}
	a.scriptLastError.Store("")
}

func (a *Agent) handleScriptUninstall() {
	_ = a.stopRunnerIfRunning()
	a.scriptLastError.Store("")
	a.scriptLastEventTS.Store(0)
	a.scriptLastPongTS.Store(0)
}

func (a *Agent) updateScriptAndRestart() (string, int64, error) {
	cfg := a.getCfg()
	base := serverHTTPBase(cfg.ServerURL)
	if base == "" {
		return "", 0, fmt.Errorf("serverUrl invalid")
	}
	downloadURL := base + "/downloads/scripts/current.js"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return downloadURL, 0, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return downloadURL, 0, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = resp.Status
		}
		return downloadURL, 0, fmt.Errorf("%s", msg)
	}
	if len(body) == 0 {
		return downloadURL, 0, fmt.Errorf("empty script")
	}
	_ = os.MkdirAll(filepath.Dir(a.scriptPath), 0o755)
	if err := os.WriteFile(a.scriptPath, body, 0o644); err != nil {
		return downloadURL, 0, err
	}
	now := time.Now().UnixMilli()
	a.scriptUpdatedAtTS.Store(now)
	if err := a.stopRunnerIfRunning(); err != nil {
		return downloadURL, now, err
	}
	if err := a.startRunner(); err != nil {
		return downloadURL, now, err
	}
	return downloadURL, now, nil
}

func (a *Agent) handleTxSend(in Envelope) {
	var p TxSendPayload
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		a.logf("tx_send: invalid payload: %v", err)
		return
	}
	p.OpID = strings.TrimSpace(p.OpID)
	p.Kind = strings.TrimSpace(p.Kind)
	p.JID = strings.TrimSpace(p.JID)
	p.Text = strings.TrimSpace(p.Text)
	p.QuoteStanzaID = strings.TrimSpace(p.QuoteStanzaID)
	p.ParticipantJID = strings.TrimSpace(p.ParticipantJID)
	if p.OpID == "" || p.Kind == "" || p.JID == "" {
		a.logf("tx_send: missing opId/kind/jid")
		return
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 20_000
	}
	if a.runnerPid.Load() == 0 {
		_ = a.startRunner()
	}
	rpcURL := "http://127.0.0.1:17172/rpc/tx/send"
	out := map[string]any{
		"opId":           p.OpID,
		"kind":           p.Kind,
		"jid":            p.JID,
		"text":           p.Text,
		"quoteStanzaId":  p.QuoteStanzaID,
		"participantJid": p.ParticipantJID,
		"timeoutMs":      p.TimeoutMs,
	}
	if p.MessageOrigin > 0 {
		out["messageOrigin"] = p.MessageOrigin
	}
	if p.CreationEntryPoint > 0 {
		out["creationEntryPoint"] = p.CreationEntryPoint
	}
	if p.Media != nil && (p.Kind == "image" || p.Kind == "video" || p.Kind == "audio") {
		path, caption, err := a.materializeTxMedia(p.OpID, p.Kind, p.Text, p.Media)
		if err != nil {
			a.logf("tx_send: media prep failed: %v", err)
			return
		}
		if strings.TrimSpace(path) != "" {
			out["path"] = path
		}
		if strings.TrimSpace(caption) != "" {
			out["caption"] = caption
		}
		if strings.TrimSpace(p.Media.Mime) != "" {
			out["mime"] = strings.TrimSpace(p.Media.Mime)
		}
		if strings.TrimSpace(p.Media.Filename) != "" {
			out["filename"] = strings.TrimSpace(p.Media.Filename)
		}
		if p.Kind == "audio" && p.Media.DurationSec > 0 {
			out["durationSec"] = p.Media.DurationSec
		}
	}
	body, _ := json.Marshal(out)
	cctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.TimeoutMs+3000)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		a.logf("tx_send: build request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.logf("tx_send: rpc failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bs, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(bs))
		if msg == "" {
			msg = resp.Status
		}
		a.logf("tx_send: rpc status=%d err=%s", resp.StatusCode, msg)
		return
	}
	a.logf("tx_send: dispatched opId=%s kind=%s jid=%s", p.OpID, p.Kind, p.JID)
}

func (a *Agent) materializeTxMedia(opId string, kind string, text string, media *TxSendMediaPayload) (string, string, error) {
	opId = strings.TrimSpace(opId)
	kind = strings.TrimSpace(kind)
	if media == nil {
		return "", "", fmt.Errorf("media missing")
	}
	src := strings.TrimSpace(media.Source)
	urlStr := strings.TrimSpace(media.URL)
	b64 := strings.TrimSpace(media.Base64)
	devPath := strings.TrimSpace(media.DevicePath)
	filename := strings.TrimSpace(media.Filename)
	caption := strings.TrimSpace(media.Caption)
	if caption == "" && (kind == "image" || kind == "video") {
		caption = strings.TrimSpace(text)
	}
	if src == "" {
		if devPath != "" {
			src = "devicePath"
		} else if urlStr != "" {
			src = "url"
		} else if b64 != "" {
			src = "base64"
		}
	}
	if src == "devicePath" {
		if devPath == "" {
			return "", caption, fmt.Errorf("devicePath missing")
		}
		return devPath, caption, nil
	}
	dir := filepath.Join(filepath.Dir(a.scriptPath), "media", "tx")
	cfg := a.getCfg()
	if cfg.WhatsApp.ChatStoragePath != "" {
		dir = filepath.Join(filepath.Dir(strings.TrimSpace(cfg.WhatsApp.ChatStoragePath)), "QQwAgentMedia", "tx")
	}
	_ = os.MkdirAll(dir, 0o755)
	ext := strings.TrimSpace(filepath.Ext(filename))
	if ext == "" {
		if kind == "image" {
			ext = ".jpg"
		} else if kind == "video" {
			ext = ".mp4"
		} else if kind == "audio" {
			ext = ".m4a"
		} else {
			ext = ".bin"
		}
	}
	baseName := strings.TrimSpace(opId)
	if baseName == "" {
		baseName = fmt.Sprintf("%d", time.Now().UnixMilli())
	}
	outPath := filepath.Join(dir, baseName+ext)
	maxBytes := int64(50 << 20)
	finalize := func() {
		_ = os.Chmod(outPath, 0o644)
		_ = os.Chown(outPath, 501, 501)
	}

	if src == "url" {
		if urlStr == "" {
			return "", caption, fmt.Errorf("url missing")
		}
		if err := downloadToFile(urlStr, outPath, maxBytes); err != nil {
			return "", caption, err
		}
		finalize()
		return outPath, caption, nil
	}
	if src == "base64" {
		if b64 == "" {
			return "", caption, fmt.Errorf("base64 missing")
		}
		if idx := strings.Index(b64, "base64,"); idx >= 0 {
			b64 = b64[idx+len("base64,"):]
		}
		dec, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return "", caption, err
		}
		if int64(len(dec)) > maxBytes {
			return "", caption, fmt.Errorf("media too large")
		}
		if err := os.WriteFile(outPath, dec, 0o644); err != nil {
			return "", caption, err
		}
		finalize()
		return outPath, caption, nil
	}
	if src == "url_or_base64" {
		if urlStr != "" {
			if err := downloadToFile(urlStr, outPath, maxBytes); err == nil {
				finalize()
				return outPath, caption, nil
			}
		}
		if b64 != "" {
			if idx := strings.Index(b64, "base64,"); idx >= 0 {
				b64 = b64[idx+len("base64,"):]
			}
			dec, err := base64.StdEncoding.DecodeString(b64)
			if err != nil {
				return "", caption, err
			}
			if int64(len(dec)) > maxBytes {
				return "", caption, fmt.Errorf("media too large")
			}
			if err := os.WriteFile(outPath, dec, 0o644); err != nil {
				return "", caption, err
			}
			finalize()
			return outPath, caption, nil
		}
		return "", caption, fmt.Errorf("no media source")
	}
	return "", caption, fmt.Errorf("unknown media source")
}

func downloadToFile(urlStr string, outPath string, maxBytes int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bs, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(bs))
		if msg == "" {
			msg = resp.Status
		}
		return fmt.Errorf("download status=%d err=%s", resp.StatusCode, msg)
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	lr := io.LimitReader(resp.Body, maxBytes+1)
	n, err := io.Copy(f, lr)
	if err != nil {
		return err
	}
	if n > maxBytes {
		_ = os.Remove(outPath)
		return fmt.Errorf("download too large")
	}
	return nil
}

func (a *Agent) handleTxMsgAction(in Envelope) {
	var p TxMsgActionPayload
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		a.logf("tx_msg_action: invalid payload: %v", err)
		return
	}
	p.OpID = strings.TrimSpace(p.OpID)
	p.Action = strings.TrimSpace(p.Action)
	p.JID = strings.TrimSpace(p.JID)
	p.StanzaID = strings.TrimSpace(p.StanzaID)
	p.Text = strings.TrimSpace(p.Text)
	p.ParticipantJID = strings.TrimSpace(p.ParticipantJID)
	if p.OpID == "" || p.Action == "" || p.JID == "" || p.StanzaID == "" {
		a.logf("tx_msg_action: missing opId/action/jid/stanzaId")
		return
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 20_000
	}
	if a.runnerPid.Load() == 0 {
		_ = a.startRunner()
	}
	rpcURL := "http://127.0.0.1:17172/rpc/msg/action"
	body, _ := json.Marshal(map[string]any{
		"opId":           p.OpID,
		"action":         p.Action,
		"jid":            p.JID,
		"stanzaId":       p.StanzaID,
		"text":           p.Text,
		"participantJid": p.ParticipantJID,
		"timeoutMs":      p.TimeoutMs,
	})
	cctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.TimeoutMs+3000)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		a.logf("tx_msg_action: build request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.logf("tx_msg_action: rpc failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bs, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(bs))
		if msg == "" {
			msg = resp.Status
		}
		a.logf("tx_msg_action: rpc status=%d err=%s", resp.StatusCode, msg)
		return
	}
	a.logf("tx_msg_action: dispatched opId=%s action=%s jid=%s stanzaId=%s", p.OpID, p.Action, p.JID, p.StanzaID)
}

func (a *Agent) handleTxAvatarURL(in Envelope) {
	var p TxAvatarURLPayload
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		a.logf("tx_avatar_url: invalid payload: %v", err)
		return
	}
	p.OpID = strings.TrimSpace(p.OpID)
	p.JID = strings.TrimSpace(p.JID)
	if p.OpID == "" || p.JID == "" {
		a.logf("tx_avatar_url: missing opId/jid")
		return
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 20_000
	}
	if a.runnerPid.Load() == 0 {
		_ = a.startRunner()
	}
	rpcURL := "http://127.0.0.1:17172/rpc/avatar/url"
	body, _ := json.Marshal(map[string]any{
		"opId":      p.OpID,
		"jid":       p.JID,
		"fullSize":  p.FullSize,
		"timeoutMs": p.TimeoutMs,
	})
	cctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.TimeoutMs+3000)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		a.logf("tx_avatar_url: build request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.logf("tx_avatar_url: rpc failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bs, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(bs))
		if msg == "" {
			msg = resp.Status
		}
		a.logf("tx_avatar_url: rpc status=%d err=%s", resp.StatusCode, msg)
		return
	}
	a.logf("tx_avatar_url: dispatched opId=%s jid=%s", p.OpID, p.JID)
}

func (a *Agent) handleTxSelfCard(in Envelope) {
	var p TxSelfCardPayload
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		a.logf("tx_self_card: invalid payload: %v", err)
		return
	}
	p.OpID = strings.TrimSpace(p.OpID)
	if p.OpID == "" {
		a.logf("tx_self_card: missing opId")
		return
	}
	if p.TimeoutMs <= 0 {
		p.TimeoutMs = 20_000
	}
	if a.runnerPid.Load() == 0 {
		_ = a.startRunner()
	}
	rpcURL := "http://127.0.0.1:17172/rpc/self/card"
	body, _ := json.Marshal(map[string]any{
		"opId":      p.OpID,
		"timeoutMs": p.TimeoutMs,
	})
	cctx, cancel := context.WithTimeout(context.Background(), time.Duration(p.TimeoutMs+3000)*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, rpcURL, bytes.NewReader(body))
	if err != nil {
		a.logf("tx_self_card: build request failed: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.logf("tx_self_card: rpc failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		bs, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(bs))
		if msg == "" {
			msg = resp.Status
		}
		a.logf("tx_self_card: rpc status=%d err=%s", resp.StatusCode, msg)
		return
	}
	a.logf("tx_self_card: dispatched opId=%s", p.OpID)
}

func (a *Agent) handleDbSyncStart(in Envelope) {
	cfg := a.getCfg()
	var p DbSyncStartPayload
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		a.lastDbSyncTS.Store(time.Now().UnixMilli())
		a.lastDbSyncState.Store("invalid_payload")
		a.lastDbSyncErr.Store(err.Error())
		a.logf("dbsync: invalid payload: %v", err)
		return
	}
	if p.JobID == "" || p.UploadURL == "" {
		a.lastDbSyncTS.Store(time.Now().UnixMilli())
		a.lastDbSyncJobID.Store(p.JobID)
		a.lastDbSyncUploadURL.Store(p.UploadURL)
		a.lastDbSyncState.Store("missing_fields")
		a.lastDbSyncErr.Store("missing jobId/uploadUrl")
		a.logf("dbsync: missing jobId/uploadUrl")
		return
	}
	a.lastDbSyncTS.Store(time.Now().UnixMilli())
	a.lastDbSyncJobID.Store(p.JobID)
	a.lastDbSyncUploadURL.Store(p.UploadURL)
	a.lastDbSyncState.Store("started")
	a.lastDbSyncErr.Store("")
	if cfg.WhatsApp.ChatStoragePath == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		found, _, err := locateChatStorage(ctx)
		cancel()
		if err != nil {
			a.lastDbSyncTS.Store(time.Now().UnixMilli())
			a.lastDbSyncState.Store("locate_failed")
			a.lastDbSyncErr.Store(err.Error())
			a.logf("dbsync: chatStoragePath not configured (locate failed: %v)", err)
			a.lastWhatsAppLocateTS.Store(time.Now().UnixMilli())
			a.lastWhatsAppLocateErr.Store(err.Error())
			return
		}
		a.lastWhatsAppLocateTS.Store(time.Now().UnixMilli())
		a.lastWhatsAppLocateErr.Store("")
		next := cfg
		next.WhatsApp.ChatStoragePath = found
		_ = normalizeConfig(&next)
		_ = a.persistConfig(next)
		a.setCfg(next)
		cfg = next
	}
	if cfg.DeviceSecret == "" {
		a.lastDbSyncTS.Store(time.Now().UnixMilli())
		a.lastDbSyncState.Store("device_secret_missing")
		a.lastDbSyncErr.Store("deviceSecret missing")
		a.logf("dbsync: deviceSecret missing (hello_ack not received?)")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := uploadFileMultipart(ctx, p.UploadURL, a.deviceID, cfg.DeviceSecret, cfg.WhatsApp.ChatStoragePath, "ChatStorage.sqlite"); err != nil {
		a.lastDbSyncTS.Store(time.Now().UnixMilli())
		a.lastDbSyncState.Store("upload_failed")
		a.lastDbSyncErr.Store(err.Error())
		a.logf("dbsync: upload failed jobId=%s err=%v", p.JobID, err)
		return
	}
	a.lastDbSyncTS.Store(time.Now().UnixMilli())
	a.lastDbSyncState.Store("upload_ok")
	a.lastDbSyncErr.Store("")
	a.logf("dbsync: upload ok jobId=%s", p.JobID)
}

func valueOrEmptyString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func uploadFileMultipart(ctx context.Context, uploadURL, deviceID, deviceSecret, filePath, fileName string) error {
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return err
	}
	if stat.Size() <= 0 {
		return errors.New("empty file")
	}

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	contentType := writer.FormDataContentType()

	go func() {
		defer pw.Close()
		defer writer.Close()
		_ = writer.WriteField("fileName", fileName)
		part, err := writer.CreateFormFile("file", fileName)
		if err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if _, err := io.Copy(part, f); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadURL, pr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("X-Device-Id", deviceID)
	req.Header.Set("X-Device-Secret", deviceSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("upload failed status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

func (a *Agent) handleOpenTunnel(ctx context.Context, ws *websocket.Conn, sessionID string, in Envelope) {
	cfg := a.getCfg()
	var p OpenTunnelPayload
	_ = json.Unmarshal(in.Payload, &p)
	if p.Target == "" {
		p.Target = "frida"
	}
	a.logf("tunnel: open id=%s target=%s", in.TunnelID, p.Target)
	if p.Target != "frida" {
		a.sendTunnelReady(ctx, ws, sessionID, in.TunnelID, false, "UNSUPPORTED_TARGET")
		a.logf("tunnel: open id=%s fail err=UNSUPPORTED_TARGET", in.TunnelID)
		return
	}

	if cfg.Frida.EnsureRunning {
		_ = ensureFridaUp(cfg.Frida.Host, cfg.Frida.Port, cfg.Frida.StartCmd)
	}

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(dialCtx, "tcp", net.JoinHostPort(cfg.Frida.Host, fmt.Sprintf("%d", cfg.Frida.Port)))
	if err != nil {
		a.sendTunnelReady(ctx, ws, sessionID, in.TunnelID, false, "FRIDA_CONNECT_FAILED")
		a.logf("tunnel: open id=%s fail err=FRIDA_CONNECT_FAILED", in.TunnelID)
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
	a.logf("tunnel: open id=%s ok", in.TunnelID)

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

func normalizeConfig(cfg *Config) error {
	if cfg.ServerURL == "" {
		return errors.New("serverUrl is required")
	}
	if cfg.DeviceIDPath == "" {
		cfg.DeviceIDPath = "/var/mobile/Library/QQwAgent/device_id"
	}
	if cfg.ControlListen == "" {
		cfg.ControlListen = "127.0.0.1:17171"
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
	return nil
}

func (a *Agent) getCfg() Config {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.cfg
}

func (a *Agent) setCfg(cfg Config) {
	a.cfgMu.Lock()
	a.cfg = cfg
	a.cfgMu.Unlock()
}

func (a *Agent) setRunCancel(cancel context.CancelFunc) {
	a.runCancelMu.Lock()
	a.runCancel = cancel
	a.runCancelMu.Unlock()
}

func (a *Agent) clearRunCancel() {
	a.runCancelMu.Lock()
	a.runCancel = nil
	a.runCancelMu.Unlock()
}

func (a *Agent) requestReconnect() {
	a.runCancelMu.Lock()
	cancel := a.runCancel
	a.runCancelMu.Unlock()
	if cancel != nil {
		cancel()
	}
	select {
	case a.reconnectNow <- struct{}{}:
	default:
	}
	a.logf("ws: reconnect requested")
}

func (a *Agent) logf(format string, args ...any) {
	ts := time.Now().Format(time.RFC3339Nano)
	_, _ = fmt.Fprintf(os.Stderr, "%s %s\n", ts, fmt.Sprintf(format, args...))
}
