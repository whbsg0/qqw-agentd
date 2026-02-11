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

type DbSyncStartPayload struct {
	JobID     string `json:"jobId"`
	UploadURL string `json:"uploadUrl"`
}

type Agent struct {
	cfgMu sync.RWMutex
	cfg   Config

	deviceID string

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
		tunnels:      make(map[string]*Tunnel),
		startedAt:    time.Now(),
		reconnectNow: make(chan struct{}, 1),
	}

	a.startControlServer(cfgPath)
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
		case "dbsync_start":
			go a.handleDbSyncStart(in)
		}
	}
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
