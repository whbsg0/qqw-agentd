package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"nhooyr.io/websocket"
)

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
	RegisterToken  string                 `json:"registerToken,omitempty"`
	DeviceSecret   string                 `json:"deviceSecret,omitempty"`
	FridaServerVer string                 `json:"fridaServerVersion,omitempty"`
	Capabilities   map[string]any         `json:"capabilities,omitempty"`
	Extra          map[string]interface{} `json:"-"`
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

type AgentSession struct {
	deviceID string
	session  string
	ws       *websocket.Conn
	wsMu     sync.Mutex
	lastSeen time.Time
	remoteIP string
}

type Tunnel struct {
	id        string
	deviceID  string
	listener  net.Listener
	connMu    sync.Mutex
	conn      net.Conn
	readyCh   chan TunnelReadyPayload
	closeOnce sync.Once
	closed    chan struct{}
}

type Broker struct {
	heartbeatSec int
	secretMu     sync.Mutex
	deviceSecret map[string]string

	sessionsMu sync.Mutex
	sessions   map[string]*AgentSession

	tunnelsMu sync.Mutex
	tunnels   map[string]*Tunnel

	db *sql.DB

	dbErrMu        sync.Mutex
	lastDBErrLogMs map[string]int64

	controlPlaneURL   string
	controlPlaneProxy *httputil.ReverseProxy
	brokerAdminToken  string
	publicBaseURL     string
}

func main() {
	addr := envOr("BROKER_ADDR", ":8080")
	hb := 20
	b := &Broker{
		heartbeatSec:   hb,
		deviceSecret:   make(map[string]string),
		sessions:       make(map[string]*AgentSession),
		tunnels:        make(map[string]*Tunnel),
		lastDBErrLogMs: make(map[string]int64),
	}

	if dsn := strings.TrimSpace(os.Getenv("DATABASE_URL")); dsn != "" {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		db.SetMaxOpenConns(10)
		db.SetMaxIdleConns(10)
		db.SetConnMaxLifetime(30 * time.Minute)
		b.db = db
	}

	controlPlaneURL := envOr("CONTROL_PLANE_INTERNAL_URL", "http://127.0.0.1:8090")
	brokerAdminToken := os.Getenv("BROKER_ADMIN_TOKEN")
	if brokerAdminToken == "" {
		brokerAdminToken = os.Getenv("CONTROL_PLANE_ADMIN_TOKEN")
	}
	publicBaseURL := os.Getenv("BROKER_PUBLIC_BASE_URL")
	if publicBaseURL == "" {
		publicBaseURL = "https://api.bbrbr.com"
	}
	b.controlPlaneURL = controlPlaneURL
	b.brokerAdminToken = brokerAdminToken
	b.publicBaseURL = strings.TrimRight(publicBaseURL, "/")

	cp, err := url.Parse(controlPlaneURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "invalid CONTROL_PLANE_INTERNAL_URL")
		os.Exit(1)
	}
	b.controlPlaneProxy = httputil.NewSingleHostReverseProxy(cp)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", b.handleHealthz)
	mux.HandleFunc("/agent/ws", b.handleAgentWS)
	mux.HandleFunc("/api/devices", b.handleDevices)
	mux.HandleFunc("/api/open", b.handleOpenTunnel)
	mux.HandleFunc("/api/tunnels/", b.handleTunnelInfo)
	mux.HandleFunc("/api/broker/devices/", b.handleBrokerDeviceSubroutes)
	mux.HandleFunc("/api/device/", b.handleDeviceUpload)
	mux.HandleFunc("/api/", b.handleAPIProxy)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logJSON("broker_listening", map[string]any{"addr": addr})
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func (b *Broker) handleHealthz(w http.ResponseWriter, r *http.Request) {
	b.sessionsMu.Lock()
	sessions := len(b.sessions)
	b.sessionsMu.Unlock()
	b.tunnelsMu.Lock()
	tunnels := len(b.tunnels)
	b.tunnelsMu.Unlock()
	out := map[string]any{
		"ok":       true,
		"ts":       time.Now().UnixMilli(),
		"sessions": sessions,
		"tunnels":  tunnels,
	}
	if b.db != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := b.db.PingContext(ctx); err != nil {
			out["dbOk"] = false
			out["dbErr"] = err.Error()
		} else {
			out["dbOk"] = true
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (b *Broker) shouldLogDBErr(deviceID string) bool {
	now := time.Now().UnixMilli()
	b.dbErrMu.Lock()
	defer b.dbErrMu.Unlock()
	last := b.lastDBErrLogMs[deviceID]
	if last > 0 && now-last < 60_000 {
		return false
	}
	b.lastDBErrLogMs[deviceID] = now
	return true
}

func (b *Broker) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		logJSON("agent_ws_accept_failed", map[string]any{"remote": r.RemoteAddr, "err": err.Error()})
		return
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	logJSON("agent_ws_accepted", map[string]any{"remote": r.RemoteAddr})

	ctx := r.Context()
	ws.SetReadLimit(8 * 1024 * 1024)

	var sess *AgentSession
	remoteIP := clientIP(r)

	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			if sess != nil {
				b.removeSession(sess.deviceID, sess.session)
				b.recordSessionDisconnected(sess.deviceID, sess.session)
				logJSON("agent_ws_closed", map[string]any{
					"deviceId":  sess.deviceID,
					"sessionId": sess.session,
				})
			}
			return
		}
		var in Envelope
		if err := json.Unmarshal(data, &in); err != nil {
			continue
		}
		switch in.Type {
		case "hello":
			var p HelloPayload
			_ = json.Unmarshal(in.Payload, &p)
			sessionID := uuidV4Must()
			deviceSecret := b.getOrCreateDeviceSecret(in.DeviceID, p.DeviceSecret)
			s := &AgentSession{
				deviceID: in.DeviceID,
				session:  sessionID,
				ws:       ws,
				lastSeen: time.Now(),
				remoteIP: remoteIP,
			}
			sess = s
			b.upsertSession(s)
			b.recordSessionConnected(s.deviceID, s.session, s.remoteIP)
			logJSON("agent_hello", map[string]any{
				"deviceId":         in.DeviceID,
				"sessionId":        sessionID,
				"fridaServerVer":   p.FridaServerVer,
				"hasRegisterToken": p.RegisterToken != "",
			})
			ackPayload, _ := json.Marshal(HelloAckPayload{
				SessionID:    sessionID,
				DeviceSecret: deviceSecret,
				HeartbeatSec: b.heartbeatSec,
			})
			ack := Envelope{
				V:        1,
				Type:     "hello_ack",
				DeviceID: in.DeviceID,
				Session:  sessionID,
				TS:       time.Now().UnixMilli(),
				Payload:  ackPayload,
			}
			_ = s.send(ctx, ack)
		case "ping":
			if sess != nil {
				sess.lastSeen = time.Now()
				b.recordSessionSeen(sess.deviceID, sess.session, sess.remoteIP)
			}
			pong := Envelope{
				V:        1,
				Type:     "pong",
				DeviceID: in.DeviceID,
				Session:  in.Session,
				TS:       time.Now().UnixMilli(),
			}
			if sess != nil {
				_ = sess.send(ctx, pong)
			}
		case "tunnel_ready":
			b.onTunnelReady(in)
		case "tunnel_data":
			b.onTunnelData(in)
		}
	}
}

func (b *Broker) handleDevices(w http.ResponseWriter, r *http.Request) {
	if !b.requireAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	type row struct {
		DeviceID  string `json:"deviceId"`
		SessionID string `json:"sessionId"`
		LastSeen  int64  `json:"lastSeen"`
	}
	b.sessionsMu.Lock()
	out := make([]row, 0, len(b.sessions))
	for _, s := range b.sessions {
		out = append(out, row{DeviceID: s.deviceID, SessionID: s.session, LastSeen: s.lastSeen.UnixMilli()})
	}
	b.sessionsMu.Unlock()
	writeJSON(w, http.StatusOK, out)
}

func (b *Broker) handleBrokerDeviceSubroutes(w http.ResponseWriter, r *http.Request) {
	if !b.requireAdmin(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/broker/devices/")
	parts := strings.Split(path, "/")
	if len(parts) >= 3 && parts[1] == "dbsync" && parts[2] == "start" {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		deviceID := parts[0]
		var req struct {
			JobID string `json:"jobId"`
		}
		if err := readJSON(r, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if deviceID == "" || req.JobID == "" {
			http.Error(w, "deviceId and jobId required", http.StatusBadRequest)
			return
		}
		sess := b.getSession(deviceID)
		if sess == nil {
			http.Error(w, "device offline", http.StatusNotFound)
			return
		}
		payload, _ := json.Marshal(DbSyncStartPayload{
			JobID:     req.JobID,
			UploadURL: fmt.Sprintf("%s/api/device/%s/dbsync/jobs/%s/files", b.publicBaseURL, deviceID, req.JobID),
		})
		env := Envelope{
			V:        1,
			Type:     "dbsync_start",
			DeviceID: deviceID,
			Session:  sess.session,
			TS:       time.Now().UnixMilli(),
			Payload:  payload,
		}
		if err := sess.send(r.Context(), env); err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (b *Broker) handleDeviceUpload(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/device/")
	parts := strings.Split(path, "/")
	deviceID := ""
	target := ""
	if len(parts) == 2 && parts[1] == "asset-snapshot" {
		deviceID = parts[0]
		if deviceID == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if hdrID := strings.TrimSpace(r.Header.Get("X-Device-Id")); hdrID == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		} else if hdrID != deviceID {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		secret := r.Header.Get("X-Device-Secret")
		if secret == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !b.verifyDeviceSecret(deviceID, secret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if b.brokerAdminToken == "" {
			http.Error(w, "broker admin token not configured", http.StatusServiceUnavailable)
			return
		}
		target = fmt.Sprintf("%s/api/admin/devices/%s/asset-snapshot", strings.TrimRight(b.controlPlaneURL, "/"), url.PathEscape(deviceID))
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header.Set("Authorization", "Bearer "+b.brokerAdminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	} else if len(parts) == 4 && parts[1] == "asset" && parts[2] == "egress-ip" && parts[3] == "fill" {
		deviceID = parts[0]
		if deviceID == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if hdrID := strings.TrimSpace(r.Header.Get("X-Device-Id")); hdrID == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		} else if hdrID != deviceID {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		secret := r.Header.Get("X-Device-Secret")
		if secret == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !b.verifyDeviceSecret(deviceID, secret) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sess := b.getSession(deviceID)
		if sess == nil || strings.TrimSpace(sess.remoteIP) == "" {
			http.Error(w, "device not online", http.StatusServiceUnavailable)
			return
		}
		if b.brokerAdminToken == "" {
			http.Error(w, "broker admin token not configured", http.StatusServiceUnavailable)
			return
		}
		target = fmt.Sprintf("%s/api/admin/devices/%s/asset/egress-ip", strings.TrimRight(b.controlPlaneURL, "/"), url.PathEscape(deviceID))
		body, _ := json.Marshal(map[string]any{"egressIp": strings.TrimSpace(sess.remoteIP)})
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		req.Header.Set("Authorization", "Bearer "+b.brokerAdminToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
		return
	} else if len(parts) == 5 && parts[1] == "dbsync" && parts[2] == "jobs" && parts[4] == "files" {
		deviceID = parts[0]
		jobID := parts[3]
		if deviceID == "" || jobID == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		target = fmt.Sprintf("%s/api/admin/dbsync/jobs/%s/files", strings.TrimRight(b.controlPlaneURL, "/"), jobID)
		r.Body = http.MaxBytesReader(w, r.Body, 256<<20)
	} else if len(parts) == 3 && parts[1] == "asset" && parts[2] == "egress-ip" {
		deviceID = parts[0]
		if deviceID == "" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		target = fmt.Sprintf("%s/api/admin/devices/%s/asset/egress-ip", strings.TrimRight(b.controlPlaneURL, "/"), deviceID)
	} else {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if hdrID := strings.TrimSpace(r.Header.Get("X-Device-Id")); hdrID == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	} else if hdrID != deviceID {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	secret := r.Header.Get("X-Device-Secret")
	if secret == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !b.verifyDeviceSecret(deviceID, secret) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if b.brokerAdminToken == "" {
		http.Error(w, "broker admin token not configured", http.StatusServiceUnavailable)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, target, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	req.Header.Set("Authorization", "Bearer "+b.brokerAdminToken)
	if ct := r.Header.Get("Content-Type"); ct != "" {
		req.Header.Set("Content-Type", ct)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (b *Broker) handleAPIProxy(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/admin/") || strings.HasPrefix(r.URL.Path, "/api/employee/") || strings.HasPrefix(r.URL.Path, "/api/enrollments/") || strings.HasPrefix(r.URL.Path, "/api/trades") || strings.HasPrefix(r.URL.Path, "/api/audit") {
		b.controlPlaneProxy.ServeHTTP(w, r)
		return
	}
	http.Error(w, "not found", http.StatusNotFound)
}

func (b *Broker) requireAdmin(r *http.Request) bool {
	if b.brokerAdminToken == "" {
		return true
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		return false
	}
	token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	return token == b.brokerAdminToken
}

func (b *Broker) verifyDeviceSecret(deviceID, provided string) bool {
	b.secretMu.Lock()
	defer b.secretMu.Unlock()
	sec, ok := b.deviceSecret[deviceID]
	return ok && sec != "" && sec == provided
}

func (b *Broker) handleOpenTunnel(w http.ResponseWriter, r *http.Request) {
	deviceID := r.URL.Query().Get("deviceId")
	if deviceID == "" {
		http.Error(w, "deviceId required", http.StatusBadRequest)
		return
	}
	sess := b.getSession(deviceID)
	if sess == nil {
		http.Error(w, "device offline", http.StatusNotFound)
		return
	}

	tunnelID := uuidV4Must()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logJSON("tunnel_listen_failed", map[string]any{"deviceId": deviceID, "tunnelId": tunnelID, "err": err.Error()})
		http.Error(w, "listen failed", http.StatusInternalServerError)
		return
	}

	t := &Tunnel{
		id:       tunnelID,
		deviceID: deviceID,
		listener: ln,
		readyCh:  make(chan TunnelReadyPayload, 1),
		closed:   make(chan struct{}),
	}
	b.addTunnel(t)

	openPayload, _ := json.Marshal(OpenTunnelPayload{Target: "frida"})
	openMsg := Envelope{
		V:        1,
		Type:     "open_tunnel",
		DeviceID: deviceID,
		Session:  sess.session,
		TunnelID: tunnelID,
		TS:       time.Now().UnixMilli(),
		Payload:  openPayload,
	}
	if err := sess.send(r.Context(), openMsg); err != nil {
		logJSON("open_tunnel_send_failed", map[string]any{"deviceId": deviceID, "tunnelId": tunnelID, "err": err.Error()})
		b.removeTunnel(tunnelID)
		_ = ln.Close()
		http.Error(w, "open_tunnel send failed", http.StatusBadGateway)
		return
	}

	select {
	case ready := <-t.readyCh:
		if !ready.OK {
			logJSON("tunnel_ready_failed", map[string]any{"deviceId": deviceID, "tunnelId": tunnelID, "err": ready.Error})
			b.removeTunnel(tunnelID)
			_ = ln.Close()
			http.Error(w, ready.Error, http.StatusBadGateway)
			return
		}
	case <-time.After(10 * time.Second):
		logJSON("tunnel_ready_timeout", map[string]any{"deviceId": deviceID, "tunnelId": tunnelID})
		b.removeTunnel(tunnelID)
		_ = ln.Close()
		http.Error(w, "tunnel_ready timeout", http.StatusGatewayTimeout)
		return
	}

	go b.acceptOnceAndPump(sess, t)

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	logJSON("tunnel_opened", map[string]any{"deviceId": deviceID, "tunnelId": tunnelID, "localHost": "127.0.0.1", "localPort": portStr})
	writeJSON(w, http.StatusOK, map[string]any{
		"deviceId":  deviceID,
		"tunnelId":  tunnelID,
		"localHost": "127.0.0.1",
		"localPort": portStr,
	})
}

func (b *Broker) handleTunnelInfo(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/api/tunnels/"):]
	if id == "" {
		http.Error(w, "tunnelId required", http.StatusBadRequest)
		return
	}
	t := b.getTunnel(id)
	if t == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	t.connMu.Lock()
	hasConn := t.conn != nil
	t.connMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"tunnelId": id,
		"deviceId": t.deviceID,
		"hasConn":  hasConn,
	})
}

func (b *Broker) acceptOnceAndPump(sess *AgentSession, t *Tunnel) {
	defer b.cleanupTunnel(sess, t)
	_ = t.listener.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
	conn, err := t.listener.Accept()
	if err != nil {
		logJSON("tunnel_accept_failed", map[string]any{"deviceId": t.deviceID, "tunnelId": t.id, "err": err.Error()})
		return
	}
	logJSON("tunnel_local_connected", map[string]any{"deviceId": t.deviceID, "tunnelId": t.id})
	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		buf := make([]byte, 16*1024)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(120 * time.Second))
			n, err := conn.Read(buf)
			if n > 0 {
				p, _ := json.Marshal(TunnelDataPayload{B64: base64.StdEncoding.EncodeToString(buf[:n])})
				msg := Envelope{
					V:        1,
					Type:     "tunnel_data",
					DeviceID: t.deviceID,
					Session:  sess.session,
					TunnelID: t.id,
					TS:       time.Now().UnixMilli(),
					Payload:  p,
				}
				_ = sess.send(context.Background(), msg)
			}
			if err != nil {
				cancel()
				return
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
	}()

	<-ctx.Done()
}

func (b *Broker) onTunnelReady(in Envelope) {
	var p TunnelReadyPayload
	if err := json.Unmarshal(in.Payload, &p); err != nil {
		return
	}
	t := b.getTunnel(in.TunnelID)
	if t == nil {
		return
	}
	select {
	case t.readyCh <- p:
	default:
	}
}

func (b *Broker) onTunnelData(in Envelope) {
	t := b.getTunnel(in.TunnelID)
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
	t.connMu.Lock()
	conn := t.conn
	t.connMu.Unlock()
	if conn == nil {
		return
	}
	_, _ = conn.Write(raw)
}

func (b *Broker) cleanupTunnel(sess *AgentSession, t *Tunnel) {
	t.closeOnce.Do(func() {
		close(t.closed)
	})
	_ = t.listener.Close()
	t.connMu.Lock()
	if t.conn != nil {
		_ = t.conn.Close()
	}
	t.connMu.Unlock()
	b.removeTunnel(t.id)
	logJSON("tunnel_closed", map[string]any{"deviceId": t.deviceID, "tunnelId": t.id})
	closeMsg := Envelope{
		V:        1,
		Type:     "close_tunnel",
		DeviceID: t.deviceID,
		Session:  sess.session,
		TunnelID: t.id,
		TS:       time.Now().UnixMilli(),
	}
	_ = sess.send(context.Background(), closeMsg)
}

func (b *Broker) getOrCreateDeviceSecret(deviceID, provided string) string {
	b.secretMu.Lock()
	defer b.secretMu.Unlock()
	if s, ok := b.deviceSecret[deviceID]; ok {
		return s
	}
	if provided != "" {
		b.deviceSecret[deviceID] = provided
		return provided
	}
	s := uuidV4Must()
	b.deviceSecret[deviceID] = s
	return s
}

func (b *Broker) upsertSession(s *AgentSession) {
	b.sessionsMu.Lock()
	prev := b.sessions[s.deviceID]
	b.sessions[s.deviceID] = s
	b.sessionsMu.Unlock()
	if prev != nil && prev.session != s.session {
		_ = prev.ws.Close(websocket.StatusNormalClosure, "replaced")
	}
}

func (b *Broker) removeSession(deviceID, sessionID string) {
	b.sessionsMu.Lock()
	cur := b.sessions[deviceID]
	if cur != nil && cur.session == sessionID {
		delete(b.sessions, deviceID)
	}
	b.sessionsMu.Unlock()
}

func (b *Broker) recordSessionConnected(deviceID, sessionID, ip string) {
	if b.db == nil {
		return
	}
	deviceID = strings.TrimSpace(deviceID)
	sessionID = strings.TrimSpace(sessionID)
	ip = normalizeIP(ip)
	if deviceID == "" || sessionID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := b.db.ExecContext(ctx, `insert into devices(device_id, updated_at) values ($1, now()) on conflict (device_id) do update set updated_at=now()`, deviceID); err != nil {
		if b.shouldLogDBErr(deviceID) {
			logJSON("db_write_failed", map[string]any{"op": "devices_upsert", "deviceId": deviceID, "err": err.Error()})
		}
	}
	if _, err := b.db.ExecContext(ctx, `
insert into agent_sessions(device_id, session_id, connected_at, last_seen_at, last_ip)
values ($1, $2, now(), now(), nullif($3,'')::inet)
on conflict (device_id, session_id) do update set
  disconnected_at = null,
  last_seen_at = now(),
  last_ip = excluded.last_ip
`, deviceID, sessionID, ip); err != nil {
		if b.shouldLogDBErr(deviceID) {
			logJSON("db_write_failed", map[string]any{"op": "agent_sessions_connect", "deviceId": deviceID, "sessionId": sessionID, "err": err.Error()})
		}
	}
}

func (b *Broker) recordSessionSeen(deviceID, sessionID, ip string) {
	if b.db == nil {
		return
	}
	deviceID = strings.TrimSpace(deviceID)
	sessionID = strings.TrimSpace(sessionID)
	ip = normalizeIP(ip)
	if deviceID == "" || sessionID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := b.db.ExecContext(ctx, `update devices set updated_at=now() where device_id=$1`, deviceID); err != nil {
		if b.shouldLogDBErr(deviceID) {
			logJSON("db_write_failed", map[string]any{"op": "devices_touch", "deviceId": deviceID, "err": err.Error()})
		}
	}
	if _, err := b.db.ExecContext(ctx, `update agent_sessions set last_seen_at=now(), last_ip=nullif($3,'')::inet where device_id=$1 and session_id=$2 and disconnected_at is null`, deviceID, sessionID, ip); err != nil {
		if b.shouldLogDBErr(deviceID) {
			logJSON("db_write_failed", map[string]any{"op": "agent_sessions_ping", "deviceId": deviceID, "sessionId": sessionID, "err": err.Error()})
		}
	}
}

func (b *Broker) recordSessionDisconnected(deviceID, sessionID string) {
	if b.db == nil {
		return
	}
	deviceID = strings.TrimSpace(deviceID)
	sessionID = strings.TrimSpace(sessionID)
	if deviceID == "" || sessionID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := b.db.ExecContext(ctx, `update devices set updated_at=now() where device_id=$1`, deviceID); err != nil {
		if b.shouldLogDBErr(deviceID) {
			logJSON("db_write_failed", map[string]any{"op": "devices_touch", "deviceId": deviceID, "err": err.Error()})
		}
	}
	if _, err := b.db.ExecContext(ctx, `update agent_sessions set disconnected_at=now() where device_id=$1 and session_id=$2 and disconnected_at is null`, deviceID, sessionID); err != nil {
		if b.shouldLogDBErr(deviceID) {
			logJSON("db_write_failed", map[string]any{"op": "agent_sessions_disconnect", "deviceId": deviceID, "sessionId": sessionID, "err": err.Error()})
		}
	}
}

func normalizeIP(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if ip := net.ParseIP(v); ip == nil {
		return ""
	}
	return v
}

func clientIP(r *http.Request) string {
	xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if xff != "" {
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			if ip := strings.TrimSpace(parts[0]); ip != "" {
				return ip
			}
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && strings.TrimSpace(host) != "" {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func (b *Broker) getSession(deviceID string) *AgentSession {
	b.sessionsMu.Lock()
	s := b.sessions[deviceID]
	b.sessionsMu.Unlock()
	return s
}

func (b *Broker) addTunnel(t *Tunnel) {
	b.tunnelsMu.Lock()
	b.tunnels[t.id] = t
	b.tunnelsMu.Unlock()
}

func (b *Broker) removeTunnel(id string) {
	b.tunnelsMu.Lock()
	delete(b.tunnels, id)
	b.tunnelsMu.Unlock()
}

func (b *Broker) getTunnel(id string) *Tunnel {
	b.tunnelsMu.Lock()
	t := b.tunnels[id]
	b.tunnelsMu.Unlock()
	return t
}

func (s *AgentSession) send(ctx context.Context, env Envelope) error {
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	s.wsMu.Lock()
	defer s.wsMu.Unlock()
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return s.ws.Write(wctx, websocket.MessageText, b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func logJSON(event string, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any)
	}
	fields["event"] = event
	fields["ts"] = time.Now().UnixMilli()
	b, err := json.Marshal(fields)
	if err != nil {
		log.Println(event)
		return
	}
	log.Println(string(b))
}

func uuidV4Must() string {
	id, err := uuidV4()
	if err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return id
}

func uuidV4() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[0], b[1], b[2], b[3],
		b[4], b[5],
		b[6], b[7],
		b[8], b[9],
		b[10], b[11], b[12], b[13], b[14], b[15],
	), nil
}
