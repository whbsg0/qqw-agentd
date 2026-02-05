package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

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

type AgentSession struct {
	deviceID string
	session  string
	ws       *websocket.Conn
	wsMu     sync.Mutex
	lastSeen time.Time
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
}

func main() {
	addr := envOr("BROKER_ADDR", ":8080")
	hb := 20
	b := &Broker{
		heartbeatSec: hb,
		deviceSecret: make(map[string]string),
		sessions:     make(map[string]*AgentSession),
		tunnels:      make(map[string]*Tunnel),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/agent/ws", b.handleAgentWS)
	mux.HandleFunc("/api/devices", b.handleDevices)
	mux.HandleFunc("/api/open", b.handleOpenTunnel)
	mux.HandleFunc("/api/tunnels/", b.handleTunnelInfo)

	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	fmt.Println("broker listening on", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func (b *Broker) handleAgentWS(w http.ResponseWriter, r *http.Request) {
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	ctx := r.Context()
	ws.SetReadLimit(8 * 1024 * 1024)

	var sess *AgentSession

	for {
		_, data, err := ws.Read(ctx)
		if err != nil {
			if sess != nil {
				b.removeSession(sess.deviceID, sess.session)
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
			}
			sess = s
			b.upsertSession(s)
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
		b.removeTunnel(tunnelID)
		_ = ln.Close()
		http.Error(w, "open_tunnel send failed", http.StatusBadGateway)
		return
	}

	select {
	case ready := <-t.readyCh:
		if !ready.OK {
			b.removeTunnel(tunnelID)
			_ = ln.Close()
			http.Error(w, ready.Error, http.StatusBadGateway)
			return
		}
	case <-time.After(10 * time.Second):
		b.removeTunnel(tunnelID)
		_ = ln.Close()
		http.Error(w, "tunnel_ready timeout", http.StatusGatewayTimeout)
		return
	}

	go b.acceptOnceAndPump(sess, t)

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
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
		return
	}
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
	b.sessions[s.deviceID] = s
	b.sessionsMu.Unlock()
}

func (b *Broker) removeSession(deviceID, sessionID string) {
	b.sessionsMu.Lock()
	cur := b.sessions[deviceID]
	if cur != nil && cur.session == sessionID {
		delete(b.sessions, deviceID)
	}
	b.sessionsMu.Unlock()
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

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
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
