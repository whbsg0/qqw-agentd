package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

type txSendRPCReq struct {
	OpID               string `json:"opId"`
	Kind               string `json:"kind"`
	JID                string `json:"jid"`
	Text               string `json:"text,omitempty"`
	QuoteStanzaID      string `json:"quoteStanzaId,omitempty"`
	ParticipantJID     string `json:"participantJid,omitempty"`
	MessageOrigin      int    `json:"messageOrigin,omitempty"`
	CreationEntryPoint int    `json:"creationEntryPoint,omitempty"`
	TimeoutMs          int    `json:"timeoutMs,omitempty"`
}

func startRPCServer(addr string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil || strings.TrimSpace(host) != "127.0.0.1" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/rpc/tx/send", handleRPCTxSend)
	mux.HandleFunc("/rpc/tx/status", handleRPCTxStatus)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	_ = srv.ListenAndServe()
}

func handleRPCTxStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"ts":          time.Now().UnixMilli(),
		"scriptReady": scriptReady(),
	})
}

func handleRPCTxSend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req txSendRPCReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.OpID = strings.TrimSpace(req.OpID)
	req.Kind = strings.TrimSpace(req.Kind)
	req.JID = strings.TrimSpace(req.JID)
	req.Text = strings.TrimSpace(req.Text)
	req.QuoteStanzaID = strings.TrimSpace(req.QuoteStanzaID)
	req.ParticipantJID = strings.TrimSpace(req.ParticipantJID)
	if req.OpID == "" || req.Kind == "" || req.JID == "" {
		http.Error(w, "opId/kind/jid required", http.StatusBadRequest)
		return
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = 20_000
	}
	if !scriptReady() {
		http.Error(w, "script not ready", http.StatusServiceUnavailable)
		return
	}
	msg := map[string]any{
		"type": "qqw.tx_send",
		"payload": map[string]any{
			"opId":               req.OpID,
			"kind":               req.Kind,
			"jid":                req.JID,
			"text":               req.Text,
			"quoteStanzaId":      req.QuoteStanzaID,
			"participantJid":     req.ParticipantJID,
			"messageOrigin":      req.MessageOrigin,
			"creationEntryPoint": req.CreationEntryPoint,
			"timeoutMs":          req.TimeoutMs,
		},
	}
	b, _ := json.Marshal(msg)
	if err := postToScriptJSON(string(b)); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

