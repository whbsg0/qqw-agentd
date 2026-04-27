package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"
)

type txSendRPCReq struct {
	OpID               string          `json:"opId"`
	Kind               string          `json:"kind"`
	JID                string          `json:"jid"`
	Text               string          `json:"text,omitempty"`
	QuoteStanzaID      string          `json:"quoteStanzaId,omitempty"`
	ParticipantJID     string          `json:"participantJid,omitempty"`
	MessageOrigin      int             `json:"messageOrigin,omitempty"`
	CreationEntryPoint int             `json:"creationEntryPoint,omitempty"`
	TimeoutMs          int             `json:"timeoutMs,omitempty"`
	MediaRef           json.RawMessage `json:"mediaRef,omitempty"`
	Path               string          `json:"path,omitempty"`
	Caption            string          `json:"caption,omitempty"`
	Mime               string          `json:"mime,omitempty"`
	Filename           string          `json:"filename,omitempty"`
	ThumbnailPath      string          `json:"thumbnailPath,omitempty"`
	DurationSec        int             `json:"durationSec,omitempty"`
}

type msgActionRPCReq struct {
	OpID           string `json:"opId"`
	Action         string `json:"action"`
	JID            string `json:"jid"`
	StanzaID       string `json:"stanzaId"`
	Text           string `json:"text,omitempty"`
	ParticipantJID string `json:"participantJid,omitempty"`
	TimeoutMs      int    `json:"timeoutMs,omitempty"`
}

type avatarURLRPCReq struct {
	OpID      string `json:"opId"`
	JID       string `json:"jid"`
	FullSize  bool   `json:"fullSize,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
}

type selfCardRPCReq struct {
	OpID      string `json:"opId"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
}

type contactsNoteUpsertRPCReq struct {
	V               int    `json:"v,omitempty"`
	OpID            string `json:"opId"`
	ChatJid         string `json:"chatJid,omitempty"`
	ContactPhoneJid string `json:"contactPhoneJid,omitempty"`
	PhoneDigits     string `json:"phoneDigits"`
	NoteText        string `json:"noteText"`
	TimeoutMs       int    `json:"timeoutMs,omitempty"`
}

type contactsAddRPCReq struct {
	V         int    `json:"v,omitempty"`
	OpID      string `json:"opId"`
	ChatJid   string `json:"chatJid,omitempty"`
	PhoneRaw  string `json:"phoneRaw,omitempty"`
	PhoneE164 string `json:"phoneE164"`
	GivenName string `json:"givenName,omitempty"`
	TimeoutMs int    `json:"timeoutMs,omitempty"`
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
	mux.HandleFunc("/rpc/health", handleRPCHealth)
	mux.HandleFunc("/rpc/tx/send", handleRPCTxSend)
	mux.HandleFunc("/rpc/tx/status", handleRPCTxStatus)
	mux.HandleFunc("/rpc/msg/action", handleRPCMsgAction)
	mux.HandleFunc("/rpc/avatar/url", handleRPCAvatarURL)
	mux.HandleFunc("/rpc/self/card", handleRPCSelfCard)
	mux.HandleFunc("/rpc/contacts/note/upsert", handleRPCContactsNoteUpsert)
	mux.HandleFunc("/rpc/contacts/add", handleRPCContactsAdd)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	_ = srv.ListenAndServe()
}

func handleRPCContactsNoteUpsert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req contactsNoteUpsertRPCReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.OpID = strings.TrimSpace(req.OpID)
	req.ChatJid = strings.TrimSpace(req.ChatJid)
	req.ContactPhoneJid = strings.TrimSpace(req.ContactPhoneJid)
	req.PhoneDigits = strings.TrimSpace(req.PhoneDigits)
	req.NoteText = strings.TrimSpace(req.NoteText)
	if req.OpID == "" || req.PhoneDigits == "" {
		http.Error(w, "opId/phoneDigits required", http.StatusBadRequest)
		return
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = 15_000
	}
	msg := map[string]any{
		"type": "qqw.contacts_note_upsert",
		"payload": map[string]any{
			"v":               1,
			"opId":            req.OpID,
			"chatJid":         req.ChatJid,
			"contactPhoneJid": req.ContactPhoneJid,
			"phoneDigits":     req.PhoneDigits,
			"noteText":        req.NoteText,
			"timeoutMs":       req.TimeoutMs,
		},
	}
	bs, _ := json.Marshal(msg)
	if err := postToScriptJSON(string(bs)); err != nil {
		http.Error(w, "script post failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleRPCContactsAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req contactsAddRPCReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.OpID = strings.TrimSpace(req.OpID)
	req.ChatJid = strings.TrimSpace(req.ChatJid)
	req.PhoneRaw = strings.TrimSpace(req.PhoneRaw)
	req.PhoneE164 = strings.TrimSpace(req.PhoneE164)
	req.GivenName = strings.TrimSpace(req.GivenName)
	if req.OpID == "" || req.PhoneE164 == "" {
		http.Error(w, "opId/phoneE164 required", http.StatusBadRequest)
		return
	}
	if req.TimeoutMs <= 0 {
		req.TimeoutMs = 15_000
	}
	if req.GivenName == "" {
		req.GivenName = "联系人"
	}
	msg := map[string]any{
		"type": "qqw.contacts_add",
		"payload": map[string]any{
			"v":         1,
			"opId":      req.OpID,
			"chatJid":   req.ChatJid,
			"phoneRaw":  req.PhoneRaw,
			"phoneE164": req.PhoneE164,
			"givenName": req.GivenName,
			"timeoutMs": req.TimeoutMs,
		},
	}
	bs, _ := json.Marshal(msg)
	if err := postToScriptJSON(string(bs)); err != nil {
		http.Error(w, "script post failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleRPCHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"ts":           time.Now().UnixMilli(),
		"startedAtMs":  runnerStartedAtMs,
		"scriptReady":  scriptReady(),
		"scriptPath":   strings.TrimSpace(runnerScriptPath),
		"scriptSha256": strings.TrimSpace(runnerScriptSha256),
		"scriptBuild":  strings.TrimSpace(runnerScriptBuild),
	})
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
	req.Path = strings.TrimSpace(req.Path)
	req.Caption = strings.TrimSpace(req.Caption)
	req.Mime = strings.TrimSpace(req.Mime)
	req.Filename = strings.TrimSpace(req.Filename)
	req.ThumbnailPath = strings.TrimSpace(req.ThumbnailPath)
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
	payload := map[string]any{
		"opId":           req.OpID,
		"kind":           req.Kind,
		"jid":            req.JID,
		"text":           req.Text,
		"quoteStanzaId":  req.QuoteStanzaID,
		"participantJid": req.ParticipantJID,
		"timeoutMs":      req.TimeoutMs,
		"path":           req.Path,
		"caption":        req.Caption,
		"mime":           req.Mime,
		"filename":       req.Filename,
		"thumbnailPath":  req.ThumbnailPath,
		"durationSec":    req.DurationSec,
	}
	if len(req.MediaRef) > 0 {
		var mr any
		if json.Unmarshal(req.MediaRef, &mr) == nil && mr != nil {
			payload["mediaRef"] = mr
		}
	}
	if req.MessageOrigin > 0 {
		payload["messageOrigin"] = req.MessageOrigin
	}
	if req.CreationEntryPoint > 0 {
		payload["creationEntryPoint"] = req.CreationEntryPoint
	}
	msg := map[string]any{
		"type":    "qqw.tx_send",
		"payload": payload,
	}
	b, _ := json.Marshal(msg)
	if err := postToScriptJSON(string(b)); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleRPCMsgAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req msgActionRPCReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.OpID = strings.TrimSpace(req.OpID)
	req.Action = strings.TrimSpace(req.Action)
	req.JID = strings.TrimSpace(req.JID)
	req.StanzaID = strings.TrimSpace(req.StanzaID)
	req.Text = strings.TrimSpace(req.Text)
	req.ParticipantJID = strings.TrimSpace(req.ParticipantJID)
	if req.OpID == "" || req.Action == "" || req.JID == "" || req.StanzaID == "" {
		http.Error(w, "opId/action/jid/stanzaId required", http.StatusBadRequest)
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
		"type": "qqw.msg_action",
		"payload": map[string]any{
			"opId":           req.OpID,
			"action":         req.Action,
			"jid":            req.JID,
			"stanzaId":       req.StanzaID,
			"text":           req.Text,
			"participantJid": req.ParticipantJID,
			"timeoutMs":      req.TimeoutMs,
		},
	}
	b, _ := json.Marshal(msg)
	if err := postToScriptJSON(string(b)); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleRPCAvatarURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req avatarURLRPCReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.OpID = strings.TrimSpace(req.OpID)
	req.JID = strings.TrimSpace(req.JID)
	if req.OpID == "" || req.JID == "" {
		http.Error(w, "opId/jid required", http.StatusBadRequest)
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
		"type": "qqw.avatar_url",
		"payload": map[string]any{
			"opId":      req.OpID,
			"jid":       req.JID,
			"fullSize":  req.FullSize,
			"timeoutMs": req.TimeoutMs,
		},
	}
	b, _ := json.Marshal(msg)
	if err := postToScriptJSON(string(b)); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleRPCSelfCard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req selfCardRPCReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}
	req.OpID = strings.TrimSpace(req.OpID)
	if req.OpID == "" {
		http.Error(w, "opId required", http.StatusBadRequest)
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
		"type": "qqw.self_card",
		"payload": map[string]any{
			"opId":      req.OpID,
			"timeoutMs": req.TimeoutMs,
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
