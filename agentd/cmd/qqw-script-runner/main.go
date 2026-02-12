package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type fridaMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

func main() {
	var fridaHost string
	var fridaPort int
	var scriptPath string
	var eventsURL string
	flag.StringVar(&fridaHost, "fridaHost", "", "frida host")
	flag.IntVar(&fridaPort, "fridaPort", 0, "frida port")
	flag.StringVar(&scriptPath, "scriptPath", "", "script path")
	flag.StringVar(&eventsURL, "eventsUrl", "", "events url")
	flag.Parse()

	fridaHost = strings.TrimSpace(fridaHost)
	scriptPath = strings.TrimSpace(scriptPath)
	eventsURL = strings.TrimSpace(eventsURL)
	if fridaHost == "" || fridaPort <= 0 || scriptPath == "" || eventsURL == "" {
		_, _ = io.WriteString(os.Stderr, "invalid args\n")
		os.Exit(2)
	}

	if st, err := os.Stat(scriptPath); err != nil || st.IsDir() {
		_, _ = io.WriteString(os.Stderr, "script not found\n")
		os.Exit(2)
	}

	hostPort := fridaHost + ":" + strconv.Itoa(fridaPort)
	cmd := exec.Command("frida",
		"-H", hostPort,
		"-n", "WhatsApp",
		"-l", scriptPath,
		"--no-pause",
		"--runtime=v8",
		"-q",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error()+"\n")
		os.Exit(2)
	}
	_ = stdin

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error()+"\n")
		os.Exit(2)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error()+"\n")
		os.Exit(2)
	}

	client := &http.Client{Timeout: 8 * time.Second}
	go func() {
		_ = cmd.Wait()
		os.Exit(0)
	}()

	sc := bufio.NewScanner(stdout)
	buf := make([]byte, 0, 1024*1024)
	sc.Buffer(buf, 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, "{") {
			if i := strings.IndexByte(line, '{'); i >= 0 {
				line = strings.TrimSpace(line[i:])
			}
		}
		var msg fridaMessage
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			continue
		}
		if msg.Type != "send" || len(bytes.TrimSpace(msg.Payload)) == 0 {
			continue
		}
		if err := postJSON(client, eventsURL, msg.Payload); err != nil {
			_, _ = io.WriteString(os.Stderr, err.Error()+"\n")
		}
	}
}

func postJSON(client *http.Client, url string, body json.RawMessage) error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		msg := strings.TrimSpace(string(b))
		if msg == "" {
			msg = resp.Status
		}
		return errors.New(msg)
	}
	return nil
}
