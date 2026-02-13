package main

import (
	"flag"
	"io"
	"os"
	"strings"
)

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

	scriptBytes, err := os.ReadFile(scriptPath)
	if err != nil || len(scriptBytes) == 0 {
		_, _ = io.WriteString(os.Stderr, "script read failed\n")
		os.Exit(2)
	}
	if err := run(fridaHost, fridaPort, string(scriptBytes), eventsURL); err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error()+"\n")
		os.Exit(2)
	}
}
