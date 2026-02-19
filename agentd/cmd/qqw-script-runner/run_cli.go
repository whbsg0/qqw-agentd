//go:build !ios

package main

import (
	"bufio"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func run(fridaHost string, fridaPort int, processName string, bundleID string, requireForeground bool, waitForegroundMs int, scriptSource string, eventsURL string) error {
	poster := newEventPoster(eventsURL)

	tmp, err := os.CreateTemp("", "qqw-script-*.js")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	if err := os.WriteFile(tmpPath, []byte(scriptSource), 0o644); err != nil {
		return err
	}

	hostPort := strings.TrimSpace(fridaHost) + ":" + strconv.Itoa(fridaPort)
	cmd := exec.Command("frida",
		"-H", hostPort,
		"-n", strings.TrimSpace(processName),
		"-l", tmpPath,
		"--no-pause",
		"--runtime=v8",
		"-q",
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}

	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		handleFridaMessageJSONLine(poster, sc.Text())
	}
	_ = cmd.Wait()
	if err := sc.Err(); err != nil {
		return err
	}
	return errors.New("runner exited")
}

func scriptReady() bool {
	return false
}

func postToScriptJSON(_ string) error {
	return errors.New("script post not supported in cli runner")
}
