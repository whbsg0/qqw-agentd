package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	runnerStartedAtMs   int64
	runnerScriptPath    string
	runnerScriptSha256  string
	runnerScriptBuild   string
	runnerHealthMu      sync.RWMutex
	runnerLastHealthErr string
)

// setRunnerLastHealthErr 更新 runner 健康摘要中的最近错误文本，供 /rpc/health 与 agentd ping 透传取证。
// 参数：msg 为最近一次错误摘要；空字符串表示当前无错误。
// 返回：无。
func setRunnerLastHealthErr(msg string) {
	runnerHealthMu.Lock()
	defer runnerHealthMu.Unlock()
	runnerLastHealthErr = strings.TrimSpace(msg)
}

// getRunnerLastHealthErr 读取 runner 健康摘要中的最近错误文本。
// 参数：无。
// 返回：最近一次错误摘要；无错误时返回空字符串。
func getRunnerLastHealthErr() string {
	runnerHealthMu.RLock()
	defer runnerHealthMu.RUnlock()
	return strings.TrimSpace(runnerLastHealthErr)
}

func main() {
	var fridaHost string
	var fridaPort int
	var scriptPath string
	var eventsURL string
	var rpcAddr string
	var processName string
	var bundleID string
	var requireForeground bool
	var waitForegroundMs int
	flag.StringVar(&fridaHost, "fridaHost", "", "frida host")
	flag.IntVar(&fridaPort, "fridaPort", 0, "frida port")
	flag.StringVar(&scriptPath, "scriptPath", "", "script path")
	flag.StringVar(&eventsURL, "eventsUrl", "", "events url")
	flag.StringVar(&rpcAddr, "rpcAddr", "127.0.0.1:17172", "local rpc listen addr")
	flag.StringVar(&processName, "processName", "WhatsApp", "target process name")
	flag.StringVar(&bundleID, "bundleId", "", "target bundle id (spawn fallback)")
	flag.BoolVar(&requireForeground, "requireForeground", true, "require target app to be frontmost before injection")
	flag.IntVar(&waitForegroundMs, "waitForegroundMs", 30000, "max wait for target app to become frontmost")
	flag.Parse()

	fridaHost = strings.TrimSpace(fridaHost)
	scriptPath = strings.TrimSpace(scriptPath)
	eventsURL = strings.TrimSpace(eventsURL)
	rpcAddr = strings.TrimSpace(rpcAddr)
	processName = strings.TrimSpace(processName)
	bundleID = strings.TrimSpace(bundleID)
	if fridaHost == "" || fridaPort <= 0 || scriptPath == "" || eventsURL == "" || processName == "" {
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
	runnerStartedAtMs = time.Now().UnixMilli()
	runnerScriptPath = scriptPath
	sum := sha256.Sum256(scriptBytes)
	runnerScriptSha256 = hex.EncodeToString(sum[:])
	re := regexp.MustCompile(`\bSCRIPT_BUILD_ID\s*=\s*"([^"]+)"`)
	if m := re.FindSubmatch(scriptBytes); len(m) == 2 {
		runnerScriptBuild = strings.TrimSpace(string(m[1]))
	}
	if rpcAddr != "" {
		go startRPCServer(rpcAddr)
	}
	if err := run(fridaHost, fridaPort, processName, bundleID, requireForeground, waitForegroundMs, string(scriptBytes), eventsURL); err != nil {
		_, _ = io.WriteString(os.Stderr, "inject failed: "+err.Error()+"\n")
		os.Exit(2)
	}
}
