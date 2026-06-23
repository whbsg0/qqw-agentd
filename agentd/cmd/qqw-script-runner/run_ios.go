//go:build ios

package main

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <frida-core.h>

extern void goFridaOnMessage(char *message);

typedef struct {
  GMainLoop *loop;
  gboolean detached;
  FridaSessionDetachReason detached_reason;
} qqw_ctx_t;

static GMutex g_script_mu;
static FridaScript *g_script = NULL;
static const char *qqw_runner_debug_local_log_path = "/var/mobile/Library/QQwAgent/trae-debug-log-guard-fuse-errors.ndjson";
static const char *qqw_runner_debug_afc_log_path = "/var/mobile/Media/QQwAgent/trae-debug-log-guard-fuse-errors.ndjson";

static gchar * qqw_strdup_printf2(const gchar *prefix, const gchar *msg);

// qqw_runner_retryable_detach 判断当前 detach 原因是否属于可在进程内重连的临时断链。
// 参数：reason 为 Frida 会话断开原因。
// 返回：TRUE 表示允许在当前 runner 进程内重试；FALSE 表示应直接结束本轮。
static gboolean qqw_runner_retryable_detach(FridaSessionDetachReason reason) {
  return reason == FRIDA_SESSION_DETACH_REASON_CONNECTION_TERMINATED
      || reason == FRIDA_SESSION_DETACH_REASON_DEVICE_LOST;
}

// qqw_runner_debug_append_line 追加一行调试文本到设备私有路径或 AFC 镜像路径。
// 参数：path 为目标路径；line 为已经格式化完成的单行日志。
// 返回：无。
static void qqw_runner_debug_append_line(const char *path, const gchar *line) {
  if (path == NULL || path[0] == '\0' || line == NULL || line[0] == '\0') {
    return;
  }
  FILE *fp = fopen(path, "a");
  if (fp == NULL) {
    return;
  }
  fputs(line, fp);
  fputc('\n', fp);
  fclose(fp);
}

// qqw_runner_debug_log_stage 将 runner 注入生命周期阶段写入设备侧调试日志。
// 参数：stage 为阶段名；detail 为附加文本；value 为阶段相关整数值。
// 返回：无。
static void qqw_runner_debug_log_stage(const gchar *stage, const gchar *detail, gint value) {
  (void) stage;
  (void) detail;
  (void) value;
}

static void qqw_set_script(FridaScript *script) {
  qqw_runner_debug_log_stage("before_set_script", script != NULL ? "script_present" : "script_nil", 0);
  g_mutex_lock(&g_script_mu);
  if (g_script != NULL) {
    g_object_unref(g_script);
    g_script = NULL;
  }
  if (script != NULL) {
    g_script = script;
    g_object_ref(g_script);
  }
  g_mutex_unlock(&g_script_mu);
  qqw_runner_debug_log_stage("after_set_script", script != NULL ? "script_present" : "script_nil", 0);
}

static int qqw_script_ready() {
  g_mutex_lock(&g_script_mu);
  int ok = (g_script != NULL);
  g_mutex_unlock(&g_script_mu);
  return ok;
}

static int qqw_post_json(const char *json, char **error_out) {
  if (json == NULL) {
    *error_out = g_strdup("post: empty");
    return 2;
  }
  g_mutex_lock(&g_script_mu);
  if (g_script == NULL) {
    g_mutex_unlock(&g_script_mu);
    *error_out = g_strdup("post: script not ready");
    return 2;
  }
  frida_script_post(g_script, json, NULL);
  g_mutex_unlock(&g_script_mu);
  return 0;
}

static gchar * qqw_strdup_printf2(const gchar *prefix, const gchar *msg) {
  if (prefix == NULL) prefix = "";
  if (msg == NULL) msg = "";
  return g_strdup_printf("%s%s", prefix, msg);
}

static gchar * qqw_strdup_printf3(const gchar *prefix, const gchar *mid, const gchar *msg) {
  if (prefix == NULL) prefix = "";
  if (mid == NULL) mid = "";
  if (msg == NULL) msg = "";
  return g_strdup_printf("%s%s%s", prefix, mid, msg);
}

static void on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data) {
  if (message == NULL) return;
  qqw_runner_debug_log_stage("callback_message", message, 0);
  goFridaOnMessage((char *) message);
}

static void on_detached(FridaSession *session, FridaSessionDetachReason reason, gpointer crash, gpointer user_data) {
  qqw_ctx_t *ctx = (qqw_ctx_t *) user_data;
  if (ctx == NULL || ctx->loop == NULL) return;
  fprintf(stderr, "frida detached: reason=%d\n", (int) reason);
  ctx->detached = TRUE;
  ctx->detached_reason = reason;
  qqw_runner_debug_log_stage("callback_detached", NULL, (gint) reason);
  qqw_set_script(NULL);
  g_main_loop_quit(ctx->loop);
}

static guint find_pid(FridaDevice *device, const gchar *name, GError **error) {
  FridaProcessList *plist = frida_device_enumerate_processes_sync(device, NULL, NULL, error);
  if (*error != NULL) return 0;
  gint n = frida_process_list_size(plist);
  guint pid = 0;
  for (gint i = 0; i < n; i++) {
    FridaProcess *p = frida_process_list_get(plist, i);
    const gchar *pn = frida_process_get_name(p);
    if (pn != NULL && g_strcmp0(pn, name) == 0) {
      pid = frida_process_get_pid(p);
      g_object_unref(p);
      break;
    }
    g_object_unref(p);
  }
  g_object_unref(plist);
  return pid;
}

static int qqw_run(const char *address, const char *process_name, const char *bundle_id, int require_foreground, int wait_foreground_ms, const char *script_source, char **error_out) {
  qqw_runner_debug_log_stage("enter_run", address, wait_foreground_ms);
  frida_init();
  qqw_runner_debug_log_stage("after_frida_init", process_name, require_foreground);
  GError *error = NULL;

  const gchar *proc = process_name != NULL && process_name[0] != '\0' ? process_name : "WhatsApp";
  const gchar *bid = bundle_id != NULL ? bundle_id : "";
  const int max_attempts = 3;
  const int max_detach_retries = 3;
  int detach_retry_count = 0;

  FridaDeviceManager *manager = NULL;
  FridaDevice *device = NULL;

  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    qqw_runner_debug_log_stage("attempt_begin", NULL, attempt);
    if (device != NULL) { g_object_unref(device); device = NULL; }
    if (manager != NULL) { g_object_unref(manager); manager = NULL; }
    if (error != NULL) { g_error_free(error); error = NULL; }

    manager = frida_device_manager_new();
    qqw_runner_debug_log_stage("after_manager_new", NULL, manager != NULL ? 1 : 0);
    qqw_runner_debug_log_stage("before_add_remote_device", address, attempt);
    device = frida_device_manager_add_remote_device_sync(manager, address, NULL, NULL, &error);
    if (error != NULL && address != NULL) {
      qqw_runner_debug_log_stage("add_remote_device_primary_error", error->message, attempt);
      const char *colon = strchr(address, ':');
      if (colon != NULL) {
        gchar *host_only = g_strndup(address, (gsize) (colon - address));
        g_error_free(error);
        error = NULL;
        qqw_runner_debug_log_stage("before_add_remote_device_host_only", host_only, attempt);
        device = frida_device_manager_add_remote_device_sync(manager, host_only, NULL, NULL, &error);
        g_free(host_only);
      }
    }
    qqw_runner_debug_log_stage("after_add_remote_device", error != NULL ? error->message : NULL, device != NULL ? 1 : 0);
    if (error != NULL) {
      if (attempt < max_attempts && g_strcmp0(error->message, "Timeout was reached") == 0) {
        g_usleep((gulong) (200000 * attempt));
        continue;
      }
      *error_out = qqw_strdup_printf2("add_remote_device: ", error->message);
      g_error_free(error);
      if (device != NULL) g_object_unref(device);
      g_object_unref(manager);
      return 2;
    }

    if (require_foreground) {
      FridaFrontmostQueryOptions *fopts = frida_frontmost_query_options_new();
      frida_frontmost_query_options_set_scope(fopts, FRIDA_SCOPE_MINIMAL);
      gint64 deadline = g_get_monotonic_time() + (gint64) wait_foreground_ms * 1000;
      for (;;) {
        if (error != NULL) { g_error_free(error); error = NULL; }
        FridaApplication *front = frida_device_get_frontmost_application_sync(device, fopts, NULL, &error);
        if (error != NULL) {
          fprintf(stderr, "frontmost query failed: %s\n", error->message);
          qqw_runner_debug_log_stage("frontmost_query_error", error->message, attempt);
          g_error_free(error);
          error = NULL;
          break;
        }
        if (front != NULL) {
          const gchar *fid = frida_application_get_identifier(front);
          const gchar *fname = frida_application_get_name(front);
          gboolean ok = FALSE;
          if (bid[0] != '\0' && fid != NULL && g_strcmp0(fid, bid) == 0) ok = TRUE;
          if (!ok && fname != NULL && g_strcmp0(fname, proc) == 0) ok = TRUE;
          g_object_unref(front);
          if (ok) break;
        }
        if (wait_foreground_ms <= 0 || g_get_monotonic_time() >= deadline) {
          fprintf(stderr, "frontmost: timeout waiting for target app (ignored)\n");
          break;
        }
        g_usleep(200000);
      }
      g_object_unref(fopts);
    }

    guint pid = find_pid(device, proc, &error);
    qqw_runner_debug_log_stage("after_find_pid", proc, (gint) pid);
    if (error != NULL) {
      if (attempt < max_attempts && (g_strcmp0(error->message, "Timeout was reached") == 0 || g_strrstr(error->message, "end-of-stream") != NULL)) {
        g_error_free(error);
        error = NULL;
        g_usleep((gulong) (200000 * attempt));
        continue;
      }
      *error_out = qqw_strdup_printf2("enumerate_processes: ", error->message);
      g_error_free(error);
      g_object_unref(device);
      g_object_unref(manager);
      return 2;
    }
    if (pid == 0) {
      *error_out = qqw_strdup_printf3("process not found: ", proc, "");
      g_object_unref(device);
      g_object_unref(manager);
      return 2;
    }

    qqw_runner_debug_log_stage("before_attach", proc, (gint) pid);
    FridaSession *session = frida_device_attach_sync(device, pid, NULL, NULL, &error);
    qqw_runner_debug_log_stage("after_attach", error != NULL ? error->message : NULL, session != NULL ? 1 : 0);
    if (error != NULL || session == NULL) {
      if (attempt < max_attempts && error != NULL) {
        if (g_strcmp0(error->message, "Timeout was reached") == 0 || g_strrstr(error->message, "end-of-stream") != NULL) {
          g_error_free(error);
          error = NULL;
          g_usleep((gulong) (800000 * attempt));
          continue;
        }
      }
      if (error != NULL) {
        *error_out = qqw_strdup_printf2("attach: ", error->message);
        g_error_free(error);
      } else {
        *error_out = g_strdup("attach: failed");
      }
      g_object_unref(device);
      g_object_unref(manager);
      return 2;
    }

    qqw_runner_debug_log_stage("before_create_script", NULL, attempt);
    FridaScript *script = frida_session_create_script_sync(session, script_source, NULL, NULL, &error);
    qqw_runner_debug_log_stage("after_create_script", error != NULL ? error->message : NULL, script != NULL ? 1 : 0);
    if (error != NULL) {
      *error_out = qqw_strdup_printf2("create_script: ", error->message);
      g_error_free(error);
      g_object_unref(session);
      g_object_unref(device);
      g_object_unref(manager);
      return 2;
    }

    qqw_ctx_t ctx;
    ctx.loop = g_main_loop_new(NULL, FALSE);
    ctx.detached = FALSE;
    ctx.detached_reason = 0;
    qqw_runner_debug_log_stage("after_loop_new", NULL, ctx.loop != NULL ? 1 : 0);
    g_signal_connect(script, "message", G_CALLBACK(on_message), &ctx);
    g_signal_connect(session, "detached", G_CALLBACK(on_detached), &ctx);

    qqw_runner_debug_log_stage("before_script_load", NULL, attempt);
    frida_script_load_sync(script, NULL, &error);
    qqw_runner_debug_log_stage("after_script_load", error != NULL ? error->message : NULL, 0);
    if (error != NULL) {
      *error_out = qqw_strdup_printf2("script_load: ", error->message);
      g_error_free(error);
      g_main_loop_unref(ctx.loop);
      g_object_unref(script);
      g_object_unref(session);
      g_object_unref(device);
      g_object_unref(manager);
      return 2;
    }
    qqw_set_script(script);

    qqw_runner_debug_log_stage("before_main_loop_run", NULL, 0);
    g_main_loop_run(ctx.loop);
    qqw_runner_debug_log_stage("after_main_loop_run", NULL, 0);

    gboolean retryable_detach = ctx.detached && qqw_runner_retryable_detach(ctx.detached_reason);

    qqw_set_script(NULL);
    qqw_runner_debug_log_stage("before_script_unload", NULL, 0);
    frida_script_unload_sync(script, NULL, NULL);
    qqw_runner_debug_log_stage("after_script_unload", NULL, 0);
    g_main_loop_unref(ctx.loop);
    g_object_unref(script);
    g_object_unref(session);
    g_object_unref(device);
    g_object_unref(manager);
    if (retryable_detach) {
      detach_retry_count++;
      qqw_runner_debug_log_stage("retry_after_detach", NULL, detach_retry_count);
      if (detach_retry_count <= max_detach_retries) {
        attempt = 0;
        g_usleep((gulong) (300000 * detach_retry_count));
        continue;
      }
      *error_out = g_strdup_printf("detached: %d", (int) ctx.detached_reason);
      return 2;
    }
    detach_retry_count = 0;
    qqw_runner_debug_log_stage("return_success", NULL, 0);
    return 0;
  }

  *error_out = g_strdup("attach: failed after retries");
  if (device != NULL) g_object_unref(device);
  if (manager != NULL) g_object_unref(manager);
  if (error != NULL) g_error_free(error);
  return 2;
}

static void qqw_free(char *p) {
  if (p != NULL) g_free(p);
}
*/
import "C"

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

var (
	posterMu sync.RWMutex
	poster   *eventPoster
	scriptMu sync.Mutex
)

//export goFridaOnMessage
func goFridaOnMessage(message *C.char) {
	posterMu.RLock()
	p := poster
	posterMu.RUnlock()
	if p == nil {
		return
	}
	handleFridaMessageJSONLine(p, C.GoString(message))
}

func run(fridaHost string, fridaPort int, processName string, bundleID string, requireForeground bool, waitForegroundMs int, scriptSource string, eventsURL string) error {
	posterMu.Lock()
	poster = newEventPoster(eventsURL)
	posterMu.Unlock()

	addr := fridaHost + ":" + strconv.Itoa(fridaPort)

	cAddr := C.CString(addr)
	cProc := C.CString(strings.TrimSpace(processName))
	cBundle := C.CString(strings.TrimSpace(bundleID))
	cSrc := C.CString(scriptSource)
	defer C.free(unsafe.Pointer(cAddr))
	defer C.free(unsafe.Pointer(cProc))
	defer C.free(unsafe.Pointer(cBundle))
	defer C.free(unsafe.Pointer(cSrc))

	var cErr *C.char
	rf := C.int(0)
	if requireForeground {
		rf = 1
	}
	rc := C.qqw_run(cAddr, cProc, cBundle, rf, C.int(waitForegroundMs), cSrc, &cErr)
	if cErr != nil {
		defer C.qqw_free(cErr)
		return errors.New(C.GoString(cErr))
	}
	if rc != 0 {
		return errors.New("runner exited")
	}
	return nil
}

func scriptReady() bool {
	return C.qqw_script_ready() != 0
}

func postToScriptJSON(msg string) error {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return errors.New("post: empty")
	}
	scriptMu.Lock()
	defer scriptMu.Unlock()
	cMsg := C.CString(msg)
	defer C.free(unsafe.Pointer(cMsg))
	var cErr *C.char
	rc := C.qqw_post_json(cMsg, &cErr)
	if cErr != nil {
		defer C.qqw_free(cErr)
		return errors.New(C.GoString(cErr))
	}
	if rc != 0 {
		return errors.New("post: failed")
	}
	return nil
}
