//go:build ios

package main

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <frida-core.h>

typedef struct {
  GMainLoop *loop;
  gchar *message;
} qqw_frontmost_probe_ctx_t;

static guint qqw_frontmost_find_pid(FridaDevice *device, const gchar *name, GError **error) {
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

static void qqw_frontmost_on_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data) {
  qqw_frontmost_probe_ctx_t *ctx = (qqw_frontmost_probe_ctx_t *) user_data;
  if (ctx == NULL || ctx->loop == NULL || message == NULL) return;
  if (ctx->message == NULL) {
    ctx->message = g_strdup(message);
  }
  g_main_loop_quit(ctx->loop);
}

static void qqw_frontmost_on_detached(FridaSession *session, FridaSessionDetachReason reason, gpointer crash, gpointer user_data) {
  qqw_frontmost_probe_ctx_t *ctx = (qqw_frontmost_probe_ctx_t *) user_data;
  if (ctx == NULL || ctx->loop == NULL) return;
  g_main_loop_quit(ctx->loop);
}

static gboolean qqw_frontmost_on_timeout(gpointer user_data) {
  qqw_frontmost_probe_ctx_t *ctx = (qqw_frontmost_probe_ctx_t *) user_data;
  if (ctx == NULL || ctx->loop == NULL) return G_SOURCE_REMOVE;
  g_main_loop_quit(ctx->loop);
  return G_SOURCE_REMOVE;
}

static int qqw_frontmost_probe_query(const char *address, const char *script_source, int timeout_ms, char **message_out, char **error_out) {
  frida_init();
  GError *error = NULL;
  FridaDeviceManager *manager = NULL;
  FridaDevice *device = NULL;
  FridaSession *session = NULL;
  FridaScript *script = NULL;
  qqw_frontmost_probe_ctx_t ctx;
  guint timeout_source = 0;

  ctx.loop = NULL;
  ctx.message = NULL;

  manager = frida_device_manager_new();
  device = frida_device_manager_add_remote_device_sync(manager, address, NULL, NULL, &error);
  if (error != NULL && address != NULL) {
    const char *colon = strchr(address, ':');
    if (colon != NULL) {
      gchar *host_only = g_strndup(address, (gsize) (colon - address));
      g_error_free(error);
      error = NULL;
      device = frida_device_manager_add_remote_device_sync(manager, host_only, NULL, NULL, &error);
      g_free(host_only);
    }
  }
  if (error != NULL || device == NULL) {
    if (error_out != NULL) {
      *error_out = g_strdup_printf("add_remote_device: %s", error != NULL ? error->message : "failed");
    }
    if (error != NULL) g_error_free(error);
    if (device != NULL) g_object_unref(device);
    if (manager != NULL) g_object_unref(manager);
    return 2;
  }

  guint pid = qqw_frontmost_find_pid(device, "SpringBoard", &error);
  if (error != NULL) {
    if (error_out != NULL) {
      *error_out = g_strdup_printf("enumerate_processes: %s", error->message);
    }
    g_error_free(error);
    g_object_unref(device);
    g_object_unref(manager);
    return 2;
  }
  if (pid == 0) {
    if (error_out != NULL) {
      *error_out = g_strdup("attach: SpringBoard not found");
    }
    g_object_unref(device);
    g_object_unref(manager);
    return 2;
  }

  session = frida_device_attach_sync(device, pid, NULL, NULL, &error);
  if (error != NULL || session == NULL) {
    if (error_out != NULL) {
      *error_out = g_strdup_printf("attach: %s", error != NULL ? error->message : "failed");
    }
    if (error != NULL) g_error_free(error);
    g_object_unref(device);
    g_object_unref(manager);
    return 2;
  }

  script = frida_session_create_script_sync(session, script_source, NULL, NULL, &error);
  if (error != NULL || script == NULL) {
    if (error_out != NULL) {
      *error_out = g_strdup_printf("create_script: %s", error != NULL ? error->message : "failed");
    }
    if (error != NULL) g_error_free(error);
    g_object_unref(session);
    g_object_unref(device);
    g_object_unref(manager);
    return 2;
  }

  ctx.loop = g_main_loop_new(NULL, FALSE);
  g_signal_connect(script, "message", G_CALLBACK(qqw_frontmost_on_message), &ctx);
  g_signal_connect(session, "detached", G_CALLBACK(qqw_frontmost_on_detached), &ctx);

  frida_script_load_sync(script, NULL, &error);
  if (error != NULL) {
    if (error_out != NULL) {
      *error_out = g_strdup_printf("script_load: %s", error->message);
    }
    g_error_free(error);
    g_main_loop_unref(ctx.loop);
    g_object_unref(script);
    g_object_unref(session);
    g_object_unref(device);
    g_object_unref(manager);
    return 2;
  }

  if (timeout_ms > 0) {
    timeout_source = g_timeout_add((guint) timeout_ms, qqw_frontmost_on_timeout, &ctx);
  }
  g_main_loop_run(ctx.loop);
  if (timeout_source != 0) {
    g_source_remove(timeout_source);
  }

  if (ctx.message != NULL) {
    if (message_out != NULL) {
      *message_out = ctx.message;
      ctx.message = NULL;
    }
  } else if (error_out != NULL) {
    *error_out = g_strdup("frontmost-probe timeout");
  }

  frida_script_unload_sync(script, NULL, NULL);
  frida_session_detach_sync(session, NULL, NULL);
  g_main_loop_unref(ctx.loop);
  g_object_unref(script);
  g_object_unref(session);
  g_object_unref(device);
  g_object_unref(manager);
  if (ctx.message != NULL) {
    g_free(ctx.message);
  }
  return 0;
}

static void qqw_frontmost_probe_free(char *p) {
  if (p != NULL) g_free(p);
}
*/
import "C"

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

const frontmostProbeScriptSource = `
(function () {
  function emit(obj) {
    send(obj);
  }
  function textOf(value) {
    try {
      return value ? value.toString() : "";
    } catch (e) {
      return "";
    }
  }
  function parseDescription(text) {
    var out = { bundleId: "", displayName: "", visibility: "", taskState: "" };
    if (!text) {
      return out;
    }
    var bundle = /bundle identifier:\s*([^;>]+)/i.exec(text);
    var display = /display name:\s*([^;>]+)/i.exec(text);
    var visibility = /visibility:\s*([^;>]+)/i.exec(text);
    var taskState = /taskState:\s*([^;>]+)/i.exec(text);
    if (bundle) out.bundleId = bundle[1].trim();
    if (display) out.displayName = display[1].trim();
    if (visibility) out.visibility = visibility[1].trim();
    if (taskState) out.taskState = taskState[1].trim();
    return out;
  }
  function sharedController() {
    var controllerClass = ObjC.classes.SBApplicationController;
    if (!controllerClass) {
      return null;
    }
    if (controllerClass.sharedInstance) {
      try { return controllerClass.sharedInstance(); } catch (e) {}
    }
    if (controllerClass.sharedApplicationController) {
      try { return controllerClass.sharedApplicationController(); } catch (e) {}
    }
    return null;
  }
  function pickForeground(apps) {
    var observed = null;
    var count = 0;
    if (!apps) {
      return { observed: null, count: 0 };
    }
    if (apps.objectEnumerator) {
      var enumerator = apps.objectEnumerator();
      var item = enumerator ? enumerator.nextObject() : null;
      while (item && count < 20) {
        count += 1;
        var parsed = parseDescription(textOf(item));
        if (parsed.visibility === "Foreground") {
          observed = parsed;
          break;
        }
        item = enumerator.nextObject();
      }
      return { observed: observed, count: count };
    }
    if (apps.count && apps.objectAtIndex_) {
      var total = 0;
      try {
        total = parseInt(textOf(apps.count()), 10) || 0;
      } catch (e) {
        total = 0;
      }
      var limit = Math.min(total, 20);
      for (var i = 0; i < limit; i++) {
        var parsedIndexed = parseDescription(textOf(apps.objectAtIndex_(i)));
        count += 1;
        if (parsedIndexed.visibility === "Foreground") {
          observed = parsedIndexed;
          break;
        }
      }
      return { observed: observed, count: count };
    }
    return { observed: null, count: count };
  }
  try {
    if (!ObjC.available) {
      emit({ type: "qqw.frontmost_probe", ok: false, source: "springboard.runningApplications", sampleAtMs: Date.now(), retryable: false, errorCode: "objc_unavailable", errorMessage: "Objective-C runtime unavailable" });
      return;
    }
    var controller = sharedController();
    if (!controller || !controller.runningApplications) {
      emit({ type: "qqw.frontmost_probe", ok: false, source: "springboard.runningApplications", sampleAtMs: Date.now(), retryable: true, errorCode: "not_ready", errorMessage: "SBApplicationController runningApplications unavailable" });
      return;
    }
    var apps = controller.runningApplications();
    var picked = pickForeground(apps);
    if (!picked.observed || !picked.observed.bundleId) {
      emit({ type: "qqw.frontmost_probe", ok: false, source: "springboard.runningApplications", sampleAtMs: Date.now(), retryable: true, errorCode: "not_ready", errorMessage: "foreground app not found" });
      return;
    }
    emit({
      type: "qqw.frontmost_probe",
      ok: true,
      source: "springboard.runningApplications",
      sampleAtMs: Date.now(),
      bundleId: picked.observed.bundleId,
      displayName: picked.observed.displayName,
      visibility: picked.observed.visibility,
      taskState: picked.observed.taskState,
      retryable: false,
      errorCode: "",
      errorMessage: ""
    });
  } catch (e) {
    emit({ type: "qqw.frontmost_probe", ok: false, source: "springboard.runningApplications", sampleAtMs: Date.now(), retryable: true, errorCode: "internal_error", errorMessage: String(e) });
  }
})();`

type frontmostProbePayload struct {
	Type         string `json:"type"`
	Ok           bool   `json:"ok"`
	Source       string `json:"source"`
	SampleAtMs   int64  `json:"sampleAtMs"`
	BundleID     string `json:"bundleId"`
	DisplayName  string `json:"displayName"`
	Visibility   string `json:"visibility"`
	TaskState    string `json:"taskState"`
	Retryable    bool   `json:"retryable"`
	ErrorCode    string `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

// queryFrontmostProbeOnce 在 iOS 构建下执行一次 `SpringBoard.runningApplications` 最小前台查询。
// 参数：fridaHost 为 frida 主机；fridaPort 为 frida 端口；timeoutMs 为单次探测超时。
// 返回：结构化前台探测结果；失败时通过错误字段返回稳定语义，而不是抛出进程级错误。
func queryFrontmostProbeOnce(fridaHost string, fridaPort int, timeoutMs int) frontmostProbeSnapshot {
	now := time.Now().UnixMilli()
	addr := strings.TrimSpace(fridaHost)
	if addr == "" || fridaPort <= 0 {
		return frontmostProbeSnapshot{
			Ok:           false,
			Source:       "springboard.runningApplications",
			SampleAtMs:   now,
			Retryable:    false,
			ErrorCode:    "transport_unavailable",
			ErrorMessage: "frida host/port missing",
		}
	}
	if timeoutMs <= 0 {
		timeoutMs = 3000
	}
	hostPort := addr + ":" + strconv.Itoa(fridaPort)
	cAddr := C.CString(hostPort)
	cSrc := C.CString(frontmostProbeScriptSource)
	defer C.free(unsafe.Pointer(cAddr))
	defer C.free(unsafe.Pointer(cSrc))
	var cMsg *C.char
	var cErr *C.char
	rc := C.qqw_frontmost_probe_query(cAddr, cSrc, C.int(timeoutMs), &cMsg, &cErr)
	if cErr != nil {
		defer C.qqw_frontmost_probe_free(cErr)
		return frontmostProbeSnapshot{
			Ok:           false,
			Source:       "springboard.runningApplications",
			SampleAtMs:   now,
			Retryable:    true,
			ErrorCode:    "transport_unavailable",
			ErrorMessage: strings.TrimSpace(C.GoString(cErr)),
		}
	}
	if rc != 0 || cMsg == nil {
		if cMsg != nil {
			defer C.qqw_frontmost_probe_free(cMsg)
		}
		return frontmostProbeSnapshot{
			Ok:           false,
			Source:       "springboard.runningApplications",
			SampleAtMs:   now,
			Retryable:    true,
			ErrorCode:    "rpc_timeout",
			ErrorMessage: "frontmost probe returned empty payload",
		}
	}
	defer C.qqw_frontmost_probe_free(cMsg)
	return parseFrontmostProbeMessage(C.GoString(cMsg), now)
}

// parseFrontmostProbeMessage 解析 Frida `send(...)` 返回的前台探测消息。
// 参数：raw 为 Frida 原始消息 JSON；fallbackNow 为解析失败时的兜底采样时间。
// 返回：结构化的 frontmost probe 快照。
func parseFrontmostProbeMessage(raw string, fallbackNow int64) frontmostProbeSnapshot {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return frontmostProbeSnapshot{
			Ok:           false,
			Source:       "springboard.runningApplications",
			SampleAtMs:   fallbackNow,
			Retryable:    false,
			ErrorCode:    "invalid_payload",
			ErrorMessage: "frontmost probe raw message empty",
		}
	}
	var msg fridaMessage
	if err := json.Unmarshal([]byte(raw), &msg); err != nil {
		return frontmostProbeSnapshot{
			Ok:           false,
			Source:       "springboard.runningApplications",
			SampleAtMs:   fallbackNow,
			Retryable:    false,
			ErrorCode:    "invalid_payload",
			ErrorMessage: err.Error(),
		}
	}
	if strings.TrimSpace(msg.Type) != "send" {
		return frontmostProbeSnapshot{
			Ok:           false,
			Source:       "springboard.runningApplications",
			SampleAtMs:   fallbackNow,
			Retryable:    false,
			ErrorCode:    "invalid_payload",
			ErrorMessage: "frontmost probe message type mismatch",
		}
	}
	var payload frontmostProbePayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return frontmostProbeSnapshot{
			Ok:           false,
			Source:       "springboard.runningApplications",
			SampleAtMs:   fallbackNow,
			Retryable:    false,
			ErrorCode:    "invalid_payload",
			ErrorMessage: err.Error(),
		}
	}
	snapshot := frontmostProbeSnapshot{
		Ok:           payload.Ok,
		Source:       strings.TrimSpace(payload.Source),
		SampleAtMs:   payload.SampleAtMs,
		BundleID:     strings.TrimSpace(payload.BundleID),
		DisplayName:  strings.TrimSpace(payload.DisplayName),
		Visibility:   strings.TrimSpace(payload.Visibility),
		TaskState:    strings.TrimSpace(payload.TaskState),
		Retryable:    payload.Retryable,
		ErrorCode:    strings.TrimSpace(payload.ErrorCode),
		ErrorMessage: strings.TrimSpace(payload.ErrorMessage),
	}
	if snapshot.Source == "" {
		snapshot.Source = "springboard.runningApplications"
	}
	if snapshot.SampleAtMs <= 0 {
		snapshot.SampleAtMs = fallbackNow
	}
	if strings.TrimSpace(payload.Type) != "qqw.frontmost_probe" {
		snapshot.Ok = false
		snapshot.Retryable = false
		snapshot.ErrorCode = "invalid_payload"
		snapshot.ErrorMessage = "frontmost probe payload type mismatch"
		return snapshot
	}
	if snapshot.Ok && snapshot.BundleID == "" {
		snapshot.Ok = false
		snapshot.Retryable = false
		snapshot.ErrorCode = "invalid_payload"
		snapshot.ErrorMessage = "frontmost probe bundle id missing"
	}
	if !snapshot.Ok && snapshot.ErrorCode == "" {
		snapshot.ErrorCode = "internal_error"
	}
	return snapshot
}
