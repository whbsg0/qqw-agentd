//go:build ios

package main

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#include <stdlib.h>
#include <frida-core.h>

extern void goFridaOnMessage(char *message);

typedef struct {
  GMainLoop *loop;
} qqw_ctx_t;

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
  goFridaOnMessage((char *) message);
}

static void on_detached(FridaSession *session, FridaSessionDetachReason reason, gpointer crash, gpointer user_data) {
  qqw_ctx_t *ctx = (qqw_ctx_t *) user_data;
  if (ctx == NULL || ctx->loop == NULL) return;
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

static int qqw_run(const char *address, const char *process_name, const char *bundle_id, const char *script_source, char **error_out) {
  frida_init();
  GError *error = NULL;

  const gchar *proc = process_name != NULL && process_name[0] != '\0' ? process_name : "WhatsApp";
  const gchar *bid = bundle_id != NULL ? bundle_id : "";
  const int max_attempts = 3;

  FridaDeviceManager *manager = NULL;
  FridaDevice *device = NULL;

  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    if (device != NULL) { g_object_unref(device); device = NULL; }
    if (manager != NULL) { g_object_unref(manager); manager = NULL; }
    if (error != NULL) { g_error_free(error); error = NULL; }

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

    guint pid = find_pid(device, proc, &error);
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

    guint target_pid = pid;
    FridaSession *session = NULL;
    int spawned = 0;
    if (target_pid != 0) {
      session = frida_device_attach_sync(device, target_pid, NULL, NULL, &error);
      if (error != NULL && bid[0] != '\0' && g_strcmp0(error->message, "Timeout was reached") == 0) {
        g_error_free(error);
        error = NULL;
        target_pid = frida_device_spawn_sync(device, bid, NULL, NULL, &error);
        spawned = 1;
        if (error == NULL && target_pid != 0) {
          g_usleep(200000);
          session = frida_device_attach_sync(device, target_pid, NULL, NULL, &error);
        }
      }
    } else if (bid[0] != '\0') {
      target_pid = frida_device_spawn_sync(device, bid, NULL, NULL, &error);
      spawned = 1;
      if (error == NULL && target_pid != 0) {
        g_usleep(200000);
        session = frida_device_attach_sync(device, target_pid, NULL, NULL, &error);
      }
    } else {
      *error_out = qqw_strdup_printf3("process not found: ", proc, "");
      g_object_unref(device);
      g_object_unref(manager);
      return 2;
    }

    if (error != NULL || session == NULL) {
      if (attempt < max_attempts && error != NULL) {
        if (g_strcmp0(error->message, "Timeout was reached") == 0 || g_strrstr(error->message, "end-of-stream") != NULL) {
          g_error_free(error);
          error = NULL;
          if (spawned && target_pid != 0) {
            frida_device_kill_sync(device, target_pid, NULL, NULL);
          }
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

  FridaScript *script = frida_session_create_script_sync(session, script_source, NULL, NULL, &error);
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
  g_signal_connect(script, "message", G_CALLBACK(on_message), &ctx);
  g_signal_connect(session, "detached", G_CALLBACK(on_detached), &ctx);

  frida_script_load_sync(script, NULL, &error);
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
  if (spawned) {
    frida_device_resume_sync(device, target_pid, NULL, &error);
    if (error != NULL) {
      *error_out = qqw_strdup_printf2("resume: ", error->message);
      g_error_free(error);
      g_main_loop_unref(ctx.loop);
      g_object_unref(script);
      g_object_unref(session);
      g_object_unref(device);
      g_object_unref(manager);
      return 2;
    }
  }

  g_main_loop_run(ctx.loop);

  frida_script_unload_sync(script, NULL, NULL);
  g_main_loop_unref(ctx.loop);
  g_object_unref(script);
  g_object_unref(session);
  g_object_unref(device);
  g_object_unref(manager);
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

func run(fridaHost string, fridaPort int, processName string, bundleID string, scriptSource string, eventsURL string) error {
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
	rc := C.qqw_run(cAddr, cProc, cBundle, cSrc, &cErr)
	if cErr != nil {
		defer C.qqw_free(cErr)
		return errors.New(C.GoString(cErr))
	}
	if rc != 0 {
		return errors.New("runner exited")
	}
	return nil
}
