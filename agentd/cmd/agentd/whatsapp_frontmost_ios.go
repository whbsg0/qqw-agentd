//go:build ios

package main

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#include <stdlib.h>
#include <string.h>
#include <frida-core.h>

static gchar *qqw_guard_strdup2(const gchar *prefix, const gchar *msg) {
  if (prefix == NULL) prefix = "";
  if (msg == NULL) msg = "";
  return g_strdup_printf("%s%s", prefix, msg);
}

static int qqw_guard_query_frontmost(const char *address, const char *process_name, const char *bundle_id, char **error_out) {
  frida_init();
  GError *error = NULL;

  const gchar *proc = process_name != NULL && process_name[0] != '\0' ? process_name : "WhatsApp";
  const gchar *bid = bundle_id != NULL ? bundle_id : "";
  const int max_attempts = 3;

  FridaDeviceManager *manager = NULL;
  FridaDevice *device = NULL;

  for (int attempt = 1; attempt <= max_attempts; attempt++) {
    if (device != NULL) {
      g_object_unref(device);
      device = NULL;
    }
    if (manager != NULL) {
      g_object_unref(manager);
      manager = NULL;
    }
    if (error != NULL) {
      g_error_free(error);
      error = NULL;
    }

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
      if (attempt < max_attempts && (g_strcmp0(error->message, "Timeout was reached") == 0 || g_strrstr(error->message, "end-of-stream") != NULL)) {
        g_error_free(error);
        error = NULL;
        g_usleep((gulong) (200000 * attempt));
        continue;
      }
      *error_out = qqw_guard_strdup2("frontmost add_remote_device: ", error->message);
      g_error_free(error);
      if (device != NULL) g_object_unref(device);
      g_object_unref(manager);
      return -1;
    }

    FridaFrontmostQueryOptions *fopts = frida_frontmost_query_options_new();
    frida_frontmost_query_options_set_scope(fopts, FRIDA_SCOPE_MINIMAL);
    FridaApplication *front = frida_device_get_frontmost_application_sync(device, fopts, NULL, &error);
    g_object_unref(fopts);
    if (error != NULL) {
      if (attempt < max_attempts && (g_strcmp0(error->message, "Timeout was reached") == 0 || g_strrstr(error->message, "end-of-stream") != NULL)) {
        g_error_free(error);
        error = NULL;
        g_usleep((gulong) (200000 * attempt));
        continue;
      }
      *error_out = qqw_guard_strdup2("frontmost query: ", error->message);
      g_error_free(error);
      g_object_unref(device);
      g_object_unref(manager);
      return -1;
    }

    int matched = 0;
    if (front != NULL) {
      const gchar *fid = frida_application_get_identifier(front);
      const gchar *fname = frida_application_get_name(front);
      if (bid[0] != '\0' && fid != NULL && g_strcmp0(fid, bid) == 0) {
        matched = 1;
      } else if (fname != NULL && g_strcmp0(fname, proc) == 0) {
        matched = 1;
      }
      g_object_unref(front);
    }

    g_object_unref(device);
    g_object_unref(manager);
    return matched;
  }

  if (device != NULL) g_object_unref(device);
  if (manager != NULL) g_object_unref(manager);
  if (error != NULL) g_error_free(error);
  *error_out = g_strdup("frontmost query: failed after retries");
  return -1;
}

static void qqw_guard_free(char *p) {
  if (p != NULL) g_free(p);
}
*/
import "C"

import (
	"errors"
	"strconv"
	"strings"
	"unsafe"
)

// guardFrontmostQueryEnabled 返回当前构建是否具备宿主直接 frontmost 真查询能力。
// 参数：无。
// 返回：iOS Frida 构建返回 true。
func guardFrontmostQueryEnabled() bool {
	return true
}

// detectWhatsAppFrontmost 查询 WhatsApp 当前是否处于前台。
// 参数：无。
// 返回：第一个返回值表示 WhatsApp 是否前台；第二个返回值表示查询错误。
func (a *Agent) detectWhatsAppFrontmost() (bool, error) {
	cfg := a.getCfg()
	host := strings.TrimSpace(cfg.Frida.Host)
	if host == "" || cfg.Frida.Port <= 0 {
		// #region debug-point H3:frontmost-config
		debugGuardReport("pre-fix", "H3", "whatsapp_frontmost_ios.go:detectWhatsAppFrontmost", "frontmost config missing", map[string]any{
			"host": host,
			"port": cfg.Frida.Port,
		})
		// #endregion
		return false, errors.New("frida host/port missing")
	}
	bundleID := strings.TrimSpace(cfg.WhatsApp.BundleID)
	if bundleID == "" {
		bundleID = "net.whatsapp.WhatsApp"
	}
	addr := host + ":" + strconv.Itoa(cfg.Frida.Port)
	cAddr := C.CString(addr)
	cProc := C.CString("WhatsApp")
	cBundle := C.CString(bundleID)
	defer C.free(unsafe.Pointer(cAddr))
	defer C.free(unsafe.Pointer(cProc))
	defer C.free(unsafe.Pointer(cBundle))
	var cErr *C.char
	rc := C.qqw_guard_query_frontmost(cAddr, cProc, cBundle, &cErr)
	if cErr != nil {
		defer C.qqw_guard_free(cErr)
		err := errors.New(C.GoString(cErr))
		// #region debug-point H3:frontmost-query-error
		debugGuardReport("pre-fix", "H3", "whatsapp_frontmost_ios.go:detectWhatsAppFrontmost", "frontmost query returned c error", map[string]any{
			"addr":     addr,
			"bundleId": bundleID,
			"error":    err.Error(),
		})
		// #endregion
		return false, err
	}
	if rc < 0 {
		// #region debug-point H3:frontmost-query-negative
		debugGuardReport("pre-fix", "H3", "whatsapp_frontmost_ios.go:detectWhatsAppFrontmost", "frontmost query returned negative rc", map[string]any{
			"addr":     addr,
			"bundleId": bundleID,
			"rc":       rc,
		})
		// #endregion
		return false, errors.New("frontmost query failed")
	}
	matched := rc != 0
	// #region debug-point H3:frontmost-query-result
	debugGuardReport("pre-fix", "H3", "whatsapp_frontmost_ios.go:detectWhatsAppFrontmost", "frontmost query result", map[string]any{
		"addr":      addr,
		"bundleId":  bundleID,
		"matched":   matched,
		"rc":        rc,
	})
	// #endregion
	return matched, nil
}
