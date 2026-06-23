//go:build ios

package main

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <frida-core.h>

static gchar *qqw_guard_strdup2(const gchar *prefix, const gchar *msg) {
  if (prefix == NULL) prefix = "";
  if (msg == NULL) msg = "";
  return g_strdup_printf("%s%s", prefix, msg);
}

// qqw_guard_cfstring_to_utf8 将 CFStringRef 安全转换为 UTF-8 副本。
// 参数：value 为待转换的 CoreFoundation 字符串。
// 返回：成功时返回 g_strdup 分配的 UTF-8 字符串；失败返回空串副本。
static gchar *qqw_guard_cfstring_to_utf8(CFStringRef value) {
  if (value == NULL) {
    return g_strdup("");
  }
  const char *direct = CFStringGetCStringPtr(value, kCFStringEncodingUTF8);
  if (direct != NULL) {
    return g_strdup(direct);
  }
  CFIndex length = CFStringGetLength(value);
  CFIndex max_size = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
  gchar *buffer = g_malloc0((gsize) max_size);
  if (!CFStringGetCString(value, buffer, max_size, kCFStringEncodingUTF8)) {
    g_free(buffer);
    return g_strdup("");
  }
  return buffer;
}

// qqw_guard_string_has_printable_text 判断 UTF-8 字符串是否包含可接受的可打印内容。
// 参数：value 为待检查字符串。
// 返回：true 表示字符串非空且不含控制字符；false 表示为空或含异常控制字符。
static gboolean qqw_guard_string_has_printable_text(const gchar *value) {
  if (value == NULL || value[0] == '\0') {
    return FALSE;
  }
  for (const guchar *p = (const guchar *) value; *p != '\0'; p++) {
    if (*p < 0x20 || *p == 0x7f) {
      return FALSE;
    }
  }
  return TRUE;
}

// qqw_guard_cfstring_to_utf8_checked 仅在对象确认为 CFString 时才转换为 UTF-8。
// 参数：value 为待转换对象；label 为字段名；error_out 输出类型错误原因。
// 返回：成功时返回 UTF-8 副本；失败时返回 NULL。
static gchar *qqw_guard_cfstring_to_utf8_checked(CFTypeRef value, const gchar *label, char **error_out) {
  if (value == NULL) {
    return g_strdup("");
  }
  if (CFGetTypeID(value) != CFStringGetTypeID()) {
    if (error_out != NULL) {
      *error_out = g_strdup_printf("frontmost fallback sbs invalid %s type: %lu",
        label != NULL ? label : "value",
        (unsigned long) CFGetTypeID(value));
    }
    return NULL;
  }
  return qqw_guard_cfstring_to_utf8((CFStringRef) value);
}

// qqw_guard_query_frontmost_sbs 在 Frida frontmost 返回空值时改用 SBS 取前台 display identifier。
// 参数：process_name 为目标进程名；bundle_id 为目标 bundle id；detail_out 输出诊断细节；error_out 输出失败原因。
// 返回：1 表示目标前台；0 表示已明确不是目标前台；-1 表示 fallback 也无法得到可信前台真值。
static int qqw_guard_query_frontmost_sbs(const char *process_name, const char *bundle_id, char **detail_out, char **error_out) {
  const gchar *proc = process_name != NULL && process_name[0] != '\0' ? process_name : "WhatsApp";
  const gchar *bid = bundle_id != NULL ? bundle_id : "";
  void *handle = dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_GLOBAL | RTLD_LAZY);
  if (handle == NULL) {
    if (error_out != NULL) {
      const char *msg = dlerror();
      *error_out = qqw_guard_strdup2("frontmost fallback sbs dlopen: ", msg != NULL ? msg : "unknown");
    }
    return -1;
  }

  typedef CFStringRef (*qqw_sbs_copy_frontmost_application_display_identifier_fn)(void);
  typedef CFStringRef (*qqw_sbs_copy_localized_application_name_for_display_identifier_fn)(CFStringRef identifier);

  dlerror();
  qqw_sbs_copy_frontmost_application_display_identifier_fn copy_frontmost =
    (qqw_sbs_copy_frontmost_application_display_identifier_fn) dlsym(handle, "SBSCopyFrontmostApplicationDisplayIdentifier");
  const char *frontmost_sym_error = dlerror();
  if (copy_frontmost == NULL || frontmost_sym_error != NULL) {
    if (error_out != NULL) {
      *error_out = qqw_guard_strdup2("frontmost fallback sbs symbol: ",
        frontmost_sym_error != NULL ? frontmost_sym_error : "SBSCopyFrontmostApplicationDisplayIdentifier missing");
    }
    dlclose(handle);
    return -1;
  }

  dlerror();
  qqw_sbs_copy_localized_application_name_for_display_identifier_fn copy_name =
    (qqw_sbs_copy_localized_application_name_for_display_identifier_fn) dlsym(handle, "SBSCopyLocalizedApplicationNameForDisplayIdentifier");
  const char *name_sym_error = dlerror();
  if (name_sym_error != NULL) {
    copy_name = NULL;
  }

  CFStringRef front_id_ref = copy_frontmost();
  if (front_id_ref == NULL) {
    if (detail_out != NULL) {
      *detail_out = g_strdup_printf("front.source=sbs front.id= front.name= expected.id=%s expected.name=%s front=nil",
        bid != NULL ? bid : "",
        proc != NULL ? proc : "");
    }
    if (error_out != NULL) {
      *error_out = g_strdup("frontmost fallback sbs returned nil");
    }
    dlclose(handle);
    return -1;
  }

  gchar *front_id = qqw_guard_cfstring_to_utf8_checked(front_id_ref, "identifier", error_out);
  if (front_id == NULL) {
    if (detail_out != NULL) {
      *detail_out = g_strdup_printf("front.source=sbs front.id= front.name= expected.id=%s expected.name=%s invalid.id.type",
        bid != NULL ? bid : "",
        proc != NULL ? proc : "");
    }
    CFRelease(front_id_ref);
    dlclose(handle);
    return -1;
  }
  CFStringRef front_name_ref = NULL;
  gchar *front_name = g_strdup("");
  if (copy_name != NULL) {
    front_name_ref = copy_name(front_id_ref);
    if (front_name_ref != NULL) {
      g_free(front_name);
      front_name = qqw_guard_cfstring_to_utf8_checked(front_name_ref, "name", error_out);
      if (front_name == NULL) {
        if (detail_out != NULL) {
          *detail_out = g_strdup_printf("front.source=sbs front.id= front.name= expected.id=%s expected.name=%s invalid.name.type",
            bid != NULL ? bid : "",
            proc != NULL ? proc : "");
        }
        if (front_name_ref != NULL) {
          CFRelease(front_name_ref);
        }
        CFRelease(front_id_ref);
        dlclose(handle);
        return -1;
      }
    }
  }

  if (!qqw_guard_string_has_printable_text(front_id)) {
    if (detail_out != NULL) {
      *detail_out = g_strdup_printf("front.source=sbs front.id=%s front.name=%s expected.id=%s expected.name=%s invalid.front.id",
        front_id != NULL ? front_id : "",
        front_name != NULL ? front_name : "",
        bid != NULL ? bid : "",
        proc != NULL ? proc : "");
    }
    if (error_out != NULL) {
      *error_out = g_strdup_printf("frontmost fallback sbs invalid front identifier: %s",
        front_id != NULL ? front_id : "");
    }
    if (front_name_ref != NULL) {
      CFRelease(front_name_ref);
    }
    CFRelease(front_id_ref);
    g_free(front_id);
    g_free(front_name);
    dlclose(handle);
    return -1;
  }

  if (detail_out != NULL) {
    *detail_out = g_strdup_printf("front.source=sbs front.id=%s front.name=%s expected.id=%s expected.name=%s",
      front_id != NULL ? front_id : "",
      front_name != NULL ? front_name : "",
      bid != NULL ? bid : "",
      proc != NULL ? proc : "");
  }

  int matched = 0;
  if (bid[0] != '\0' && front_id != NULL && g_strcmp0(front_id, bid) == 0) {
    matched = 1;
  } else if (front_name != NULL && g_strcmp0(front_name, proc) == 0) {
    matched = 1;
  }

  if (front_name_ref != NULL) {
    CFRelease(front_name_ref);
  }
  CFRelease(front_id_ref);
  g_free(front_id);
  g_free(front_name);
  dlclose(handle);
  return matched;
}

static int qqw_guard_query_frontmost(const char *address, const char *process_name, const char *bundle_id, char **detail_out, char **error_out) {
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
      if (detail_out != NULL) {
        *detail_out = g_strdup_printf("front.source=frida front.id=%s front.name=%s expected.id=%s expected.name=%s",
          fid != NULL ? fid : "",
          fname != NULL ? fname : "",
          bid != NULL ? bid : "",
          proc != NULL ? proc : "");
      }
      if (bid[0] != '\0' && fid != NULL && g_strcmp0(fid, bid) == 0) {
        matched = 1;
      } else if (fname != NULL && g_strcmp0(fname, proc) == 0) {
        matched = 1;
      }
      g_object_unref(front);
    } else {
      int sbs_matched = qqw_guard_query_frontmost_sbs(proc, bid, detail_out, error_out);
      g_object_unref(device);
      g_object_unref(manager);
      if (sbs_matched >= 0) {
        return sbs_matched;
      }
      return -1;
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
	var cDetail *C.char
	rc := C.qqw_guard_query_frontmost(cAddr, cProc, cBundle, &cDetail, &cErr)
	detail := ""
	if cDetail != nil {
		defer C.qqw_guard_free(cDetail)
		detail = C.GoString(cDetail)
	}
	if cErr != nil {
		defer C.qqw_guard_free(cErr)
		err := errors.New(C.GoString(cErr))
		// #region debug-point H3:frontmost-query-error
		debugGuardReport("pre-fix", "H3", "whatsapp_frontmost_ios.go:detectWhatsAppFrontmost", "frontmost query returned c error", map[string]any{
			"addr":     addr,
			"bundleId": bundleID,
			"detail":   detail,
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
		"addr":     addr,
		"bundleId": bundleID,
		"detail":   detail,
		"matched":  matched,
		"rc":       rc,
	})
	// #endregion
	return matched, nil
}
