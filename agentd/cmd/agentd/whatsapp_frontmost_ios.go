//go:build ios

package main

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <mach/mach.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <frida-core.h>

extern kern_return_t bootstrap_look_up_per_user (mach_port_t bp, const char * service_name, uid_t target_user, mach_port_t * sp);
extern mach_port_t bootstrap_port;

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

// qqw_guard_build_sbs_context 采集当前 SBS / bootstrap 上下文，便于定位 daemon 与 mobile user 端口差异。
// 参数：handle 为已打开的 SpringBoardServices 动态库句柄。
// 返回：调用方负责释放的上下文描述字符串。
static gchar *qqw_guard_build_sbs_context(void *handle) {
  typedef mach_port_t (*qqw_sbs_springboard_background_server_port_fn)(void);

  mach_port_t bg_port = MACH_PORT_NULL;
  mach_port_t lookup_port = MACH_PORT_NULL;
  kern_return_t lookup_kr = -1;
  const gchar *lookup_service = "com.apple.springboard.backgroundappservices";

  dlerror();
  qqw_sbs_springboard_background_server_port_fn background_port =
    (qqw_sbs_springboard_background_server_port_fn) dlsym(handle, "SBSSpringBoardBackgroundServerPort");
  const char *port_sym_error = dlerror();
  if (background_port != NULL && port_sym_error == NULL) {
    bg_port = background_port();
  }

  lookup_kr = bootstrap_look_up_per_user(bootstrap_port, lookup_service, 501, &lookup_port);
  return g_strdup_printf("sbs.bg_port=%u bootstrap.lookup.kr=%d bootstrap.lookup.port=%u bootstrap.service=%s",
    (unsigned int) bg_port,
    (int) lookup_kr,
    (unsigned int) lookup_port,
    lookup_service);
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

  gchar *sbs_ctx = qqw_guard_build_sbs_context(handle);

  CFStringRef front_id_ref = copy_frontmost();
  if (front_id_ref == NULL) {
    if (detail_out != NULL) {
      *detail_out = g_strdup_printf("front.source=sbs front.id= front.name= expected.id=%s expected.name=%s front=nil %s",
        bid != NULL ? bid : "",
        proc != NULL ? proc : "",
        sbs_ctx != NULL ? sbs_ctx : "");
    }
    if (error_out != NULL) {
      *error_out = g_strdup("frontmost fallback sbs returned nil");
    }
    g_free(sbs_ctx);
    dlclose(handle);
    return -1;
  }

  gchar *front_id = qqw_guard_cfstring_to_utf8_checked(front_id_ref, "identifier", error_out);
  if (front_id == NULL) {
    if (detail_out != NULL) {
      *detail_out = g_strdup_printf("front.source=sbs front.id= front.name= expected.id=%s expected.name=%s invalid.id.type %s",
        bid != NULL ? bid : "",
        proc != NULL ? proc : "",
        sbs_ctx != NULL ? sbs_ctx : "");
    }
    CFRelease(front_id_ref);
    g_free(sbs_ctx);
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
          *detail_out = g_strdup_printf("front.source=sbs front.id= front.name= expected.id=%s expected.name=%s invalid.name.type %s",
            bid != NULL ? bid : "",
            proc != NULL ? proc : "",
            sbs_ctx != NULL ? sbs_ctx : "");
        }
        if (front_name_ref != NULL) {
          CFRelease(front_name_ref);
        }
        CFRelease(front_id_ref);
        g_free(sbs_ctx);
        dlclose(handle);
        return -1;
      }
    }
  }

  if (!qqw_guard_string_has_printable_text(front_id)) {
    if (detail_out != NULL) {
      *detail_out = g_strdup_printf("front.source=sbs front.id=%s front.name=%s expected.id=%s expected.name=%s invalid.front.id %s",
        front_id != NULL ? front_id : "",
        front_name != NULL ? front_name : "",
        bid != NULL ? bid : "",
        proc != NULL ? proc : "",
        sbs_ctx != NULL ? sbs_ctx : "");
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
    g_free(sbs_ctx);
    dlclose(handle);
    return -1;
  }

  if (detail_out != NULL) {
    *detail_out = g_strdup_printf("front.source=sbs front.id=%s front.name=%s expected.id=%s expected.name=%s %s",
      front_id != NULL ? front_id : "",
      front_name != NULL ? front_name : "",
      bid != NULL ? bid : "",
      proc != NULL ? proc : "",
      sbs_ctx != NULL ? sbs_ctx : "");
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
  g_free(sbs_ctx);
  dlclose(handle);
  return matched;
}

// qqw_guard_find_pid 按进程名在当前 Frida 设备中查找 PID。
// 参数：device 为已连接设备；name 为目标进程名；error 为 Frida 错误输出。
// 返回：找到时返回 PID，未找到或错误返回 0。
static guint qqw_guard_find_pid(FridaDevice *device, const gchar *name, GError **error) {
  FridaProcessList *plist = frida_device_enumerate_processes_sync(device, NULL, NULL, error);
  if (error == NULL || *error != NULL || plist == NULL) {
    return 0;
  }
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

typedef struct {
  GMainLoop *loop;
  gchar *payload;
  gchar *error;
  gboolean finished;
} qqw_guard_sb_probe_ctx_t;

// qqw_guard_extract_result_payload 从 Frida message JSON 中抽取指定 marker 开头的 payload 字符串。
// 参数：message 为 Frida 回调 JSON；marker 为结果前缀。
// 返回：成功时返回新分配字符串；失败返回 NULL。
static gchar *qqw_guard_extract_result_payload(const gchar *message, const gchar *marker) {
  if (message == NULL || marker == NULL || marker[0] == '\0') {
    return NULL;
  }
  const gchar *start = strstr(message, marker);
  if (start == NULL) {
    return NULL;
  }
  const gchar *end = start;
  while (*end != '\0' && *end != '"') {
    end++;
  }
  return g_strndup(start, (gsize) (end - start));
}

// qqw_guard_result_get 提取 `key=value` 结果中的字段值。
// 参数：payload 为结果字符串；key 为目标字段名。
// 返回：成功时返回新分配字符串；字段不存在返回 NULL。
static gchar *qqw_guard_result_get(const gchar *payload, const gchar *key) {
  if (payload == NULL || key == NULL || key[0] == '\0') {
    return NULL;
  }
  gchar *needle = g_strdup_printf("%s=", key);
  const gchar *start = strstr(payload, needle);
  g_free(needle);
  if (start == NULL) {
    return NULL;
  }
  start += strlen(key) + 1;
  const gchar *end = start;
  while (*end != '\0' && *end != ';') {
    end++;
  }
  return g_strndup(start, (gsize) (end - start));
}

// qqw_guard_sb_probe_finish 在 SpringBoard probe 完成时写入结果并退出主循环。
// 参数：ctx 为 probe 上下文；payload 为结果字符串；error 为错误字符串。
// 返回：无。
static void qqw_guard_sb_probe_finish(qqw_guard_sb_probe_ctx_t *ctx, gchar *payload, gchar *error) {
  if (ctx == NULL || ctx->finished) {
    if (payload != NULL) g_free(payload);
    if (error != NULL) g_free(error);
    return;
  }
  ctx->finished = TRUE;
  ctx->payload = payload;
  ctx->error = error;
  if (ctx->loop != NULL) {
    g_main_loop_quit(ctx->loop);
  }
}

// qqw_guard_on_springboard_message 处理 SpringBoard probe 的第一条结果消息。
// 参数：script 为 Frida 脚本；message 为 Frida JSON 消息；data 为附加二进制；user_data 为上下文。
// 返回：无。
static void qqw_guard_on_springboard_message(FridaScript *script, const gchar *message, GBytes *data, gpointer user_data) {
  qqw_guard_sb_probe_ctx_t *ctx = (qqw_guard_sb_probe_ctx_t *) user_data;
  if (ctx == NULL || message == NULL || ctx->finished) {
    return;
  }
  gchar *payload = qqw_guard_extract_result_payload(message, "QQW_SB_RESULT ");
  if (payload != NULL) {
    qqw_guard_sb_probe_finish(ctx, payload, NULL);
    return;
  }
  if (g_strrstr(message, "\"type\":\"error\"") != NULL) {
    qqw_guard_sb_probe_finish(ctx, NULL, qqw_guard_strdup2("springboard probe script error: ", message));
  }
}

// qqw_guard_on_springboard_detached 在 SpringBoard 会话断开时终止 probe。
// 参数：session 为 Frida 会话；reason 为断开原因；crash 为崩溃信息；user_data 为上下文。
// 返回：无。
static void qqw_guard_on_springboard_detached(FridaSession *session, FridaSessionDetachReason reason, gpointer crash, gpointer user_data) {
  qqw_guard_sb_probe_ctx_t *ctx = (qqw_guard_sb_probe_ctx_t *) user_data;
  if (ctx == NULL || ctx->finished) {
    return;
  }
  qqw_guard_sb_probe_finish(ctx, NULL, g_strdup_printf("springboard probe detached: %d", (int) reason));
}

// qqw_guard_on_springboard_timeout 在 probe 超时时结束本轮查询。
// 参数：user_data 为上下文。
// 返回：FALSE 表示只触发一次。
static gboolean qqw_guard_on_springboard_timeout(gpointer user_data) {
  qqw_guard_sb_probe_ctx_t *ctx = (qqw_guard_sb_probe_ctx_t *) user_data;
  if (ctx == NULL || ctx->finished) {
    return FALSE;
  }
  qqw_guard_sb_probe_finish(ctx, NULL, g_strdup("springboard probe timeout"));
  return FALSE;
}

// qqw_guard_query_frontmost_springboard 在 SpringBoard 宿主内读取 runningApplications 的前台真值。
// 参数：device 为当前 Frida 设备；process_name 为目标进程名；bundle_id 为目标 bundle id；detail_out 输出细节；error_out 输出错误。
// 返回：1 表示目标前台；0 表示已明确不是目标前台；-1 表示未拿到可信真值。
static int qqw_guard_query_frontmost_springboard(FridaDevice *device, const char *process_name, const char *bundle_id, char **detail_out, char **error_out) {
  if (device == NULL) {
    if (error_out != NULL) {
      *error_out = g_strdup("springboard probe device missing");
    }
    return -1;
  }

  const gchar *proc = process_name != NULL && process_name[0] != '\0' ? process_name : "WhatsApp";
  const gchar *bid = bundle_id != NULL ? bundle_id : "";
  GError *error = NULL;

  guint springboard_pid = qqw_guard_find_pid(device, "SpringBoard", &error);
  if (error != NULL) {
    if (error_out != NULL) {
      *error_out = qqw_guard_strdup2("springboard enumerate_processes: ", error->message);
    }
    g_error_free(error);
    return -1;
  }
  if (springboard_pid == 0) {
    if (error_out != NULL) {
      *error_out = g_strdup("springboard process not found");
    }
    return -1;
  }

  FridaSession *session = frida_device_attach_sync(device, springboard_pid, NULL, NULL, &error);
  if (error != NULL || session == NULL) {
    if (error_out != NULL) {
      *error_out = error != NULL ? qqw_guard_strdup2("springboard attach: ", error->message) : g_strdup("springboard attach failed");
    }
    if (error != NULL) {
      g_error_free(error);
    }
    return -1;
  }

  gchar *script_source = g_strdup_printf(
    "(function(){"
    "if(!ObjC.available){send('QQW_SB_RESULT ok=0;code=objc_unavailable');return;}"
    "try{"
      "var ac=ObjC.classes.SBApplicationController.sharedInstance();"
      "var arr=ac.runningApplications();"
      "var count=arr?arr.count():0;"
      "var observed='';"
      "var visibility='';"
      "var taskState='';"
      "var apps=[];"
      "for(var i=0;i<count&&i<20;i++){"
        "var app=arr.objectAtIndex_(i);"
        "var desc=String(app);"
        "var bundleMatch=desc.match(/<SBApplication:[^;]+;\\s*([^>]+)>/);"
        "var stateMatch=desc.match(/taskState:\\s*([A-Za-z]+);\\s*visibility:\\s*([A-Za-z]+)/);"
        "var bundle=bundleMatch?bundleMatch[1]:'';"
        "var task=stateMatch?stateMatch[1]:'';"
        "var vis=stateMatch?stateMatch[2]:'';"
        "if(bundle){apps.push(bundle+':' + vis + ':' + task);}"
        "if(vis==='Foreground'){observed=bundle; visibility=vis; taskState=task; break;}"
      "}"
      "if(observed){"
        "send('QQW_SB_RESULT ok=1;matched='+(observed==='"
        "%s"
        "'?'1':'0')+';observed='+observed+';visibility='+visibility+';taskState='+taskState+';source=springboard.runningApplications;apps='+apps.join(','));"
      "}else{"
        "send('QQW_SB_RESULT ok=0;code=no_foreground_running_application;source=springboard.runningApplications;apps='+apps.join(','));"
      "}"
    "}catch(e){"
      "send('QQW_SB_RESULT ok=0;code=exception;source=springboard.runningApplications;detail='+String(e).replace(/[^A-Za-z0-9._:-]/g,'_'));"
    "}"
    "})();",
    bid);

  FridaScript *script = frida_session_create_script_sync(session, script_source, NULL, NULL, &error);
  g_free(script_source);
  if (error != NULL || script == NULL) {
    if (error_out != NULL) {
      *error_out = error != NULL ? qqw_guard_strdup2("springboard create_script: ", error->message) : g_strdup("springboard create_script failed");
    }
    if (error != NULL) {
      g_error_free(error);
    }
    g_object_unref(session);
    return -1;
  }

  qqw_guard_sb_probe_ctx_t ctx;
  ctx.loop = g_main_loop_new(NULL, FALSE);
  ctx.payload = NULL;
  ctx.error = NULL;
  ctx.finished = FALSE;

  g_signal_connect(script, "message", G_CALLBACK(qqw_guard_on_springboard_message), &ctx);
  g_signal_connect(session, "detached", G_CALLBACK(qqw_guard_on_springboard_detached), &ctx);
  guint timeout_id = g_timeout_add(3000, qqw_guard_on_springboard_timeout, &ctx);

  frida_script_load_sync(script, NULL, &error);
  if (error != NULL) {
    if (error_out != NULL) {
      *error_out = qqw_guard_strdup2("springboard script_load: ", error->message);
    }
    g_error_free(error);
    if (timeout_id != 0) g_source_remove(timeout_id);
    g_main_loop_unref(ctx.loop);
    g_object_unref(script);
    g_object_unref(session);
    return -1;
  }

  g_main_loop_run(ctx.loop);

  if (timeout_id != 0) g_source_remove(timeout_id);
  frida_script_unload_sync(script, NULL, NULL);
  g_main_loop_unref(ctx.loop);
  g_object_unref(script);
  g_object_unref(session);

  if (ctx.error != NULL) {
    if (error_out != NULL) {
      *error_out = ctx.error;
      ctx.error = NULL;
    }
    if (ctx.payload != NULL) g_free(ctx.payload);
    return -1;
  }
  if (ctx.payload == NULL) {
    if (error_out != NULL) {
      *error_out = g_strdup("springboard probe missing payload");
    }
    return -1;
  }

  gchar *ok = qqw_guard_result_get(ctx.payload, "ok");
  gchar *matched = qqw_guard_result_get(ctx.payload, "matched");
  gchar *observed = qqw_guard_result_get(ctx.payload, "observed");
  gchar *visibility = qqw_guard_result_get(ctx.payload, "visibility");
  gchar *task_state = qqw_guard_result_get(ctx.payload, "taskState");
  gchar *source = qqw_guard_result_get(ctx.payload, "source");
  gchar *apps = qqw_guard_result_get(ctx.payload, "apps");
  gchar *code = qqw_guard_result_get(ctx.payload, "code");
  gchar *detail = qqw_guard_result_get(ctx.payload, "detail");

  if (detail_out != NULL) {
    *detail_out = g_strdup_printf("front.source=springboard front.id=%s front.name=%s expected.id=%s expected.name=%s visibility=%s taskState=%s source=%s apps=%s",
      observed != NULL ? observed : "",
      proc != NULL ? proc : "",
      bid != NULL ? bid : "",
      proc != NULL ? proc : "",
      visibility != NULL ? visibility : "",
      task_state != NULL ? task_state : "",
      source != NULL ? source : "springboard.runningApplications",
      apps != NULL ? apps : "");
  }

  int rc = -1;
  if (ok != NULL && g_strcmp0(ok, "1") == 0) {
    rc = (matched != NULL && g_strcmp0(matched, "1") == 0) ? 1 : 0;
  } else {
    if (error_out != NULL) {
      *error_out = g_strdup_printf("springboard probe %s%s%s",
        code != NULL ? code : "failed",
        detail != NULL ? ": " : "",
        detail != NULL ? detail : "");
    }
    rc = -1;
  }

  g_free(ok);
  g_free(matched);
  g_free(observed);
  g_free(visibility);
  g_free(task_state);
  g_free(source);
  g_free(apps);
  g_free(code);
  g_free(detail);
  g_free(ctx.payload);
  if (ctx.error != NULL) g_free(ctx.error);
  return rc;
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
      int springboard_matched = qqw_guard_query_frontmost_springboard(device, proc, bid, detail_out, error_out);
      if (springboard_matched >= 0) {
        g_object_unref(device);
        g_object_unref(manager);
        return springboard_matched;
      }
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
		errText := C.GoString(cErr)
		if strings.TrimSpace(detail) != "" {
			errText += ": " + strings.TrimSpace(detail)
		}
		err := errors.New(errText)
		return false, err
	}
	if rc < 0 {
		if strings.TrimSpace(detail) != "" {
			return false, errors.New("frontmost query failed: " + strings.TrimSpace(detail))
		}
		return false, errors.New("frontmost query failed")
	}
	matched := rc != 0
	return matched, nil
}
