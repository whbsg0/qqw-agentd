const SCRIPT_BUILD_ID = "status_probe_min.v1";

/**
 * Return the current timestamp in milliseconds.
 */
function nowMs() {
  try { return Date.now(); } catch (_) { return 0; }
}

/**
 * Convert arbitrary input into a Frida pointer safely.
 */
function toPtr(p) {
  try {
    if (!p) return ptr("0x0");
    if (p.isNull !== undefined) return p;
    return ptr(String(p));
  } catch (_) {
    return ptr("0x0");
  }
}

/**
 * Wrap a pointer as ObjC.Object when possible.
 */
function safeObj(p) {
  try {
    if (!ObjC.available) return null;
    const pp = toPtr(p);
    if (!pp || pp.isNull()) return null;
    return new ObjC.Object(pp);
  } catch (_) {
    return null;
  }
}

/**
 * Check whether an ObjC object or class can call a selector.
 */
function objcCanCall(objOrCls, sel) {
  try {
    if (!ObjC.available) return false;
    if (!objOrCls || !sel) return false;
    const f = objOrCls[sel];
    return !!(f && f.implementation);
  } catch (_) {
    return false;
  }
}

/**
 * Check whether an ObjC object responds to a selector.
 */
function objcHasSelector(obj, selName) {
  try {
    if (!ObjC.available || !obj || !selName) return false;
    const o = obj instanceof ObjC.Object ? obj : safeObj(obj);
    if (!o) return false;
    const sel = ObjC.selector(String(selName));
    if (!sel) return false;
    if (o.respondsToSelector_) return !!o.respondsToSelector_(sel);
    return false;
  } catch (_) {
    return false;
  }
}

/**
 * Detect whether the current thread is the main thread.
 */
function isMainThread() {
  try {
    const NSThread = ObjC.classes.NSThread;
    if (!NSThread || !NSThread["+ isMainThread"]) return false;
    return !!NSThread["+ isMainThread"]();
  } catch (_) {
    return false;
  }
}

/**
 * Run a function synchronously on the main queue.
 */
function runOnMainQueueSync(fn, timeoutMs) {
  const tmo = Math.max(50, Math.min(30000, Number(timeoutMs) || 1500));
  if (!ObjC.available) return { ok: false, error: "ObjC not available" };
  if (isMainThread()) {
    try { return fn(); } catch (e) { return { ok: false, error: String(e) }; }
  }
  const state = { done: false, res: null, err: null };
  ObjC.schedule(ObjC.mainQueue, () => {
    try { state.res = fn(); } catch (e) { state.err = String(e); }
    state.done = true;
  });
  const start = Date.now();
  while (!state.done && Date.now() - start < tmo) Thread.sleep(0.01);
  if (!state.done) return { ok: false, error: "timeout" };
  if (state.err) return { ok: false, error: state.err };
  return state.res;
}

/**
 * Get UIApplication delegate safely.
 */
function getUIApplicationDelegate() {
  try {
    const UIApp = ObjC.classes.UIApplication;
    if (!UIApp || !UIApp["+ sharedApplication"]) return null;
    const app = safeObj(UIApp["+ sharedApplication"]());
    if (!app) return null;
    try { if (app.delegate) return safeObj(app.delegate()); } catch (_) {}
    try { if (objcCanCall(app, "- delegate")) return safeObj(app["- delegate"]()); } catch (_) {}
    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Resolve the fixed WAContextMain core from app delegate.
 */
function resolveCoreFixed() {
  if (!ObjC.available) return { ok: false, error: "ObjC not available" };
  const del = getUIApplicationDelegate();
  if (!del) return { ok: false, error: "UIApplication.delegate unavailable" };
  let ctx = null;
  try { if (del.$ivars) ctx = del.$ivars._userContext || null; } catch (_) { ctx = null; }
  ctx = safeObj(ctx);
  if (!ctx) return { ok: false, error: "delegate._userContext nil" };
  const cn = String(ctx.$className || "");
  if (cn !== "WAContextMain") return { ok: false, error: "userContext not WAContextMain", className: cn };
  return { ok: true, ctxMain: ctx };
}

/**
 * Resolve a stable WAContextMain using the same priority as current_explore.
 */
function resolveCtxMainStable() {
  try {
    if (!ObjC.available) return { ok: false, error: "ObjC not available", source: "" };
    const cls = ObjC.classes.WAContextMain;
    const sels = ["+ sharedInstance", "+ shared", "+ main", "+ sharedMain", "+ sharedContext", "+ defaultContext", "+ currentContext", "+ context"];
    const isCtx = (o) => {
      try {
        if (!o) return false;
        const cn = String(o.$className || "");
        if (cn === "WAContextMain") return true;
        return !!(objcHasSelector(o, "chatStorage") || objcHasSelector(o, "messageSender"));
      } catch (_) {
        return false;
      }
    };
    if (cls) {
      for (let i = 0; i < sels.length; i++) {
        const s = sels[i];
        try {
          if (!cls[s] || typeof cls[s] !== "function") continue;
          const v = cls[s]();
          const o = safeObj(v);
          if (o && isCtx(o)) return { ok: true, ctxMain: o, source: "WAContextMain." + s };
        } catch (_) {}
      }
    }
    const fixed = resolveCoreFixed();
    if (fixed && fixed.ok && fixed.ctxMain) return { ok: true, ctxMain: fixed.ctxMain, source: "UIApplication.delegate.$ivars" };
    return { ok: false, error: fixed ? String(fixed.error || "no context") : "no context", source: "" };
  } catch (e) {
    return { ok: false, error: String(e), source: "" };
  }
}

/**
 * Summarize WAContextMain shared-style class methods and their return objects.
 */
function inspectWAContextMainSharedCandidates() {
  const out = { classExists: false, candidates: [] };
  try {
    if (!ObjC.available) return out;
    const cls = ObjC.classes.WAContextMain;
    if (!cls) return out;
    out.classExists = true;
    const sels = ["+ sharedInstance", "+ shared", "+ main", "+ sharedMain", "+ sharedContext", "+ defaultContext", "+ currentContext", "+ context"];
    for (let i = 0; i < sels.length; i++) {
      const s = sels[i];
      const row = { sel: s, callable: false, value: null, error: "" };
      try {
        row.callable = !!(cls[s] && typeof cls[s] === "function");
        if (row.callable) {
          const v = safeObj(cls[s]());
          row.value = objectSummary(v);
        }
      } catch (e) {
        row.error = String(e);
      }
      out.candidates.push(row);
    }
    return out;
  } catch (_) {
    return out;
  }
}

/**
 * Check whether a key name is interesting for status provider recovery.
 */
function isInterestingKey(k) {
  const s = String(k || "").toLowerCase();
  if (!s) return false;
  return s.indexOf("status") !== -1 || s.indexOf("model") !== -1 || s.indexOf("provider") !== -1;
}

/**
 * Produce a lightweight debug summary for deep-scanned objects.
 */
function safeObjMeta(v) {
  try {
    const o = v instanceof ObjC.Object ? v : safeObj(v);
    if (!o) return null;
    return { ptr: o.handle.toString(), className: String(o.$className || "") };
  } catch (_) {
    return null;
  }
}

/**
 * Read selected ivars and summarize their raw object values.
 */
function inspectNamedIvars(obj, keys) {
  const out = {};
  try {
    const o = obj instanceof ObjC.Object ? obj : safeObj(obj);
    if (!o) return out;
    let ivs = {};
    try { ivs = o.$ivars || {}; } catch (_) { ivs = {}; }
    const names = keys || [];
    for (let i = 0; i < names.length; i++) {
      const k = String(names[i] || "");
      if (!k) continue;
      let exists = false;
      let meta = null;
      try {
        exists = Object.prototype.hasOwnProperty.call(ivs, k);
        if (exists) meta = safeObjMeta(ivs[k]);
      } catch (_) {
        exists = false;
        meta = null;
      }
      out[k] = { exists, meta };
    }
    return out;
  } catch (_) {
    return out;
  }
}

/**
 * Check whether an object can be treated as a status model provider.
 */
function pickProviderFromObjMin(obj, src) {
  try {
    if (!obj) return null;
    const o = obj instanceof ObjC.Object ? obj : safeObj(obj);
    if (!o) return null;
    if (objcHasSelector(o, "getStatusModelFor:")) {
      return { ok: true, provider: objectSummary(o), source: src };
    }
    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Run a bounded ivar-only deep scan for status provider-like objects.
 */
function deepScanForProvider(rootObj, src, maxDepth) {
  const seen = {};
  const queue = [{ obj: rootObj, src, depth: 0 }];
  const scanned = [];
  const capNodes = 60;
  const capKeys = 40;
  while (queue.length) {
    const it = queue.shift();
    if (!it || !it.obj) continue;
    const o = it.obj instanceof ObjC.Object ? it.obj : safeObj(it.obj);
    if (!o) continue;
    const ptxt = o.handle.toString();
    if (seen[ptxt]) continue;
    seen[ptxt] = 1;

    const direct = pickProviderFromObjMin(o, it.src);
    if (direct) return { ok: true, found: direct, scanned };
    if (it.depth >= maxDepth) continue;

    let ivs = {};
    try { ivs = o.$ivars || {}; } catch (_) { ivs = {}; }
    const keys = Object.keys(ivs || {});
    const interesting = [];
    for (let i = 0; i < keys.length && interesting.length < capKeys; i++) {
      const k = String(keys[i] || "");
      if (!k || !isInterestingKey(k)) continue;
      interesting.push(k);
    }
    const keyDebug = [];
    for (let i = 0; i < interesting.length; i++) {
      const k = interesting[i];
      let meta = null;
      try { meta = safeObjMeta(ivs[k]); } catch (_) { meta = null; }
      keyDebug.push({ k, meta });
      if (keyDebug.length >= 10) break;
    }
    scanned.push({
      source: it.src,
      depth: it.depth,
      self: safeObjMeta(o),
      keys: interesting,
      flags: {
        hasGetStatusModelFor: objcHasSelector(o, "getStatusModelFor:"),
        hasStatusModelProviderSel: objcHasSelector(o, "statusModelProvider")
      },
      keyDebug
    });
    if (scanned.length > capNodes) continue;
    for (let i = 0; i < interesting.length; i++) {
      const k = interesting[i];
      let v = null;
      try { v = ivs[k]; } catch (_) { v = null; }
      if (!v) continue;
      queue.push({ obj: v, src: it.src + ".$ivars." + k, depth: it.depth + 1 });
    }
  }
  return { ok: false, error: "no provider in deep scan", scanned };
}

/**
 * Build a lightweight identity summary without calling description.
 */
function objectSummary(obj) {
  try {
    const o = obj instanceof ObjC.Object ? obj : safeObj(obj);
    if (!o) return null;
    return {
      ptr: o.handle.toString(),
      className: String(o.$className || "")
    };
  } catch (_) {
    return null;
  }
}

/**
 * Call a no-argument ObjC selector and summarize the returned object.
 */
function callNoArgSummary(obj, sel) {
  const out = { ok: false, sel: String(sel || ""), value: null, error: "" };
  try {
    const o = obj instanceof ObjC.Object ? obj : safeObj(obj);
    if (!o) {
      out.error = "obj nil";
      return out;
    }
    const v = objcCallNoArg(o, sel);
    if (v === null || v === undefined) {
      out.error = "selector unavailable";
      return out;
    }
    const so = safeObj(v);
    out.ok = true;
    out.value = so ? objectSummary(so) : { ptr: String(v), className: "" };
    return out;
  } catch (e) {
    out.error = String(e);
    return out;
  }
}

/**
 * Call a no-argument selector using both Frida forms.
 */
function objcCallNoArg(obj, selName) {
  try {
    if (!ObjC.available || !obj || !selName) return null;
    const o = obj instanceof ObjC.Object ? obj : safeObj(obj);
    if (!o) return null;
    const m1 = "- " + String(selName);
    if (o[m1] && typeof o[m1] === "function") return o[m1]();
    if (o[selName] && typeof o[selName] === "function") return o[selName]();
    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Call the first available selector from a candidate list and return the object.
 */
function callAnyNoArgObject(obj, sels) {
  try {
    const o = obj instanceof ObjC.Object ? obj : safeObj(obj);
    if (!o) return { ok: false, error: "obj nil", usedSel: "", obj: null };
    const arr = Array.isArray(sels) ? sels : [sels];
    for (let i = 0; i < arr.length; i++) {
      const sel = String(arr[i] || "");
      if (!sel) continue;
      if (!objcHasSelector(o, sel) && !objcCanCall(o, sel) && !objcCanCall(o, "- " + sel)) continue;
      const v = safeObj(objcCallNoArg(o, sel));
      if (v) return { ok: true, usedSel: sel, obj: v };
    }
    return { ok: false, error: "selector unavailable", usedSel: "", obj: null };
  } catch (e) {
    return { ok: false, error: String(e), usedSel: "", obj: null };
  }
}

/**
 * Read a raw pointer slot from an object at the given offset.
 */
function readRawSlotSummary(obj, off) {
  try {
    const o = obj instanceof ObjC.Object ? obj : safeObj(obj);
    if (!o) return null;
    const addr = o.handle.add(Number(off) | 0);
    const vp = Memory.readPointer(addr);
    if (!vp || vp.isNull()) return { ptr: "0x0", className: "", ok: false };
    const vo = safeObj(vp);
    return vo ? { ptr: vo.handle.toString(), className: String(vo.$className || ""), ok: true } : { ptr: vp.toString(), className: "", ok: false };
  } catch (_) {
    return null;
  }
}

/**
 * Read the first non-null ivar object by candidate names.
 */
function getIvarObj(obj, keys) {
  try {
    const o = obj instanceof ObjC.Object ? obj : safeObj(obj);
    if (!o || !o.$ivars) return null;
    const arr = Array.isArray(keys) ? keys : [keys];
    for (let i = 0; i < arr.length; i++) {
      const k = String(arr[i] || "");
      if (!k) continue;
      try {
        const v = o.$ivars[k];
        const so = safeObj(v);
        if (so) return so;
      } catch (_) {}
    }
    return null;
  } catch (_) {
    return null;
  }
}

/**
 * Try selector first, then fall back to ivar lookup.
 */
function tryGetPropOrIvarObj(obj, selName, ivarKeys) {
  try {
    const fromSel = callAnyNoArgObject(obj, [selName]);
    if (fromSel && fromSel.obj) return { obj: fromSel.obj, source: "selector", usedSel: fromSel.usedSel, error: "" };
    const fromIvar = getIvarObj(obj, ivarKeys || []);
    if (fromIvar) return { obj: fromIvar, source: "ivar", usedSel: "", error: "" };
    return { obj: null, source: "", usedSel: "", error: fromSel ? String(fromSel.error || "not found") : "not found" };
  } catch (e) {
    return { obj: null, source: "", usedSel: "", error: String(e) };
  }
}

/**
 * Inspect the fixed status storage graph used by no-UI status hydration.
 */
function statusstorageprobe() {
  return runOnMainQueueSync(() => {
    const fixed = resolveCoreFixed();
    const core = resolveCtxMainStable();
    if (!core || !core.ok || !core.ctxMain) return { ok: false, build: SCRIPT_BUILD_ID, error: core ? core.error : "core failed", source: core ? core.source : "" };

    const ctxMain = core.ctxMain;
    const chatStorageRes = tryGetPropOrIvarObj(ctxMain, "chatStorage", ["_chatStorage", "chatStorage"]);
    const chatStorageObj = chatStorageRes.obj;
    const statusManagerRes = tryGetPropOrIvarObj(ctxMain, "statusManagerIfRegistered", ["_statusManager", "statusManager"]);
    const statusManagerObj = statusManagerRes.obj;
    const statusManagerStatusStorageRes = tryGetPropOrIvarObj(statusManagerObj, "statusStorage", ["_statusStorage", "statusStorage"]);
    const statusManagerStatusStorageObj = statusManagerStatusStorageRes.obj;
    const statusManagerStatusStoringRes = tryGetPropOrIvarObj(statusManagerObj, "statusStoring", ["_statusStoring", "statusStoring"]);
    const statusManagerStatusStoringObj = statusManagerStatusStoringRes.obj;
    const statusManagerStatusFetcherRes = tryGetPropOrIvarObj(statusManagerObj, "statusFetcher", ["_statusFetcher", "statusFetcher"]);
    const statusManagerStatusFetcherObj = statusManagerStatusFetcherRes.obj;
    const statusManagerStatusWriterRes = tryGetPropOrIvarObj(statusManagerObj, "statusWriter", ["_statusWriter", "statusWriter"]);
    const statusManagerStatusWriterObj = statusManagerStatusWriterRes.obj;
    const statusStorageAfterManagerRes = tryGetPropOrIvarObj(ctxMain, "statusStorage", ["_statusStorage", "statusStorage"]);
    const archiveRollbackManagerRes = tryGetPropOrIvarObj(ctxMain, "statusArchiveRollbackManager", ["_statusArchiveRollbackManager", "statusArchiveRollbackManager"]);
    const archiveRollbackManagerObj = archiveRollbackManagerRes.obj;
    const archiveStatusStorageRes = tryGetPropOrIvarObj(archiveRollbackManagerObj, "statusStorage", ["_statusStorage", "statusStorage"]);
    const archiveStatusStorageObj = archiveStatusStorageRes.obj;
    const statusStorageRes = statusStorageAfterManagerRes;
    const validationManagerRes = tryGetPropOrIvarObj(ctxMain, "statusDatabaseValidationManager", ["_statusDatabaseValidationManager", "statusDatabaseValidationManager"]);
    const statusModelProviderRes = tryGetPropOrIvarObj(ctxMain, "statusModelProvider", ["_statusModelProvider", "statusModelProvider"]);
    let resolvedStatusModelProvider = null;
    try {
      if (ObjC.protocols && ObjC.protocols.WAStatusModelProviding && objcHasSelector(ctxMain, "resolveObject:")) {
        resolvedStatusModelProvider = safeObj(ctxMain["- resolveObject:"](ObjC.protocols.WAStatusModelProviding));
      }
    } catch (_) {
      resolvedStatusModelProvider = null;
    }
    const statusStorageObj = statusStorageRes.obj;
    const fetcherRes = tryGetPropOrIvarObj(statusStorageObj, "fetcher", ["_fetcher", "fetcher"]);
    const observerRes = tryGetPropOrIvarObj(statusStorageObj, "observer", ["_observer", "observer"]);
    const writerRes = tryGetPropOrIvarObj(statusStorageObj, "writer", ["_writer", "writer"]);
    const cachedFetcherRes = tryGetPropOrIvarObj(observerRes.obj, "cachedFetcher", ["_cachedFetcher", "cachedFetcher"]);
    const statusFetcherRes = tryGetPropOrIvarObj(cachedFetcherRes.obj, "statusFetcher", ["_statusFetcher", "statusFetcher"]);
    const statusInfoObserverRes = tryGetPropOrIvarObj(observerRes.obj, "statusInfoObserver", ["_statusInfoObserver", "statusInfoObserver"]);
    const fetcherObj = fetcherRes.obj;
    const observerObj = observerRes.obj;
    const writerObj = writerRes.obj;
    const cachedFetcherObj = cachedFetcherRes.obj;
    const statusFetcherObj = statusFetcherRes.obj;
    const statusInfoObserverObj = statusInfoObserverRes.obj;
    const deepCtx = deepScanForProvider(ctxMain, "ctxMain", 3);
    const deepStorage = deepScanForProvider(chatStorageObj, "chatStorage", 3);
    const deepStatusManager = deepScanForProvider(statusManagerObj, "statusManager", 3);

    return {
      ok: true,
      build: SCRIPT_BUILD_ID,
      ts: nowMs(),
      source: String(core.source || ""),
      sharedCandidates: inspectWAContextMainSharedCandidates(),
      fixedCtxMain: {
        summary: objectSummary(fixed && fixed.ok ? fixed.ctxMain : null),
        error: fixed && !fixed.ok ? String(fixed.error || "") : ""
      },
      ctxMain: objectSummary(ctxMain),
      ctxMainEqualsFixed: !!(fixed && fixed.ok && fixed.ctxMain && String(fixed.ctxMain.handle) === String(ctxMain.handle)),
      ctxMainFlags: {
        chatStorage: objcHasSelector(ctxMain, "chatStorage"),
        messageSender: objcHasSelector(ctxMain, "messageSender"),
        statusStorage: objcHasSelector(ctxMain, "statusStorage"),
        statusDatabaseValidationManager: objcHasSelector(ctxMain, "statusDatabaseValidationManager"),
        statusModelProvider: objcHasSelector(ctxMain, "statusModelProvider"),
        resolveObject: objcHasSelector(ctxMain, "resolveObject:")
      },
      ctxMainDirect: {
        chatStorage: { summary: objectSummary(chatStorageObj), source: chatStorageRes.source, usedSel: chatStorageRes.usedSel, error: chatStorageRes.error },
        statusManagerIfRegistered: { summary: objectSummary(statusManagerObj), source: statusManagerRes.source, usedSel: statusManagerRes.usedSel, error: statusManagerRes.error },
        statusManagerStatusStorage: { summary: objectSummary(statusManagerStatusStorageObj), source: statusManagerStatusStorageRes.source, usedSel: statusManagerStatusStorageRes.usedSel, error: statusManagerStatusStorageRes.error },
        statusManagerStatusStoring: { summary: objectSummary(statusManagerStatusStoringObj), source: statusManagerStatusStoringRes.source, usedSel: statusManagerStatusStoringRes.usedSel, error: statusManagerStatusStoringRes.error },
        statusManagerStatusFetcher: { summary: objectSummary(statusManagerStatusFetcherObj), source: statusManagerStatusFetcherRes.source, usedSel: statusManagerStatusFetcherRes.usedSel, error: statusManagerStatusFetcherRes.error },
        statusManagerStatusWriter: { summary: objectSummary(statusManagerStatusWriterObj), source: statusManagerStatusWriterRes.source, usedSel: statusManagerStatusWriterRes.usedSel, error: statusManagerStatusWriterRes.error },
        statusArchiveRollbackManager: { summary: objectSummary(archiveRollbackManagerObj), source: archiveRollbackManagerRes.source, usedSel: archiveRollbackManagerRes.usedSel, error: archiveRollbackManagerRes.error },
        archiveStatusStorage: { summary: objectSummary(archiveStatusStorageObj), source: archiveStatusStorageRes.source, usedSel: archiveStatusStorageRes.usedSel, error: archiveStatusStorageRes.error },
        statusStorage: { summary: objectSummary(statusStorageRes.obj), source: statusStorageRes.source, usedSel: statusStorageRes.usedSel, error: statusStorageRes.error },
        statusDatabaseValidationManager: { summary: objectSummary(validationManagerRes.obj), source: validationManagerRes.source, usedSel: validationManagerRes.usedSel, error: validationManagerRes.error },
        statusModelProvider: { summary: objectSummary(statusModelProviderRes.obj), source: statusModelProviderRes.source, usedSel: statusModelProviderRes.usedSel, error: statusModelProviderRes.error },
        resolvedStatusModelProvider: { summary: objectSummary(resolvedStatusModelProvider) }
      },
      deepProviderSearch: {
        ctxMain: deepCtx,
        chatStorage: deepStorage,
        statusManager: deepStatusManager
      },
      statusStorage: {
        summary: objectSummary(statusStorageObj),
        source: { kind: statusStorageRes.source, usedSel: statusStorageRes.usedSel, error: statusStorageRes.error || "" },
        calls: {
          fetcher: callNoArgSummary(statusStorageObj, "fetcher"),
          writer: callNoArgSummary(statusStorageObj, "writer"),
          observer: callNoArgSummary(statusStorageObj, "observer"),
          statusDatabase: callNoArgSummary(statusStorageObj, "statusDatabase")
        },
        rawOffsets: {
          off0x58: readRawSlotSummary(statusStorageObj, 0x58),
          off0x60: readRawSlotSummary(statusStorageObj, 0x60),
          off0x68: readRawSlotSummary(statusStorageObj, 0x68),
          off0x70: readRawSlotSummary(statusStorageObj, 0x70),
          off0x78: readRawSlotSummary(statusStorageObj, 0x78),
          off0x80: readRawSlotSummary(statusStorageObj, 0x80),
          off0x88: readRawSlotSummary(statusStorageObj, 0x88)
        }
      },
      archiveStatusStorage: {
        summary: objectSummary(archiveStatusStorageObj),
        source: { kind: archiveStatusStorageRes.source, usedSel: archiveStatusStorageRes.usedSel, error: archiveStatusStorageRes.error || "" },
        calls: {
          fetcher: callNoArgSummary(archiveStatusStorageObj, "fetcher"),
          observer: callNoArgSummary(archiveStatusStorageObj, "observer"),
          statusDatabase: callNoArgSummary(archiveStatusStorageObj, "statusDatabase"),
          writer: callNoArgSummary(archiveStatusStorageObj, "writer")
        },
        rawOffsets: {
          off0x58: readRawSlotSummary(archiveStatusStorageObj, 0x58),
          off0x60: readRawSlotSummary(archiveStatusStorageObj, 0x60),
          off0x68: readRawSlotSummary(archiveStatusStorageObj, 0x68),
          off0x70: readRawSlotSummary(archiveStatusStorageObj, 0x70),
          off0x78: readRawSlotSummary(archiveStatusStorageObj, 0x78),
          off0x80: readRawSlotSummary(archiveStatusStorageObj, 0x80),
          off0x88: readRawSlotSummary(archiveStatusStorageObj, 0x88)
        }
      },
      statusManager: {
        summary: objectSummary(statusManagerObj),
        source: { kind: statusManagerRes.source, usedSel: statusManagerRes.usedSel, error: statusManagerRes.error || "" },
        calls: {
          statusStorage: callNoArgSummary(statusManagerObj, "statusStorage"),
          statusSender: callNoArgSummary(statusManagerObj, "statusSender"),
          sender: callNoArgSummary(statusManagerObj, "sender"),
          statusDatabaseValidationManager: callNoArgSummary(statusManagerObj, "statusDatabaseValidationManager")
        },
        rawNamedIvars: inspectNamedIvars(statusManagerObj, ["statusStoring", "statusFetcher", "statusWriter"]),
        statusStorage: {
          summary: objectSummary(statusManagerStatusStorageObj),
          source: { kind: statusManagerStatusStorageRes.source, usedSel: statusManagerStatusStorageRes.usedSel, error: statusManagerStatusStorageRes.error || "" }
        },
        statusStoring: {
          summary: objectSummary(statusManagerStatusStoringObj),
          source: { kind: statusManagerStatusStoringRes.source, usedSel: statusManagerStatusStoringRes.usedSel, error: statusManagerStatusStoringRes.error || "" }
        },
        statusFetcher: {
          summary: objectSummary(statusManagerStatusFetcherObj),
          source: { kind: statusManagerStatusFetcherRes.source, usedSel: statusManagerStatusFetcherRes.usedSel, error: statusManagerStatusFetcherRes.error || "" },
          calls: {
            statusModelProvider: callNoArgSummary(statusManagerStatusFetcherObj, "statusModelProvider"),
            statusDatabase: callNoArgSummary(statusManagerStatusFetcherObj, "statusDatabase"),
            context: callNoArgSummary(statusManagerStatusFetcherObj, "context")
          }
        },
        statusWriter: {
          summary: objectSummary(statusManagerStatusWriterObj),
          source: { kind: statusManagerStatusWriterRes.source, usedSel: statusManagerStatusWriterRes.usedSel, error: statusManagerStatusWriterRes.error || "" },
          calls: {
            statusDatabase: callNoArgSummary(statusManagerStatusWriterObj, "statusDatabase"),
            statusFetcher: callNoArgSummary(statusManagerStatusWriterObj, "statusFetcher")
          }
        }
      },
      fetcher: {
        summary: objectSummary(fetcherObj),
        source: { kind: fetcherRes.source, usedSel: fetcherRes.usedSel, error: fetcherRes.error || "" },
        calls: {
          statusFetcher: callNoArgSummary(fetcherObj, "statusFetcher"),
          statusMessageItemFetcher: callNoArgSummary(fetcherObj, "statusMessageItemFetcher"),
          statusModelProvider: callNoArgSummary(fetcherObj, "statusModelProvider")
        },
        rawOffsets: {
          off0x18: readRawSlotSummary(fetcherObj, 0x18),
          off0x20: readRawSlotSummary(fetcherObj, 0x20),
          off0x28: readRawSlotSummary(fetcherObj, 0x28)
        }
      },
      observer: {
        summary: objectSummary(observerObj),
        source: { kind: observerRes.source, usedSel: observerRes.usedSel, error: observerRes.error || "" },
        calls: {
          fetcher: callNoArgSummary(observerObj, "fetcher"),
          cachedFetcher: callNoArgSummary(observerObj, "cachedFetcher"),
          statusInfoObserver: callNoArgSummary(observerObj, "statusInfoObserver")
        },
        rawOffsets: {
          off0x38: readRawSlotSummary(observerObj, 0x38),
          off0x40: readRawSlotSummary(observerObj, 0x40),
          off0xC0: readRawSlotSummary(observerObj, 0xC0),
          off0xC8: readRawSlotSummary(observerObj, 0xC8),
          off0xF8: readRawSlotSummary(observerObj, 0xF8),
          off0x100: readRawSlotSummary(observerObj, 0x100)
        }
      },
      cachedFetcher: {
        summary: objectSummary(cachedFetcherObj),
        source: { kind: cachedFetcherRes.source, usedSel: cachedFetcherRes.usedSel, error: cachedFetcherRes.error || "" },
        calls: {
          statusFetcher: callNoArgSummary(cachedFetcherObj, "statusFetcher")
        },
        rawOffsets: {
          off0x60: readRawSlotSummary(cachedFetcherObj, 0x60),
          off0x68: readRawSlotSummary(cachedFetcherObj, 0x68),
          off0x88: readRawSlotSummary(cachedFetcherObj, 0x88),
          off0x90: readRawSlotSummary(cachedFetcherObj, 0x90)
        }
      },
      statusFetcher: {
        summary: objectSummary(statusFetcherObj),
        source: { kind: statusFetcherRes.source, usedSel: statusFetcherRes.usedSel, error: statusFetcherRes.error || "" }
      },
      statusInfoObserver: {
        summary: objectSummary(statusInfoObserverObj),
        source: { kind: statusInfoObserverRes.source, usedSel: statusInfoObserverRes.usedSel, error: statusInfoObserverRes.error || "" },
        calls: {
          fetcher: callNoArgSummary(statusInfoObserverObj, "fetcher"),
          cachedFetcher: callNoArgSummary(statusInfoObserverObj, "cachedFetcher")
        },
        rawOffsets: {
          off0x70: readRawSlotSummary(statusInfoObserverObj, 0x70),
          off0x78: readRawSlotSummary(statusInfoObserverObj, 0x78),
          off0x98: readRawSlotSummary(statusInfoObserverObj, 0x98),
          off0xA0: readRawSlotSummary(statusInfoObserverObj, 0xA0)
        }
      },
      writer: {
        summary: objectSummary(writerObj)
      }
    };
  }, 2500);
}

/**
 * Return available RPC export names.
 */
function entries() {
  return { ok: true, build: SCRIPT_BUILD_ID, exports: Object.keys(rpc.exports || {}).sort() };
}

/**
 * Return a minimal environment heartbeat.
 */
function ping() {
  return { ok: true, build: SCRIPT_BUILD_ID, ts: nowMs(), objc: !!(ObjC && ObjC.available) };
}

rpc.exports = {
  entries,
  ping,
  statusstorageprobe
};
