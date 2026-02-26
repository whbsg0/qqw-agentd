const SCRIPT_BUILD_ID = "explore.chatstorage.v12";

function objcAvailable() {
  try { return !!(ObjC && ObjC.available); } catch (_) { return false; }
}

function safeObjCInvoke(fn) {
  try {
    if (!objcAvailable()) return;
    try { ObjC.schedule(ObjC.mainQueue, fn); return; } catch (_) {}
    try { fn(); } catch (_) {}
  } catch (_) {}
}

function _objcGetRuntimeFns() {
  const out = {};
  try {
    const get = (name, ret, args) => {
      try {
        const p = Module.findExportByName("libobjc.A.dylib", name) || Module.findExportByName(null, name);
        if (!p) return null;
        return new NativeFunction(p, ret, args);
      } catch (_) {
        return null;
      }
    };
    out.object_getClass = get("object_getClass", "pointer", ["pointer"]);
    out.class_getName = get("class_getName", "pointer", ["pointer"]);
    out.class_copyIvarList = get("class_copyIvarList", "pointer", ["pointer", "pointer"]);
    out.ivar_getName = get("ivar_getName", "pointer", ["pointer"]);
    out.ivar_getOffset = get("ivar_getOffset", "ulong", ["pointer"]);
    out.ivar_getTypeEncoding = get("ivar_getTypeEncoding", "pointer", ["pointer"]);
    try {
      const pFree = Module.findExportByName(null, "free");
      out.free = pFree ? new NativeFunction(pFree, "void", ["pointer"]) : null;
    } catch (_) {
      out.free = null;
    }
  } catch (_) {}
  return out;
}

function _objcClassNameNoTouch(p) {
  try {
    const x = ptr(p);
    if (!x || x.isNull()) return "";
    const f = _objcGetRuntimeFns();
    if (!f.object_getClass || !f.class_getName) return "";
    const cls = f.object_getClass(x);
    if (!cls || cls.isNull()) return "";
    const namep = f.class_getName(cls);
    if (!namep || namep.isNull()) return "";
    return String(Memory.readCString(namep) || "");
  } catch (_) {
    return "";
  }
}

function _listIvarsNoTouch(objPtrStr, maxN) {
  try {
    const p = ptr(String(objPtrStr || "").trim() || "0x0");
    if (p.isNull()) return { ok: false, error: "null ptr" };
    const f = _objcGetRuntimeFns();
    if (!f.object_getClass || !f.class_getName || !f.class_copyIvarList || !f.ivar_getName || !f.ivar_getOffset) {
      return { ok: false, error: "objc ivar api unavailable" };
    }
    const cls = f.object_getClass(p);
    const cn = cls && !cls.isNull() ? String(Memory.readCString(f.class_getName(cls)) || "") : "";
    const outCount = Memory.alloc(8);
    Memory.writeU64(outCount, uint64(0));
    const listPtr = f.class_copyIvarList(cls, outCount);
    const n0 = Number(Memory.readU64(outCount)) | 0;
    const cap = Math.max(1, Math.min(500, (maxN | 0) || 120));
    const out = [];
    if (listPtr && !listPtr.isNull() && n0 > 0) {
      for (let i = 0; i < n0 && out.length < cap; i++) {
        const iv = Memory.readPointer(listPtr.add(i * Process.pointerSize));
        if (!iv || iv.isNull()) continue;
        let name = "";
        let typeEnc = "";
        let off = 0;
        try {
          const np = f.ivar_getName(iv);
          if (np && !np.isNull()) name = String(Memory.readCString(np) || "");
        } catch (_) {}
        try {
          const tp = f.ivar_getTypeEncoding ? f.ivar_getTypeEncoding(iv) : null;
          if (tp && !tp.isNull()) typeEnc = String(Memory.readCString(tp) || "");
        } catch (_) {}
        try { off = Number(f.ivar_getOffset(iv)) | 0; } catch (_) { off = 0; }
        if (name) out.push({ name, off, type: typeEnc });
      }
    }
    try { if (f.free && listPtr && !listPtr.isNull()) f.free(listPtr); } catch (_) {}
    return { ok: true, ptr: p.toString(), className: cn, count: out.length, ivars: out };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function impof(className, selName) {
  try {
    if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
    const cn = String(className || "").trim();
    const sel = String(selName || "").trim();
    if (!cn || !sel) return { ok: false, error: "missing className/sel" };
    const cls = ObjC.classes[cn];
    if (!cls) return { ok: false, error: "class not found", className: cn };
    const out = { ok: true, className: cn, sel: sel, found: [] };
    const probe = (kind, key) => {
      try {
        const m = cls[key];
        if (!m) return;
        const imp = m.implementation ? ptr(m.implementation) : ptr("0x0");
        const mod = !imp.isNull() ? (Process.findModuleByAddress(imp) || null) : null;
        out.found.push({
          kind,
          key,
          imp: imp.toString(),
          module: mod ? { name: String(mod.name || ""), base: ptr(mod.base).toString() } : null,
          types: (function () { try { return String(m.types || ""); } catch (_) { return ""; } })(),
        });
      } catch (_) {}
    };
    probe("instance", "- " + sel);
    probe("class", "+ " + sel);
    if (!out.found.length) return { ok: false, error: "method not found", className: cn, sel: sel };
    return out;
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _isReadablePtr(p, minBytes) {
  try {
    const x = ptr(p);
    if (!x || x.isNull()) return false;
    const r = Process.findRangeByAddress(x);
    if (!r) return false;
    const prot = String(r.protection || "");
    if (prot.indexOf("r") === -1) return false;
    if (!minBytes || minBytes <= 0) return true;
    const end = r.base.add(r.size);
    return x.add(minBytes).compare(end) <= 0;
  } catch (_) {
    return false;
  }
}

function _callMessageIDFromParsedMessageKey(keyPtr) {
  try {
    const kp = ptr(keyPtr);
    if (!kp || kp.isNull()) return ptr("0x0");
    const mod = _pickModuleByHints(["WhatsApp", "WhatsAppDecrypted", "WhatsApp_Decrypted"]);
    if (!mod || !mod.base) return ptr("0x0");
    const addr = mod.base.add(ptr("0x278ad98"));
    if (!_isReadablePtr(addr, 4)) return ptr("0x0");
    if (!globalThis.__QQW_MSGID_FROM_KEY_FN) {
      globalThis.__QQW_MSGID_FROM_KEY_FN = new NativeFunction(addr, "pointer", ["pointer"]);
    }
    const fn = globalThis.__QQW_MSGID_FROM_KEY_FN;
    const out = fn(kp);
    return out ? ptr(out) : ptr("0x0");
  } catch (_) {
    return ptr("0x0");
  }
}

function nsString(s) {
  try { return ObjC.classes.NSString.stringWithString_(String(s || "")); } catch (_) { return null; }
}

function toNSStringOrNull(s) {
  try {
    const v = String(s || "");
    return v.length ? nsString(v) : null;
  } catch (_) {
    return null;
  }
}

function tryReadNSString(x) {
  try {
    if (!x) return "";
    return String(x);
  } catch (_) {
    return "";
  }
}

function nowMs() { try { return Date.now(); } catch (_) { return 0; } }

function normalizeJid(s) {
  try { return String(s || "").trim().toLowerCase(); } catch (_) { return ""; }
}

function getHomeDir() {
  try {
    const p = Module.findExportByName(null, "NSHomeDirectory");
    if (p) {
      const f = new NativeFunction(p, "pointer", []);
      const ns = f();
      if (ns) return String(new ObjC.Object(ns));
    }
  } catch (_) {}
  try {
    const fm = ObjC.classes.NSFileManager.defaultManager();
    const cd = fm.currentDirectoryPath();
    return cd ? String(cd) : "";
  } catch (_) {}
  return "";
}

function joinPath(a, b) {
  try {
    const aa = String(a || "").replace(/\/+$/g, "");
    const bb = String(b || "").replace(/^\/+/g, "");
    if (!aa) return bb;
    if (!bb) return aa;
    return aa + "/" + bb;
  } catch (_) {
    return String(a || "") + "/" + String(b || "");
  }
}

function fileExists(path) {
  try {
    if (!objcAvailable()) return false;
    const fm = ObjC.classes.NSFileManager.defaultManager();
    return !!fm.fileExistsAtPath_(nsString(String(path || "")));
  } catch (_) {
    return false;
  }
}

function extractDigits(s) {
  try {
    const x = String(s || "");
    let out = "";
    for (let i = 0; i < x.length; i++) {
      const c = x.charCodeAt(i);
      if (c >= 48 && c <= 57) out += x[i];
    }
    return out;
  } catch (_) {
    return "";
  }
}

function derivePhoneFromJid(jid) {
  jid = String(jid || "").trim();
  if (!jid) return "";
  const at = jid.indexOf("@");
  const left = at >= 0 ? jid.slice(0, at) : jid;
  if (!left) return "";
  if (left.startsWith("a_")) return extractDigits(left.slice(2));
  const d = extractDigits(left);
  return d.length >= 8 ? d : "";
}

function objcHasSelector(obj, selName) {
  try {
    if (!objcAvailable() || !obj) return false;
    const sel = selName ? ObjC.selector(String(selName)) : null;
    if (!sel) return false;
    if (obj.respondsToSelector_) return !!obj.respondsToSelector_(sel);
    return false;
  } catch (_) {
    return false;
  }
}

function tryCall0(obj, selName) {
  try {
    if (!obj || !selName) return null;
    const fn = obj[selName];
    if (typeof fn !== "function") return null;
    const v = fn.call(obj);
    return v === undefined || v === null ? null : v;
  } catch (_) {
    return null;
  }
}

function tryCall1(obj, selName, arg1) {
  try {
    if (!obj || !selName) return null;
    const fn = obj[selName];
    if (typeof fn !== "function") return null;
    const v = fn.call(obj, arg1);
    return v === undefined || v === null ? null : v;
  } catch (_) {
    return null;
  }
}

function tryGetSingletonInstance(klass) {
  if (!klass) return null;
  const candidates = ["sharedInstance", "shared", "default", "current", "main", "sharedManager"];
  for (let i = 0; i < candidates.length; i++) {
    const m = candidates[i];
    try {
      if (klass[m] && typeof klass[m] === "function") {
        const inst = klass[m]();
        if (inst) return inst;
      }
    } catch (_) {}
  }
  return null;
}

function listClassesRespondingToSelector(selName, limit) {
  const out = [];
  const cap = Math.max(1, Math.min(500, (limit | 0) || 200));
  if (!objcAvailable()) return out;
  try {
    const selNameStr = String(selName || "").trim();
    if (!selNameStr) return out;
    const sel = ObjC.selector(selNameStr);
    if (!sel) return out;
    for (let name in ObjC.classes) {
      if (out.length >= cap) return out;
      const n = String(name || "");
      if (!n) continue;
      try {
        if (!(n.indexOf("WA") !== -1 || n.indexOf("Receipt") !== -1 || n.indexOf("Read") !== -1 || n.indexOf("Chat") !== -1 || n.indexOf("Storage") !== -1)) {
          continue;
        }
      } catch (_) {}
      try {
        const k = ObjC.classes[name];
        if (!k) continue;
        if (k.instancesRespondToSelector_(sel) || k.respondsToSelector_(sel)) out.push(name);
      } catch (_) {}
    }
  } catch (_) {}
  return out;
}

const READ_PROBE = { installed: false, err: "", last: null, count: 0, _ls: [], lastSelfPtr: "" };
const READ_TRACE = { installed: false, err: "", hits: [], maxHits: 0, _h: null, _timer: null };
const RX_PINNED = { installed: false, err: "", installedAt: 0, events: 0, maxEvents: 500, last: null, lastN: [], maxLastN: 50, _h: null, retainedAuthorPtr: "0x0", msgByKey: {}, msgKeys: [], maxMsgKeys: 80 };
const STATUS_MSG_PROBE = { installed: false, err: "", installedAt: 0, count: 0, last: null, lastN: [], maxLastN: 50, _hs: [], msgByKey: {}, msgKeys: [], maxMsgKeys: 200 };
const SEND_PROBE = { installed: false, err: "", last: null, count: 0, _ls: [], hooked: [] };
const LIKE_PROBE = { installed: false, err: "", last: null, count: 0, _h: null, retainedPtr: "0x0", retainedConnPtr: "0x0", lastText: "" };
const STATUS_LIKE = { template: null, last: null, armedUntilMs: 0, lastXMPP: null };
const XMPP_SEND = { last: null };
const LIKE_BUILD = { installed: false, err: "", armedUntilMs: 0, events: [], maxEvents: 200, _hs: [], last: null, retained: [], templateStanzaPtr: "0x0" };
const REACT2 = { retainedPtr: "0x0", lastBuild: null };
const REACT2_DEBUG = { lastStep: null };

function _pickModuleByHints(hints) {
  try {
    const hs = (hints || []).map(s => String(s || "")).filter(Boolean);
    const mods = Process.enumerateModules();
    for (let i = 0; i < hs.length; i++) {
      const h = hs[i];
      for (let j = 0; j < mods.length; j++) {
        const m = mods[j];
        if (m && String(m.name || "").indexOf(h) !== -1) return m;
      }
    }
    return mods.length ? mods[0] : null;
  } catch (_) {
    return null;
  }
}

function _isGroupJidString(jidStr) {
  try {
    const s = String(jidStr || "");
    if (!s) return false;
    return s.indexOf("@g.us") !== -1 || s.indexOf("@group") !== -1;
  } catch (_) {
    return false;
  }
}

function _deriveChatJidFromUniqueKey(uniqueKeyStr) {
  try {
    const s = String(uniqueKeyStr || "");
    const idx = s.indexOf("_");
    if (idx <= 0) return "";
    const jid = s.slice(0, idx);
    return jid && jid.indexOf("@") !== -1 ? jid : "";
  } catch (_) {
    return "";
  }
}

function _deriveIsFromMeFromUniqueKey(uniqueKeyStr) {
  try {
    const s = String(uniqueKeyStr || "");
    const parts = s.split("_");
    if (parts.length < 3) return null;
    const flag = parts[parts.length - 2];
    if (flag === "0") return false;
    if (flag === "1") return true;
    return null;
  } catch (_) {
    return null;
  }
}

function _tryCallBoolNoArg(obj, sel) {
  try {
    if (!obj || !sel || String(sel).indexOf(":") !== -1) return null;
    const fn = obj[sel];
    if (typeof fn !== "function") return null;
    const v = fn.call(obj);
    if (v === null || v === undefined) return null;
    if (typeof v === "boolean") return v;
    if (typeof v === "number") return v !== 0;
    try {
      if (ObjC.classes.NSNumber && v instanceof ObjC.Object && v.isKindOfClass_(ObjC.classes.NSNumber)) return Number(v) !== 0;
    } catch (_) {}
    return null;
  } catch (_) {
    return null;
  }
}

function _extractStanzaFieldsFromContextPinned(ctxPtr) {
  const out = { stanzaId: "", uniqueKey: "", chatJid: "", senderJid: "", isGroup: false, isFromMe: null, statusAuthorJid: "", statusAuthorPtr: "0x0", statusAuthorClass: "", msgPtr: "0x0", msgClass: "" };
  try {
    const ctxObj = _safeObj(ctxPtr);
    if (!ctxObj) return out;
    let stanzaObj = null;
    try { stanzaObj = objcCallNoArg(ctxObj, "orderedMessageStanza") || objcCallNoArg(ctxObj, "messageStanza"); } catch (_) { stanzaObj = null; }
    if (!stanzaObj) return out;
    const stanza = stanzaObj instanceof ObjC.Object ? stanzaObj : new ObjC.Object(stanzaObj);
    if (!stanza) return out;

    try {
      const stanzaId = objcCallNoArg(stanza, "uniqueStanzaID");
      if (stanzaId) out.stanzaId = String(stanzaId);
    } catch (_) {}
    try {
      const uk = objcCallNoArg(stanza, "uniqueKey");
      if (uk) out.uniqueKey = String(uk);
    } catch (_) {}

    const chatCand =
      objcCallNoArg(stanza, "chatJID") ||
      objcCallNoArg(stanza, "chatJid") ||
      objcCallNoArg(stanza, "remoteJID") ||
      objcCallNoArg(stanza, "remoteJid");
    out.chatJid = _extractJidStringFromMaybeObj(chatCand) || "";
    if (!out.chatJid && out.uniqueKey) out.chatJid = _deriveChatJidFromUniqueKey(out.uniqueKey);

    const senderCand =
      objcCallNoArg(stanza, "threadMsgSenderJID") ||
      objcCallNoArg(stanza, "participant");
    out.senderJid = _extractJidStringFromMaybeObj(senderCand) || "";

    if (out.chatJid === "status@broadcast") {
      const authorCand = objcCallNoArg(stanza, "incomingOriginalAuthorUserJID") || senderCand;
      out.statusAuthorJid = _extractJidStringFromMaybeObj(authorCand) || "";
      try {
        const ao = authorCand instanceof ObjC.Object ? authorCand : _safeObj(authorCand);
        if (ao) {
          out.statusAuthorPtr = ao.handle ? ptr(ao.handle).toString() : ptr(ao).toString();
          out.statusAuthorClass = String(ao.$className || "");
        }
      } catch (_) {}
    }

    try {
      const msgCand =
        objcCallNoArg(ctxObj, "orderedMessage") ||
        objcCallNoArg(ctxObj, "message") ||
        objcCallNoArg(ctxObj, "orderedMessageItem") ||
        objcCallNoArg(ctxObj, "messageItem") ||
        objcCallNoArg(ctxObj, "orderedMessageRecord");
      const mo = msgCand instanceof ObjC.Object ? msgCand : _safeObj(msgCand);
      if (mo) {
        const cn = String(mo.$className || "");
        if (cn && (cn.indexOf("WAMessage") !== -1 || objcHasSelector(mo, "updateOutgoingReaction:") || objcHasSelector(mo, "createOutgoingReactionWithUnicode:metadata:error:"))) {
          out.msgPtr = mo.handle ? ptr(mo.handle).toString() : ptr(mo).toString();
          out.msgClass = cn;
        }
      }
    } catch (_) {}

    out.isGroup = out.chatJid ? _isGroupJidString(out.chatJid) : false;
    const fm = _tryCallBoolNoArg(stanza, "isFromMe");
    out.isFromMe = fm !== null && fm !== undefined ? fm : _tryCallBoolNoArg(stanza, "fromMe");
    if ((out.isFromMe === null || out.isFromMe === undefined) && out.uniqueKey) out.isFromMe = _deriveIsFromMeFromUniqueKey(out.uniqueKey);
    return out;
  } catch (_) {
    return out;
  }
}

function rxPinnedOn() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (RX_PINNED.installed) return { ok: true, installed: true, installedAt: RX_PINNED.installedAt, events: RX_PINNED.events, err: RX_PINNED.err || "" };
  RX_PINNED.err = "";
  RX_PINNED.events = 0;
  RX_PINNED.last = null;
  RX_PINNED.lastN = [];
  try {
    const mod = _pickModuleByHints(["WhatsApp", "WhatsAppDecrypted", "WhatsApp_Decrypted"]);
    if (!mod || !mod.base) return { ok: false, error: "module not found" };
    const rva = 0x35B1CE4;
    const addr = mod.base.add(ptr(rva));
    const allow = [
      "reallyProcessResultsAfterSignalForContext:plaintextProtobuf:originalMessageData:notificationBehavior:journalID:error:retryCount:origin:reportEmptyPlaintextError:",
      "processResultsAfterSignalForContext:plaintextProtobuf:originalMessageData:notificationBehavior:journalID:error:retryCount:origin:reportEmptyPlaintextError:",
    ];
    const reentry = {};
    RX_PINNED._h = Interceptor.attach(addr, {
      onEnter(args) {
        try {
          if (!RX_PINNED.installed) return;
          if (RX_PINNED.events >= RX_PINNED.maxEvents) return;
          const tid = Process.getCurrentThreadId();
          if (reentry[tid]) return;
          reentry[tid] = 1;
          RX_PINNED.events += 1;

          let cmdSel = null;
          try { cmdSel = ObjC.selectorAsString ? ObjC.selectorAsString(args[1]) : null; } catch (_) { cmdSel = null; }
          if (allow.length && (!cmdSel || allow.indexOf(String(cmdSel)) === -1)) return;
          const ctxPtr = args[2];
          const doWork = () => {
            try {
              const stanza = _extractStanzaFieldsFromContextPinned(ctxPtr);
              const chatJid = String(stanza.chatJid || "").trim();
              const senderJid = String(stanza.senderJid || "").trim();
              const statusAuthorJid = String(stanza.statusAuthorJid || "").trim();
              const statusAuthorPtr = String(stanza.statusAuthorPtr || "").trim();
              const statusAuthorClass = String(stanza.statusAuthorClass || "").trim();
              const msgPtr = String(stanza.msgPtr || "").trim();
              const msgClass = String(stanza.msgClass || "").trim();
              const effectiveSenderJid = (chatJid === "status@broadcast" && statusAuthorJid) ? statusAuthorJid : senderJid;
              const ev = {
                type: "qqw.explore.recv.pinned",
                build: SCRIPT_BUILD_ID,
                ts: nowMs(),
                stanzaId: stanza.stanzaId,
                uniqueKey: stanza.uniqueKey,
                chatJid: chatJid,
                senderJid: senderJid,
                isGroup: !!stanza.isGroup,
                isFromMe: stanza.isFromMe,
                statusAuthorJid: statusAuthorJid,
                statusAuthorPtr: statusAuthorPtr,
                statusAuthorClass: statusAuthorClass,
                msgPtr: msgPtr,
                msgClass: msgClass,
                effectiveSenderJid: effectiveSenderJid,
                diag: { cmdSel: cmdSel ? String(cmdSel) : "" }
              };
              try {
                if (chatJid === "status@broadcast" && statusAuthorPtr && statusAuthorPtr !== "0x0") {
                  try { _objcReleasePtrStr(RX_PINNED.retainedAuthorPtr); } catch (_) {}
                  RX_PINNED.retainedAuthorPtr = _objcRetainPtrStr(statusAuthorPtr);
                }
              } catch (_) {}
              try {
                if (chatJid === "status@broadcast" && msgPtr && msgPtr !== "0x0" && statusAuthorJid && stanza.stanzaId) {
                  const key = String(statusAuthorJid) + "|" + String(stanza.stanzaId);
                  if (key) {
                    if (RX_PINNED.msgByKey[key]) {
                      try { _objcReleasePtrStr(RX_PINNED.msgByKey[key]); } catch (_) {}
                    } else {
                      RX_PINNED.msgKeys.push(key);
                      if (RX_PINNED.msgKeys.length > RX_PINNED.maxMsgKeys) {
                        const old = RX_PINNED.msgKeys.shift();
                        if (old && RX_PINNED.msgByKey[old]) {
                          try { _objcReleasePtrStr(RX_PINNED.msgByKey[old]); } catch (_) {}
                          delete RX_PINNED.msgByKey[old];
                        }
                      }
                    }
                    RX_PINNED.msgByKey[key] = _objcRetainPtrStr(msgPtr);
                  }
                }
              } catch (_) {}
              RX_PINNED.last = ev;
              RX_PINNED.lastN.push(ev);
              if (RX_PINNED.lastN.length > RX_PINNED.maxLastN) RX_PINNED.lastN.shift();
              send(ev);
            } catch (_) {}
          };
          try { doWork(); } catch (_) { safeObjCInvoke(doWork); }
        } catch (_) {}
      },
      onLeave() {
        try {
          const tid = Process.getCurrentThreadId();
          if (reentry[tid]) delete reentry[tid];
        } catch (_) {}
      }
    });
    RX_PINNED.installed = true;
    RX_PINNED.installedAt = nowMs();
    return { ok: true, installed: true, module: String(mod.name || ""), rva: "0x" + rva.toString(16), addr: addr.toString() };
  } catch (e) {
    RX_PINNED.err = String(e);
    return { ok: false, error: RX_PINNED.err };
  }
}

function rxPinnedOff() {
  try { if (RX_PINNED._h) RX_PINNED._h.detach(); } catch (_) {}
  RX_PINNED._h = null;
  RX_PINNED.installed = false;
  try { _objcReleasePtrStr(RX_PINNED.retainedAuthorPtr); } catch (_) {}
  RX_PINNED.retainedAuthorPtr = "0x0";
  try {
    const ks = RX_PINNED.msgKeys || [];
    for (let i = 0; i < ks.length; i++) {
      const k = ks[i];
      const p = RX_PINNED.msgByKey ? RX_PINNED.msgByKey[k] : null;
      if (p) {
        try { _objcReleasePtrStr(p); } catch (_) {}
      }
    }
  } catch (_) {}
  RX_PINNED.msgByKey = {};
  RX_PINNED.msgKeys = [];
  return { ok: true };
}

function rxPinnedStatus() {
  return { ok: true, installed: RX_PINNED.installed, installedAt: RX_PINNED.installedAt, events: RX_PINNED.events, err: RX_PINNED.err || "", last: RX_PINNED.last };
}

function rxPinnedLast(maxN) {
  const lim = Math.max(1, Math.min(200, Number(maxN || 50) | 0));
  const xs = RX_PINNED.lastN || [];
  const n = Math.min(lim, xs.length);
  const out = [];
  for (let i = xs.length - n; i < xs.length; i++) out.push(xs[i]);
  return { ok: true, installed: RX_PINNED.installed, count: xs.length, last: out };
}

function statusMsgProbeOn() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (STATUS_MSG_PROBE.installed) return { ok: true, installed: true, installedAt: STATUS_MSG_PROBE.installedAt, count: STATUS_MSG_PROBE.count, err: STATUS_MSG_PROBE.err || "" };
  STATUS_MSG_PROBE.err = "";
  STATUS_MSG_PROBE.count = 0;
  STATUS_MSG_PROBE.last = null;
  STATUS_MSG_PROBE.lastN = [];
  try {
    const cls = ObjC.classes.WAMutableChatSession;
    if (!cls) return { ok: false, error: "WAMutableChatSession missing" };
    const sels = [
      "- fetchMessageWithStanzaID:authorUserJID:",
      "- fetchMessageWithStanzaID:participantUserJID:isFromMe:",
    ];
    const hs = [];
    const reentry = {};
    for (let i = 0; i < sels.length; i++) {
      const m = sels[i];
      const fn = cls[m];
      if (!fn || !fn.implementation) continue;
      const imp = fn.implementation;
      const h = Interceptor.attach(imp, {
        onEnter(args) {
          try {
            const tid = Process.getCurrentThreadId();
            if (reentry[tid]) return;
            reentry[tid] = 1;
            this._sel = m;
            this._self = args[0];
            this._stanza = args[2];
            this._p = args[3];
            this._fromMe = (m.indexOf("isFromMe:") !== -1) ? (args[4] ? 1 : 0) : null;
          } catch (_) {}
        },
        onLeave(retval) {
          try {
            const tid = Process.getCurrentThreadId();
            if (reentry[tid]) delete reentry[tid];
            STATUS_MSG_PROBE.count += 1;
            let stanzaId = "";
            try { stanzaId = String(new ObjC.Object(this._stanza) || ""); } catch (_) { stanzaId = ""; }
            let authorJid = "";
            try { authorJid = _extractJidStringFromMaybeObj(_safeObj(this._p)) || ""; } catch (_) { authorJid = ""; }
            const csObj = _safeObj(this._self);
            const csPtr = this._self ? ptr(this._self).toString() : "0x0";
            const csClass = csObj ? String(csObj.$className || "") : "";
            const msgPtr = retval && !ptr(retval).isNull() ? ptr(retval).toString() : "0x0";
            let msgClass = "";
            try {
              if (msgPtr && msgPtr !== "0x0") msgClass = String((_safeObj(ptr(msgPtr)) || {}).$className || "");
            } catch (_) { msgClass = ""; }
            const ev = {
              type: "qqw.explore.statusmsgprobe",
              build: SCRIPT_BUILD_ID,
              ts: nowMs(),
              sel: String(this._sel || ""),
              chatSessionPtr: csPtr,
              chatSessionClass: csClass,
              stanzaId: stanzaId,
              authorJid: authorJid,
              fromMe: this._fromMe,
              msgPtr: msgPtr,
              msgClass: msgClass,
            };
            if (authorJid && stanzaId && msgPtr && msgPtr !== "0x0") {
              const key = String(authorJid) + "|" + String(stanzaId);
              if (key) {
                if (STATUS_MSG_PROBE.msgByKey[key]) {
                  try { _objcReleasePtrStr(STATUS_MSG_PROBE.msgByKey[key]); } catch (_) {}
                } else {
                  STATUS_MSG_PROBE.msgKeys.push(key);
                  if (STATUS_MSG_PROBE.msgKeys.length > STATUS_MSG_PROBE.maxMsgKeys) {
                    const old = STATUS_MSG_PROBE.msgKeys.shift();
                    if (old && STATUS_MSG_PROBE.msgByKey[old]) {
                      try { _objcReleasePtrStr(STATUS_MSG_PROBE.msgByKey[old]); } catch (_) {}
                      delete STATUS_MSG_PROBE.msgByKey[old];
                    }
                  }
                }
                STATUS_MSG_PROBE.msgByKey[key] = _objcRetainPtrStr(msgPtr);
              }
            }
            STATUS_MSG_PROBE.last = ev;
            STATUS_MSG_PROBE.lastN.push(ev);
            if (STATUS_MSG_PROBE.lastN.length > STATUS_MSG_PROBE.maxLastN) STATUS_MSG_PROBE.lastN.shift();
            send(ev);
          } catch (_) {}
        }
      });
      hs.push(h);
    }
    if (!hs.length) return { ok: false, error: "no supported fetchMessageWithStanzaID:* methods found on WAMutableChatSession" };
    STATUS_MSG_PROBE._hs = hs;
    STATUS_MSG_PROBE.installed = true;
    STATUS_MSG_PROBE.installedAt = nowMs();
    return { ok: true, installed: true, installedAt: STATUS_MSG_PROBE.installedAt, hooks: sels };
  } catch (e) {
    STATUS_MSG_PROBE.err = String(e);
    return { ok: false, error: STATUS_MSG_PROBE.err };
  }
}

function statusMsgProbeOff() {
  try {
    const hs = STATUS_MSG_PROBE._hs || [];
    for (let i = 0; i < hs.length; i++) {
      try { hs[i].detach(); } catch (_) {}
    }
  } catch (_) {}
  STATUS_MSG_PROBE._hs = [];
  STATUS_MSG_PROBE.installed = false;
  try {
    const ks = STATUS_MSG_PROBE.msgKeys || [];
    for (let i = 0; i < ks.length; i++) {
      const k = ks[i];
      const p = STATUS_MSG_PROBE.msgByKey ? STATUS_MSG_PROBE.msgByKey[k] : null;
      if (p) {
        try { _objcReleasePtrStr(p); } catch (_) {}
      }
    }
  } catch (_) {}
  STATUS_MSG_PROBE.msgByKey = {};
  STATUS_MSG_PROBE.msgKeys = [];
  return { ok: true };
}

function statusMsgProbeStatus() {
  return { ok: true, installed: STATUS_MSG_PROBE.installed, installedAt: STATUS_MSG_PROBE.installedAt, count: STATUS_MSG_PROBE.count, err: STATUS_MSG_PROBE.err || "", last: STATUS_MSG_PROBE.last };
}

function statusMsgProbeLast(maxN) {
  const lim = Math.max(1, Math.min(200, Number(maxN || 50) | 0));
  const xs = STATUS_MSG_PROBE.lastN || [];
  const n = Math.min(lim, xs.length);
  const out = [];
  for (let i = xs.length - n; i < xs.length; i++) out.push(xs[i]);
  return { ok: true, installed: STATUS_MSG_PROBE.installed, count: xs.length, last: out };
}

function statusReplyArgsLast() {
  const last = RX_PINNED.last;
  if (!last) return { ok: false, error: "no last event" };
  const chatJid = String(last.chatJid || "").trim();
  if (chatJid !== "status@broadcast") return { ok: false, error: "last is not status@broadcast", chatJid };
  const author = String(last.effectiveSenderJid || last.statusAuthorJid || "").trim();
  if (!author) return { ok: false, error: "missing statusAuthorJid" };
  const quoteStanzaId = String(last.stanzaId || "").trim();
  if (!quoteStanzaId) return { ok: false, error: "missing status stanzaId" };
  return { ok: true, jid: author, quoteStanzaId, statusAuthorJid: String(last.statusAuthorJid || ""), statusStanzaId: quoteStanzaId, statusAuthorPtr: String(last.statusAuthorPtr || ""), statusAuthorClass: String(last.statusAuthorClass || "") };
}

function _captureObj(p) {
  try {
    const pp = ptr(p);
    if (pp.isNull()) return { ptr: pp.toString(), className: "", desc: "" };
    const o = _safeObj(pp);
    if (!o) return { ptr: pp.toString(), className: "", desc: "" };
    return { ptr: pp.toString(), className: String(o.$className || ""), desc: _safeDesc(o) };
  } catch (_) {
    try { return { ptr: ptr(p).toString(), className: "", desc: "" }; } catch (_) { return { ptr: "0x0", className: "", desc: "" }; }
  }
}

function installSendProbe(maxHooks) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (SEND_PROBE.installed) return { ok: true, installed: true, count: SEND_PROBE.count, hooked: SEND_PROBE.hooked || [], err: SEND_PROBE.err || "" };
  SEND_PROBE.err = "";
  SEND_PROBE._ls = [];
  SEND_PROBE.hooked = [];
  try {
    const cls = ObjC.classes.WAMessageSender;
    if (!cls) return { ok: false, error: "WAMessageSender missing" };
    const idaBase = ptr("0x100000000");
    const reentry = {};
    const methods = cls.$ownMethods || [];
    const want = [];
    for (let i = 0; i < methods.length; i++) {
      const m = String(methods[i] || "");
      if (!m) continue;
      if (m.indexOf("sendMessageWithText:") === -1) continue;
      if (m.indexOf("inChatSession:") === -1) continue;
      want.push(m);
    }
    if (!want.length) return { ok: false, error: "no sendMessageWithText:*inChatSession:* methods found on WAMessageSender" };

    const _score = (sig) => {
      try {
        const s = String(sig || "");
        let sc = 0;
        if (s.indexOf("beforeSendCallback:completion:") !== -1) sc += 120;
        if (s.indexOf("replyContext:") !== -1) sc += 90;
        if (s.indexOf("creationEntryPoint:") !== -1) sc += 80;
        if (s.indexOf("hasTextFromURL:openedFromURL:") !== -1) sc += 30;
        if (s.indexOf("multicast:") !== -1) sc += 25;
        if (s.indexOf("status") !== -1 || s.indexOf("Status") !== -1) sc += 20;
        sc -= Math.min(30, Math.max(0, Math.floor(s.length / 120)));
        return sc;
      } catch (_) {
        return 0;
      }
    };
    want.sort((a, b) => _score(b) - _score(a));

    const lim = Math.max(1, Math.min(8, Number(maxHooks || 2) | 0));
    const hooks = want.slice(0, lim);
    for (let i = 0; i < hooks.length; i++) {
      const sel = hooks[i];
      const m = cls[sel];
      if (!m || !m.implementation) continue;
      const h = Interceptor.attach(m.implementation, {
        onEnter(args) {
          try {
            const tid = Process.getCurrentThreadId();
            if (reentry[tid]) return;
            reentry[tid] = 1;
            if (SEND_PROBE.count >= 50) return;
            const ra = ptr(this.returnAddress);
            let callerIda = "0x0";
            try {
              const m0 = Process.findModuleByAddress(ra);
              if (m0) {
                const off = ra.sub(ptr(m0.base));
                callerIda = idaBase.add(off).toString();
              }
            } catch (_) { callerIda = "0x0"; }
            const snap = {
              ts: nowMs(),
              tid: tid,
              selector: sel.replace(/^\s*[-+]\s*/g, ""),
              callerReturnAddress: ra.toString(),
              callerIda: callerIda,
              selfPtr: ptr(args[0]).toString(),
              a2Ptr: ptr(args[2]).toString(),
              a3Ptr: ptr(args[3]).toString(),
              a4Ptr: ptr(args[4]).toString(),
              a5Ptr: ptr(args[5]).toString(),
              a6Ptr: ptr(args[6]).toString(),
              a7Ptr: ptr(args[7]).toString(),
              a8Ptr: ptr(args[8]).toString(),
              a9Ptr: ptr(args[9]).toString(),
              a10Ptr: ptr(args[10]).toString(),
              a11Ptr: ptr(args[11]).toString(),
              a12Ptr: ptr(args[12]).toString(),
              a13Ptr: ptr(args[13]).toString(),
              a14Ptr: ptr(args[14]).toString(),
              a15Ptr: ptr(args[15]).toString(),
              a16Ptr: ptr(args[16]).toString(),
            };
            SEND_PROBE.last = snap;
            SEND_PROBE.count++;
            send({ type: "qqw.explore.send_probe", ok: true, ...snap });
            try {
              const now = nowMs();
              if (STATUS_LIKE.armedUntilMs && now <= STATUS_LIKE.armedUntilMs) {
                const sn = String(snap.selector || "");
                if (sn.indexOf("sendMessageWithText:multicast:attachments:messageOrigin:creationEntryPoint:inChatSession:") !== -1 && sn.indexOf("beforeSendCallback:completion:") !== -1) {
                  STATUS_LIKE.template = {
                    ts: now,
                    selector: String(snap.selector || ""),
                    messageOriginPtr: String(snap.a5Ptr || ""),
                    creationEntryPointPtr: String(snap.a6Ptr || ""),
                    inChatSessionPtr: String(snap.a7Ptr || ""),
                    callerIda: String(snap.callerIda || "")
                  };
                  STATUS_LIKE.armedUntilMs = 0;
                  send({ type: "qqw.explore.status_like_template", ok: true, template: STATUS_LIKE.template });
                }
              }
            } catch (_) {}
          } catch (e) {
            try { send({ type: "qqw.explore.send_probe", ok: false, error: String(e) }); } catch (_) {}
          } finally {
            try {
              const tid = Process.getCurrentThreadId();
              if (reentry[tid]) delete reentry[tid];
            } catch (_) {}
          }
        },
      });
      SEND_PROBE._ls.push(h);
      SEND_PROBE.hooked.push({ className: "WAMessageSender", selector: sel.replace(/^\s*[-+]\s*/g, "") });
    }
    SEND_PROBE.installed = true;
    return { ok: true, installed: true, hooked: SEND_PROBE._ls.length, hooks: SEND_PROBE.hooked };
  } catch (e) {
    SEND_PROBE.err = String(e);
    return { ok: false, error: SEND_PROBE.err };
  }
}

function sendProbeInspect(ptrStr) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const p = ptr(String(ptrStr || "").trim() || "0x0");
  if (p.isNull()) return { ok: false, error: "null ptr" };
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      try {
        const o = new ObjC.Object(p);
        const cn = String(o.$className || "");
        resolve({ ok: true, ptr: p.toString(), className: cn });
      } catch (e) {
        resolve({ ok: false, ptr: p.toString(), error: String(e) });
      }
    });
  });
}

function sendProbeStatus() {
  return { ok: true, installed: SEND_PROBE.installed, count: SEND_PROBE.count, last: SEND_PROBE.last, hooks: SEND_PROBE.hooked || [], err: SEND_PROBE.err || "" };
}

function sendProbeClear() {
  SEND_PROBE.last = null;
  SEND_PROBE.count = 0;
  return { ok: true };
}

function sendProbeOff() {
  try {
    const ls = SEND_PROBE._ls || [];
    for (let i = 0; i < ls.length; i++) {
      try { ls[i].detach(); } catch (_) {}
    }
  } catch (_) {}
  SEND_PROBE._ls = [];
  SEND_PROBE.hooked = [];
  SEND_PROBE.installed = false;
  return { ok: true };
}

function likeProbeOn() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (LIKE_PROBE.installed) return { ok: true, installed: true, count: LIKE_PROBE.count, err: LIKE_PROBE.err || "" };
  LIKE_PROBE.err = "";
  LIKE_PROBE.last = null;
  LIKE_PROBE.count = 0;
  LIKE_PROBE.lastText = "";
  LIKE_PROBE.retainedPtr = "0x0";
  LIKE_PROBE.retainedConnPtr = "0x0";
  try {
    const cls = ObjC.classes.XMPPConnectionMain;
    if (!cls) return { ok: false, error: "XMPPConnectionMain missing" };
    const sel = "- sendMessageStanza:";
    const m = cls[sel];
    if (!m || !m.implementation) return { ok: false, error: "method missing", selector: sel };
    const idaBase = ptr("0x100000000");
    const reentry = {};
    let objcRetain = null;
    let objcRelease = null;
    try {
      const pRet = Module.findExportByName(null, "objc_retain");
      const pRel = Module.findExportByName(null, "objc_release");
      if (pRet) objcRetain = new NativeFunction(pRet, "pointer", ["pointer"]);
      if (pRel) objcRelease = new NativeFunction(pRel, "void", ["pointer"]);
    } catch (_) { objcRetain = null; objcRelease = null; }

    LIKE_PROBE._h = Interceptor.attach(m.implementation, {
      onEnter(args) {
        try {
          const now = nowMs();
          if (!STATUS_LIKE.armedUntilMs || now > STATUS_LIKE.armedUntilMs) return;
          const tid = Process.getCurrentThreadId();
          if (reentry[tid]) return;
          reentry[tid] = 1;
          if (LIKE_PROBE.count >= 50) return;
          const ra = ptr(this.returnAddress);
          let callerIda = "0x0";
          let callerModule = "";
          let callerOff = "0x0";
          try {
            const m0 = Process.findModuleByAddress(ra);
            if (m0) {
              callerModule = String(m0.name || "");
              callerOff = ra.sub(ptr(m0.base)).toString();
              callerIda = idaBase.add(ptr(callerOff)).toString();
            }
          } catch (_) { callerIda = "0x0"; callerModule = ""; callerOff = "0x0"; }
          const snap = {
            ts: now,
            tid: tid,
            selector: "sendMessageStanza:",
            callerReturnAddress: ra.toString(),
            callerIda: callerIda,
            callerModule: callerModule,
            callerOff: callerOff,
            stanzaPtr: ptr(args[2]).toString(),
          };
          try {
            const sp = ptr(args[2]);
            if (!sp.isNull() && objcRetain) {
              const rp = objcRetain(sp);
              if (rp && !ptr(rp).isNull()) {
                try {
                  const old = ptr(String(LIKE_PROBE.retainedPtr || "0x0"));
                  if (objcRelease && old && !old.isNull()) objcRelease(old);
                } catch (_) {}
                LIKE_PROBE.retainedPtr = ptr(rp).toString();
              }
            }
          } catch (_) {}
          try {
            const cp = ptr(args[0]);
            if (!cp.isNull() && objcRetain) {
              const rp = objcRetain(cp);
              if (rp && !ptr(rp).isNull()) {
                try {
                  const old = ptr(String(LIKE_PROBE.retainedConnPtr || "0x0"));
                  if (objcRelease && old && !old.isNull()) objcRelease(old);
                } catch (_) {}
                LIKE_PROBE.retainedConnPtr = ptr(rp).toString();
              }
            }
          } catch (_) {}
          LIKE_PROBE.last = snap;
          LIKE_PROBE.count++;
          STATUS_LIKE.lastXMPP = snap;
          STATUS_LIKE.armedUntilMs = 0;
          send({ type: "qqw.explore.like_probe", ok: true, ...snap });

          try {
            const rpStr = String(LIKE_PROBE.retainedPtr || "0x0");
            if (rpStr && rpStr !== "0x0") {
              safeObjCInvoke(() => {
                try {
                  const stanza = new ObjC.Object(ptr(rpStr));
                  if (stanza && objcHasSelector(stanza, "stringRepresentation")) {
                    const s = objcCallNoArgString(stanza, "stringRepresentation");
                    if (s) {
                      LIKE_PROBE.lastText = String(s).slice(0, 4000);
                      send({ type: "qqw.explore.like_probe_text", ok: true, ptr: rpStr, text: LIKE_PROBE.lastText });
                    }
                  }
                  if (!LIKE_PROBE.lastText && stanza && objcHasSelector(stanza, "description")) {
                    const d = objcCallNoArgString(stanza, "description");
                    if (d) {
                      LIKE_PROBE.lastText = String(d).slice(0, 4000);
                      send({ type: "qqw.explore.like_probe_text", ok: true, ptr: rpStr, text: LIKE_PROBE.lastText });
                    }
                  }
                } catch (_) {}
              });
            }
          } catch (_) {}
        } catch (e) {
          try { send({ type: "qqw.explore.like_probe", ok: false, error: String(e) }); } catch (_) {}
        } finally {
          try {
            const tid = Process.getCurrentThreadId();
            if (reentry[tid]) delete reentry[tid];
          } catch (_) {}
        }
      }
    });
    LIKE_PROBE.installed = true;
    return { ok: true, installed: true };
  } catch (e) {
    LIKE_PROBE.err = String(e);
    return { ok: false, error: LIKE_PROBE.err };
  }
}

function likeProbeGet() {
  return { ok: true, installed: LIKE_PROBE.installed, count: LIKE_PROBE.count, last: LIKE_PROBE.last, retainedPtr: LIKE_PROBE.retainedPtr || "0x0", retainedConnPtr: LIKE_PROBE.retainedConnPtr || "0x0", hasText: LIKE_PROBE.lastText ? 1 : 0, err: LIKE_PROBE.err || "" };
}

function likeProbeClear() {
  LIKE_PROBE.last = null;
  LIKE_PROBE.count = 0;
  LIKE_PROBE.lastText = "";
  try {
    const pRel = Module.findExportByName(null, "objc_release");
    if (pRel) {
      const objcRelease = new NativeFunction(pRel, "void", ["pointer"]);
      const old = ptr(String(LIKE_PROBE.retainedPtr || "0x0"));
      if (old && !old.isNull()) objcRelease(old);
      const old2 = ptr(String(LIKE_PROBE.retainedConnPtr || "0x0"));
      if (old2 && !old2.isNull()) objcRelease(old2);
    }
  } catch (_) {}
  LIKE_PROBE.retainedPtr = "0x0";
  LIKE_PROBE.retainedConnPtr = "0x0";
  return { ok: true };
}

function likeProbeOff() {
  try { if (LIKE_PROBE._h) LIKE_PROBE._h.detach(); } catch (_) {}
  LIKE_PROBE._h = null;
  LIKE_PROBE.installed = false;
  try { likeProbeClear(); } catch (_) {}
  return { ok: true };
}

function likeProbeInspect(ptrStr) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const p = ptr(String(ptrStr || "").trim() || "0x0");
  if (p.isNull()) return { ok: false, error: "null ptr" };
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      try {
        const o = new ObjC.Object(p);
        const cn = String(o.$className || "");
        resolve({ ok: true, ptr: p.toString(), className: cn });
      } catch (e) {
        resolve({ ok: false, ptr: p.toString(), error: String(e) });
      }
    });
  });
}

function likeProbeStanzaMethods(ptrStr, regex, maxN) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const p = ptr(String(ptrStr || "").trim() || "0x0");
  if (p.isNull()) return { ok: false, error: "null ptr" };
  return objSelectors(p.toString(), String(regex || ""), Number(maxN || 200) | 0, true);
}

function likeProbeStanzaMethodsLast(regex, maxN) {
  const last = LIKE_PROBE && LIKE_PROBE.last ? LIKE_PROBE.last : null;
  if (!last) return { ok: false, error: "no like_probe last" };
  const p = String(LIKE_PROBE.retainedPtr || last.stanzaPtr || "").trim();
  if (!p || p === "0x0") return { ok: false, error: "missing stanza ptr" };
  const rx = String(regex || "").trim() || "(xml|string|desc|repr|data|serialize|bytes|utf8|reaction|like|emoji)";
  const n = Number.isFinite(Number(maxN)) ? Number(maxN) : 200;
  return likeProbeStanzaMethods(p, rx, n);
}

function likeProbeStanzaCallNoArg(ptrStr, selName, maxChars) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const p = ptr(String(ptrStr || "").trim() || "0x0");
  if (p.isNull()) return Promise.resolve({ ok: false, error: "null ptr" });
  const sel = String(selName || "").trim();
  if (!sel || sel.indexOf(":") !== -1) return Promise.resolve({ ok: false, error: "selName must be no-arg" });
  const lim = Math.max(200, Math.min(16000, Number(maxChars || 4000) | 0));
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      try {
        const stanza = new ObjC.Object(p);
        if (!objcHasSelector(stanza, sel)) return resolve({ ok: false, error: "selector not found", ptr: p.toString(), className: String(stanza.$className || ""), selector: sel });
        const v = objcCallNoArg(stanza, sel);
        if (v === null || v === undefined) return resolve({ ok: true, ptr: p.toString(), className: String(stanza.$className || ""), selector: sel, type: "nil", text: "" });
        const o = v instanceof ObjC.Object ? v : _safeObj(v);
        if (!o) return resolve({ ok: true, ptr: p.toString(), className: String(stanza.$className || ""), selector: sel, type: typeof v, text: String(v).slice(0, lim) });
        try {
          const NSData = ObjC.classes.NSData;
          if (NSData && o.isKindOfClass_ && o.isKindOfClass_(NSData) && objcHasSelector(o, "base64EncodedStringWithOptions:")) {
            const b64 = o.base64EncodedStringWithOptions_(0);
            const s = b64 ? String(b64) : "";
            return resolve({ ok: true, ptr: p.toString(), className: String(stanza.$className || ""), selector: sel, type: "NSData.base64", text: s.slice(0, lim) });
          }
        } catch (_) {}
        let s = "";
        try { s = String(o); } catch (_) { s = ""; }
        return resolve({ ok: true, ptr: p.toString(), className: String(stanza.$className || ""), selector: sel, type: String(o.$className || ""), text: s ? s.slice(0, lim) : "" });
      } catch (e) {
        resolve({ ok: false, ptr: p.toString(), error: String(e), selector: sel });
      }
    });
  });
}

function likeProbeStanzaCallNoArgLast(selName, maxChars) {
  const last = LIKE_PROBE && LIKE_PROBE.last ? LIKE_PROBE.last : null;
  if (!last) return Promise.resolve({ ok: false, error: "no like_probe last" });
  const p = String(LIKE_PROBE.retainedPtr || last.stanzaPtr || "").trim();
  if (!p || p === "0x0") return Promise.resolve({ ok: false, error: "missing stanza ptr" });
  return likeProbeStanzaCallNoArg(p, selName, maxChars);
}

function _chooseOneInstance(className, onFound, onDone, maxN) {
  try {
    if (!objcAvailable()) return onDone(null);
    const cn = String(className || "").trim();
    const cls = cn ? ObjC.classes[cn] : null;
    if (!cls) return onDone(null);
    let found = null;
    let n = 0;
    ObjC.choose(cls, {
      onMatch(inst) {
        if (found) return;
        found = inst;
        n++;
        if (n >= (Number(maxN || 1) | 0)) return "stop";
        return undefined;
      },
      onComplete() {
        try { onFound(found); } catch (_) {}
        try { onDone(found); } catch (_) {}
      }
    });
  } catch (_) {
    try { onDone(null); } catch (_) {}
  }
}

function xmppSendStanzaPtr(stanzaPtrStr) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const sp = ptr(String(stanzaPtrStr || "").trim() || "0x0");
  if (sp.isNull()) return Promise.resolve({ ok: false, error: "null stanza ptr" });
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      try {
        const stanza = new ObjC.Object(sp);
        const cn = String(stanza.$className || "");
        let inst0 = null;
        try {
          const p = String(LIKE_PROBE.retainedConnPtr || "").trim();
          if (p && p !== "0x0") inst0 = new ObjC.Object(ptr(p));
        } catch (_) { inst0 = null; }
        if (!inst0) {
          try {
            const cls = ObjC.classes.XMPPConnectionMain;
            const cands = ["sharedInstance", "shared", "main", "mainInstance", "defaultInstance", "defaultConnection", "sharedConnection", "connectionMain"];
            for (let i = 0; i < cands.length; i++) {
              const s = cands[i];
              if (!cls) break;
              if (!objcHasSelector(cls, s)) continue;
              const x = objcCallClassNoArg(cls, s);
              if (x) { inst0 = x; break; }
            }
          } catch (_) { inst0 = null; }
        }

        const run = (inst) => {
          try {
            if (!inst) return resolve({ ok: false, error: "XMPPConnectionMain instance not found" });
            if (!objcHasSelector(inst, "sendMessageStanza:")) return resolve({ ok: false, error: "XMPPConnectionMain missing sendMessageStanza:" });
            inst.sendMessageStanza_(stanza);
            XMPP_SEND.last = { ts: nowMs(), stanzaPtr: sp.toString(), className: cn };
            resolve({ ok: true, stanzaPtr: sp.toString(), className: cn, used: "sendMessageStanza:" });
          } catch (e) {
            resolve({ ok: false, error: String(e), stanzaPtr: sp.toString(), className: cn });
          }
        };

        if (inst0) return run(inst0 instanceof ObjC.Object ? inst0 : new ObjC.Object(inst0));
        resolve({ ok: false, error: "XMPPConnectionMain instance not found (no retained conn ptr; no shared instance)", stanzaPtr: sp.toString(), className: cn });
      } catch (e) {
        resolve({ ok: false, error: String(e), stanzaPtr: sp.toString() });
      }
    });
  });
}

function likeResendLast() {
  const last = LIKE_PROBE && LIKE_PROBE.last ? LIKE_PROBE.last : null;
  if (!last) return Promise.resolve({ ok: false, error: "no like_probe last" });
  const p = String(LIKE_PROBE.retainedPtr || last.stanzaPtr || "").trim();
  if (!p || p === "0x0") return Promise.resolve({ ok: false, error: "missing stanza ptr" });
  return xmppSendStanzaPtr(p);
}

function objcCall1Arg(obj, selName, arg1) {
  try {
    if (!objcAvailable() || !obj || !selName) return null;
    const m1 = "- " + String(selName);
    if (obj[m1] && typeof obj[m1] === "function") return obj[m1](arg1);
    if (obj[selName] && typeof obj[selName] === "function") return obj[selName](arg1);
    return null;
  } catch (_) {
    return null;
  }
}

function likeProbeStanzaCall1Arg(ptrStr, selName, argStr, maxChars) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const p = ptr(String(ptrStr || "").trim() || "0x0");
  if (p.isNull()) return Promise.resolve({ ok: false, error: "null ptr" });
  const sel = String(selName || "").trim();
  if (!sel || sel.indexOf(":") === -1) return Promise.resolve({ ok: false, error: "selName must contain one ':'" });
  const lim = Math.max(200, Math.min(16000, Number(maxChars || 4000) | 0));
  const nsArg = nsString(String(argStr || ""));
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      try {
        const stanza = new ObjC.Object(p);
        if (!objcHasSelector(stanza, sel)) return resolve({ ok: false, error: "selector not found", ptr: p.toString(), className: String(stanza.$className || ""), selector: sel });
        const v = objcCall1Arg(stanza, sel, nsArg);
        if (v === null || v === undefined) return resolve({ ok: true, ptr: p.toString(), className: String(stanza.$className || ""), selector: sel, type: "nil", text: "" });
        const o = v instanceof ObjC.Object ? v : _safeObj(v);
        if (!o) return resolve({ ok: true, ptr: p.toString(), className: String(stanza.$className || ""), selector: sel, type: typeof v, text: String(v).slice(0, lim) });
        try {
          const NSData = ObjC.classes.NSData;
          if (NSData && o.isKindOfClass_ && o.isKindOfClass_(NSData) && objcHasSelector(o, "base64EncodedStringWithOptions:")) {
            const b64 = o.base64EncodedStringWithOptions_(0);
            const s = b64 ? String(b64) : "";
            return resolve({ ok: true, ptr: p.toString(), className: String(stanza.$className || ""), selector: sel, type: "NSData.base64", text: s.slice(0, lim) });
          }
        } catch (_) {}
        let s = "";
        try { s = String(o); } catch (_) { s = ""; }
        return resolve({ ok: true, ptr: p.toString(), className: String(stanza.$className || ""), selector: sel, type: String(o.$className || ""), text: s ? s.slice(0, lim) : "" });
      } catch (e) {
        resolve({ ok: false, ptr: p.toString(), error: String(e), selector: sel });
      }
    });
  });
}

function likeProbeStanzaCall1ArgLast(selName, argStr, maxChars) {
  const last = LIKE_PROBE && LIKE_PROBE.last ? LIKE_PROBE.last : null;
  if (!last) return Promise.resolve({ ok: false, error: "no like_probe last" });
  const p = String(LIKE_PROBE.retainedPtr || last.stanzaPtr || "").trim();
  if (!p || p === "0x0") return Promise.resolve({ ok: false, error: "missing stanza ptr" });
  return likeProbeStanzaCall1Arg(p, selName, argStr, maxChars);
}

function likeStanzaDumpLast() {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const last = LIKE_PROBE && LIKE_PROBE.last ? LIKE_PROBE.last : null;
  if (!last) return Promise.resolve({ ok: false, error: "no like_probe last" });
  const p = String(LIKE_PROBE.retainedPtr || last.stanzaPtr || "").trim();
  if (!p || p === "0x0") return Promise.resolve({ ok: false, error: "missing stanza ptr" });
  const pp = ptr(p);
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      try {
        const stanza = new ObjC.Object(pp);
        const out = { ok: true, ptr: pp.toString(), className: String(stanza.$className || ""), desc: String(LIKE_PROBE.lastText || ""), isReaction: null };
        try {
          if (objcHasSelector(stanza, "isReaction")) {
            const r = stanza.isReaction();
            out.isReaction = (r === 1 || r === true || String(r) === "1");
          }
        } catch (_) { out.isReaction = null; }
        resolve(out);
      } catch (e) {
        resolve({ ok: false, error: String(e), ptr: pp.toString() });
      }
    });
  });
}

function _likeBuildOn() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (LIKE_BUILD.installed) return { ok: true, installed: true, hooks: LIKE_BUILD._hs.length };
  LIKE_BUILD.err = "";
  LIKE_BUILD._hs = [];
  try {
    const cls = ObjC.classes.XMPPMessageStanza;
    if (!cls) return { ok: false, error: "XMPPMessageStanza missing" };
    let waBase = null;
    try { waBase = Process.getModuleByName("WhatsApp").base; } catch (_) { waBase = null; }
    const reentry = {};
    let objcRetain = null;
    let objcRelease = null;
    try {
      const pRet = Module.findExportByName(null, "objc_retain");
      const pRel = Module.findExportByName(null, "objc_release");
      if (pRet) objcRetain = new NativeFunction(pRet, "pointer", ["pointer"]);
      if (pRel) objcRelease = new NativeFunction(pRel, "void", ["pointer"]);
    } catch (_) { objcRetain = null; objcRelease = null; }

    const sels = [
      "- setAttributeWithName:value:",
      "- setAttributeWithName:value:sanitize:",
      "- setStringValue:sanitize:",
      "- setDataValue:",
      "- setElementValue:",
      "- setToRemoteJID:",
      "- setFromRemoteJID:",
      "- setParticipant:",
      "- setParticipantValue:",
      "- setToAttributeValue:",
      "- setFromAttributeValue:",
      "- setUniqueIdentifier:",
      "- setServerID:",
      "- setType:",
    ];
    for (let i = 0; i < sels.length; i++) {
      const sel = sels[i];
      const m = cls[sel];
      if (!m || !m.implementation) continue;
      const h = Interceptor.attach(m.implementation, {
        onEnter(args) {
          try {
            const now = nowMs();
            if (!LIKE_BUILD.armedUntilMs || now > LIKE_BUILD.armedUntilMs) return;
            const tid = Process.getCurrentThreadId();
            if (reentry[tid]) return;
            reentry[tid] = 1;
            if (LIKE_BUILD.events.length >= LIKE_BUILD.maxEvents) return;
            const ra = ptr(this.returnAddress);
            let callerIda = "0x0";
            let callerModule = "";
            let callerOff = "0x0";
            try {
              const m0 = Process.findModuleByAddress(ra);
              if (m0) {
                callerModule = String(m0.name || "");
                callerOff = ra.sub(ptr(m0.base)).toString();
                callerIda = idaBase.add(ptr(callerOff)).toString();
              }
            } catch (_) { callerIda = "0x0"; callerModule = ""; callerOff = "0x0"; }
            const selfP = ptr(args[0]).toString();
            const a2P = ptr(args[2]).toString();
            const a3P = ptr(args[3]).toString();
            const a4P = ptr(args[4]).toString();
            const retainIfObj = (pstr) => {
              try {
                if (!objcRetain) return "0x0";
                const pp = ptr(String(pstr || "0x0"));
                if (pp.isNull()) return "0x0";
                if (pp.compare(ptr("0x10000")) < 0) return "0x0";
                let isa = null;
                try { isa = Memory.readPointer(pp); } catch (_) { isa = null; }
                if (!isa) return "0x0";
                try { if (!Process.findModuleByAddress(isa)) return "0x0"; } catch (_) { return "0x0"; }
                const rp = objcRetain(pp);
                if (!rp || ptr(rp).isNull()) return "0x0";
                const rs = ptr(rp).toString();
                LIKE_BUILD.retained.push(rs);
                return rs;
              } catch (_) {
                return "0x0";
              }
            };
            const ev = {
              ts: now,
              selector: sel.replace(/^\s*[-+]\s*/g, ""),
              callerIda: callerIda,
              callerModule: callerModule,
              callerOff: callerOff,
              selfPtr: selfP,
              a2Ptr: a2P,
              a3Ptr: a3P,
              a4Ptr: a4P,
              a2Class: "",
              a3Class: "",
              a4Class: "",
              name: "",
              a2Ret: retainIfObj(a2P),
              a3Ret: retainIfObj(a3P),
              a4Ret: retainIfObj(a4P),
            };
            LIKE_BUILD.events.push(ev);
            LIKE_BUILD.last = ev;
          } catch (_) {
          } finally {
            try {
              const tid = Process.getCurrentThreadId();
              if (reentry[tid]) delete reentry[tid];
            } catch (_) {}
          }
        }
      });
      LIKE_BUILD._hs.push(h);
    }
    LIKE_BUILD.installed = true;
    return { ok: true, installed: true, hooks: LIKE_BUILD._hs.length };
  } catch (e) {
    LIKE_BUILD.err = String(e);
    return { ok: false, error: LIKE_BUILD.err };
  }
}

function likeBuildArm(ms) {
  const dur = Math.max(1000, Math.min(60000, Number(ms || 15000) | 0));
  const on = _likeBuildOn();
  if (!on.ok) return on;
  try {
    const pRel = Module.findExportByName(null, "objc_release");
    if (pRel && LIKE_BUILD.retained && LIKE_BUILD.retained.length) {
      const objcRelease = new NativeFunction(pRel, "void", ["pointer"]);
      for (let i = 0; i < LIKE_BUILD.retained.length; i++) {
        try {
          const rp = ptr(String(LIKE_BUILD.retained[i] || "0x0"));
          if (rp && !rp.isNull()) objcRelease(rp);
        } catch (_) {}
      }
    }
  } catch (_) {}
  LIKE_BUILD.retained = [];
  LIKE_BUILD.events = [];
  LIKE_BUILD.last = null;
  LIKE_BUILD.templateStanzaPtr = String(LIKE_PROBE.retainedPtr || "0x0");
  LIKE_BUILD.armedUntilMs = nowMs() + dur;
  return { ok: true, armedUntilMs: LIKE_BUILD.armedUntilMs, ms: dur, hooks: on.hooks || 0 };
}

function likeBuildGet(maxEvents) {
  const lim = Math.max(1, Math.min(LIKE_BUILD.maxEvents, Number(maxEvents || 120) | 0));
  const xs = (LIKE_BUILD.events || []).slice(Math.max(0, LIKE_BUILD.events.length - lim));
  const lastProbe = LIKE_PROBE && LIKE_PROBE.last ? LIKE_PROBE.last : null;
  const stanzaPtr = String(LIKE_PROBE.retainedPtr || (lastProbe ? lastProbe.stanzaPtr : "") || "").trim();
  const filtered = stanzaPtr ? xs.filter(e => String(e.selfPtr || "") === stanzaPtr) : xs;
  return {
    ok: true,
    installed: LIKE_BUILD.installed,
    armedUntilMs: LIKE_BUILD.armedUntilMs || 0,
    stanzaPtr: stanzaPtr || "",
    templateStanzaPtr: String(LIKE_BUILD.templateStanzaPtr || ""),
    retainedCount: (LIKE_BUILD.retained || []).length,
    count: filtered.length,
    events: filtered
  };
}

function likeBuildExtract(maxEvents) {
  const lim = Math.max(1, Math.min(LIKE_BUILD.maxEvents, Number(maxEvents || 120) | 0));
  const xs = (LIKE_BUILD.events || []).slice(Math.max(0, LIKE_BUILD.events.length - lim));
  const lastProbe = LIKE_PROBE && LIKE_PROBE.last ? LIKE_PROBE.last : null;
  const stanzaPtr = String(LIKE_PROBE.retainedPtr || (lastProbe ? lastProbe.stanzaPtr : "") || "").trim();
  const filtered = stanzaPtr ? xs.filter(e => String(e.selfPtr || "") === stanzaPtr) : xs;
  const take = [];
  for (let i = 0; i < filtered.length; i++) {
    const ev = filtered[i];
    const sel = String(ev.selector || "");
    if (!sel) continue;
    if (sel === "setAttributeWithName:value:" || sel === "setAttributeWithName:value:sanitize:" || sel === "setStringValue:sanitize:" || sel === "setDataValue:" || sel === "setElementValue:" || sel === "setToAttributeValue:" || sel === "setFromAttributeValue:" || sel === "setParticipantValue:" || sel === "setParticipant:" || sel === "setType:" || sel === "setUniqueIdentifier:" || sel === "setServerID:") {
      const a2 = String(ev.a2Ret && ev.a2Ret !== "0x0" ? ev.a2Ret : ev.a2Ptr);
      const a3 = String(ev.a3Ret && ev.a3Ret !== "0x0" ? ev.a3Ret : ev.a3Ptr);
      const a4 = String(ev.a4Ret && ev.a4Ret !== "0x0" ? ev.a4Ret : ev.a4Ptr);
      take.push({
        i: i,
        selector: sel,
        callerIda: String(ev.callerIda || ""),
        callerModule: String(ev.callerModule || ""),
        callerOff: String(ev.callerOff || ""),
        a2Ptr: a2,
        a3Ptr: a3,
        a4Ptr: a4,
        a2Class: String(ev.a2Class || ""),
        a3Class: String(ev.a3Class || ""),
        a4Class: String(ev.a4Class || ""),
        name: String(ev.name || "")
      });
    }
  }
  return { ok: true, stanzaPtr: stanzaPtr || "", count: take.length, events: take };
}

function likeBuildOff() {
  try {
    const hs = LIKE_BUILD._hs || [];
    for (let i = 0; i < hs.length; i++) { try { hs[i].detach(); } catch (_) {} }
  } catch (_) {}
  try {
    const pRel = Module.findExportByName(null, "objc_release");
    if (pRel && LIKE_BUILD.retained && LIKE_BUILD.retained.length) {
      const objcRelease = new NativeFunction(pRel, "void", ["pointer"]);
      for (let i = 0; i < LIKE_BUILD.retained.length; i++) {
        try {
          const rp = ptr(String(LIKE_BUILD.retained[i] || "0x0"));
          if (rp && !rp.isNull()) objcRelease(rp);
        } catch (_) {}
      }
    }
  } catch (_) {}
  LIKE_BUILD.retained = [];
  LIKE_BUILD._hs = [];
  LIKE_BUILD.installed = false;
  LIKE_BUILD.armedUntilMs = 0;
  LIKE_BUILD.events = [];
  LIKE_BUILD.last = null;
  LIKE_BUILD.templateStanzaPtr = "0x0";
  return { ok: true };
}

function _objcCallNoArgNSStringText(obj, selName, maxChars) {
  try {
    const o = obj instanceof ObjC.Object ? obj : (obj ? new ObjC.Object(obj) : null);
    if (!o) return "";
    const v = objcCallNoArg(o, selName);
    if (v === null || v === undefined) return "";
    if (typeof v === "string") return String(v).slice(0, Math.max(0, Number(maxChars || 2000) | 0));
    const vv = v instanceof ObjC.Object ? v : _safeObj(v);
    if (!vv) return "";
    const NSString = ObjC.classes.NSString;
    if (NSString && vv.isKindOfClass_ && vv.isKindOfClass_(NSString)) {
      const s = String(vv);
      if (!s) return "";
      const lim = Math.max(0, Number(maxChars || 2000) | 0);
      return lim ? s.slice(0, lim) : s;
    }
    return "";
  } catch (_) {
    return "";
  }
}

function likeProbeStanzaSummary(ptrStr, maxChars) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const p = ptr(String(ptrStr || "").trim() || "0x0");
  if (p.isNull()) return Promise.resolve({ ok: false, error: "null ptr" });
  const lim = Math.max(200, Math.min(8000, Number(maxChars || 2000) | 0));
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      try {
        const stanza = new ObjC.Object(p);
        const cn = String(stanza.$className || "");
        const candidates = ["stringRepresentation", "compactXMLString", "prettyXMLString", "xmlString", "XMLString", "debugDescription", "description"];
        let text = "";
        let used = "";
        for (let i = 0; i < candidates.length; i++) {
          const s = candidates[i];
          if (!objcHasSelector(stanza, s)) continue;
          const t = _objcCallNoArgNSStringText(stanza, s, lim);
          if (t) { text = t; used = s; break; }
        }
        const hint = (function () {
          const low = String(text || "").toLowerCase();
          if (!low) return "";
          if (low.indexOf("reaction") !== -1) return "reaction";
          if (low.indexOf("like") !== -1) return "like";
          if (low.indexOf("status") !== -1) return "status";
          return "";
        })();
        resolve({ ok: true, ptr: p.toString(), className: cn, used, hint, text });
      } catch (e) {
        resolve({ ok: false, ptr: p.toString(), error: String(e) });
      }
    });
  });
}

function likeProbeStanzaLast(maxChars) {
  const last = LIKE_PROBE && LIKE_PROBE.last ? LIKE_PROBE.last : null;
  if (!last) return Promise.resolve({ ok: false, error: "no like_probe last" });
  if (LIKE_PROBE.lastText) return Promise.resolve({ ok: true, mode: "cached_text", text: String(LIKE_PROBE.lastText || ""), ptr: String(LIKE_PROBE.retainedPtr || last.stanzaPtr || "0x0") });
  const p = String(LIKE_PROBE.retainedPtr || last.stanzaPtr || "").trim();
  if (!p || p === "0x0") return Promise.resolve({ ok: false, error: "missing stanza ptr" });
  return likeProbeStanzaSummary(p, maxChars);
}

function statusLikeCapture() {
  const last = SEND_PROBE && SEND_PROBE.last ? SEND_PROBE.last : null;
  if (!last) {
    const lx = STATUS_LIKE.lastXMPP || (LIKE_PROBE && LIKE_PROBE.last ? LIKE_PROBE.last : null);
    if (lx) return { ok: true, mode: "xmpp", template: null, lastXMPP: lx };
    return { ok: false, error: "no send_probe last (run statuslikearm then tap Like in UI)" };
  }
  const csPtr = String(last.a7Ptr || "").trim();
  if (!csPtr || csPtr === "0x0") return { ok: false, error: "missing inChatSession ptr" };
  STATUS_LIKE.template = {
    ts: nowMs(),
    selector: String(last.selector || "").trim(),
    messageOriginPtr: String(last.a5Ptr || "").trim(),
    creationEntryPointPtr: String(last.a6Ptr || "").trim(),
    inChatSessionPtr: csPtr,
    callerIda: String(last.callerIda || "").trim(),
  };
  return { ok: true, template: STATUS_LIKE.template };
}

function statusLikeArm(ms) {
  const dur = Math.max(1000, Math.min(60000, Number(ms || 15000) | 0));
  STATUS_LIKE.template = null;
  STATUS_LIKE.armedUntilMs = nowMs() + dur;
  STATUS_LIKE.lastXMPP = null;
  return { ok: true, armedUntilMs: STATUS_LIKE.armedUntilMs, ms: dur };
}

function _asBoolFromPtrText(p) {
  try {
    const s = String(p || "").trim().toLowerCase();
    if (!s || s === "0x0") return false;
    if (s === "0x1") return true;
    const n = _parseHexPtrToInt(s, 0);
    return !!n;
  } catch (_) {
    return false;
  }
}

function _u64FromPtrText(p) {
  try {
    const s = String(p || "").trim().toLowerCase();
    if (!s) return uint64(0);
    if (s.startsWith("0x")) return uint64(s);
    const n = Number(s);
    if (!Number.isFinite(n)) return uint64(0);
    return uint64(n);
  } catch (_) {
    return uint64(0);
  }
}

function _callSenderLongTextSend(senderObj, selectorNoDash, args) {
  try {
    const sender = senderObj instanceof ObjC.Object ? senderObj : _safeObj(senderObj);
    if (!sender) return { ok: false, error: "sender missing" };
    const sel = "- " + String(selectorNoDash || "").trim();
    const fn = sender[sel];
    if (!fn || !fn.implementation) return { ok: false, error: "selector missing", selector: sel };
    fn.apply(sender, args);
    return { ok: true, used: String(selectorNoDash || "").trim() };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _makeWAJIDFromStringExplore(jidStr) {
  try {
    const s = String(jidStr || "").trim();
    if (!s) return null;
    const ns = nsString(s);
    if (!ns) return null;
    const C = ObjC.classes.WAJID;
    if (C && C["+ withString:"] && typeof C["+ withString:"] === "function") {
      try {
        const v = C["+ withString:"](ns);
        if (v) return v;
      } catch (_) {}
    }
    try {
      const u = _makeAuthorUserJIDFromString(s);
      if (u) return u;
    } catch (_) {}
    try {
      const c = _makeWAChatJIDFromString(s);
      if (c) return c;
    } catch (_) {}
    return null;
  } catch (_) {
    return null;
  }
}

function _makeWAMessageIDForReactionExplore(stanzaIdStr, chatJidObj, participantJidObj) {
  try {
    const sid = String(stanzaIdStr || "").trim();
    if (!sid) return null;
    const nsSid = nsString(sid);
    if (!nsSid) return null;
    const midCls = ObjC.classes.WAMessageID;
    const tryInitOnClass = (C, methodKey, callFn) => {
      try {
        if (!C) return null;
        if (!C[methodKey] || typeof C[methodKey] !== "function") return null;
        const v = callFn(C);
        return v ? (v instanceof ObjC.Object ? v : new ObjC.Object(v)) : null;
      } catch (_) {
        return null;
      }
    };

    if (midCls) {
      const initSel = "- initWithStanzaID:chatJID:participantJID:";
      const o0 = tryInitOnClass(midCls, initSel, (C) => C.alloc().initWithStanzaID_chatJID_participantJID_(nsSid, chatJidObj, participantJidObj));
      if (o0) return o0;
      const o1 = tryInitOnClass(midCls, initSel, (C) => C.alloc().initWithStanzaID_chatJID_participantJID_(nsSid, chatJidObj, null));
      if (o1) return o1;
    }

    return null;
  } catch (_) {
    return null;
  }
}

function _debugMakeWAMessageIDForReactionExplore(stanzaIdStr, chatJidObj, participantJidObj) {
  const out = { ok: false, sid: String(stanzaIdStr || "").trim(), hasClass: false, hasInit: false, allocOk: false, initErr0: "", initErr1: "", midClassName: "", midPtr: "" };
  try {
    if (!objcAvailable()) { out.initErr0 = "objc_unavailable"; return out; }
    if (!out.sid) { out.initErr0 = "missing stanzaId"; return out; }
    const nsSid = nsString(out.sid);
    if (!nsSid) { out.initErr0 = "stanzaId->NSString failed"; return out; }
    const midCls = ObjC.classes.WAMessageID;
    if (!midCls) { out.initErr0 = "WAMessageID missing"; return out; }
    out.hasClass = true;
    const initSel = "- initWithStanzaID:chatJID:participantJID:";
    out.hasInit = !!(midCls[initSel] && typeof midCls[initSel] === "function");
    if (!out.hasInit) { out.initErr0 = "init selector missing"; }
    let a = null;
    try { if (out.hasInit) { a = midCls.alloc(); out.allocOk = !!a; } } catch (e) { out.initErr0 = out.initErr0 || String(e); a = null; }
    if (a && out.hasInit) {
      try {
        const o0 = a.initWithStanzaID_chatJID_participantJID_(nsSid, chatJidObj, participantJidObj);
        if (o0) {
          const o = o0 instanceof ObjC.Object ? o0 : new ObjC.Object(o0);
          out.ok = true;
          out.midClassName = String(o.$className || "");
          out.midPtr = ptr(o).toString();
          return out;
        }
      } catch (e0) { out.initErr0 = out.initErr0 || String(e0); }
      try {
        const o1 = midCls.alloc().initWithStanzaID_chatJID_participantJID_(nsSid, chatJidObj, null);
        if (o1) {
          const o = o1 instanceof ObjC.Object ? o1 : new ObjC.Object(o1);
          out.ok = true;
          out.midClassName = String(o.$className || "");
          out.midPtr = ptr(o).toString();
          return out;
        }
      } catch (e1) { out.initErr1 = String(e1); }
    }
    return out;
  } catch (e) {
    out.initErr0 = String(e);
    return out;
  }
}

function _makeWAMessageIDForStatusExplore(stanzaIdStr, authorJidStr) {
  try {
    const sid = String(stanzaIdStr || "").trim();
    if (!sid) return null;
    const statusChatJid = _makeWAChatJIDFromString("status@broadcast");
    if (!statusChatJid) return null;
    const author = String(authorJidStr || "").trim();
    const pu = author ? _makeAuthorUserJIDFromString(author) : null;
    const pj = author ? _makeWAJIDFromStringExplore(author) : null;
    const mid = pu ? _makeWAMessageIDForReactionExplore(sid, statusChatJid, pu) : (pj ? _makeWAMessageIDForReactionExplore(sid, statusChatJid, pj) : _makeWAMessageIDForReactionExplore(sid, statusChatJid, null));
    return mid;
  } catch (_) {
    return null;
  }
}

function _genUniqueStanzaIDExplore() {
  try {
    const cls = ObjC.classes.XMPPConnectionMain;
    if (!cls) return "";
    const cands = ["sharedInstance", "shared", "main", "mainInstance", "defaultInstance", "defaultConnection", "sharedConnection", "connectionMain"];
    let inst = null;
    for (let i = 0; i < cands.length; i++) {
      const s = cands[i];
      if (!objcHasSelector(cls, s)) continue;
      const x = objcCallClassNoArg(cls, s);
      if (x) { inst = x; break; }
    }
    if (!inst) return "";
    const o = inst instanceof ObjC.Object ? inst : new ObjC.Object(inst);
    if (!objcHasSelector(o, "uniqueStanzaID")) return "";
    const v = objcCallNoArgString(o, "uniqueStanzaID");
    return String(v || "").trim();
  } catch (_) {
    return "";
  }
}

function _resolveManagedObjectContextExplore(core) {
  try {
    const isMOC = (o) => {
      try {
        if (!o) return false;
        const obj = o instanceof ObjC.Object ? o : new ObjC.Object(o);
        const cn = String(obj.$className || "");
        if (cn.indexOf("NSManagedObjectContext") !== -1) return true;
        if (objcHasSelector(obj, "executeFetchRequest:error:")) return true;
        if (objcHasSelector(obj, "performBlock:")) return true;
        return false;
      } catch (_) {
        return false;
      }
    };
    const pickFrom = (o, sels) => {
      try {
        if (!o) return null;
        const obj = o instanceof ObjC.Object ? o : new ObjC.Object(o);
        for (let i = 0; i < sels.length; i++) {
          const s = sels[i];
          if (!objcHasSelector(obj, s)) continue;
          const v = objcCallNoArg(obj, s);
          if (!v) continue;
          const out = v instanceof ObjC.Object ? v : new ObjC.Object(v);
          if (isMOC(out)) return out;
        }
      } catch (_) {}
      return null;
    };
    const cands = ["managedObjectContext", "mainManagedObjectContext", "mainQueueContext", "viewContext", "context"];
    const v1 = pickFrom(core && core.ctxMain ? core.ctxMain : null, cands);
    if (v1) return { ok: true, moc: v1, source: "ctxMain.selector" };
    const v2 = pickFrom(core && core.storage ? core.storage : null, cands);
    if (v2) return { ok: true, moc: v2, source: "chatStorage.selector" };

    try {
      const ctx = core && core.ctxMain ? core.ctxMain : null;
      const v = ctx ? _getIvarLike(ctx, ["managedobjectcontext", "mainqueuecontext", "viewcontext", "context", "moc"]) : null;
      if (v) {
        const out = v instanceof ObjC.Object ? v : new ObjC.Object(v);
        if (isMOC(out)) return { ok: true, moc: out, source: "ctxMain.ivars" };
      }
    } catch (_) {}
    try {
      const st = core && core.storage ? core.storage : null;
      const v = st ? _getIvarLike(st, ["managedobjectcontext", "mainqueuecontext", "viewcontext", "context", "moc"]) : null;
      if (v) {
        const out = v instanceof ObjC.Object ? v : new ObjC.Object(v);
        if (isMOC(out)) return { ok: true, moc: out, source: "chatStorage.ivars" };
      }
    } catch (_) {}

    return { ok: false, error: "managedObjectContext not found" };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _deriveUserJIDFromStatusMessageExplore(msgObj) {
  try {
    const msg = msgObj instanceof ObjC.Object ? msgObj : (msgObj ? new ObjC.Object(msgObj) : null);
    if (!msg) return { ok: false, error: "msg nil" };
    const sels = ["participantUserJID", "authorUserJID", "participantJID", "authorJID"];
    for (let i = 0; i < sels.length; i++) {
      const s = sels[i];
      if (!objcHasSelector(msg, s)) continue;
      try {
        const v = objcCallNoArg(msg, s);
        if (!v) continue;
        const o = v instanceof ObjC.Object ? v : new ObjC.Object(v);
        return { ok: true, jidObj: o, source: "msg." + s, desc: _safeDesc(o) };
      } catch (_) {}
    }
    return { ok: false, error: "no participant/author jid on message" };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _resolveStatusModelProviderExplore(core) {
  try {
    const ctx = core && core.ctxMain ? (core.ctxMain instanceof ObjC.Object ? core.ctxMain : new ObjC.Object(core.ctxMain)) : null;
    if (!ctx) return { ok: false, error: "ctxMain nil" };
    let p = null;
    let source = "";
    const readPtrAtOffset = (obj, off) => {
      try {
        if (!obj) return null;
        const o = obj instanceof ObjC.Object ? obj : new ObjC.Object(obj);
        const base = ptr(o);
        const p = Memory.readPointer(base.add(off));
        if (!p || p.isNull()) return null;
        try { return new ObjC.Object(p); } catch (_) { return p; }
      } catch (_) {
        return null;
      }
    };
    const pickProviderFromObj = (obj, src) => {
      try {
        if (!obj) return null;
        const o = obj instanceof ObjC.Object ? obj : new ObjC.Object(obj);
        if (objcHasSelector(o, "getStatusModelFor:")) return { ok: true, provider: o, source: src, className: String(o.$className || "") };
        try {
          const cn = String(o.$className || "");
          if (cn === "WAStatusStorage.StatusModelFetcher") {
            const v = readPtrAtOffset(o, 0x28);
            const r = v ? pickProviderFromObj(v, src + ".off0x28") : null;
            if (r) return r;
          }
          if (cn === "WAStatusStorage.StatusMessageItemFetcher") {
            const v = readPtrAtOffset(o, 0x38);
            const r = v ? pickProviderFromObj(v, src + ".off0x38") : null;
            if (r) return r;
          }
          if (cn === "WAStatusStorage.StatusMessageItemWriter") {
            const v = readPtrAtOffset(o, 0x10);
            const r = v ? pickProviderFromObj(v, src + ".off0x10") : null;
            if (r) return r;
          }
          if (cn === "WAStatusStorage.WAStatusDatabaseValidationManager") {
            const v = readPtrAtOffset(o, 0x30);
            const r = v ? pickProviderFromObj(v, src + ".off0x30") : null;
            if (r) return r;
          }
        } catch (_) {}
        const iv = _getIvarLike(o, ["statusmodelprovider", "modelprovider", "statusprovider"]);
        if (iv) {
          const io = iv instanceof ObjC.Object ? iv : new ObjC.Object(iv);
          if (objcHasSelector(io, "getStatusModelFor:")) return { ok: true, provider: io, source: src + ".$ivars", className: String(io.$className || "") };
        }
        if (objcHasSelector(o, "statusModelProvider")) {
          try {
            const v = objcCallNoArg(o, "statusModelProvider");
            if (v) {
              const vp = v instanceof ObjC.Object ? v : new ObjC.Object(v);
              if (objcHasSelector(vp, "getStatusModelFor:")) return { ok: true, provider: vp, source: src + ".statusModelProvider", className: String(vp.$className || "") };
            }
          } catch (_) {}
        }
      } catch (_) {}
      return null;
    };

    const tryCtxGetter = () => {
      try {
        if (objcHasSelector(ctx, "statusModelProvider")) {
          const v = objcCallNoArg(ctx, "statusModelProvider");
          if (v) return pickProviderFromObj(v, "ctxMain.statusModelProvider");
        }
      } catch (_) {}
      return null;
    };
    const direct = tryCtxGetter();
    if (direct) return direct;

    const isInterestingKey = (k) => {
      const s = String(k || "").toLowerCase();
      if (!s) return false;
      return s.indexOf("status") !== -1 || s.indexOf("model") !== -1 || s.indexOf("provider") !== -1;
    };
    const safeObjMeta = (v) => {
      try {
        if (!v) return null;
        const o = v instanceof ObjC.Object ? v : new ObjC.Object(v);
        return { ptr: ptr(o).toString(), className: String(o.$className || ""), desc: _safeDesc(o) };
      } catch (_) {
        return null;
      }
    };
    const deepScan = (rootObj, src, maxDepth) => {
      const seen = {};
      const queue = [{ obj: rootObj, src, depth: 0 }];
      const scanned = [];
      const capNodes = 60;
      const capKeys = 40;
      while (queue.length) {
        const it = queue.shift();
        if (!it || !it.obj) continue;
        let o = null;
        try { o = it.obj instanceof ObjC.Object ? it.obj : new ObjC.Object(it.obj); } catch (_) { o = null; }
        if (!o) continue;
        const ptxt = ptr(o).toString();
        if (seen[ptxt]) continue;
        seen[ptxt] = 1;

        const direct = pickProviderFromObj(o, it.src);
        if (direct) return { ok: true, found: direct, scanned };

        if (it.depth >= maxDepth) continue;
        let ivs = null;
        try { ivs = o.$ivars || {}; } catch (_) { ivs = {}; }
        const keys = Object.keys(ivs || {});
        const interesting = [];
        for (let i = 0; i < keys.length && interesting.length < capKeys; i++) {
          const k = String(keys[i] || "");
          if (!k) continue;
          if (!isInterestingKey(k)) continue;
          interesting.push(k);
        }
        const keyDebug = [];
        for (let i = 0; i < interesting.length; i++) {
          const k = interesting[i];
          const kl = k.toLowerCase();
          if (kl.indexOf("provider") === -1 && kl.indexOf("model") === -1) continue;
          try {
            const v = ivs[k];
            const meta = safeObjMeta(v);
            keyDebug.push({ k, ok: !!v, meta });
          } catch (e) {
            keyDebug.push({ k, ok: false, error: String(e) });
          }
          if (keyDebug.length >= 10) break;
        }
        scanned.push({
          source: it.src,
          depth: it.depth,
          self: safeObjMeta(o),
          keys: interesting,
          flags: { hasGetStatusModelFor: objcHasSelector(o, "getStatusModelFor:"), hasStatusModelProviderSel: objcHasSelector(o, "statusModelProvider") },
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
    };

    const rCtx = deepScan(ctx, "ctxMain", 3);
    if (rCtx && rCtx.ok && rCtx.found) return rCtx.found;
    let rSt = null;
    try {
      const st = core && core.storage ? (core.storage instanceof ObjC.Object ? core.storage : new ObjC.Object(core.storage)) : null;
      if (st) rSt = deepScan(st, "chatStorage", 3);
      if (rSt && rSt.ok && rSt.found) return rSt.found;
    } catch (_) { rSt = null; }

    return {
      ok: false,
      error: "statusModelProvider not found",
      details: {
        ctxMain: rCtx && !rCtx.ok ? rCtx : null,
        chatStorage: rSt && !rSt.ok ? rSt : null
      }
    };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _fetchStatusMessageViaStatusModelExplore(core, statusIdStr, authorJidStr) {
  try {
    const sid = String(statusIdStr || "").trim();
    if (!sid) return { ok: false, error: "missing statusId" };
    const provRes = _resolveStatusModelProviderExplore(core);
    if (!provRes || !provRes.ok) return { ok: false, error: provRes ? provRes.error : "statusModelProvider failed", provider: provRes || null };
    const nsId = nsString(sid);
    if (!nsId) return { ok: false, error: "statusId->NSString failed" };
    let sm = null;
    try {
      const p = provRes.provider;
      if (p && p["+ getStatusModelFor:"] && typeof p["+ getStatusModelFor:"] === "function") sm = p["+ getStatusModelFor:"](nsId);
      else if (p && p["- getStatusModelFor:"] && typeof p["- getStatusModelFor:"] === "function") sm = p["- getStatusModelFor:"](nsId);
      else if (p && p.getStatusModelFor_ && typeof p.getStatusModelFor_ === "function") sm = p.getStatusModelFor_(nsId);
      else sm = null;
    } catch (_) { sm = null; }
    if (!sm) return { ok: false, error: "getStatusModelFor returned nil", provider: { className: provRes.className, source: provRes.source } };
    const smObj = sm instanceof ObjC.Object ? sm : new ObjC.Object(sm);
    const isWAMessage = (o) => {
      try {
        if (!o) return false;
        const x = o instanceof ObjC.Object ? o : new ObjC.Object(o);
        const cn = String(x.$className || "");
        if (!cn) return false;
        if (cn.indexOf("WAMessageID") !== -1) return false;
        return cn.indexOf("WAMessage") !== -1;
      } catch (_) { return false; }
    };
    const tryNoArg = (o, sel) => {
      try {
        if (!o) return null;
        const x = o instanceof ObjC.Object ? o : new ObjC.Object(o);
        if (!objcHasSelector(x, sel)) return null;
        const v = objcCallNoArg(x, sel);
        return v ? (v instanceof ObjC.Object ? v : new ObjC.Object(v)) : null;
      } catch (_) { return null; }
    };
    const midFetch = { tried: false, ok: false, error: "", keyPtr: "", keyClassName: "", midPtr: "", midClassName: "", used: "" };
    const tryCall = (o, sel, args) => {
      try {
        if (!o) return null;
        const x = o instanceof ObjC.Object ? o : new ObjC.Object(o);
        const dash = "- " + String(sel || "").trim();
        if (x[dash] && typeof x[dash] === "function") {
          const v = x[dash].apply(x, args || []);
          return v ? (v instanceof ObjC.Object ? v : new ObjC.Object(v)) : null;
        }
        if (x[sel] && typeof x[sel] === "function") {
          const v = x[sel].apply(x, args || []);
          return v ? (v instanceof ObjC.Object ? v : new ObjC.Object(v)) : null;
        }
      } catch (_) {}
      return null;
    };

    try {
      midFetch.tried = true;
      try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "status_model_fetch", step: "before_statusNotificationMessageKey", sid: sid, ts: nowMs() }; } catch (_) {}
      let keyObj = null;
      let midObjFromIvar = null;
      let midPtrFromIvar = ptr("0x0");
      try {
        const pSelf = ptr(smObj);
        const iv = _listIvarsNoTouch(pSelf.toString(), 260);
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "status_model_fetch", step: "ivars_listed", sid: sid, ok: !!(iv && iv.ok), ts: nowMs() }; } catch (_) {}
        try {
          if (iv && iv.ok && Array.isArray(iv.ivars)) {
            const keep = [];
            for (let i = 0; i < iv.ivars.length; i++) {
              const it = iv.ivars[i];
              const nm = String((it && it.name) ? it.name : "");
              if (!nm) continue;
              if (/(key|message|storage|manager|id)/i.test(nm)) keep.push(it);
              if (keep.length >= 60) break;
            }
            midFetch.ivars = keep;
          }
        } catch (_) {}
        if (iv && iv.ok && Array.isArray(iv.ivars)) {
          const probePtrAtOff = (off) => {
            try {
              const addr = pSelf.add(off | 0);
              if (!_isReadablePtr(addr, Process.pointerSize)) return null;
              const vp = Memory.readPointer(addr);
              if (!vp || vp.isNull()) return { ptr: ptr("0x0"), className: "", ok: false, reason: "nil" };
              let cn = "";
              try { if (_isReadablePtr(vp, Process.pointerSize)) cn = _objcClassNameNoTouch(vp); } catch (_) { cn = ""; }
              let s = "";
              if (cn && (cn.indexOf("String") !== -1 || cn.indexOf("NSString") !== -1)) {
                try {
                  const so = new ObjC.Object(vp);
                  s = String(so);
                  if (s && s.length > 240) s = s.slice(0, 240);
                } catch (_) { s = ""; }
              }
              return { ptr: vp, className: cn, ok: !!cn, reason: cn ? "" : "non_objc_or_unreadable", string: s };
            } catch (_) { return null; }
          };
          try {
            if (midFetch.ivars && Array.isArray(midFetch.ivars)) {
              const probes = [];
              for (let i = 0; i < midFetch.ivars.length && probes.length < 60; i++) {
                const it = midFetch.ivars[i];
                const nm = String((it && it.name) ? it.name : "");
                const off = Number((it && it.off) ? it.off : 0) | 0;
                if (!nm || off <= 0 || off > 0x900) continue;
                const pr = probePtrAtOff(off);
                probes.push({ name: nm, off, ptr: pr ? pr.ptr.toString() : "", className: pr ? String(pr.className || "") : "", ok: pr ? !!pr.ok : false, reason: pr ? String(pr.reason || "") : "", string: pr ? String(pr.string || "") : "" });
              }
              midFetch.ivarsProbe = probes;
            }
          } catch (_) {}
          const pickIvarPtr = (re) => {
            try {
              for (let i = 0; i < iv.ivars.length; i++) {
                const it = iv.ivars[i];
                const nm = String((it && it.name) ? it.name : "");
                const off = Number((it && it.off) ? it.off : 0) | 0;
                if (!nm || off <= 0 || off > 0x900) continue;
                if (!re.test(nm)) continue;
                const pr = probePtrAtOff(off);
                if (!pr || !pr.ok) continue;
                return { name: nm, off, ptr: pr.ptr, className: pr.className };
              }
            } catch (_) {}
            return null;
          };

          const msgHit =
            pickIvarPtr(/^(?:_)?message$/i) ||
            pickIvarPtr(/waMessage/i) ||
            pickIvarPtr(/chatMessage/i);
          if (msgHit && isWAMessage(msgHit.className)) {
            try {
              const mo = new ObjC.Object(msgHit.ptr);
              if (isWAMessage(mo)) {
                return {
                  ok: true,
                  msg: mo,
                  provider: { className: provRes.className, source: provRes.source },
                  statusModel: { className: String(smObj.$className || ""), desc: _safeDesc(smObj) },
                  via: "statusItem.ivarMessage"
                };
              }
            } catch (_) {}
          }

          if (msgHit && !keyObj && !midObjFromIvar && msgHit.className && msgHit.className.indexOf("String") !== -1) {
            let msgText = "";
            try { msgText = String(new ObjC.Object(msgHit.ptr) || ""); } catch (_) { msgText = ""; }
            msgText = String(msgText || "").trim();
            if (msgText) {
              midFetch.msgIvar = msgHit.name;
              midFetch.msgOff = msgHit.off;
              midFetch.msgPtr = msgHit.ptr.toString();
              midFetch.msgClassName = msgHit.className;
              midFetch.msgText = msgText.length > 240 ? msgText.slice(0, 240) : msgText;
              try {
                const mid2 = _makeWAMessageIDForStatusExplore(msgText, authorJidStr);
                if (mid2) {
                  const mocRes2 = _resolveManagedObjectContextExplore(core);
                  const moc2 = (mocRes2 && mocRes2.ok && mocRes2.moc) ? mocRes2.moc : null;
                  const fres2 = _fetchMessageByMessageIDExplore(core.storage, mid2, moc2);
                  if (fres2 && fres2.ok && fres2.msg) {
                    const mo2 = fres2.msg instanceof ObjC.Object ? fres2.msg : new ObjC.Object(fres2.msg);
                    if (isWAMessage(mo2)) {
                      midFetch.ok = true;
                      midFetch.used = String(fres2.used || "");
                      return {
                        ok: true,
                        msg: mo2,
                        provider: { className: provRes.className, source: provRes.source },
                        statusModel: { className: String(smObj.$className || ""), desc: _safeDesc(smObj) },
                        via: "statusItem.messageString->WAMessageID->chatStorage." + String(fres2.used || "")
                      };
                    }
                  }
                }
              } catch (_) {}
            }
          }

          const midHit = pickIvarPtr(/messageid/i);
          if (midHit) {
            midFetch.midIvar = midHit.name;
            midFetch.midOff = midHit.off;
            try {
              midPtrFromIvar = midHit.ptr;
              midFetch.midPtr = midPtrFromIvar.toString();
              midFetch.midClassName = String(midHit.className || "");
              if (midFetch.midClassName.indexOf("WAMessageID") !== -1) {
                try { midObjFromIvar = new ObjC.Object(midPtrFromIvar); } catch (_) { midObjFromIvar = null; }
              }
            } catch (_) { midObjFromIvar = null; }
          }

          if (!midObjFromIvar) {
            const keyHit =
              pickIvarPtr(/statusnotificationmessagekey/i) ||
              pickIvarPtr(/notificationmessagekey/i) ||
              pickIvarPtr(/parsedmessagekey/i) ||
              pickIvarPtr(/messagekey/i);
            if (keyHit) {
              midFetch.keyIvar = keyHit.name;
              midFetch.keyOff = keyHit.off;
              try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "status_model_fetch", step: "read_key_ivar", sid: sid, off: keyHit.off, ts: nowMs() }; } catch (_) {}
              try { keyObj = new ObjC.Object(keyHit.ptr); } catch (_) { keyObj = null; }
            } else {
              midFetch.error = "key/messageID ivar not found";
            }
          }
        } else {
          midFetch.error = "list ivars failed";
        }
      } catch (_) { keyObj = null; }

      if (midObjFromIvar) {
        const mocRes = _resolveManagedObjectContextExplore(core);
        const moc = (mocRes && mocRes.ok && mocRes.moc) ? mocRes.moc : null;
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "status_model_fetch", step: "before_fetchMessageWithMessageID", sid: sid, ts: nowMs() }; } catch (_) {}
        const fres = _fetchMessageByMessageIDExplore(core.storage, midObjFromIvar, moc);
        if (fres && fres.ok && fres.msg) {
          const mo = fres.msg instanceof ObjC.Object ? fres.msg : new ObjC.Object(fres.msg);
          if (isWAMessage(mo)) {
            midFetch.ok = true;
            midFetch.used = String(fres.used || "");
            return {
              ok: true,
              msg: mo,
              provider: { className: provRes.className, source: provRes.source },
              statusModel: { className: String(smObj.$className || ""), desc: _safeDesc(smObj) },
              via: "statusItem.ivarMessageID->chatStorage." + String(fres.used || "")
            };
          }
        } else {
          if (!midFetch.error) midFetch.error = String((fres && fres.error) ? fres.error : "fetchMessageWithMessageID returned nil");
        }
      }

      if (keyObj) {
        midFetch.keyPtr = ptr(keyObj).toString();
        midFetch.keyClassName = String(keyObj.$className || "");
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "status_model_fetch", step: "before_native_sub_10278AD98", sid: sid, ts: nowMs() }; } catch (_) {}
        const midp = _callMessageIDFromParsedMessageKey(ptr(keyObj));
        if (midp && !midp.isNull()) {
          midFetch.midPtr = midp.toString();
          midFetch.midClassName = _objcClassNameNoTouch(midp);
          let midObj = null;
          try { midObj = new ObjC.Object(midp); } catch (_) { midObj = null; }
          if (midObj && midFetch.midClassName.indexOf("WAMessageID") !== -1) {
            try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "status_model_fetch", step: "before_fetchMessageWithMessageID", sid: sid, ts: nowMs() }; } catch (_) {}
            const mocRes = _resolveManagedObjectContextExplore(core);
            const moc = (mocRes && mocRes.ok && mocRes.moc) ? mocRes.moc : null;
            const fres = _fetchMessageByMessageIDExplore(core.storage, midObj, moc);
            if (fres && fres.ok && fres.msg) {
              const mo = fres.msg instanceof ObjC.Object ? fres.msg : new ObjC.Object(fres.msg);
              if (isWAMessage(mo)) {
                midFetch.ok = true;
                midFetch.used = String(fres.used || "");
                return {
                  ok: true,
                  msg: mo,
                  provider: { className: provRes.className, source: provRes.source },
                  statusModel: { className: String(smObj.$className || ""), desc: _safeDesc(smObj) },
                  via: "statusItem.statusNotificationMessageKey->native.sub_10278AD98->chatStorage." + String(fres.used || "")
                };
              }
            } else {
              midFetch.error = String((fres && fres.error) ? fres.error : "fetchMessageWithMessageID returned nil");
            }
          } else if (!midObj) {
            midFetch.error = "midObj build failed";
          } else {
            midFetch.error = "native returned non-WAMessageID";
          }
        } else {
          if (!midFetch.error) midFetch.error = "native sub_10278AD98 returned null";
        }
      } else {
        if (!midFetch.error) midFetch.error = "no key/messageID available";
      }
    } catch (e) {
      midFetch.error = String(e);
    }

    const itemNoArgs = ["waMessage", "wamessage", "message", "chatMessage", "messageObject", "waMessageObject", "baseMessage", "originalMessage"];
    for (let i = 0; i < itemNoArgs.length; i++) {
      const v = tryNoArg(smObj, itemNoArgs[i]);
      if (v && isWAMessage(v)) return { ok: true, msg: v, provider: { className: provRes.className, source: provRes.source }, statusModel: { className: String(smObj.$className || ""), desc: _safeDesc(smObj) }, via: "statusItem." + itemNoArgs[i] };
    }

    const pObj = provRes.provider instanceof ObjC.Object ? provRes.provider : new ObjC.Object(provRes.provider);
    const pSels = [
      "waMessageForStatusMessageItem:",
      "waMessageForStatusMessageItem:context:",
      "messageForStatusMessageItem:",
      "messageForStatusMessageItem:context:",
      "fetchMessageForStatusMessageItem:context:",
      "fetchWAMessageForStatusMessageItem:context:",
      "messageWithStatusMessageItem:context:",
    ];
    for (let i = 0; i < pSels.length; i++) {
      const s = pSels[i];
      if (!objcHasSelector(pObj, s)) continue;
      const argc = String(s).split(":").length - 1;
      const args = argc === 2 ? [smObj, core.ctxMain] : [smObj];
      const v = tryCall(pObj, s, args);
      if (v && isWAMessage(v)) return { ok: true, msg: v, provider: { className: provRes.className, source: provRes.source }, statusModel: { className: String(smObj.$className || ""), desc: _safeDesc(smObj) }, via: "provider." + s };
    }

    const rawMeta = null;

    const statusInfoFetch = { tried: false, error: "disabled_due_to_objc_exception_throw", note: "IDA shows provider takes id arg; need derive correct arg object (not NSString) before calling getStatusInfoModelFor:" };

    const pmeta = { ptr: ptr(pObj).toString(), className: String(provRes.className || ""), source: String(provRes.source || "") };
    const smeta = { ptr: ptr(smObj).toString(), className: String(smObj.$className || ""), desc: _safeDesc(smObj) };
    return { ok: false, error: "status model resolved but WAMessage not resolved", provider: pmeta, statusModel: smeta, rawReturn: rawMeta, midFetch, statusInfoFetch };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _filterMethodsByRegex(objOrClass, regexStr, maxN) {
  try {
    const cap = Math.max(1, Math.min(200, (maxN | 0) || 80));
    const re = regexStr ? new RegExp(String(regexStr), "i") : null;
    const o = objOrClass instanceof ObjC.Object ? objOrClass : (objOrClass ? new ObjC.Object(objOrClass) : null);
    if (!o) return { ok: false, error: "obj nil" };
    const cn = String(o.$className || "");
    const C = o.$class || ObjC.classes[cn];
    let ms = C ? (C.$methods || C.$ownMethods || []) : [];
    const listRuntime = () => {
      try {
        const pObjGetClass = Module.findExportByName("libobjc.A.dylib", "object_getClass") || Module.findExportByName(null, "object_getClass");
        const pClassCopyMethodList = Module.findExportByName("libobjc.A.dylib", "class_copyMethodList") || Module.findExportByName(null, "class_copyMethodList");
        const pMethodGetName = Module.findExportByName("libobjc.A.dylib", "method_getName") || Module.findExportByName(null, "method_getName");
        const pSelGetName = Module.findExportByName("libobjc.A.dylib", "sel_getName") || Module.findExportByName(null, "sel_getName");
        const pFree = Module.findExportByName(null, "free");
        if (!pObjGetClass || !pClassCopyMethodList || !pMethodGetName || !pSelGetName) return [];
        const objGetClass = new NativeFunction(pObjGetClass, "pointer", ["pointer"]);
        const classCopyMethodList = new NativeFunction(pClassCopyMethodList, "pointer", ["pointer", "pointer"]);
        const methodGetName = new NativeFunction(pMethodGetName, "pointer", ["pointer"]);
        const selGetName = new NativeFunction(pSelGetName, "pointer", ["pointer"]);
        const freeFn = pFree ? new NativeFunction(pFree, "void", ["pointer"]) : null;
        const clsPtr = objGetClass(ptr(o));
        if (!clsPtr || clsPtr.isNull()) return [];
        const outCount = Memory.alloc(8);
        Memory.writeU64(outCount, uint64(0));
        const listPtr = classCopyMethodList(clsPtr, outCount);
        const n = Number(Memory.readU64(outCount)) | 0;
        if (!listPtr || listPtr.isNull() || n <= 0) return [];
        const out = [];
        const seen = {};
        for (let i = 0; i < n; i++) {
          const mptr = Memory.readPointer(listPtr.add(i * Process.pointerSize));
          if (!mptr || mptr.isNull()) continue;
          const sel = methodGetName(mptr);
          if (!sel || sel.isNull()) continue;
          const namep = selGetName(sel);
          if (!namep || namep.isNull()) continue;
          let s = "";
          try { s = String(Memory.readCString(namep) || ""); } catch (_) { s = ""; }
          if (!s) continue;
          if (seen[s]) continue;
          seen[s] = 1;
          out.push("- " + s);
          if (out.length >= 500) break;
        }
        try { if (freeFn) freeFn(listPtr); } catch (_) {}
        return out;
      } catch (_) {
        return [];
      }
    };
    if (!ms || !ms.length) ms = listRuntime();
    const out = [];
    for (let i = 0; i < ms.length; i++) {
      const m = String(ms[i] || "");
      if (!m) continue;
      if (re && !re.test(m)) continue;
      out.push(m);
      if (out.length >= cap) break;
    }
    return { ok: true, className: cn, count: out.length, methods: out };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function statuslikeinspect(authorJid, statusStanzaId, regex, maxN) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const author = String(authorJid || "").trim();
  const sid = String(statusStanzaId || "").trim();
  const rx = String(regex || "(WAMessage|wamessage|waMessage|statusMessage|StatusMessage|messageItem|MessageItem|converter|Convert|messageFor|waMessageFor)").trim();
  const cap = Number.isFinite(Number(maxN)) ? (Number(maxN) | 0) : 120;
  if (!sid) return Promise.resolve({ ok: false, error: "missing statusStanzaId" });
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const core = _resolveCoreForSendExplore();
        if (!core || !core.ok) return resolve({ ok: false, error: core ? core.error : "core failed" });
        const r = _fetchStatusMessageViaStatusModelExplore(core, sid, author);
        if (!r || !r.provider || !r.statusModel) return resolve({ ok: false, error: r ? String(r.error || "no provider/statusModel") : "no result", result: r || null });
        const pptr = String(r.provider.ptr || "");
        const sptr = String(r.statusModel.ptr || "");
        let pobj = null;
        let sobj = null;
        try { if (pptr) pobj = new ObjC.Object(ptr(pptr)); } catch (_) { pobj = null; }
        try { if (sptr) sobj = new ObjC.Object(ptr(sptr)); } catch (_) { sobj = null; }
        const pm = pobj ? _filterMethodsByRegex(pobj, rx, cap) : { ok: false, error: "provider ptr invalid" };
        const sm = sobj ? _filterMethodsByRegex(sobj, rx, cap) : { ok: false, error: "statusModel ptr invalid" };
        resolve({ ok: true, tried: { authorJid: author, statusStanzaId: sid }, result: r, providerMethods: pm, statusModelMethods: sm });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function _fetchMessageByMessageIDExplore(storageObj, messageIdObj, mocObj) {
  try {
    const st = storageObj instanceof ObjC.Object ? storageObj : (storageObj ? new ObjC.Object(storageObj) : null);
    const mid = messageIdObj instanceof ObjC.Object ? messageIdObj : (messageIdObj ? new ObjC.Object(messageIdObj) : null);
    const moc = mocObj instanceof ObjC.Object ? mocObj : (mocObj ? new ObjC.Object(mocObj) : null);
    if (!st || !mid) return { ok: false, error: "storage/messageId nil" };

    if (objcHasSelector(st, "fetchMessageWithMessageID:")) {
      try {
        const m = st.fetchMessageWithMessageID_(mid);
        if (m) return { ok: true, msg: m, used: "fetchMessageWithMessageID:" };
      } catch (_) {}
    }
    if (moc && objcHasSelector(st, "fetchMessageWithMessageID:inContext:")) {
      try {
        const m = st.fetchMessageWithMessageID_inContext_(mid, moc);
        if (m) return { ok: true, msg: m, used: "fetchMessageWithMessageID:inContext:" };
      } catch (_) {}
    }
    return { ok: false, error: "fetchMessageWithMessageID returned nil", hasInContext: !!(moc && objcHasSelector(st, "fetchMessageWithMessageID:inContext:")), hasNoContext: objcHasSelector(st, "fetchMessageWithMessageID:") };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _resolveMessagingDataProviderExplore(ctxMain) {
  try {
    if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
    const ctx = ctxMain instanceof ObjC.Object ? ctxMain : _safeObj(ctxMain);
    const trySel = (o, s) => {
      try {
        if (!o) return null;
        if (!objcHasSelector(o, s)) return null;
        const v = objcCallNoArg(o, s);
        return v ? (v instanceof ObjC.Object ? v : new ObjC.Object(v)) : null;
      } catch (_) { return null; }
    };
    const cands = ["messagingDataProvider", "messagingProvider", "dataProvider", "messagingDataProviderForChatStorage", "messagingDataProviderForChat"];
    for (let i = 0; i < cands.length; i++) {
      const v = trySel(ctx, cands[i]);
      if (v) return { ok: true, provider: v, source: "ctxMain." + cands[i] };
    }
    const C = ObjC.classes.WAMessagingDataProvider;
    if (C) {
      const classCands = ["+ sharedInstance", "+ shared", "+ main", "+ defaultProvider"];
      for (let i = 0; i < classCands.length; i++) {
        const s = classCands[i];
        try {
          if (!C[s] || typeof C[s] !== "function") continue;
          const v = C[s]();
          const o = v ? (v instanceof ObjC.Object ? v : new ObjC.Object(v)) : null;
          if (o) return { ok: true, provider: o, source: "WAMessagingDataProvider." + s };
        } catch (_) {}
      }
    }
    return { ok: false, error: "messaging data provider not found" };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function statuslikepure(authorJid, statusStanzaId, emojiCode) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  let author = String(authorJid || "").trim();
  const sid = String(statusStanzaId || "").trim();
  const code = Number.isFinite(Number(emojiCode)) ? (Number(emojiCode) | 0) : null;
  if (!sid) return Promise.resolve({ ok: false, error: "missing statusStanzaId" });
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { installCrashSniffer(); } catch (_) {}
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikepure", step: "begin", sid: sid, author: author, ts: nowMs() }; } catch (_) {}
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const core = _resolveCoreForSendExplore();
        if (!core || !core.ok) return resolve({ ok: false, error: core ? core.error : "core failed" });
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikepure", step: "core_ok", sid: sid, author: author, ts: nowMs() }; } catch (_) {}

        const statusChatJid = _makeWAChatJIDFromString("status@broadcast");
        if (!statusChatJid) return resolve({ ok: false, error: "status@broadcast jid parse failed" });
        const csStatus = _fetchChatSession(core.storage, statusChatJid);
        if (!csStatus) return resolve({ ok: false, error: "fetchChatSession status@broadcast failed" });
        const mcsStatus = _getMutableChatSession(csStatus);
        if (!mcsStatus) return resolve({ ok: false, error: "mutableChatSession status@broadcast failed" });

        const nsSid = nsString(sid);
        if (!nsSid) return resolve({ ok: false, error: "stanzaId->NSString failed" });

        let participantJidObj = author ? _makeAuthorUserJIDFromString(author) : null;
        if (author && !participantJidObj) return resolve({ ok: false, error: "authorUserJID build failed", authorJid: author });

        const hasA = objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:authorJID:");
        const hasAU = objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:authorUserJID:");
        const hasPUF = objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:participantUserJID:isFromMe:");
        const hasPJF = objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:participantJID:isFromMe:");
        const hasPjF = objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:participantJid:isFromMe:");
        const hasPj = objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:participantJid:");
        const hasPJ = objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:participantJID:");

        let targetMsg = null;
        try { targetMsg = _fetchMessageByStanzaId(mcsStatus, sid, author); } catch (_) { targetMsg = null; }
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikepure", step: "after_fetch_by_stanza", sid: sid, author: author, hasTarget: !!targetMsg, ts: nowMs() }; } catch (_) {}

        let ctxFetch = { has: false, tried: false, mocOk: false, mocSource: "", mocClassName: "", hitFromMe: -1, midTried: false, midBuildOk: false, midBuildMode: "", midUsed: "", midOk: false };
        if (!targetMsg) {
          try {
            ctxFetch.has = objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:isFromMe:context:");
            const mocRes = _resolveManagedObjectContextExplore(core);
            ctxFetch.mocOk = !!(mocRes && mocRes.ok && mocRes.moc);
            ctxFetch.mocSource = String((mocRes && mocRes.source) ? mocRes.source : "");
            ctxFetch.mocClassName = String((mocRes && mocRes.moc && mocRes.moc.$className) ? mocRes.moc.$className : "");
            if (ctxFetch.has && mocRes && mocRes.ok && mocRes.moc) {
              ctxFetch.tried = true;
              try {
                const m0 = mcsStatus.fetchMessageWithStanzaID_isFromMe_context_(nsSid, 0, mocRes.moc);
                if (m0) { targetMsg = m0; ctxFetch.hitFromMe = 0; }
              } catch (_) {}
              if (!targetMsg) {
                try {
                  const m1 = mcsStatus.fetchMessageWithStanzaID_isFromMe_context_(nsSid, 1, mocRes.moc);
                  if (m1) { targetMsg = m1; ctxFetch.hitFromMe = 1; }
                } catch (_) {}
              }
            }

            if (!targetMsg && mocRes && mocRes.ok && mocRes.moc) {
              try {
                ctxFetch.midTried = true;
                const pu = author ? _makeAuthorUserJIDFromString(author) : null;
                const pJid = _makeWAJIDFromStringExplore(author);
                let mid = null;
                if (pu) {
                  mid = _makeWAMessageIDForReactionExplore(sid, statusChatJid, pu);
                  ctxFetch.midBuildMode = "authorUserJID";
                } else if (pJid) {
                  mid = _makeWAMessageIDForReactionExplore(sid, statusChatJid, pJid);
                  ctxFetch.midBuildMode = "WAJID";
                } else if (participantJidObj) {
                  mid = _makeWAMessageIDForReactionExplore(sid, statusChatJid, participantJidObj);
                  ctxFetch.midBuildMode = "authorUserJID";
                } else {
                  mid = _makeWAMessageIDForReactionExplore(sid, statusChatJid, null);
                  ctxFetch.midBuildMode = "nil";
                }
                ctxFetch.midBuildOk = !!mid;
                if (!mid) {
                  ctxFetch.midOk = false;
                  ctxFetch.midUsed = "messageID build failed";
                } else {
                  const fres = _fetchMessageByMessageIDExplore(core.storage, mid, mocRes.moc);
                  if (fres && fres.ok && fres.msg) {
                    targetMsg = fres.msg;
                    ctxFetch.midOk = true;
                    ctxFetch.midUsed = String(fres.used || "");
                  } else {
                    ctxFetch.midOk = false;
                    ctxFetch.midUsed = String((fres && fres.error) ? fres.error : "");
                  }
                }
              } catch (_) {}
            }
          } catch (_) {}
        }

        let modelFetch = { tried: false, ok: false, error: "", provider: null, statusModel: null };
        if (!targetMsg) {
          try {
            modelFetch.tried = true;
            try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikepure", step: "before_model_fetch", sid: sid, author: author, ts: nowMs() }; } catch (_) {}
            const r = _fetchStatusMessageViaStatusModelExplore(core, sid, author);
            if (r && r.ok && r.msg) {
              targetMsg = r.msg;
              modelFetch.ok = true;
              modelFetch.provider = r.provider || null;
              modelFetch.statusModel = r.statusModel || null;
              try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikepure", step: "model_fetch_ok", sid: sid, author: author, via: String(r.via || ""), ts: nowMs() }; } catch (_) {}
            } else {
              modelFetch.ok = false;
              modelFetch.error = String((r && r.error) ? r.error : "status model fetch failed");
              modelFetch.provider = r && r.provider ? r.provider : (r && r.provider === null ? null : null);
              modelFetch.statusModel = r && r.statusModel ? r.statusModel : null;
              try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikepure", step: "model_fetch_fail", sid: sid, author: author, err: String(modelFetch.error || ""), ts: nowMs() }; } catch (_) {}
            }
          } catch (e) {
            modelFetch.ok = false;
            modelFetch.error = String(e);
          }
        }

        if (!targetMsg) {
          const pinned = (RX_PINNED && RX_PINNED.last) ? RX_PINNED.last : null;
          return resolve({
            ok: false,
            error: "status target message not found",
            note: "target status message is not available locally (status@broadcast fetch returned nil). Either wait for it to arrive, or use rxpinned to capture the exact WAMessage pointer.",
            tried: { authorJid: author, statusStanzaId: sid },
            ctxFetch,
            modelFetch,
            selectors: { authorJID: hasA, authorUserJID: hasAU, participantUserJID_isFromMe: hasPUF, participantJID_isFromMe: hasPJF, participantJid_isFromMe: hasPjF, participantJid: hasPj, participantJID: hasPJ },
            participant: { className: String((participantJidObj && participantJidObj.$className) ? participantJidObj.$className : ""), desc: _safeDesc(participantJidObj) },
            pinnedLast: pinned ? { stanzaId: String(pinned.stanzaId || ""), statusAuthorJid: String(pinned.statusAuthorJid || ""), chatJid: String(pinned.chatJid || ""), msgPtr: String(pinned.msgPtr || "") } : null,
            hint: "run: rxpinnedon; or ensure the status is present in status@broadcast; then retry statuslikepure"
          });
        }
        const targetMsgObj = targetMsg instanceof ObjC.Object ? targetMsg : new ObjC.Object(targetMsg);

        if (!participantJidObj) {
          const d = _deriveUserJIDFromStatusMessageExplore(targetMsgObj);
          if (d && d.ok && d.jidObj) {
            participantJidObj = d.jidObj;
            try {
              const ds = String(d.desc || "");
              const m = ds.match(/<([^>]+)>/);
              if (m && m[1]) author = String(m[1]).trim();
            } catch (_) {}
          }
        }
        if (!participantJidObj) return resolve({ ok: false, error: "cannot resolve participantJid for status target message" });

        const provRes = _resolveMessagingDataProviderExplore(core.ctxMain);
        if (!provRes || !provRes.ok) return resolve({ ok: false, error: provRes ? provRes.error : "messaging data provider failed" });
        const provider = provRes.provider;
        if (!provider || !objcHasSelector(provider, "dataSourceForStatusStickerReactionWithTargetMessage:reactionId:")) {
          return resolve({ ok: false, error: "provider missing dataSourceForStatusStickerReactionWithTargetMessage:reactionId:", providerClass: provider ? String(provider.$className || "") : "" });
        }

        const rid = _genUniqueStanzaIDExplore();
        if (!rid) return resolve({ ok: false, error: "uniqueStanzaID failed" });
        const reactionMsgId = _makeWAMessageIDForReactionExplore(rid, statusChatJid, participantJidObj);
        if (!reactionMsgId) return resolve({ ok: false, error: "reaction messageID build failed" });

        const ds = provider.dataSourceForStatusStickerReactionWithTargetMessage_reactionId_(targetMsgObj, reactionMsgId);
        if (!ds) return resolve({ ok: false, error: "dataSourceForStatusStickerReaction returned nil" });
        const dsObj = ds instanceof ObjC.Object ? ds : new ObjC.Object(ds);

        let stanza = null;
        if (objcHasSelector(dsObj, "messageStanza")) {
          try { stanza = objcCallNoArg(dsObj, "messageStanza"); } catch (_) { stanza = null; }
        }
        if (!stanza) return resolve({ ok: false, error: "dataSource missing messageStanza" });
        const stanzaObj = stanza instanceof ObjC.Object ? stanza : new ObjC.Object(stanza);

        try {
          const U = ObjC.classes.WAMessageSecretMessageDecryptionUtils;
          if (U && U["+ findTargetMessageIDWithMessageStanza:accountProvider:"] && typeof U["+ findTargetMessageIDWithMessageStanza:accountProvider:"] === "function") {
            const ap = objcCallNoArg(core.ctxMain, "accountProvider");
            if (ap) {
              const mid = U["+ findTargetMessageIDWithMessageStanza:accountProvider:"](stanzaObj, ap);
              const midObj = mid ? (mid instanceof ObjC.Object ? mid : new ObjC.Object(mid)) : null;
              let midSid = "";
              try {
                if (midObj && objcHasSelector(midObj, "stanzaID")) midSid = String(objcCallNoArgString(midObj, "stanzaID") || "");
                else if (midObj && objcHasSelector(midObj, "stanzaId")) midSid = String(objcCallNoArgString(midObj, "stanzaId") || "");
              } catch (_) { midSid = ""; }
              if (midSid && String(midSid).trim() !== sid) {
                return resolve({ ok: false, error: "built reaction stanza target mismatch", expectedTargetStanzaId: sid, parsedTargetStanzaId: String(midSid).trim(), reactionStanzaId: rid });
              }
            }
          }
        } catch (_) {}

        let xmpp = null;
        try {
          const cls = ObjC.classes.XMPPConnectionMain;
          const cands = ["sharedInstance", "shared", "main", "mainInstance", "defaultInstance", "defaultConnection", "sharedConnection", "connectionMain"];
          for (let i = 0; i < cands.length; i++) {
            const s = cands[i];
            if (!cls) break;
            if (!objcHasSelector(cls, s)) continue;
            const x = objcCallClassNoArg(cls, s);
            if (x) { xmpp = x; break; }
          }
        } catch (_) { xmpp = null; }
        if (!xmpp) return resolve({ ok: false, error: "XMPPConnectionMain instance not found" });
        const xmppObj = xmpp instanceof ObjC.Object ? xmpp : new ObjC.Object(xmpp);
        if (!objcHasSelector(xmppObj, "sendMessageStanza:")) return resolve({ ok: false, error: "XMPPConnectionMain missing sendMessageStanza:" });
        xmppObj.sendMessageStanza_(stanzaObj);

        let text = "";
        try {
          if (objcHasSelector(stanzaObj, "stringRepresentation")) text = String(objcCallNoArgString(stanzaObj, "stringRepresentation")).slice(0, 2000);
        } catch (_) { text = ""; }

        resolve({
          ok: true,
          authorJid: author,
          statusStanzaId: sid,
          emojiCode: code,
          providerSource: String(provRes.source || ""),
          targetMessage: { ptr: ptr(targetMsgObj).toString(), className: String(targetMsgObj.$className || "") },
          dataSource: { ptr: ptr(dsObj).toString(), className: String(dsObj.$className || "") },
          reactionMessageId: { ptr: ptr(reactionMsgId).toString(), stanzaId: rid },
          stanza: { ptr: ptr(stanzaObj).toString(), className: String(stanzaObj.$className || ""), text: text },
        });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function _strictPickSenderQuotedTextSelector() {
  try {
    const last = SEND_PROBE && SEND_PROBE.last ? SEND_PROBE.last : null;
    if (!last) return "";
    const sel = String(last.selector || "").trim();
    if (!sel) return "";
    if (sel.indexOf("sendMessageWithText:") !== 0) return "";
    if (sel.indexOf("multicast:") === -1) return "";
    if (sel.indexOf("attachments:") === -1) return "";
    if (sel.indexOf("messageOrigin:") === -1) return "";
    if (sel.indexOf("creationEntryPoint:") === -1) return "";
    if (sel.indexOf("inChatSession:") === -1) return "";
    if (sel.indexOf("beforeSendCallback:completion:") === -1) return "";
    return sel;
  } catch (_) {
    return "";
  }
}

function _buildArgsForQuotedTextSelector(selectorNoDash, nsText, attachmentsObj, chatSessionObj) {
  const labels = String(selectorNoDash || "").split(":");
  const n = Math.max(0, labels.length - 1);
  const args = new Array(n);
  const last = SEND_PROBE && SEND_PROBE.last ? SEND_PROBE.last : null;
  const multicast = last ? _asBoolFromPtrText(last.a3Ptr) : false;
  const origin = last ? _parseHexPtrToInt(last.a5Ptr, 1) : 1;
  const entryPoint = last ? _parseHexPtrToInt(last.a6Ptr, 0) : 0;

  for (let i = 0; i < n; i++) {
    const lab = String(labels[i] || "");
    if (lab === "sendMessageWithText") { args[i] = nsText; continue; }
    if (lab === "multicast") { args[i] = multicast; continue; }
    if (lab === "attachments") { args[i] = attachmentsObj; continue; }
    if (lab === "messageOrigin") { args[i] = origin; continue; }
    if (lab === "creationEntryPoint") { args[i] = entryPoint; continue; }
    if (lab === "inChatSession") { args[i] = chatSessionObj; continue; }
    if (lab === "replyContext") { args[i] = null; continue; }
    if (lab === "beforeSendCallback") { args[i] = null; continue; }
    if (lab === "completion") { args[i] = null; continue; }
    if (lab === "hasTextFromURL") { args[i] = false; continue; }
    if (lab === "openedFromURL") { args[i] = false; continue; }
    args[i] = null;
  }
  return { ok: true, args, origin, entryPoint, multicast };
}

function statuslike(emojiText, authorJid, statusStanzaId) {
  const author = String(authorJid || "").trim();
  const sid = String(statusStanzaId || "").trim();
  if (!author || !sid) return Promise.resolve({ ok: false, error: "missing authorJid/statusStanzaId" });
  return statuslikepure(author, sid, null);
}

function statuslikefind(authorJid, statusStanzaId) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const author = String(authorJid || "").trim();
  const sid = String(statusStanzaId || "").trim();
  if (!sid) return Promise.resolve({ ok: false, error: "missing statusStanzaId" });
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { installCrashSniffer(); } catch (_) {}
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikefind", step: "begin", sid: sid, author: author, ts: nowMs() }; } catch (_) {}
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const core = _resolveCoreForSendExplore();
        if (!core || !core.ok) return resolve({ ok: false, error: core ? core.error : "core failed" });
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikefind", step: "core_ok", sid: sid, author: author, ts: nowMs() }; } catch (_) {}
        const statusChatJid = _makeWAChatJIDFromString("status@broadcast");
        if (!statusChatJid) return resolve({ ok: false, error: "status@broadcast jid parse failed" });
        const csStatus = _fetchChatSession(core.storage, statusChatJid);
        if (!csStatus) return resolve({ ok: false, error: "fetchChatSession status@broadcast failed" });
        const mcsStatus = _getMutableChatSession(csStatus);
        if (!mcsStatus) return resolve({ ok: false, error: "mutableChatSession status@broadcast failed" });

        const nsSid = nsString(sid);
        if (!nsSid) return resolve({ ok: false, error: "stanzaId->NSString failed" });

        let msg = null;
        try { msg = _fetchMessageByStanzaId(mcsStatus, sid, author); } catch (_) { msg = null; }
        let via = msg ? "mcs.fetch" : "";
        if (!msg && author) {
          try {
            const aU = _makeAuthorUserJIDFromString(author);
            if (aU && objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:authorUserJID:")) {
              const m2 = mcsStatus.fetchMessageWithStanzaID_authorUserJID_(nsSid, aU);
              if (m2) { msg = m2; via = "mcs.fetchMessageWithStanzaID:authorUserJID:"; }
            }
          } catch (_) {}
        }
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikefind", step: "after_fetch_by_stanza", sid: sid, author: author, hasMsg: !!msg, ts: nowMs() }; } catch (_) {}

        let ctxFetch = { has: objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:isFromMe:context:"), hasAuthor: objcHasSelector(mcsStatus, "fetchMessageWithStanzaID:authorUserJID:"), tried: false, mocOk: false, mocSource: "", mocClassName: "", hitFromMe: -1, midTried: false, midBuildOk: false, midBuildMode: "", midUsed: "", midOk: false, via: via };
        if (!msg) {
          const mocRes = _resolveManagedObjectContextExplore(core);
          ctxFetch.mocOk = !!(mocRes && mocRes.ok && mocRes.moc);
          ctxFetch.mocSource = String((mocRes && mocRes.source) ? mocRes.source : "");
          ctxFetch.mocClassName = String((mocRes && mocRes.moc && mocRes.moc.$className) ? mocRes.moc.$className : "");
          if (ctxFetch.has && mocRes && mocRes.ok && mocRes.moc) {
            ctxFetch.tried = true;
            try {
              const m0 = mcsStatus.fetchMessageWithStanzaID_isFromMe_context_(nsSid, 0, mocRes.moc);
              if (m0) { msg = m0; ctxFetch.hitFromMe = 0; }
            } catch (_) {}
            if (!msg) {
              try {
                const m1 = mcsStatus.fetchMessageWithStanzaID_isFromMe_context_(nsSid, 1, mocRes.moc);
                if (m1) { msg = m1; ctxFetch.hitFromMe = 1; }
              } catch (_) {}
            }
          }

          if (!msg && mocRes && mocRes.ok && mocRes.moc) {
            try {
              const statusChatJid = _makeWAChatJIDFromString("status@broadcast");
              if (!statusChatJid) {
                ctxFetch.midTried = true;
                ctxFetch.midBuildOk = false;
                ctxFetch.midBuildMode = "statusChatJid_nil";
                ctxFetch.midOk = false;
                ctxFetch.midUsed = "status@broadcast jid parse failed";
              } else {
              ctxFetch.midTried = true;
              const pu = author ? _makeAuthorUserJIDFromString(author) : null;
              const pJid = author ? _makeWAJIDFromStringExplore(author) : null;
              let mid = null;
              if (pu) {
                mid = _makeWAMessageIDForReactionExplore(sid, statusChatJid, pu);
                ctxFetch.midBuildMode = "authorUserJID";
              } else if (pJid) {
                mid = _makeWAMessageIDForReactionExplore(sid, statusChatJid, pJid);
                ctxFetch.midBuildMode = "WAJID";
              } else {
                mid = _makeWAMessageIDForReactionExplore(sid, statusChatJid, null);
                ctxFetch.midBuildMode = "nil";
              }
              ctxFetch.midBuildOk = !!mid;
              if (!mid) {
                ctxFetch.midOk = false;
                ctxFetch.midUsed = "messageID build failed";
              } else {
                const fres = _fetchMessageByMessageIDExplore(core.storage, mid, mocRes.moc);
                if (fres && fres.ok && fres.msg) {
                  msg = fres.msg;
                  ctxFetch.midOk = true;
                  ctxFetch.midUsed = String(fres.used || "");
                } else {
                  ctxFetch.midOk = false;
                  ctxFetch.midUsed = String((fres && fres.error) ? fres.error : "");
                }
              }
              }
            } catch (_) {}
          }
        }

        let modelFetch = { tried: false, ok: false, error: "", provider: null, statusModel: null };
        if (!msg) {
          try {
            modelFetch.tried = true;
            try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikefind", step: "before_model_fetch", sid: sid, author: author, ts: nowMs() }; } catch (_) {}
            const r = _fetchStatusMessageViaStatusModelExplore(core, sid, author);
            if (r && r.ok && r.msg) {
              msg = r.msg;
              modelFetch.ok = true;
              modelFetch.provider = r.provider || null;
              modelFetch.statusModel = r.statusModel || null;
              modelFetch.via = String(r.via || "");
              try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikefind", step: "model_fetch_ok", sid: sid, author: author, via: String(r.via || ""), ts: nowMs() }; } catch (_) {}
            } else {
              modelFetch.ok = false;
              modelFetch.error = String((r && r.error) ? r.error : "status model fetch failed");
              modelFetch.provider = r && r.provider ? r.provider : null;
              modelFetch.statusModel = r && r.statusModel ? r.statusModel : null;
              modelFetch.via = String(r && r.via ? r.via : "");
              modelFetch.midFetch = r && r.midFetch ? r.midFetch : null;
              modelFetch.rawReturn = r && r.rawReturn ? r.rawReturn : null;
              try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "statuslikefind", step: "model_fetch_fail", sid: sid, author: author, err: String(modelFetch.error || ""), via: String(modelFetch.via || ""), ts: nowMs() }; } catch (_) {}
            }
          } catch (e) {
            modelFetch.ok = false;
            modelFetch.error = String(e);
          }
        }

        if (!msg) return resolve({ ok: false, error: "message not found", tried: { authorJid: author, statusStanzaId: sid }, ctxFetch, modelFetch });

        const msgObj = msg instanceof ObjC.Object ? msg : new ObjC.Object(msg);
        const msgCn = String(msgObj.$className || "");
        const isWAMessage = msgCn.indexOf("WAMessage") !== -1 && msgCn.indexOf("WAMessageID") === -1;
        if (!isWAMessage) {
          return resolve({
            ok: false,
            error: "resolved object is not WAMessage",
            tried: { authorJid: author, statusStanzaId: sid },
            ctxFetch,
            modelFetch,
            resolved: { ptr: ptr(msgObj).toString(), className: msgCn, desc: _safeDesc(msgObj) }
          });
        }
        resolve({
          ok: true,
          tried: { authorJid: author, statusStanzaId: sid },
          via: via || (ctxFetch.hitFromMe >= 0 ? "mcs.fetch.context" : "unknown"),
          ctxFetch,
          modelFetch,
          msg: { ptr: ptr(msgObj).toString(), className: String(msgObj.$className || ""), desc: _safeDesc(msgObj) },
          derivedParticipant: _deriveUserJIDFromStatusMessageExplore(msgObj),
        });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function _randomHex(nBytes) {
  try {
    const n = Math.max(4, Math.min(64, Number(nBytes || 12) | 0));
    const chars = "0123456789abcdef";
    let out = "";
    for (let i = 0; i < n * 2; i++) out += chars[(Math.random() * 16) | 0];
    return out;
  } catch (_) {
    return String(Date.now());
  }
}

function _makeXMPPAttributeValueFromString(s) {
  try {
    const v = String(s || "");
    const ns = nsString(v);
    const C = ObjC.classes.XMPPAttributeValue;
    if (!C || !ns) return null;
    if (!globalThis.__QQW_XAV_FACTORY) globalThis.__QQW_XAV_FACTORY = { sel: "", candidates: [] };
    const st = globalThis.__QQW_XAV_FACTORY;
    st.candidates = ["+ withString:sanitize:", "+ withOptionalString:sanitize:"];
    const sanitize = 1;
    try {
      if (C["+ withString:sanitize:"] && typeof C["+ withString:sanitize:"] === "function") {
        const r = C["+ withString:sanitize:"](ns, sanitize);
        if (r) { st.sel = "+ withString:sanitize:"; return r; }
      }
    } catch (_) {}
    try {
      if (C["+ withOptionalString:sanitize:"] && typeof C["+ withOptionalString:sanitize:"] === "function") {
        const r = C["+ withOptionalString:sanitize:"](ns, sanitize);
        if (r) { st.sel = "+ withOptionalString:sanitize:"; return r; }
      }
    } catch (_) {}
    return null;
  } catch (_) {
    return null;
  }
}

function _makeReactionRemoteJidFromString(jidStr) {
  try {
    const s = String(jidStr || "").trim();
    if (!s) return null;
    const chat = _makeWAChatJIDFromString(s);
    if (chat) return chat;
    const u = _makeAuthorUserJIDFromString(s);
    if (u) return u;
    return null;
  } catch (_) {
    return null;
  }
}

function _patchStatusReactionStanza(stanza, authorJid, statusStanzaId, emojiCode) {
  try {
    const sid = String(statusStanzaId || "").trim();
    const toJid = String(authorJid || "").trim();
    const code = Number.isFinite(Number(emojiCode)) ? (Number(emojiCode) | 0) : null;

    try {
      if (objcHasSelector(stanza, "setUniqueIdentifier:")) stanza.setUniqueIdentifier_(nsString(_randomHex(12)));
    } catch (_) {}

    try {
      if (objcHasSelector(stanza, "setType:")) stanza.setType_(4);
    } catch (_) {}

    try {
      if (objcHasSelector(stanza, "setAttributeWithName:value:")) {
        if (sid) stanza.setAttributeWithName_value_(nsString("id"), _makeXMPPAttributeValueFromString(sid));
        if (code !== null) stanza.setAttributeWithName_value_(nsString("e"), _makeXMPPAttributeValueFromString(String(code)));
      }
    } catch (_) {}

    try {
      if (toJid && objcHasSelector(stanza, "setToRemoteJID:")) {
        const rj = _makeReactionRemoteJidFromString(toJid);
        if (rj) stanza.setToRemoteJID_(rj);
      }
    } catch (_) {}

    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function statuslikebuild(authorJid, statusStanzaId, emojiCode) {
  return Promise.resolve({
    ok: false,
    error: "disabled",
    note: "statuslikebuild previously caused a native crash because XMPPMessageStanza alloc/init is not a valid outgoing status-like construction path. Use statuslikepure after rxpinned has captured the target status message."
  });
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const author = String(authorJid || "").trim();
  const sid = String(statusStanzaId || "").trim();
  const code0 = (emojiCode === null || emojiCode === undefined || String(emojiCode).trim() === "") ? null : (Number(emojiCode) | 0);
  const code = Number.isFinite(Number(code0)) ? (Number(code0) | 0) : null;
  if (!author || !sid) return Promise.resolve({ ok: false, error: "missing authorJid/statusStanzaId" });

  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }

        const cls = ObjC.classes.XMPPMessageStanza;
        if (!cls) return resolve({ ok: false, error: "XMPPMessageStanza missing" });

        let stanza = null;
        try { stanza = cls.alloc().init(); } catch (_) { stanza = null; }
        if (!stanza) {
          try { stanza = cls.new(); } catch (_) { stanza = null; }
        }
        if (!stanza) return resolve({ ok: false, error: "failed to alloc/init XMPPMessageStanza" });

        const toChat = _makeWAChatJIDFromString("status@broadcast");
        const participant = _makeAuthorUserJIDFromString(author);
        if (!toChat) return resolve({ ok: false, error: "make status@broadcast chatJID failed" });
        if (!participant) return resolve({ ok: false, error: "make participant userJID failed", authorJid: author });

        try { if (objcHasSelector(stanza, "setToRemoteJID:")) stanza.setToRemoteJID_(toChat); } catch (_) {}
        try { if (objcHasSelector(stanza, "setParticipant:")) stanza.setParticipant_(participant); } catch (_) {}

        const pr = _patchStatusReactionStanza(stanza, author, sid, code !== null ? code : 7);
        if (!pr || !pr.ok) return resolve({ ok: false, error: pr ? pr.error : "patch failed" });

        let text = "";
        try {
          if (objcHasSelector(stanza, "stringRepresentation")) text = String(objcCallNoArgString(stanza, "stringRepresentation")).slice(0, 2000);
          else if (objcHasSelector(stanza, "description")) text = String(stanza).slice(0, 2000);
        } catch (_) { text = ""; }

        return xmppSendStanzaPtr(ptr(stanza).toString()).then((r) => {
          resolve({ ok: !!(r && r.ok), send: r, authorJid: author, statusStanzaId: sid, emojiCode: (code !== null ? code : 7), stanza: { ptr: ptr(stanza).toString(), className: String(stanza.$className || ""), text } });
        }).catch((e) => {
          resolve({ ok: false, error: String(e), authorJid: author, statusStanzaId: sid, stanza: { ptr: ptr(stanza).toString(), className: String(stanza.$className || ""), text } });
        });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function statuslikereact(statusStanzaId, emojiCode, authorJid) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const sid = String(statusStanzaId || "").trim();
  if (!sid) return Promise.resolve({ ok: false, error: "missing statusStanzaId" });
  const code = Number.isFinite(Number(emojiCode)) ? (Number(emojiCode) | 0) : null;
  const toJid = String(authorJid || "").trim();

  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const p = String(LIKE_PROBE.retainedPtr || "").trim();
        if (!p || p === "0x0") return resolve({ ok: false, error: "no reaction template; run likeprobeon + statuslikearm then tap Like in UI" });
        const tpl = new ObjC.Object(ptr(p));
        if (!tpl) return resolve({ ok: false, error: "bad template ptr", ptr: p });
        if (!objcHasSelector(tpl, "isReaction") || !(tpl.isReaction() === 1 || tpl.isReaction() === true || String(tpl.isReaction()) === "1")) {
          return resolve({ ok: false, error: "template is not a reaction stanza", className: String(tpl.$className || "") });
        }

        let stanza = null;
        try {
          if (objcHasSelector(tpl, "copy")) stanza = tpl.copy();
          else if (objcHasSelector(tpl, "mutableCopy")) stanza = tpl.mutableCopy();
        } catch (_) { stanza = null; }
        if (!stanza) stanza = tpl;

        const pr = _patchStatusReactionStanza(stanza, toJid, sid, code);
        if (!pr || !pr.ok) return resolve({ ok: false, error: pr ? pr.error : "patch failed" });

        let inst0 = null;
        try {
          const cls = ObjC.classes.XMPPConnectionMain;
          const cands = ["sharedInstance", "shared", "main", "mainInstance", "defaultInstance", "defaultConnection", "sharedConnection", "connectionMain"];
          for (let i = 0; i < cands.length; i++) {
            const s = cands[i];
            if (!cls) break;
            if (!objcHasSelector(cls, s)) continue;
            const x = objcCallClassNoArg(cls, s);
            if (x) { inst0 = x; break; }
          }
        } catch (_) { inst0 = null; }

        const sendVia = (inst) => {
          try {
            if (!inst) return resolve({ ok: false, error: "XMPPConnectionMain instance not found" });
            if (!objcHasSelector(inst, "sendMessageStanza:")) return resolve({ ok: false, error: "XMPPConnectionMain missing sendMessageStanza:" });
            inst.sendMessageStanza_(stanza);
            resolve({ ok: true, statusStanzaId: sid, emojiCode: code, authorJid: toJid, usedTemplatePtr: p, note: "patched: uniqueIdentifier/type/id/(optional e)/(optional toRemoteJID)" });
          } catch (e) {
            resolve({ ok: false, error: String(e) });
          }
        };

        if (inst0) return sendVia(inst0 instanceof ObjC.Object ? inst0 : new ObjC.Object(inst0));
        _chooseOneInstance("XMPPConnectionMain", (inst) => sendVia(inst), () => {}, 1);
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function _ptrStrToIntMaybe(pstr, fallback) {
  try {
    const s = String(pstr || "").trim().toLowerCase();
    if (!s || s === "0x0") return fallback;
    if (!s.startsWith("0x")) return fallback;
    const n = parseInt(s.slice(2), 16);
    if (!Number.isFinite(n)) return fallback;
    if (n < 0 || n > 0x7fffffff) return fallback;
    return n | 0;
  } catch (_) {
    return fallback;
  }
}

function _objcRetainPtrStr(pstr) {
  try {
    const s = String(pstr || "").trim();
    if (!s || s === "0x0") return "0x0";
    const p = ptr(s);
    if (p.isNull()) return "0x0";
    const pRet = Module.findExportByName(null, "objc_retain");
    if (!pRet) return "0x0";
    const objcRetain = new NativeFunction(pRet, "pointer", ["pointer"]);
    const rp = objcRetain(p);
    if (!rp || ptr(rp).isNull()) return "0x0";
    return ptr(rp).toString();
  } catch (_) {
    return "0x0";
  }
}

function _objcReleasePtrStr(pstr) {
  try {
    const s = String(pstr || "").trim();
    if (!s || s === "0x0") return;
    const p = ptr(s);
    if (p.isNull()) return;
    const pRel = Module.findExportByName(null, "objc_release");
    if (!pRel) return;
    const objcRelease = new NativeFunction(pRel, "void", ["pointer"]);
    objcRelease(p);
  } catch (_) {}
}

function statuslikereact2(statusStanzaId, emojiCode, authorJid) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const sid = String(statusStanzaId || "").trim();
  if (!sid) return Promise.resolve({ ok: false, error: "missing statusStanzaId" });
  const code = Number.isFinite(Number(emojiCode)) ? (Number(emojiCode) | 0) : null;
  const toJid = String(authorJid || "").trim();

  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }

        const tplPtr = String(LIKE_PROBE.retainedPtr || "").trim();
        if (!tplPtr || tplPtr === "0x0") return resolve({ ok: false, error: "no reaction template; run likeprobeon + statuslikearm then tap Like in UI" });
        const tpl = new ObjC.Object(ptr(tplPtr));
        if (!tpl) return resolve({ ok: false, error: "bad template ptr", ptr: tplPtr });
        try {
          if (!objcHasSelector(tpl, "isReaction") || !(tpl.isReaction() === 1 || tpl.isReaction() === true || String(tpl.isReaction()) === "1")) {
            return resolve({ ok: false, error: "template is not a reaction stanza", className: String(tpl.$className || "") });
          }
        } catch (_) {}

        let stanza = tpl;
        try {
          if (objcHasSelector(tpl, "copy")) stanza = tpl.copy();
          else if (objcHasSelector(tpl, "mutableCopy")) stanza = tpl.mutableCopy();
        } catch (_) { stanza = tpl; }

        const seqAll = (LIKE_BUILD && LIKE_BUILD.events) ? LIKE_BUILD.events : [];
        const seq = seqAll.filter(e => String(e.selfPtr || "") === String(tplPtr));
        if (!seq.length) return resolve({ ok: false, error: "no likebuild sequence; run likebuildarm then tap Like in UI, then retry" });

        for (let i = 0; i < seq.length; i++) {
          const ev = seq[i];
          const sel = String(ev.selector || "").trim();
          if (!sel) continue;

          if (sel === "setUniqueIdentifier:") {
            continue;
          }

          if (sel === "setAttributeWithName:value:sanitize:") {
            continue;
          }

          if (sel === "setFromRemoteJID:") continue;
          if (sel === "setToRemoteJID:") {
            try {
              if (toJid) {
                const rj = _makeReactionRemoteJidFromString(toJid);
                if (rj) stanza.setToRemoteJID_(rj);
              }
            } catch (_) {}
            continue;
          }

          if (sel === "setAttributeWithName:value:") {
            try {
              const nameP = String(ev.a2Ret && ev.a2Ret !== "0x0" ? ev.a2Ret : ev.a2Ptr);
              const valP = String(ev.a3Ret && ev.a3Ret !== "0x0" ? ev.a3Ret : ev.a3Ptr);
              const nameObj = new ObjC.Object(ptr(nameP));
              const nameStr = (function () { try { return String(nameObj); } catch (_) { return ""; } })();
              if (nameStr !== "id" && nameStr !== "e") {
                continue;
              }
              if (nameStr === "e" && code === null) {
                continue;
              }
              let valObj = null;
              if (nameStr === "id") valObj = _makeXMPPAttributeValueFromString(sid);
              else if (nameStr === "e" && code !== null) valObj = _makeXMPPAttributeValueFromString(String(code));
              if (!valObj) continue;

              stanza.setAttributeWithName_value_(nameObj, valObj);
            } catch (_) {}
            continue;
          }

          if (sel === "setType:") {
            try {
              const v = _ptrStrToIntMaybe(ev.a2Ptr, 0);
              stanza.setType_(v);
            } catch (_) {}
            continue;
          }

          try {
            const p2 = String(ev.a2Ret && ev.a2Ret !== "0x0" ? ev.a2Ret : ev.a2Ptr);
            if (!p2 || p2 === "0x0") continue;
            const n = _ptrStrToIntMaybe(p2, -1);
            if (n >= 0 && p2.length <= 6) continue;
            const o2 = new ObjC.Object(ptr(p2));
            if (sel === "setServerID:") {
              stanza.setServerID_(o2);
            } else if (sel === "setParticipant:" || sel === "setParticipantValue:" || sel === "setToAttributeValue:" || sel === "setFromAttributeValue:" || sel === "setStringValue:sanitize:" || sel === "setDataValue:" || sel === "setElementValue:") {
              const m = stanza["- " + sel];
              if (m && typeof m === "function") m.call(stanza, o2);
            }
          } catch (_) {}
        }

        let inst0 = null;
        try {
          const cls = ObjC.classes.XMPPConnectionMain;
          const cands = ["sharedInstance", "shared", "main", "mainInstance", "defaultInstance", "defaultConnection", "sharedConnection", "connectionMain"];
          for (let i = 0; i < cands.length; i++) {
            const s = cands[i];
            if (!cls) break;
            if (!objcHasSelector(cls, s)) continue;
            const x = objcCallClassNoArg(cls, s);
            if (x) { inst0 = x; break; }
          }
        } catch (_) { inst0 = null; }

        const sendVia = (inst) => {
          try {
            if (!inst) return resolve({ ok: false, error: "XMPPConnectionMain instance not found" });
            if (!objcHasSelector(inst, "sendMessageStanza:")) return resolve({ ok: false, error: "XMPPConnectionMain missing sendMessageStanza:" });
            inst.sendMessageStanza_(stanza);
            resolve({ ok: true, statusStanzaId: sid, emojiCode: code, usedTemplatePtr: tplPtr, replayed: seq.length });
          } catch (e) {
            resolve({ ok: false, error: String(e) });
          }
        };

        if (inst0) return sendVia(inst0 instanceof ObjC.Object ? inst0 : new ObjC.Object(inst0));
        _chooseOneInstance("XMPPConnectionMain", (inst) => sendVia(inst), () => {}, 1);
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function _safeObjFromPtrStr(pstr) {
  try {
    if (!objcAvailable()) return null;
    const s = String(pstr || "").trim();
    if (!s || s === "0x0") return null;
    const p = ptr(s);
    if (p.isNull()) return null;
    if (p.compare(ptr("0x10000")) < 0) return null;
    try { Memory.readPointer(p); } catch (_) { return null; }
    try { return new ObjC.Object(p); } catch (_) { return null; }
  } catch (_) {
    return null;
  }
}

function statuslikereact2build(statusStanzaId, emojiCode, authorJid) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const sid = String(statusStanzaId || "").trim();
  if (!sid) return Promise.resolve({ ok: false, error: "missing statusStanzaId" });
  const code = Number.isFinite(Number(emojiCode)) ? (Number(emojiCode) | 0) : null;
  const toJid = String(authorJid || "").trim();

  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        try { installCrashSniffer(); } catch (_) {}
        try { installExceptionSniffer(); } catch (_) {}
        try { send({ type: "qqw.explore.react2", step: "build_start" }); } catch (_) {}
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "start" }; } catch (_) {}

        const tplPtr = String(LIKE_PROBE.retainedPtr || "").trim();
        if (!tplPtr || tplPtr === "0x0") return resolve({ ok: false, error: "no reaction template; run likeprobeon + statuslikearm then tap Like in UI" });
        const tpl = _safeObjFromPtrStr(tplPtr);
        if (!tpl) return resolve({ ok: false, error: "bad template ptr", ptr: tplPtr });

        const stanza = tpl;
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "set_id" }; } catch (_) {}
        let beforeText = "";
        try {
          if (stanza && objcHasSelector(stanza, "stringRepresentation")) beforeText = String(objcCallNoArgString(stanza, "stringRepresentation")).slice(0, 2000);
        } catch (_) { beforeText = ""; }
        try {
          if (objcHasSelector(stanza, "setAttributeWithName:value:")) {
            const idVal1 = _makeXMPPAttributeValueFromString("<'" + sid + "'>");
            const idVal2 = idVal1 || _makeXMPPAttributeValueFromString(sid);
            if (!idVal2) {
              const st = globalThis.__QQW_XAV_FACTORY || {};
              return resolve({ ok: false, error: "xav_factory_failed", candidates: st.candidates || [] });
            }
            stanza.setAttributeWithName_value_(nsString("id"), idVal2);
            if (code !== null) {
              const eVal1 = _makeXMPPAttributeValueFromString("<'" + String(code) + "'>");
              const eVal2 = eVal1 || _makeXMPPAttributeValueFromString(String(code));
              if (eVal2) stanza.setAttributeWithName_value_(nsString("e"), eVal2);
            }
          }
        } catch (_) {}

        try { _patchStatusReactionStanza(stanza, toJid, sid, code); } catch (_) {}
        let afterText = "";
        try {
          if (stanza && objcHasSelector(stanza, "stringRepresentation")) afterText = String(objcCallNoArgString(stanza, "stringRepresentation")).slice(0, 2000);
        } catch (_) { afterText = ""; }
        if (afterText && afterText.indexOf("id=" + sid) === -1) {
          const st = globalThis.__QQW_XAV_FACTORY || {};
          return resolve({ ok: false, error: "id_not_updated", before: beforeText, after: afterText, xavSel: st.sel || "", candidates: st.candidates || [] });
        }

        try { _objcReleasePtrStr(REACT2.retainedPtr); } catch (_) {}
        REACT2.retainedPtr = _objcRetainPtrStr(ptr(stanza).toString());
        REACT2.lastBuild = { ts: nowMs(), tplPtr: tplPtr, statusStanzaId: sid, emojiCode: code };
        try { send({ type: "qqw.explore.react2", step: "build_ok", retainedPtr: REACT2.retainedPtr }); } catch (_) {}
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "idle" }; } catch (_) {}
        resolve({ ok: true, retainedPtr: REACT2.retainedPtr, before: beforeText, after: afterText, xavSel: (globalThis.__QQW_XAV_FACTORY && globalThis.__QQW_XAV_FACTORY.sel) ? globalThis.__QQW_XAV_FACTORY.sel : "" });
      } catch (e) {
        try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "idle" }; } catch (_) {}
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function statuslikereact2send() {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const p = String(REACT2.retainedPtr || "").trim();
  if (!p || p === "0x0") return Promise.resolve({ ok: false, error: "no built stanza; run statuslikereact2build first" });
  try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "send" }; } catch (_) {}
  return xmppSendStanzaPtr(p)
    .then((res) => {
      try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "idle" }; } catch (_) {}
      return res;
    })
    .catch((e) => {
      try { globalThis.__QQW_REACT2_LASTSTEP = { stage: "idle" }; } catch (_) {}
      return { ok: false, error: String(e) };
    });
}

function installReadProbe() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (READ_PROBE.installed) return { ok: true, installed: true, count: READ_PROBE.count, err: READ_PROBE.err || "" };
  READ_PROBE.err = "";
  READ_PROBE._ls = [];
  try {
    const candidates = [
      { className: "WAChatStorage", selectors: [
        "- markChatSession:read:",
        "- markChatSession:read:entryPoint:",
        "- markChatSessionsAsRead:",
        "- markChatSessions:read:sendReadReceipts:error:",
        "- markChatSessions:read:sendReadReceipts:isMarkedByUser:error:",
        "- sendReadReceiptsForMessagesBeforeAndIncludingMessage:inChatSession:isMarkedByUser:",
      ]},
      { className: "MarkChatAsReadSyncActionHandler", selectors: [
        "- markChatSession:read:",
        "- markChatSession:read:entryPoint:",
        "- markChatSessionsAsRead:",
        "- markChatAsReadAction",
        "- markChatAsReadAction:",
      ]},
      { className: "MarkChatAsReadSyncProvider", selectors: [
        "- markChatAsReadAction",
        "- markChatAsReadAction:",
      ]},
      { className: "MarkChatAsReadSyncAction", selectors: [
        "- markChatAsReadAction",
        "- markChatAsReadAction:",
      ]},
      { className: "_TtC14WAAppStateSync31MarkChatAsReadSyncActionHandler", selectors: [
        "- markChatSession:read:",
        "- markChatSession:read:entryPoint:",
        "- markChatSessionsAsRead:",
      ]},
      { className: "WAChatListViewController", selectors: [
        "- markChatSessionsAsRead:",
      ]},
    ];

    const hooked = [];
    for (let ci = 0; ci < candidates.length; ci++) {
      const cn = candidates[ci].className;
      const cls = ObjC.classes[cn];
      if (!cls) continue;
      const sels = candidates[ci].selectors || [];
      for (let si = 0; si < sels.length; si++) {
        const sel = sels[si];
        const m = cls[sel];
        if (!m || !m.implementation) continue;
        const h = Interceptor.attach(m.implementation, {
          onEnter(args) {
            try {
              const selfObj = _safeObj(args[0]);
              READ_PROBE.last = {
                ts: nowMs(),
                callerIda: _idaFromPtr(this.returnAddress),
                selector: sel.replace(/^\s*[-+]\s*/g, ""),
                self: _captureObj(args[0]),
                a2: _captureObj(args[2]),
                a3: _captureObj(args[3]),
                a4: _captureObj(args[4]),
                a5: _captureObj(args[5]),
                a6: _captureObj(args[6]),
                selfClassName: selfObj ? String(selfObj.$className || "") : "",
              };
              try {
                READ_PROBE.lastSelfPtr = ptr(args[0]).toString();
                if (selfObj && objcHasSelector(selfObj, "retain")) selfObj.retain();
              } catch (_) {}
              READ_PROBE.count++;
              send({ type: "qqw.explore.read_probe", ok: true, ...READ_PROBE.last });
            } catch (e) {
              try { send({ type: "qqw.explore.read_probe", ok: false, error: String(e) }); } catch (_) {}
            }
          }
        });
        READ_PROBE._ls.push(h);
        hooked.push({ className: cn, selector: sel.replace(/^\s*[-+]\s*/g, "") });
      }
    }
    READ_PROBE.installed = true;
    return { ok: true, installed: true, hooked: READ_PROBE._ls.length, hooks: hooked };
  } catch (e) {
    READ_PROBE.err = String(e);
    return { ok: false, error: READ_PROBE.err };
  }
}

function readProbeStatus() {
  return { ok: true, installed: READ_PROBE.installed, count: READ_PROBE.count, last: READ_PROBE.last, err: READ_PROBE.err || "" };
}

function readProbeOff() {
  try {
    const ls = READ_PROBE._ls || [];
    for (let i = 0; i < ls.length; i++) {
      try { ls[i].detach(); } catch (_) {}
    }
  } catch (_) {}
  READ_PROBE._ls = [];
  READ_PROBE.installed = false;
  return { ok: true };
}

function _readTraceOffNoThrow() {
  try { if (READ_TRACE._timer) { clearTimeout(READ_TRACE._timer); READ_TRACE._timer = null; } } catch (_) {}
  try { if (READ_TRACE._h) { READ_TRACE._h.detach(); READ_TRACE._h = null; } } catch (_) {}
  READ_TRACE.installed = false;
}

function readTraceOn(ms, maxHits) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (READ_TRACE.installed) return { ok: true, installed: true, count: READ_TRACE.hits.length, err: READ_TRACE.err || "" };
  READ_TRACE.err = "";
  try { READ_TRACE.hits = []; } catch (_) {}
  try { READ_TRACE.maxHits = Math.max(1, Math.min(500, Number(maxHits || 80) | 0)); } catch (_) { READ_TRACE.maxHits = 80; }

  let selGetName = null;
  let objGetClass = null;
  let classGetName = null;
  try {
    const pSelGetName = Module.findExportByName("libobjc.A.dylib", "sel_getName") || Module.findExportByName(null, "sel_getName");
    const pObjGetClass = Module.findExportByName("libobjc.A.dylib", "object_getClass") || Module.findExportByName(null, "object_getClass");
    const pClassGetName = Module.findExportByName("libobjc.A.dylib", "class_getName") || Module.findExportByName(null, "class_getName");
    if (pSelGetName) selGetName = new NativeFunction(pSelGetName, "pointer", ["pointer"]);
    if (pObjGetClass) objGetClass = new NativeFunction(pObjGetClass, "pointer", ["pointer"]);
    if (pClassGetName) classGetName = new NativeFunction(pClassGetName, "pointer", ["pointer"]);
  } catch (_) {
    selGetName = null;
    objGetClass = null;
    classGetName = null;
  }
  if (!selGetName) return { ok: false, error: "sel_getName unavailable" };

  const pats = [
    "markChat",
    "markchat",
    "markAsRead",
    "MarkChatAsRead",
    "readReceipt",
    "ReadReceipt",
    "readReceipts",
    "ReadReceipts",
    "sendRead",
    "SendRead",
    "markSeen",
    "MarkSeen",
    "seen",
    "Seen",
    "unread",
    "Unread",
  ];

  const fns = [];
  try {
    const p1 = Module.findExportByName("libobjc.A.dylib", "objc_msgSend") || Module.findExportByName(null, "objc_msgSend");
    if (p1) fns.push({ name: "objc_msgSend", ptr: p1 });
  } catch (_) {}
  try {
    const p2 = Module.findExportByName("libobjc.A.dylib", "objc_msgSendSuper2") || Module.findExportByName(null, "objc_msgSendSuper2");
    if (p2) fns.push({ name: "objc_msgSendSuper2", ptr: p2 });
  } catch (_) {}
  if (!fns.length) return { ok: false, error: "objc_msgSend not found" };

  const hs = [];
  for (let hi = 0; hi < fns.length; hi++) {
    try {
      const h = Interceptor.attach(fns[hi].ptr, {
        onEnter(args) {
          try {
            if (!READ_TRACE.installed) return;
            const selp = ptr(args[1]);
            const namep = selGetName(selp);
            if (!namep || namep.isNull()) return;
            const s = Memory.readCString(namep) || "";
            if (!s) return;
            if (s.startsWith("ready")) return;
            let hit = false;
            for (let pi = 0; pi < pats.length; pi++) {
              if (s.indexOf(pats[pi]) !== -1) { hit = true; break; }
            }
            if (!hit) return;
            const rec = {
              ts: nowMs(),
              callerIda: _idaFromPtr(this.returnAddress),
              selector: s,
              receiver: ptr(args[0]).toString(),
              a2: ptr(args[2]).toString(),
              a3: ptr(args[3]).toString(),
              a4: ptr(args[4]).toString(),
              a5: ptr(args[5]).toString(),
              a6: ptr(args[6]).toString(),
            };
            try {
              if (objGetClass && classGetName) {
                const cls = objGetClass(ptr(args[0]));
                const cnp = cls && !cls.isNull() ? classGetName(cls) : ptr("0x0");
                rec.receiverClass = cnp && !cnp.isNull() ? (Memory.readCString(cnp) || "") : "";
              } else {
                rec.receiverClass = "";
              }
            } catch (_) { rec.receiverClass = ""; }
            READ_TRACE.hits.push(rec);
            if (READ_TRACE.hits.length >= READ_TRACE.maxHits) _readTraceOffNoThrow();
          } catch (_) {}
        }
      });
      hs.push(h);
    } catch (_) {}
  }
  if (!hs.length) return { ok: false, error: "failed to attach objc_msgSend hooks" };
  READ_TRACE._h = { detach: () => { for (let i = 0; i < hs.length; i++) { try { hs[i].detach(); } catch (_) {} } } };
  READ_TRACE.installed = true;
  try {
    const dur = Math.max(0, Math.min(300000, Number(ms || 8000) | 0));
    if (dur > 0) READ_TRACE._timer = setTimeout(_readTraceOffNoThrow, dur);
  } catch (_) {}
  return { ok: true, installed: true, maxHits: READ_TRACE.maxHits, patterns: pats, hooks: fns.map(x => x.name) };
}

function readTraceGet(maxN) {
  const lim = Math.max(1, Math.min(500, Number(maxN || 120) | 0));
  const xs = READ_TRACE.hits || [];
  const n = Math.min(lim, xs.length);
  const out = [];
  for (let i = xs.length - n; i < xs.length; i++) out.push(xs[i]);
  return { ok: true, installed: READ_TRACE.installed, count: xs.length, last: out };
}

function readTraceClear() {
  try { READ_TRACE.hits = []; } catch (_) {}
  return { ok: true };
}

function readTraceOff() {
  _readTraceOffNoThrow();
  return { ok: true };
}

const SELF_SNIFF = {
  installed: false,
  installedAt: 0,
  hookedCount: 0,
  errors: [],
  last: {
    jid: "",
    name: "",
    username: "",
    ts: 0,
    sources: [],
  },
};

const SELF_CACHE = {
  ok: false,
  ts: 0,
  selfJid: "",
  selfName: "",
  selfUsername: "",
  phone: "",
  source: { ctxClass: "", usedOn: "", usedSelector: "" },
};

function refreshSelfCacheAsync() {
  safeObjCInvoke(() => {
    try {
      const a = getSelfNameActive();
      if (!a || !a.ok) return;
      SELF_CACHE.ok = true;
      SELF_CACHE.ts = nowMs();
      SELF_CACHE.selfJid = String(a.selfJid || "").trim();
      SELF_CACHE.selfName = String(a.selfName || "").trim();
      SELF_CACHE.selfUsername = String(a.selfUsername || "").trim();
      SELF_CACHE.phone = String(a.phone || "").trim();
      SELF_CACHE.source = a.source || { ctxClass: "", usedOn: "", usedSelector: "" };
    } catch (_) {}
  });
}

function _selfAddSource(s) {
  try {
    if (!s) return;
    const xs = SELF_SNIFF.last.sources;
    if (!Array.isArray(xs)) return;
    for (let i = 0; i < xs.length; i++) if (xs[i] === s) return;
    xs.push(s);
  } catch (_) {}
}

function _selfSetIfBetter(k, v, src) {
  try {
    const s = String(v || "").trim();
    if (!s) return;
    const cur = String(SELF_SNIFF.last[k] || "");
    if (cur === s) return;
    if (!cur || s.length > cur.length) {
      SELF_SNIFF.last[k] = s;
      SELF_SNIFF.last.ts = nowMs();
      _selfAddSource(src);
    }
  } catch (_) {}
}

function _selfTryStringFromRetval(retval) {
  try {
    if (!objcAvailable()) return "";
    if (!retval || retval.isNull()) return "";
    const o = new ObjC.Object(retval);
    const s = String(o);
    return s ? s.trim() : "";
  } catch (_) {
    return "";
  }
}

function _selfHookSelectorOnClass(cn, isClassMethod, selName) {
  try {
    const k = ObjC.classes[cn];
    if (!k) return false;
    const key = (isClassMethod ? "+" : "-") + " " + String(selName || "");
    const m = k[key];
    if (!m || !m.implementation) return false;
    const impl = m.implementation;
    Interceptor.attach(impl, {
      onLeave(retval) {
        try {
          const s = _selfTryStringFromRetval(retval);
          if (!s) return;
          const src = cn + " " + key;
          if (selName === "currentUserJID") _selfSetIfBetter("jid", s, src);
          else if (selName === "currentUserName") _selfSetIfBetter("name", s, src);
          else if (selName === "currentUserUsername") _selfSetIfBetter("username", s, src);
        } catch (_) {}
      }
    });
    return true;
  } catch (_) {
    return false;
  }
}

function installSelfGetterHooks() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (SELF_SNIFF.installed) return { ok: true, installed: true, hookedCount: SELF_SNIFF.hookedCount };
  SELF_SNIFF.installed = true;
  SELF_SNIFF.installedAt = nowMs();
  SELF_SNIFF.hookedCount = 0;
  SELF_SNIFF.errors = [];
  try {
    const sels = ["currentUserJID", "currentUserName", "currentUserUsername"];
    const perSelCap = 40;
    for (let si = 0; si < sels.length; si++) {
      const sel = sels[si];
      const classes = listClassesRespondingToSelector(sel, 200);
      let n = 0;
      for (let i = 0; i < classes.length && n < perSelCap; i++) {
        const cn = String(classes[i] || "");
        if (!cn) continue;
        if (_selfHookSelectorOnClass(cn, false, sel)) {
          SELF_SNIFF.hookedCount += 1;
          n += 1;
        }
        if (_selfHookSelectorOnClass(cn, true, sel)) {
          SELF_SNIFF.hookedCount += 1;
          n += 1;
        }
      }
    }
  } catch (e) {
    try { SELF_SNIFF.errors.push(String(e)); } catch (_) {}
  }
  return { ok: true, installed: true, hookedCount: SELF_SNIFF.hookedCount, installedAt: SELF_SNIFF.installedAt };
}

function tryGetCurrentUserFields() {
  const out = { ok: false, jid: "", name: "", username: "", sourceClass: "", sourceMethod: "" };
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const selectors = ["currentUserJID", "currentUserName", "currentUserUsername"];
  const candidates = listClassesRespondingToSelector("currentUserJID", 120);
  for (let i = 0; i < candidates.length; i++) {
    const cn = candidates[i];
    try {
      const k = ObjC.classes[cn];
      if (!k) continue;
      let inst = null;
      if (k.respondsToSelector_(ObjC.selector("currentUserJID"))) inst = k;
      if (!inst) inst = tryGetSingletonInstance(k);
      if (!inst) continue;
      const jidObj = tryCall0(inst, "currentUserJID");
      const jid = tryReadNSString(jidObj).trim();
      if (!jid || jid.indexOf("@") === -1) continue;
      out.jid = jid;
      out.sourceClass = cn;
      out.sourceMethod = inst === k ? "+currentUserJID" : "-currentUserJID";
      const nameObj = tryCall0(inst, "currentUserName");
      const unameObj = tryCall0(inst, "currentUserUsername");
      out.name = tryReadNSString(nameObj).trim();
      out.username = tryReadNSString(unameObj).trim();
      out.ok = true;
      return out;
    } catch (_) {}
  }
  return out;
}

function objcCallNoArg(obj, selName) {
  try {
    if (!objcAvailable() || !obj || !selName) return null;
    const m1 = "- " + String(selName);
    if (obj[m1] && typeof obj[m1] === "function") return obj[m1]();
    if (obj[selName] && typeof obj[selName] === "function") return obj[selName]();
    return null;
  } catch (_) {
    return null;
  }
}

function objcCallClassNoArg(klass, selName) {
  try {
    if (!objcAvailable() || !klass || !selName) return null;
    const m1 = "+ " + String(selName);
    if (klass[m1] && typeof klass[m1] === "function") return klass[m1]();
    if (klass[selName] && typeof klass[selName] === "function") return klass[selName]();
    return null;
  } catch (_) {
    return null;
  }
}

function objcCallNoArgString(obj, selName) {
  try {
    const v = objcCallNoArg(obj, selName);
    if (v === null || v === undefined) return "";
    const s = String(v);
    return s ? s.trim() : "";
  } catch (_) {
    return "";
  }
}

function _getUIApplicationDelegateActive() {
  try {
    if (!objcAvailable()) return null;
    const UIApp = ObjC.classes.UIApplication;
    if (!UIApp || !UIApp["+ sharedApplication"]) return null;
    const app = UIApp["+ sharedApplication"]();
    if (!app) return null;
    if (app["- delegate"] && typeof app["- delegate"] === "function") return app["- delegate"]();
    if (app.delegate && typeof app.delegate === "function") return app.delegate();
    return null;
  } catch (_) {
    return null;
  }
}

function _getKeyWindowActive(app) {
  try {
    if (!objcAvailable()) return null;
    if (!app) {
      const UIApp = ObjC.classes.UIApplication;
      if (!UIApp || !UIApp["+ sharedApplication"]) return null;
      app = UIApp["+ sharedApplication"]();
    }
    if (!app) return null;
    try {
      if (app["- keyWindow"] && typeof app["- keyWindow"] === "function") {
        const w = app["- keyWindow"]();
        if (w) return w;
      }
    } catch (_) {}
    try {
      if (app["- windows"] && typeof app["- windows"] === "function") {
        const ws = app["- windows"]();
        const n = (ws && objcHasSelector(ws, "count")) ? Number(ws.count()) : 0;
        for (let i = 0; i < n; i++) {
          let w = null;
          try { if (objcHasSelector(ws, "objectAtIndex:")) w = ws.objectAtIndex_(i); } catch (_) { w = null; }
          if (!w) continue;
          try {
            if (objcHasSelector(w, "isKeyWindow")) {
              const k = w.isKeyWindow();
              if (k === 1 || k === true || String(k) === "1") return w;
            }
          } catch (_) {}
          try {
            if (objcHasSelector(w, "windowLevel") && objcHasSelector(w, "isHidden")) {
              const hidden = w.isHidden();
              if (hidden === 1 || hidden === true || String(hidden) === "1") continue;
              return w;
            }
          } catch (_) {}
        }
      }
    } catch (_) {}
    return null;
  } catch (_) {
    return null;
  }
}

function _unwrapVC(vc) {
  try {
    if (!vc) return null;
    if (vc instanceof ObjC.Object) return vc;
    return new ObjC.Object(vc);
  } catch (_) {
    return null;
  }
}

function _pickNextViewControllers(vc) {
  const out = [];
  const o = _unwrapVC(vc);
  if (!o) return out;
  try {
    if (objcHasSelector(o, "presentedViewController")) {
      const p = o.presentedViewController();
      if (p) out.push(p);
    }
  } catch (_) {}
  try {
    if (objcHasSelector(o, "navigationController")) {
      const nc = o.navigationController();
      if (nc) {
        try { if (objcHasSelector(nc, "topViewController")) { const tv = nc.topViewController(); if (tv) out.push(tv); } } catch (_) {}
        try { if (objcHasSelector(nc, "visibleViewController")) { const vv = nc.visibleViewController(); if (vv) out.push(vv); } } catch (_) {}
      }
    }
  } catch (_) {}
  try {
    if (objcHasSelector(o, "selectedViewController")) {
      const sv = o.selectedViewController();
      if (sv) out.push(sv);
    }
  } catch (_) {}
  try {
    if (objcHasSelector(o, "childViewControllers")) {
      const cs = o.childViewControllers();
      const n = (cs && objcHasSelector(cs, "count")) ? Number(cs.count()) : 0;
      for (let i = 0; i < n; i++) {
        try { if (objcHasSelector(cs, "objectAtIndex:")) { const c = cs.objectAtIndex_(i); if (c) out.push(c); } } catch (_) {}
      }
    }
  } catch (_) {}
  try {
    if (objcHasSelector(o, "viewControllers")) {
      const vs = o.viewControllers();
      const n = (vs && objcHasSelector(vs, "count")) ? Number(vs.count()) : 0;
      for (let i = 0; i < n; i++) {
        try { if (objcHasSelector(vs, "objectAtIndex:")) { const c = vs.objectAtIndex_(i); if (c) out.push(c); } } catch (_) {}
      }
    }
  } catch (_) {}
  return out;
}

function _findViewControllerByClassName(root, wantClassName, maxNodes) {
  try {
    const want = String(wantClassName || "").trim();
    if (!want) return null;
    const cap = Math.max(20, Math.min(500, Number(maxNodes || 200) | 0));
    const q = [];
    const seen = {};
    if (root) q.push(root);
    let n = 0;
    while (q.length && n < cap) {
      const cur = _unwrapVC(q.shift());
      n++;
      if (!cur) continue;
      let key = "";
      try { key = cur.handle ? cur.handle.toString() : ""; } catch (_) { key = ""; }
      if (key && seen[key]) continue;
      if (key) seen[key] = 1;
      let cn = "";
      try { cn = String(cur.$className || ""); } catch (_) { cn = ""; }
      if (cn === want) return cur;
      const next = _pickNextViewControllers(cur);
      for (let i = 0; i < next.length; i++) q.push(next[i]);
    }
    return null;
  } catch (_) {
    return null;
  }
}

function _findWAChatListViewControllerActive() {
  try {
    if (!objcAvailable()) return null;
    const UIApp = ObjC.classes.UIApplication;
    if (!UIApp || !UIApp["+ sharedApplication"]) return null;
    const app = UIApp["+ sharedApplication"]();
    const w = _getKeyWindowActive(app);
    if (!w) return null;
    let root = null;
    try { if (objcHasSelector(w, "rootViewController")) root = w.rootViewController(); } catch (_) { root = null; }
    if (!root) return null;
    return _findViewControllerByClassName(root, "WAChatListViewController", 260);
  } catch (_) {
    return null;
  }
}

function _resolveCtxMainActive() {
  try {
    const del = _getUIApplicationDelegateActive();
    if (!del) return { ok: false, error: "no UIApplication.delegate" };
    let ctx = null;
    try {
      if (del.$ivars) {
        ctx = del.$ivars._userContext || del.$ivars.userContext || del.$ivars._context || null;
        if (!ctx) {
          const keys = Object.keys(del.$ivars || {});
          for (let i = 0; i < keys.length; i++) {
            const k = keys[i];
            if (!k) continue;
            const kl = String(k).toLowerCase();
            if (kl.indexOf("usercontext") !== -1) {
              ctx = del.$ivars[k];
              break;
            }
          }
        }
      }
    } catch (_) {
      ctx = null;
    }
    if (!ctx) return { ok: false, error: "delegate userContext nil" };
    const o = ctx instanceof ObjC.Object ? ctx : new ObjC.Object(ctx);
    const cn = String(o.$className || "");
    if (!cn) return { ok: false, error: "userContext class missing" };
    return { ok: true, ctx: o, className: cn };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _resolveCtxMainStableExplore() {
  try {
    if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
    const cls = ObjC.classes.WAContextMain;
    const sels = ["+ sharedInstance", "+ shared", "+ main", "+ sharedMain", "+ sharedContext", "+ defaultContext", "+ currentContext", "+ context"];
    const isCtx = (o) => {
      try {
        if (!o) return false;
        const cn = String(o.$className || "");
        if (cn === "WAContextMain") return true;
        return !!(objcHasSelector(o, "chatStorage") || objcHasSelector(o, "messageSender"));
      } catch (_) { return false; }
    };
    if (cls) {
      for (let i = 0; i < sels.length; i++) {
        const s = sels[i];
        try {
          if (!cls[s] || typeof cls[s] !== "function") continue;
          const v = cls[s]();
          const o = v instanceof ObjC.Object ? v : (v ? new ObjC.Object(v) : null);
          if (o && isCtx(o)) return { ok: true, ctx: o, source: "WAContextMain." + s };
        } catch (_) {}
      }
    }
    const r = _resolveCtxMainActive();
    if (r && r.ok && r.ctx) return { ok: true, ctx: r.ctx, source: "UIApplication.delegate.$ivars" };
    return { ok: false, error: "no context", source: "" };
  } catch (e) {
    return { ok: false, error: String(e), source: "" };
  }
}

function _resolveCoreFixedExplore() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const del = _getUIApplicationDelegateActive();
  if (!del) return { ok: false, error: "no UIApplication.delegate" };
  let ctx = null;
  try { if (del.$ivars) ctx = del.$ivars._userContext || del.$ivars.userContext || del.$ivars._context || null; } catch (_) { ctx = null; }
  if (!ctx) return { ok: false, error: "delegate userContext nil" };
  const o = ctx instanceof ObjC.Object ? ctx : new ObjC.Object(ctx);
  const cn = String(o.$className || "");
  if (cn !== "WAContextMain") return { ok: false, error: "userContext not WAContextMain", className: cn };
  let storage = null;
  let txnMgr = null;
  try { if (objcHasSelector(o, "chatStorage")) storage = o.chatStorage(); } catch (_) { storage = null; }
  try { if (objcHasSelector(o, "chatSessionTransactionManager")) txnMgr = o.chatSessionTransactionManager(); } catch (_) { txnMgr = null; }
  if (!storage) return { ok: false, error: "ctxMain.chatStorage nil" };
  return { ok: true, ctxMain: o, storage, txnMgr };
}

function _getIvarLike(obj, needles) {
  try {
    if (!objcAvailable() || !obj || !obj.$ivars) return null;
    const xs = Array.isArray(needles) ? needles : [String(needles || "")];
    const keys = Object.keys(obj.$ivars || {});
    for (let i = 0; i < keys.length; i++) {
      const k = String(keys[i] || "");
      const kl = k.toLowerCase();
      for (let j = 0; j < xs.length; j++) {
        const n = String(xs[j] || "").toLowerCase();
        if (n && kl.indexOf(n) !== -1) {
          try { return obj.$ivars[k]; } catch (_) { return null; }
        }
      }
    }
  } catch (_) {}
  return null;
}

function _resolveChatManager(core) {
  try {
    if (!core || !core.ok || !core.ctxMain) return { ok: false, error: "no core/ctx" };
    const ctx = core.ctxMain;
    try {
      if (objcHasSelector(ctx, "chatManager")) {
        const v = objcCallNoArg(ctx, "chatManager");
        if (v) {
          const o = v instanceof ObjC.Object ? v : new ObjC.Object(v);
          return { ok: true, mgr: o, source: "ctxMain.chatManager" };
        }
      }
    } catch (_) {}
    try {
      const iv = _getIvarLike(ctx, ["chatmanager"]);
      if (iv) {
        const o = iv instanceof ObjC.Object ? iv : new ObjC.Object(iv);
        return { ok: true, mgr: o, source: "ctxMain.$ivars.*chatmanager*" };
      }
    } catch (_) {}
    return { ok: false, error: "chatManager unavailable" };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _extractJidStringFromMaybeObj(x) {
  try {
    if (x === null || x === undefined) return "";
    if (!objcAvailable()) return String(x || "").trim();
    const o = x instanceof ObjC.Object ? x : new ObjC.Object(x);
    if (!o) return "";
    try {
      const uj = objcCallNoArg(o, "userJID");
      if (uj) {
        const s0 = objcCallNoArgString(uj instanceof ObjC.Object ? uj : new ObjC.Object(uj), "stringRepresentation");
        if (s0 && s0.indexOf("@") !== -1) return s0;
      }
    } catch (_) {}
    try {
      const dj = objcCallNoArg(o, "deviceJID");
      if (dj) {
        const djObj = dj instanceof ObjC.Object ? dj : new ObjC.Object(dj);
        const uj = objcCallNoArg(djObj, "userJID");
        if (uj) {
          const s0 = objcCallNoArgString(uj instanceof ObjC.Object ? uj : new ObjC.Object(uj), "stringRepresentation");
          if (s0 && s0.indexOf("@") !== -1) return s0;
        }
      }
    } catch (_) {}
    const s1 = objcCallNoArgString(o, "stringRepresentation");
    if (s1 && s1.indexOf("@") !== -1) return s1;
    const sJid = objcCallNoArgString(o, "jid");
    if (sJid && sJid.indexOf("@") !== -1) return sJid;
    const sJid2 = objcCallNoArgString(o, "jidString");
    if (sJid2 && sJid2.indexOf("@") !== -1) return sJid2;
    const s2 = String(o).trim();
    return s2;
  } catch (_) {
    try { return String(x || "").trim(); } catch (_) { return ""; }
  }
}

function _extractPhoneFromMaybeObj(x) {
  try {
    if (x === null || x === undefined) return "";
    const s0 = String(x).trim();
    const d0 = extractDigits(s0);
    if (d0.length >= 8) return d0;
    if (!objcAvailable()) return "";
    const o = x instanceof ObjC.Object ? x : new ObjC.Object(x);
    if (!o) return "";
    const cands = ["phoneNumber", "rawPhoneNumber", "nationalNumber", "number"];
    for (let i = 0; i < cands.length; i++) {
      const sel = cands[i];
      if (!objcHasSelector(o, sel)) continue;
      const v = objcCallNoArgString(o, sel);
      const d = extractDigits(v);
      if (d.length >= 8) return d;
    }
  } catch (_) {}
  return "";
}

function _isLikelyUsername(s) {
  try {
    const v = String(s || "").trim();
    if (!v) return false;
    if (v.length > 64) return false;
    if (v[0] === "<" && v.indexOf("0x") !== -1) return false;
    if (v.indexOf(" ") !== -1) return false;
    for (let i = 0; i < v.length; i++) {
      const c = v.charCodeAt(i);
      const ok =
        (c >= 48 && c <= 57) ||
        (c >= 65 && c <= 90) ||
        (c >= 97 && c <= 122) ||
        v[i] === "_" ||
        v[i] === "." ||
        v[i] === "-";
      if (!ok) return false;
    }
    return true;
  } catch (_) {
    return false;
  }
}

function _cleanMaybeUsername(v) {
  try {
    const s = String(v || "").trim();
    if (_isLikelyUsername(s)) return s;
  } catch (_) {}
  return "";
}

function _scanIvarsForHints(obj, tags) {
  const out = { jid: "", phone: "", username: "", name: "", hits: [] };
  try {
    if (!objcAvailable() || !obj || !obj.$ivars) return out;
    const keys = Object.keys(obj.$ivars || {});
    for (let i = 0; i < keys.length; i++) {
      const k = keys[i];
      if (!k) continue;
      const kl = String(k).toLowerCase();
      if (tags && tags.length) {
        let ok = false;
        for (let j = 0; j < tags.length; j++) {
          if (kl.indexOf(tags[j]) !== -1) { ok = true; break; }
        }
        if (!ok) continue;
      }
      let v = null;
      try { v = obj.$ivars[k]; } catch (_) { v = null; }
      if (!v) continue;
      if (!out.jid && (kl.indexOf("jid") !== -1 || kl.indexOf("userjid") !== -1)) {
        const s = _extractJidStringFromMaybeObj(v);
        if (s && s.indexOf("@") !== -1) { out.jid = s; out.hits.push("ivar:" + k); }
      }
      if (!out.phone && (kl.indexOf("phone") !== -1 || kl.indexOf("msisdn") !== -1)) {
        const p = _extractPhoneFromMaybeObj(v);
        if (p) { out.phone = p; out.hits.push("ivar:" + k); }
      }
      if (!out.username && kl.indexOf("username") !== -1) {
        const u = _cleanMaybeUsername(v);
        if (u) { out.username = u; out.hits.push("ivar:" + k); }
      }
      if (!out.name && (kl.indexOf("name") !== -1 || kl.indexOf("profilename") !== -1)) {
        const n = String(v).trim();
        if (n && n.length <= 64) { out.name = n; out.hits.push("ivar:" + k); }
      }
      if (out.jid && out.phone && out.username && out.name) break;
    }
  } catch (_) {}
  return out;
}

function getSelfNameActive() {
  const out = {
    ok: false,
    selfJid: "",
    selfName: "",
    selfUsername: "",
    phone: "",
    source: { ctxClass: "", usedOn: "", usedSelector: "" },
  };
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const res = _resolveCtxMainActive();
  if (!res || !res.ok) return { ok: false, error: String((res && res.error) || "ctx missing") };
  out.source.ctxClass = String(res.className || "");
  const ctx = res.ctx;
  const probes = [];
  probes.push({ obj: ctx, tag: "ctx" });
  try {
    const sender = ctx && (ctx["- messageSender"] ? ctx["- messageSender"]() : (ctx.$ivars ? (ctx.$ivars._messageSender || ctx.$ivars.messageSender || null) : null));
    if (sender) probes.push({ obj: sender instanceof ObjC.Object ? sender : new ObjC.Object(sender), tag: "messageSender" });
  } catch (_) {}
  try {
    const as = ctx && (ctx["- accountService"] ? ctx["- accountService"]() : (ctx.$ivars ? (ctx.$ivars._accountService || ctx.$ivars.accountService || null) : null));
    if (as) probes.push({ obj: as instanceof ObjC.Object ? as : new ObjC.Object(as), tag: "accountService" });
  } catch (_) {}
  try {
    const ap = ctx && (ctx["- accountProvider"] ? ctx["- accountProvider"]() : (ctx.$ivars ? (ctx.$ivars._accountProvider || ctx.$ivars.accountProvider || null) : null));
    if (ap) probes.push({ obj: ap instanceof ObjC.Object ? ap : new ObjC.Object(ap), tag: "accountProvider" });
  } catch (_) {}
  try {
    const fetcher = ctx && (ctx["- ownUserJIDFetcher"] ? ctx["- ownUserJIDFetcher"]() : (ctx.$ivars ? (ctx.$ivars._ownUserJIDFetcher || ctx.$ivars.ownUserJIDFetcher || null) : null));
    if (fetcher) probes.push({ obj: fetcher instanceof ObjC.Object ? fetcher : new ObjC.Object(fetcher), tag: "ownUserJIDFetcher" });
  } catch (_) {}

  try {
    const helpers = ObjC.classes.WAProfileNameHelpers;
    const sel = "currentProfileNameWithUseDeviceNameIfNeeded:userContext:";
    if (helpers && helpers["+ " + sel]) {
      const s = String(helpers["+ " + sel](1, ctx) || "").trim();
      if (s) {
        out.selfName = s;
        out.source.usedOn = "WAProfileNameHelpers";
        out.source.usedSelector = sel;
      }
    }
  } catch (_) {}

  try {
    if (!out.selfJid || !out.phone || !out.selfUsername) {
      const h = _scanIvarsForHints(ctx, ["jid", "userjid", "phone", "msisdn", "username"]);
      if (!out.selfJid && h.jid) {
        out.selfJid = h.jid;
        out.phone = derivePhoneFromJid(h.jid) || out.phone;
        if (!out.source.usedOn) out.source.usedOn = "ctx:$ivars";
        if (!out.source.usedSelector) out.source.usedSelector = (h.hits || []).join(",");
      }
      if (!out.phone && h.phone) out.phone = h.phone;
      if (!out.selfUsername && h.username) out.selfUsername = h.username;
    }
  } catch (_) {}

  const jidSelectors = ["ownUserJID", "userJID", "currentUserJID", "myUserJID", "deviceJID"];
  const nameSelectors = ["currentUserName", "currentProfileName", "profileName", "displayName", "pushName", "name"];
  const usernameSelectors = ["currentUserUsername", "username", "currentUsername", "userName"];

  for (let pi = 0; pi < probes.length; pi++) {
    const o = probes[pi].obj;
    if (!o) continue;
    const tag = probes[pi].tag;
    const cn = String(o.$className || "");
    try {
      if (!out.selfJid || !out.phone || !out.selfUsername) {
        const h = _scanIvarsForHints(o, ["jid", "userjid", "phone", "msisdn", "username"]);
        if (!out.selfJid && h.jid) {
          out.selfJid = h.jid;
          out.phone = derivePhoneFromJid(h.jid) || out.phone;
          out.source.usedOn = tag + ":" + cn + ":$ivars";
          out.source.usedSelector = (h.hits || []).join(",");
        }
        if (!out.phone && h.phone) out.phone = h.phone;
        if (!out.selfUsername && h.username) out.selfUsername = h.username;
      }
    } catch (_) {}
    try {
      if (!out.selfJid) {
        for (let si = 0; si < jidSelectors.length; si++) {
          const sel = jidSelectors[si];
          if (!objcHasSelector(o, sel)) continue;
          const jidStr = _extractJidStringFromMaybeObj(objcCallNoArg(o, sel));
          if (jidStr && jidStr.indexOf("@") !== -1) {
            out.selfJid = jidStr;
            out.phone = derivePhoneFromJid(jidStr);
            out.source.usedOn = tag + ":" + cn;
            out.source.usedSelector = sel;
            break;
          }
        }
      }
      if (!out.selfUsername) {
        for (let si = 0; si < usernameSelectors.length; si++) {
          const sel = usernameSelectors[si];
          if (!objcHasSelector(o, sel)) continue;
          const v = _cleanMaybeUsername(objcCallNoArgString(o, sel));
          if (v) {
            out.selfUsername = v;
            if (!out.source.usedOn) out.source.usedOn = tag + ":" + cn;
            if (!out.source.usedSelector) out.source.usedSelector = sel;
            break;
          }
        }
      }
      if (!out.selfName) {
        for (let si = 0; si < nameSelectors.length; si++) {
          const sel = nameSelectors[si];
          if (!objcHasSelector(o, sel)) continue;
          const v = objcCallNoArgString(o, sel);
          if (v) {
            out.selfName = v;
            if (!out.source.usedOn) out.source.usedOn = tag + ":" + cn;
            if (!out.source.usedSelector) out.source.usedSelector = sel;
            break;
          }
        }
      }
    } catch (_) {}
  }

  out.ok = !!(out.selfJid || out.selfName || out.selfUsername || out.phone);
  return out;
}

function bytesToBase64(u8) {
  try {
    if (!u8 || u8.length === 0) return "";
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let out = "";
    let i = 0;
    while (i + 2 < u8.length) {
      const n = ((u8[i] & 0xff) << 16) | ((u8[i + 1] & 0xff) << 8) | (u8[i + 2] & 0xff);
      out += alphabet[(n >>> 18) & 63];
      out += alphabet[(n >>> 12) & 63];
      out += alphabet[(n >>> 6) & 63];
      out += alphabet[n & 63];
      i += 3;
    }
    const rem = u8.length - i;
    if (rem === 1) {
      const n = (u8[i] & 0xff) << 16;
      out += alphabet[(n >>> 18) & 63];
      out += alphabet[(n >>> 12) & 63];
      out += "==";
    } else if (rem === 2) {
      const n = ((u8[i] & 0xff) << 16) | ((u8[i + 1] & 0xff) << 8);
      out += alphabet[(n >>> 18) & 63];
      out += alphabet[(n >>> 12) & 63];
      out += alphabet[(n >>> 6) & 63];
      out += "=";
    }
    return out;
  } catch (_) {
    return "";
  }
}

function nsDataToU8(nsData, hardCapBytes) {
  try {
    if (!objcAvailable() || !nsData) return null;
    const d = nsData instanceof ObjC.Object ? nsData : new ObjC.Object(nsData);
    if (!d) return null;
    const len = Number(d.length());
    if (!len || len <= 0) return new Uint8Array(0);
    const cap = Math.max(0, Math.min(len, Math.max(0, hardCapBytes | 0)));
    const bytesPtr = d.bytes();
    if (!bytesPtr || bytesPtr.isNull()) return null;
    const buf = Memory.readByteArray(bytesPtr, cap);
    if (!buf) return null;
    return new Uint8Array(buf);
  } catch (_) {
    return null;
  }
}

function _enumerateFilesUnder(root, matchFn, maxHits, maxWalk) {
  const out = [];
  const cap = Math.max(1, Math.min(50, maxHits | 0 || 10));
  const walkCap = Math.max(200, Math.min(50000, maxWalk | 0 || 8000));
  if (!objcAvailable()) return out;
  try {
    const fm = ObjC.classes.NSFileManager.defaultManager();
    const NSURL = ObjC.classes.NSURL;
    const url = NSURL.fileURLWithPath_(nsString(String(root || "")));
    const enumr = fm.enumeratorAtURL_includingPropertiesForKeys_options_errorHandler_(url, null, 0, null);
    if (!enumr) return out;
    let walked = 0;
    while (out.length < cap && walked < walkCap) {
      const next = enumr.nextObject();
      if (!next) break;
      walked += 1;
      let p = "";
      try { p = tryReadNSString(next.path()); } catch (_) { p = ""; }
      if (!p) continue;
      try {
        if (matchFn && matchFn(p)) out.push(p);
      } catch (_) {}
    }
  } catch (_) {}
  return out;
}

function _getSpotlightProfileV2Dir() {
  const home = getHomeDir();
  if (!home) return "";
  return joinPath(home, "Library/Caches/spotlight-profile-v2");
}

function _looksLikeImagePath(p) {
  try {
    const pl = String(p || "").toLowerCase();
    return pl.endsWith(".jpg") || pl.endsWith(".jpeg") || pl.endsWith(".png") || pl.endsWith(".webp");
  } catch (_) {
    return false;
  }
}

function _getSelfAvatarViaSpotlightProfileV2(hint, maxHits) {
  const out = { ok: false, dir: "", hint: String(hint || "").trim(), paths: [] };
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const dir = _getSpotlightProfileV2Dir();
  out.dir = dir;
  if (!dir || !fileExists(dir)) return { ok: false, error: "spotlight dir missing" };

  const needle = out.hint.toLowerCase();
  const matchFn = (p) => {
    const pl = String(p || "").toLowerCase();
    if (!_looksLikeImagePath(pl)) return false;
    if (!needle) return true;
    return pl.indexOf(needle) !== -1;
  };
  const xs = _enumerateFilesUnder(dir, matchFn, Math.max(1, Math.min(50, maxHits | 0 || 10)), 12000);
  out.paths = xs || [];
  out.ok = out.paths.length > 0;
  return out;
}

function _getSelfAvatarViaFileSearch(hint) {
  const out = { ok: false, home: "", hint: String(hint || "").trim(), paths: [] };
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const home = getHomeDir();
  out.home = home;
  if (!home) return { ok: false, error: "home missing" };
  const needle = out.hint.toLowerCase();
  const matchFn = (p) => {
    const pl = String(p || "").toLowerCase();
    if (needle && pl.indexOf(needle) !== -1) return true;
    if (pl.indexOf("profile") !== -1 && (pl.indexOf("picture") !== -1 || pl.indexOf("photo") !== -1)) return true;
    if (pl.indexOf("avatar") !== -1) return true;
    if (pl.indexOf("myprofile") !== -1) return true;
    if (_looksLikeImagePath(pl)) return true;
    return false;
  };
  const roots = [
    home,
    joinPath(home, "Library"),
    joinPath(home, "Library/Caches"),
    joinPath(home, "Library/Application Support"),
    joinPath(home, "Documents"),
  ];
  const seen = {};
  for (let i = 0; i < roots.length && out.paths.length < 20; i++) {
    const r = roots[i];
    const xs = _enumerateFilesUnder(r, matchFn, 20 - out.paths.length, 12000);
    for (let j = 0; j < xs.length && out.paths.length < 20; j++) {
      const p = xs[j];
      if (seen[p]) continue;
      seen[p] = true;
      out.paths.push(p);
    }
  }
  out.ok = out.paths.length > 0;
  return out;
}

function tryGetMyProfilePictureInfo(includeThumbnailData) {
  const out = {
    ok: false,
    providerClass: "",
    providerMethod: "",
    picturePath: "",
    picturePathJpg: "",
    thumbnailPath: "",
    thumbnailB64: "",
    thumbnailBytes: 0,
    pictureId: "",
  };
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };

  const pathSel0 = "defaultFullPathToMyProfilePicture";
  const thumbPathSel0 = "defaultFullPathToMyProfilePictureThumbnail";
  const picMetaSel0 = "myProfilePictureMetadata";
  const picIdSel0 = "myProfilePictureReturningFullsizeImageAvailability:";
  const thumbDataSel0 = "myProfilePictureThumbnailData";

  const candidates = [];
  const c1 = listClassesRespondingToSelector(pathSel0, 30);
  const c2 = listClassesRespondingToSelector("fullPathToMyProfilePictureUsingExtension:", 30);
  for (let i = 0; i < c1.length; i++) candidates.push(c1[i]);
  for (let i = 0; i < c2.length; i++) candidates.push(c2[i]);

  const seen = {};
  for (let i = 0; i < candidates.length; i++) {
    const cn = String(candidates[i] || "");
    if (!cn || seen[cn]) continue;
    seen[cn] = true;
    try {
      const k = ObjC.classes[cn];
      if (!k) continue;
      let inst = null;
      if (k.respondsToSelector_(ObjC.selector(pathSel0)) || k.respondsToSelector_(ObjC.selector("fullPathToMyProfilePictureUsingExtension:"))) inst = k;
      if (!inst) inst = tryGetSingletonInstance(k);
      if (!inst) continue;

      try {
        if (objcHasSelector(inst, pathSel0)) {
          const p = tryReadNSString(tryCall0(inst, pathSel0)).trim();
          if (p) out.picturePath = p;
        }
      } catch (_) {}

      try {
        if (objcHasSelector(inst, "fullPathToMyProfilePictureUsingExtension:")) {
          const fn = inst["fullPathToMyProfilePictureUsingExtension:"];
          if (typeof fn === "function") {
            const pjpg = tryReadNSString(fn.call(inst, nsString("jpg"))).trim();
            if (pjpg) out.picturePathJpg = pjpg;
          }
        }
      } catch (_) {}

      try {
        if (objcHasSelector(inst, thumbPathSel0)) {
          const p = tryReadNSString(tryCall0(inst, thumbPathSel0)).trim();
          if (p) out.thumbnailPath = p;
        }
      } catch (_) {}

      try {
        if (includeThumbnailData && objcHasSelector(inst, thumbDataSel0)) {
          const dataObj = tryCall0(inst, thumbDataSel0);
          const u8 = nsDataToU8(dataObj, 220 * 1024);
          if (u8 && u8.length) {
            out.thumbnailBytes = u8.length;
            out.thumbnailB64 = bytesToBase64(u8);
          }
        }
      } catch (_) {}

      try {
        if (objcHasSelector(inst, picMetaSel0)) {
          const meta = tryCall0(inst, picMetaSel0);
          const s = tryReadNSString(meta).trim();
          if (s) out.pictureId = s;
        }
      } catch (_) {}

      out.ok = !!(out.picturePath || out.picturePathJpg || out.thumbnailPath || out.thumbnailB64 || out.pictureId);
      if (out.ok) {
        out.providerClass = cn;
        out.providerMethod = inst === k ? "+" : "-";
        return out;
      }
    } catch (_) {}
  }
  return out;
}

const SQLITE = (() => {
  const api = {};
  api.ok = false;
  api.err = "";

  function fn(name, ret, args) {
    try {
      const p = Module.findExportByName(null, name);
      if (!p) return null;
      return new NativeFunction(p, ret, args);
    } catch (_) {
      return null;
    }
  }

  const sqlite3_open = fn("sqlite3_open", "int", ["pointer", "pointer"]);
  const sqlite3_close = fn("sqlite3_close", "int", ["pointer"]);
  const sqlite3_prepare_v2 = fn("sqlite3_prepare_v2", "int", ["pointer", "pointer", "int", "pointer", "pointer"]);
  const sqlite3_step = fn("sqlite3_step", "int", ["pointer"]);
  const sqlite3_finalize = fn("sqlite3_finalize", "int", ["pointer"]);
  const sqlite3_errmsg = fn("sqlite3_errmsg", "pointer", ["pointer"]);
  const sqlite3_column_count = fn("sqlite3_column_count", "int", ["pointer"]);
  const sqlite3_column_name = fn("sqlite3_column_name", "pointer", ["pointer", "int"]);
  const sqlite3_column_type = fn("sqlite3_column_type", "int", ["pointer", "int"]);
  const sqlite3_column_text = fn("sqlite3_column_text", "pointer", ["pointer", "int"]);
  const sqlite3_column_int64 = fn("sqlite3_column_int64", "int64", ["pointer", "int"]);
  const sqlite3_bind_text = fn("sqlite3_bind_text", "int", ["pointer", "int", "pointer", "int", "pointer"]);
  const sqlite3_reset = fn("sqlite3_reset", "int", ["pointer"]);
  const sqlite3_clear_bindings = fn("sqlite3_clear_bindings", "int", ["pointer"]);

  if (!sqlite3_open || !sqlite3_close || !sqlite3_prepare_v2 || !sqlite3_step || !sqlite3_finalize) {
    api.ok = false;
    api.err = "sqlite3 exports missing";
    return api;
  }

  api.ok = true;

  const SQLITE_ROW = 100;
  const SQLITE_DONE = 101;
  const SQLITE_TEXT = 3;
  const SQLITE_INTEGER = 1;

  function errmsg(db) {
    try {
      if (!sqlite3_errmsg || db.isNull()) return "";
      const p = sqlite3_errmsg(db);
      return p ? Memory.readUtf8String(p) : "";
    } catch (_) {
      return "";
    }
  }

  function open(path) {
    const pPath = Memory.allocUtf8String(String(path || ""));
    const outDb = Memory.alloc(Process.pointerSize);
    outDb.writePointer(ptr(0));
    const rc = sqlite3_open(pPath, outDb);
    const db = outDb.readPointer();
    if (rc !== 0 || db.isNull()) {
      try { if (!db.isNull()) sqlite3_close(db); } catch (_) {}
      return { ok: false, error: errmsg(db) || ("sqlite3_open rc=" + rc) };
    }
    return { ok: true, db };
  }

  function close(db) {
    try {
      if (!db || db.isNull()) return;
      sqlite3_close(db);
    } catch (_) {}
  }

  function query(db, sql, params, limitRows) {
    const lim = Math.max(1, Math.min(2000, (limitRows | 0) || 200));
    const pSql = Memory.allocUtf8String(String(sql || ""));
    const outStmt = Memory.alloc(Process.pointerSize);
    outStmt.writePointer(ptr(0));
    const rc = sqlite3_prepare_v2(db, pSql, -1, outStmt, ptr(0));
    const stmt = outStmt.readPointer();
    if (rc !== 0 || stmt.isNull()) {
      try { if (!stmt.isNull()) sqlite3_finalize(stmt); } catch (_) {}
      return { ok: false, error: errmsg(db) || ("prepare rc=" + rc) };
    }

    try {
      if (Array.isArray(params) && params.length && sqlite3_bind_text) {
        for (let i = 0; i < params.length; i++) {
          const v = params[i];
          const s = String(v === null || v === undefined ? "" : v);
          const pv = Memory.allocUtf8String(s);
          sqlite3_bind_text(stmt, i + 1, pv, -1, ptr(0));
        }
      }

      const colCount = sqlite3_column_count ? sqlite3_column_count(stmt) : 0;
      const cols = [];
      for (let i = 0; i < colCount; i++) {
        try {
          const pn = sqlite3_column_name ? sqlite3_column_name(stmt, i) : ptr(0);
          cols.push(pn && !pn.isNull() ? Memory.readUtf8String(pn) : ("c" + i));
        } catch (_) {
          cols.push("c" + i);
        }
      }

      const rows = [];
      while (rows.length < lim) {
        const sRc = sqlite3_step(stmt);
        if (sRc === SQLITE_ROW) {
          const row = {};
          for (let i = 0; i < colCount; i++) {
            const t = sqlite3_column_type ? sqlite3_column_type(stmt, i) : SQLITE_TEXT;
            if (t === SQLITE_INTEGER && sqlite3_column_int64) {
              try { row[cols[i]] = Number(sqlite3_column_int64(stmt, i)); } catch (_) { row[cols[i]] = 0; }
            } else if (t === SQLITE_TEXT && sqlite3_column_text) {
              try {
                const pt = sqlite3_column_text(stmt, i);
                row[cols[i]] = pt && !pt.isNull() ? Memory.readUtf8String(pt) : "";
              } catch (_) {
                row[cols[i]] = "";
              }
            } else {
              try {
                const pt = sqlite3_column_text ? sqlite3_column_text(stmt, i) : ptr(0);
                row[cols[i]] = pt && !pt.isNull() ? Memory.readUtf8String(pt) : "";
              } catch (_) {
                row[cols[i]] = "";
              }
            }
          }
          rows.push(row);
          continue;
        }
        if (sRc === SQLITE_DONE) break;
        return { ok: false, error: errmsg(db) || ("step rc=" + sRc) };
      }
      return { ok: true, rows };
    } finally {
      try {
        if (sqlite3_clear_bindings) sqlite3_clear_bindings(stmt);
        if (sqlite3_reset) sqlite3_reset(stmt);
      } catch (_) {}
      try { sqlite3_finalize(stmt); } catch (_) {}
    }
  }

  api.open = open;
  api.close = close;
  api.query = query;
  return api;
})();

function findPathsByName(fileName, maxHits) {
  const hits = [];
  const cap = Math.max(1, Math.min(50, maxHits | 0 || 10));
  if (!objcAvailable()) return hits;
  try {
    const NSFileManager = ObjC.classes.NSFileManager;
    const NSURL = ObjC.classes.NSURL;
    if (!NSFileManager || !NSURL) return hits;
    const fm = NSFileManager.defaultManager();
    const roots = [];
    const home = getHomeDir();
    if (home) {
      roots.push(home);
      roots.push(joinPath(home, "Documents"));
      roots.push(joinPath(home, "Library"));
      roots.push(joinPath(home, "Library/Application Support"));
      
      // Add common containers
      const sharedContainer = fm.containerURLForSecurityApplicationGroupIdentifier_(nsString("group.net.whatsapp.WhatsApp.shared"));
      if (sharedContainer) {
          const p = sharedContainer.path();
          if (p) roots.push(String(p));
      }
    }
    const baseName = String(fileName || "");
    if (home && baseName) {
      const candidates = [
        joinPath(home, baseName),
        joinPath(home, "Documents/" + baseName),
        joinPath(home, "Library/" + baseName),
        joinPath(home, "Library/Application Support/" + baseName),
        joinPath(home, "Library/Application Support/ChatStorage.sqlite"),
        joinPath(home, "Library/Application Support/ChatStorage/ChatStorage.sqlite"),
      ];
      for (let i = 0; i < candidates.length && hits.length < cap; i++) {
        const p = candidates[i];
        if (p && fileExists(p)) hits.push(p);
      }
      if (hits.length >= cap) return hits;
    }
    for (let i = 0; i < roots.length; i++) {
      const root = roots[i];
      if (!root) continue;
      const url = NSURL.fileURLWithPath_(nsString(root));
      const enumr = fm.enumeratorAtURL_includingPropertiesForKeys_options_errorHandler_(url, null, 0, null);
      if (!enumr) continue;
      while (hits.length < cap) {
        const next = enumr.nextObject();
        if (!next) break;
        const p = tryReadNSString(next.path());
        if (p && p.toLowerCase().endsWith(String(fileName).toLowerCase())) {
          hits.push(p);
        }
      }
      if (hits.length >= cap) break;
    }
  } catch (_) {}
  return hits;
}

function findPathsContaining(substr, maxHits) {
  const hits = [];
  const cap = Math.max(1, Math.min(50, maxHits | 0 || 10));
  const needle = String(substr || "").trim().toLowerCase();
  if (!needle || !objcAvailable()) return hits;
  try {
    const NSFileManager = ObjC.classes.NSFileManager;
    const NSURL = ObjC.classes.NSURL;
    if (!NSFileManager || !NSURL) return hits;
    const fm = NSFileManager.defaultManager();
    const roots = [];
    const home = getHomeDir();
    if (home) {
      roots.push(home);
      roots.push(joinPath(home, "Documents"));
      roots.push(joinPath(home, "Library"));
      roots.push(joinPath(home, "Library/Application Support"));
    }
    for (let i = 0; i < roots.length; i++) {
      const root = roots[i];
      if (!root) continue;
      const url = NSURL.fileURLWithPath_(nsString(root));
      const enumr = fm.enumeratorAtURL_includingPropertiesForKeys_options_errorHandler_(url, null, 0, null);
      if (!enumr) continue;
      while (hits.length < cap) {
        const next = enumr.nextObject();
        if (!next) break;
        const p = tryReadNSString(next.path());
        if (p && p.toLowerCase().indexOf(needle) !== -1) {
          hits.push(p);
        }
      }
      if (hits.length >= cap) break;
    }
  } catch (_) {}
  return hits;
}

let _dbPath = "";
let _db = null;
let _dbOpenedAtMs = 0;

function ensureDb(pathOpt) {
  const p = String(pathOpt || _dbPath || "").trim();
  if (!p) return { ok: false, error: "missing path" };
  if (!SQLITE.ok) return { ok: false, error: SQLITE.err || "sqlite not ready" };
  if (_db && _dbPath && normalizeJid(_dbPath) === normalizeJid(p)) return { ok: true, db: _db, path: _dbPath };
  try { if (_db) SQLITE.close(_db); } catch (_) {}
  const res = SQLITE.open(p);
  if (!res.ok) return res;
  _dbPath = p;
  _db = res.db;
  _dbOpenedAtMs = nowMs();
  return { ok: true, db: _db, path: _dbPath };
}

function closeDb() {
  try { if (_db) SQLITE.close(_db); } catch (_) {}
  _db = null;
  _dbPath = "";
  _dbOpenedAtMs = 0;
}

function queryDb(sql, params, limitRows, pathOpt) {
  const edb = ensureDb(pathOpt);
  if (!edb.ok) return edb;
  return SQLITE.query(edb.db, sql, params, limitRows);
}

function pickOneText(rows, col) {
  try {
    if (!rows || !rows.length) return "";
    const v = rows[0][col];
    return String(v === null || v === undefined ? "" : v).trim();
  } catch (_) {
    return "";
  }
}

function getPushName(jid, pathOpt) {
  jid = String(jid || "").trim();
  if (!jid) return { ok: false, error: "missing jid" };
  const r = queryDb("select ZPUSHNAME as pushName from ZWAPROFILEPUSHNAME where lower(ZJID)=lower(?) limit 1", [jid], 1, pathOpt);
  if (!r.ok) return r;
  return { ok: true, pushName: pickOneText(r.rows, "pushName") };
}

function getProfilePictureId(jid, pathOpt) {
  jid = String(jid || "").trim();
  if (!jid) return { ok: false, error: "missing jid" };
  const r = queryDb("select ZPICTUREID as pictureId from ZWAPROFILEPICTUREITEM where lower(ZJID)=lower(?) limit 1", [jid], 1, pathOpt);
  if (!r.ok) return r;
  return { ok: true, pictureId: pickOneText(r.rows, "pictureId") };
}

function getChatSessionPartnerName(chatJid, pathOpt) {
  chatJid = String(chatJid || "").trim();
  if (!chatJid) return { ok: false, error: "missing chatJid" };
  const r = queryDb("select ZPARTNERNAME as partnerName from ZWACHATSESSION where lower(ZCONTACTJID)=lower(?) limit 1", [chatJid], 1, pathOpt);
  if (!r.ok) return r;
  return { ok: true, partnerName: pickOneText(r.rows, "partnerName") };
}

function getChatSessionContactIdentifier(chatJid, pathOpt) {
  chatJid = String(chatJid || "").trim();
  if (!chatJid) return { ok: false, error: "missing chatJid" };
  const r = queryDb("select ZCONTACTIDENTIFIER as ident from ZWACHATSESSION where lower(ZCONTACTJID)=lower(?) limit 1", [chatJid], 1, pathOpt);
  if (!r.ok) return r;
  return { ok: true, ident: pickOneText(r.rows, "ident") };
}

function resolveDisplayName(jid, pathOpt) {
  const pn = getPushName(jid, pathOpt);
  if (pn.ok && pn.pushName) return { ok: true, displayName: pn.pushName, source: "ZWAPROFILEPUSHNAME" };
  const cs = getChatSessionPartnerName(jid, pathOpt);
  if (cs.ok && cs.partnerName) return { ok: true, displayName: cs.partnerName, source: "ZWACHATSESSION" };
  return { ok: true, displayName: "", source: "" };
}

function findSelfCandidates(pathOpt) {
  const r = queryDb("select ZCONTACTJID as jid, ZCONTACTIDENTIFIER as ident, ZPARTNERNAME as name from ZWACHATSESSION where ZPARTNERNAME like '%你%' or ZPARTNERNAME like '%\u200e你%' limit 50", [], 50, pathOpt);
  if (!r.ok) return r;
  return { ok: true, rows: r.rows };
}

function getSelfProfile(pathOpt) {
  const o = {
    ok: false,
    selfJid: "",
    selfName: "",
    selfUsername: "",
    phone: "",
    displayName: "",
    displayNameSource: "",
    pictureId: "",
    pictureIdSource: "",
    chatStoragePath: String(pathOpt || _dbPath || "").trim(),
    runtimeSourceClass: "",
    runtimeSourceMethod: ""
  };

  refreshSelfCacheAsync();
  if (SELF_CACHE.ok) {
    o.selfJid = String(SELF_CACHE.selfJid || "").trim();
    o.selfName = String(SELF_CACHE.selfName || "").trim();
    o.selfUsername = String(SELF_CACHE.selfUsername || "").trim();
    o.phone = String(SELF_CACHE.phone || "").trim();
    o.runtimeSourceClass = String((SELF_CACHE.source && SELF_CACHE.source.ctxClass) || "");
    o.runtimeSourceMethod = String((SELF_CACHE.source && SELF_CACHE.source.usedSelector) || "");
  }

  if (o.selfJid) {
    o.phone = derivePhoneFromJid(o.selfJid);
  }

  if (!o.phone && o.selfJid && o.chatStoragePath) {
    const ident = getChatSessionContactIdentifier(o.selfJid, o.chatStoragePath);
    if (ident && ident.ok && ident.ident) {
      o.phone = derivePhoneFromJid(ident.ident) || extractDigits(ident.ident);
    }
  }

  if (o.selfJid && o.chatStoragePath) {
    const dn = resolveDisplayName(o.selfJid, o.chatStoragePath);
    if (dn && dn.ok && dn.displayName) {
      o.displayName = dn.displayName;
      o.displayNameSource = dn.source;
    }
    const pic = getProfilePictureId(o.selfJid, o.chatStoragePath);
    if (pic && pic.ok && pic.pictureId) {
      o.pictureId = pic.pictureId;
      o.pictureIdSource = "ZWAPROFILEPICTUREITEM";
    }
  }

  o.ok = !!(o.selfJid || o.phone || o.displayName || o.selfName || o.pictureId);
  return o;
}

function getSelfRuntimeProfile() {
  const includeAvatar = !!arguments[0];
  const o = {
    ok: false,
    selfJid: "",
    selfName: "",
    selfUsername: "",
    phone: "",
    capturedAt: 0,
    sources: [],
    hooks: { installed: SELF_SNIFF.installed, hookedCount: SELF_SNIFF.hookedCount, installedAt: SELF_SNIFF.installedAt, errors: SELF_SNIFF.errors || [] },
    avatar: null,
  };
  const a = getSelfNameActive();
  if (a && a.ok) {
    o.selfJid = String(a.selfJid || "").trim();
    o.selfName = String(a.selfName || "").trim();
    o.selfUsername = String(a.selfUsername || "").trim();
    o.phone = String(a.phone || "").trim();
    o.sources = [String((a.source && a.source.usedOn) || "")].filter(Boolean);
    o.capturedAt = nowMs();
  }
  if (includeAvatar) {
    o.avatar = tryGetMyProfilePictureInfo(false);
  }
  o.ok = !!(o.selfJid || o.selfName || o.selfUsername || o.phone || (o.avatar && o.avatar.ok));
  return o;
}

function getSelfRuntimeName() {
  return getSelfRuntimeProfile(false);
}

function _getProfilePictureManagerFromCtx(ctx) {
  try {
    if (!objcAvailable() || !ctx) return null;
    if (objcHasSelector(ctx, "profilePictureManager")) {
      const v = objcCallNoArg(ctx, "profilePictureManager");
      if (v) return v instanceof ObjC.Object ? v : new ObjC.Object(v);
    }
    if (ctx.$ivars) {
      const keys = Object.keys(ctx.$ivars || {});
      for (let i = 0; i < keys.length; i++) {
        const k = keys[i];
        const kl = String(k || "").toLowerCase();
        if (kl.indexOf("profilepicture") === -1 && kl.indexOf("profile_picture") === -1) continue;
        const v = ctx.$ivars[k];
        if (v) return v instanceof ObjC.Object ? v : new ObjC.Object(v);
      }
    }
  } catch (_) {}
  return null;
}

function _toUrlString(obj) {
  try {
    if (obj === null || obj === undefined) return "";
    if (!objcAvailable()) return String(obj || "").trim();
    const o = obj instanceof ObjC.Object ? obj : new ObjC.Object(obj);
    if (!o) return "";
    const s1 = objcCallNoArgString(o, "absoluteString");
    if (s1 && (s1.startsWith("http://") || s1.startsWith("https://"))) return s1;
    const s2 = String(o).trim();
    return s2;
  } catch (_) {
    try { return String(obj || "").trim(); } catch (_) { return ""; }
  }
}

function getProfilePictureUrlLink(jid, pictureId) {
  const out = { ok: false, jid: "", pictureId: "", url: "", usedOn: "", usedSelector: "", note: "" };
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const me = getSelfNameActive();
  const resolvedJid = String(jid || "").trim() || (me && me.ok ? String(me.selfJid || "").trim() : "");
  out.jid = resolvedJid;
  out.pictureId = String(pictureId || "").trim();

  const ctxRes = _resolveCtxMainActive();
  const ctx = ctxRes && ctxRes.ok ? ctxRes.ctx : null;
  const objs = [];
  if (ctx) objs.push({ o: ctx, tag: "ctx:" + String(ctx.$className || "") });
  try {
    if (ctx) {
      const ap = ctx["- accountProvider"] ? ctx["- accountProvider"]() : (ctx.$ivars ? (ctx.$ivars._accountProvider || ctx.$ivars.accountProvider || null) : null);
      if (ap) objs.push({ o: ap instanceof ObjC.Object ? ap : new ObjC.Object(ap), tag: "accountProvider" });
    }
  } catch (_) {}
  try {
    const ppm = ctx ? _getProfilePictureManagerFromCtx(ctx) : null;
    if (ppm) objs.push({ o: ppm, tag: "profilePictureManager:" + String(ppm.$className || "") });
  } catch (_) {}

  const urlSelectors0 = ["profilePictureURLString", "profilePictureUrl", "profilePictureURL"];
  for (let i = 0; i < objs.length; i++) {
    const o = objs[i].o;
    const tag = objs[i].tag;
    try {
      for (let j = 0; j < urlSelectors0.length; j++) {
        const sel = urlSelectors0[j];
        if (!objcHasSelector(o, sel)) continue;
        const s = _toUrlString(objcCallNoArg(o, sel)).trim();
        if (s.startsWith("http://") || s.startsWith("https://")) {
          out.ok = true;
          out.url = s;
          out.usedOn = tag;
          out.usedSelector = sel;
          return out;
        }
      }
    } catch (_) {}
  }

  const sel1 = "getProfilePictureUrl:";
  const argCandidates = [];
  if (resolvedJid) argCandidates.push(nsString(resolvedJid));
  if (out.pictureId) argCandidates.push(nsString(out.pictureId));
  for (let i = 0; i < objs.length; i++) {
    const o = objs[i].o;
    const tag = objs[i].tag;
    if (!o) continue;
    try {
      if (!objcHasSelector(o, sel1)) continue;
      for (let ai = 0; ai < argCandidates.length; ai++) {
        const a = argCandidates[ai];
        if (!a) continue;
        const r = tryCall1(o, sel1, a);
        const s = _toUrlString(r).trim();
        if (s.startsWith("http://") || s.startsWith("https://")) {
          out.ok = true;
          out.url = s;
          out.usedOn = tag;
          out.usedSelector = sel1;
          return out;
        }
      }
    } catch (_) {}
  }

  out.note = "no URL string found; likely requires async getProfilePictureWithDirectPathForJID... completion";
  return out;
}

function getProfilePictureUrlLinkAsync(jid) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  
  // Install hooks first
  hookPPM();
  
  const ctxRes = _resolveCtxMainActive();
  if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
  const ctx = ctxRes.ctx;
  const ppm = _getProfilePictureManagerFromCtx(ctx);
  if (!ppm) return { ok: false, error: "no profilePictureManager" };

  const targetJidStr = String(jid || "").trim();
  if (!targetJidStr) return { ok: false, error: "no jid provided" };
  
  let targetJidObj = null;
  try {
     const WAUserJID = ObjC.classes.WAUserJID;
     if (WAUserJID) {
       const methods = [];
       if (WAUserJID["+ withString:"]) methods.push("withString:");
       if (WAUserJID["+ withJIDString:"]) methods.push("withJIDString:");
       if (WAUserJID["+ userJIDWithString:"]) methods.push("userJIDWithString:");
       if (WAUserJID["+ jidWithString:"]) methods.push("jidWithString:");
       
       if (WAUserJID["+ jidOrLIDWithString:"]) targetJidObj = WAUserJID.jidOrLIDWithString_(nsString(targetJidStr));
        else if (WAUserJID["+ withString:"]) targetJidObj = WAUserJID.withString_(nsString(targetJidStr));
        else if (WAUserJID["+ withJIDString:"]) targetJidObj = WAUserJID.withJIDString_(nsString(targetJidStr));
        else if (WAUserJID["+ userJIDWithString:"]) targetJidObj = WAUserJID.userJIDWithString_(nsString(targetJidStr));
        else if (WAUserJID["+ jidWithString:"]) targetJidObj = WAUserJID.jidWithString_(nsString(targetJidStr));
         
         if (!targetJidObj) {
             let debugMethods = "";
             try {
               // Show all + methods
               debugMethods = WAUserJID.$ownMethods
                 .filter(function(m) { return m.indexOf("+") !== -1; })
                 .join(", ");
             } catch(_) {}
             return { ok: false, error: "WAUserJID creation failed. Tested: jidOrLIDWithString + others. Available: " + debugMethods };
         }
      }
     if (!targetJidObj) {
       const WAJID = ObjC.classes.WAJID;
       if (WAJID && WAJID["+ withString:"]) targetJidObj = WAJID.withString_(nsString(targetJidStr));
     }
   } catch(e) { return { ok: false, error: "jid construction failed: " + e }; }

  if (!targetJidObj) return { ok: false, error: "could not create WAUserJID from string" };

  const completion = new ObjC.Block({
     retType: 'void',
     argTypes: [], // Try empty first to avoid crash on arg parsing
     implementation: function () {
       send({ type: "debug", msg: "Callback invoked (no args)" });
       // We can't get result if we don't declare args, but at least we know it works.
       // If this works, we can try adding args back one by one.
       send({ type: "qqw.explore.avatar_url", ok: false, error: "Callback reached but args disabled for safety" });
     }
   });

  const selThumb = "requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:botPersonaID:";
    const selMeta = "metadataForProfilePicture:";
    
    if (!objcHasSelector(ppm, selThumb)) return { ok: false, error: "selector " + selThumb + " not found" };
  
    try {
      ObjC.schedule(ObjC.mainQueue, function() {
          try {
                if (objcHasSelector(ppm, selMeta)) {
                    send({ type: "debug", msg: "Checking metadataForProfilePicture:..." });
                    const meta = ppm[selMeta](targetJidObj);
                    send({ type: "debug", msg: "Meta: " + String(meta) });
                    if (meta) {
                        const out = { ok: true, meta: String(meta) };
                        try {
                            const u = meta.valueForKey_(nsString("profilePictureURLString"));
                            if (u) out.url = String(u);
                        } catch(_) {}
                        try {
                            const dp = meta.valueForKey_(nsString("directPath"));
                            if (dp) out.directPath = String(dp);
                        } catch(_) {}
                        try {
                            const pu = meta.valueForKey_(nsString("previewURLString"));
                            if (pu) out.previewUrl = String(pu);
                        } catch(_) {}
                        try {
                             if (!out.previewUrl) {
                                const pu2 = meta.valueForKey_(nsString("linkPreviewURLString"));
                                if (pu2) out.previewUrl = String(pu2);
                             }
                        } catch(_) {}
                        
                        if (out.url || out.directPath || out.previewUrl) {
                            send({ type: "qqw.explore.avatar_url", ...out });
                            return;
                        }
                    }
                }
                
                send({ type: "debug", msg: "No meta/URL. Active request disabled for stability." });
                // ppm[selThumb](targetJidObj, false, null); // Disabled to prevent crash
                send({ type: "qqw.explore.avatar_url", ok: false, error: "No cached metadata found. Active request disabled." });
          } catch(e) {
                send({ type: "qqw.explore.avatar_url", error: "invocation exception: " + e });
          }
      });
    
    return { ok: true, status: "pending", note: "async request sent; watch logs for qqw.explore.avatar_url" };
  } catch (e) {
    return { ok: false, error: "invocation failed: " + e };
  }
}

function getProfilePictureUrlLinkActive(jid) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };

  const ctxRes = _resolveCtxMainActive();
  if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
  const ctx = ctxRes.ctx;
  const ppm = _getProfilePictureManagerFromCtx(ctx);
  if (!ppm) return { ok: false, error: "no profilePictureManager" };

  const targetJidStr = String(jid || "").trim();
  if (!targetJidStr) return { ok: false, error: "no jid provided" };

  let targetJidObj = null;
  try {
    const WAUserJID = ObjC.classes.WAUserJID;
    if (WAUserJID) {
      if (WAUserJID["+ jidOrLIDWithString:"]) targetJidObj = WAUserJID.jidOrLIDWithString_(nsString(targetJidStr));
      else if (WAUserJID["+ withString:"]) targetJidObj = WAUserJID.withString_(nsString(targetJidStr));
      else if (WAUserJID["+ withJIDString:"]) targetJidObj = WAUserJID.withJIDString_(nsString(targetJidStr));
      else if (WAUserJID["+ userJIDWithString:"]) targetJidObj = WAUserJID.userJIDWithString_(nsString(targetJidStr));
      else if (WAUserJID["+ jidWithString:"]) targetJidObj = WAUserJID.jidWithString_(nsString(targetJidStr));
    }
    if (!targetJidObj) {
      const WAJID = ObjC.classes.WAJID;
      if (WAJID && WAJID["+ withString:"]) targetJidObj = WAJID.withString_(nsString(targetJidStr));
    }
  } catch (e) {
    return { ok: false, error: "jid construction failed: " + e };
  }

  if (!targetJidObj) return { ok: false, error: "could not create JID object" };

  const selMeta = "metadataForProfilePicture:";
  const selFullAsync = "requestFullSizedProfilePictureForIdentifierProvidingAsync:unconditionallyFetchPictureData:botPersonaID:completion:";
  const selPrefetch = "prefetchProfilePictureThumbnailForIdentifiers:";
  const selBestUrl = "bestAvailablePictureURLForIdentifierProviding:isFullSized:";
  const selSyncThumb = "syncProfilePictureThumbnailForIdentifierProviding:";

  const startMs = nowMs();
  const maxWaitMs = 12000;

  const poll = () => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        try {
          if (objcHasSelector(ppm, selBestUrl)) {
            const u0 = ppm[selBestUrl](targetJidObj, true);
            const s0 = _toUrlString(u0).trim();
            if (s0.startsWith("http://") || s0.startsWith("https://")) {
              send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "active", url: s0, source: "bestAvailablePictureURLForIdentifierProviding:isFullSized:" });
              return;
            }
          }
        } catch (_) {}
        if (!objcHasSelector(ppm, selMeta)) return;
        const meta = ppm[selMeta](targetJidObj);
        if (meta) {
          const out = { ok: true, jid: targetJidStr, meta: String(meta) };
          try {
            const u = meta.valueForKey_(nsString("profilePictureURLString"));
            if (u) out.url = String(u);
          } catch (_) {}
          try {
            const dp = meta.valueForKey_(nsString("directPath"));
            if (dp) out.directPath = String(dp);
          } catch (_) {}
          try {
            const pu = meta.valueForKey_(nsString("previewURLString"));
            if (pu) out.previewUrl = String(pu);
          } catch (_) {}
          try {
            if (!out.previewUrl) {
              const pu2 = meta.valueForKey_(nsString("linkPreviewURLString"));
              if (pu2) out.previewUrl = String(pu2);
            }
          } catch (_) {}

          if (out.url || out.directPath || out.previewUrl) {
            send({ type: "qqw.explore.avatar_url", ...out, mode: "active" });
            return;
          }
        }

        const elapsed = nowMs() - startMs;
        if (elapsed >= maxWaitMs) {
          send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active", error: "timeout waiting metadata" });
          return;
        }
        setTimeout(poll, 700);
      } catch (e) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active", error: "poll exception: " + e });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  };

  safeObjCInvoke(() => {
    let pool = null;
    try {
      try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
      if (objcHasSelector(ppm, selSyncThumb)) {
        try { ppm[selSyncThumb](targetJidObj); } catch (_) {}
      }
      if (objcHasSelector(ppm, selPrefetch)) {
        const NSArray = ObjC.classes.NSArray;
        const xs = NSArray && NSArray["+ arrayWithObject:"] ? NSArray.arrayWithObject_(targetJidObj) : null;
        if (!xs) {
          send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active", error: "NSArray arrayWithObject unavailable" });
          return;
        }
        ppm[selPrefetch](xs);
      } else {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active", error: "no active fetch selector found" });
        return;
      }

      send({ type: "debug", msg: "Active request triggered; polling metadataForProfilePicture..." });
    } catch (e) {
      send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active", error: "invoke exception: " + e });
    } finally {
      try { if (pool) pool.release(); } catch (_) {}
    }
  });

  setTimeout(poll, 700);
  return { ok: true, status: "pending", note: "active request sent; watch qqw.explore.avatar_url" };
}

function getProfilePictureUrlLinkActiveFull(jid) {
  return { ok: false, error: "disabled_for_stability" };
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };

  const ctxRes = _resolveCtxMainActive();
  if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
  const ctx = ctxRes.ctx;
  const ppm = _getProfilePictureManagerFromCtx(ctx);
  if (!ppm) return { ok: false, error: "no profilePictureManager" };

  const targetJidStr = String(jid || "").trim();
  if (!targetJidStr) return { ok: false, error: "no jid provided" };

  let targetJidObj = null;
  try {
    const WAUserJID = ObjC.classes.WAUserJID;
    if (WAUserJID) {
      if (WAUserJID["+ jidOrLIDWithString:"]) targetJidObj = WAUserJID.jidOrLIDWithString_(nsString(targetJidStr));
      else if (WAUserJID["+ withString:"]) targetJidObj = WAUserJID.withString_(nsString(targetJidStr));
      else if (WAUserJID["+ withJIDString:"]) targetJidObj = WAUserJID.withJIDString_(nsString(targetJidStr));
      else if (WAUserJID["+ userJIDWithString:"]) targetJidObj = WAUserJID.userJIDWithString_(nsString(targetJidStr));
      else if (WAUserJID["+ jidWithString:"]) targetJidObj = WAUserJID.jidWithString_(nsString(targetJidStr));
    }
    if (!targetJidObj) {
      const WAJID = ObjC.classes.WAJID;
      if (WAJID && WAJID["+ withString:"]) targetJidObj = WAJID.withString_(nsString(targetJidStr));
    }
  } catch (e) {
    return { ok: false, error: "jid construction failed: " + e };
  }

  if (!targetJidObj) return { ok: false, error: "could not create JID object" };

  const selMeta = "metadataForProfilePicture:";
  const selFullAsync = "requestFullSizedProfilePictureForIdentifierProvidingAsync:unconditionallyFetchPictureData:botPersonaID:completion:";

  const startMs = nowMs();
  const maxWaitMs = 20000;

  const poll = () => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        if (objcHasSelector(ppm, "bestAvailablePictureURLForIdentifierProviding:isFullSized:")) {
          try {
            const u0 = ppm["bestAvailablePictureURLForIdentifierProviding:isFullSized:"](targetJidObj, true);
            const s0 = _toUrlString(u0).trim();
            if (s0.startsWith("http://") || s0.startsWith("https://")) {
              send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "active_full", url: s0, source: "bestAvailablePictureURLForIdentifierProviding:isFullSized:" });
              return;
            }
          } catch (_) {}
        }
        if (objcHasSelector(ppm, selMeta)) {
          const meta = ppm[selMeta](targetJidObj);
          if (meta) {
            const out = { ok: true, jid: targetJidStr, mode: "active_full", meta: String(meta) };
            try {
              const u = meta.valueForKey_(nsString("profilePictureURLString"));
              if (u) out.url = String(u);
            } catch (_) {}
            try {
              const dp = meta.valueForKey_(nsString("directPath"));
              if (dp) out.directPath = String(dp);
            } catch (_) {}
            if (out.url || out.directPath) {
              send({ type: "qqw.explore.avatar_url", ...out });
              return;
            }
          }
        }
        const elapsed = nowMs() - startMs;
        if (elapsed >= maxWaitMs) {
          send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_full", error: "timeout waiting metadata" });
          return;
        }
        setTimeout(poll, 800);
      } catch (e) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_full", error: "poll exception: " + e });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  };

  safeObjCInvoke(() => {
    let pool = null;
    try {
      try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
      if (!objcHasSelector(ppm, selFullAsync)) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_full", error: "fullsize async selector missing" });
        return;
      }
      const completion = new ObjC.Block({
        retType: "void",
        argTypes: [],
        implementation: function () {
          try { send({ type: "debug", msg: "fullsize completion invoked" }); } catch (_) {}
          setTimeout(poll, 200);
        }
      });
      ppm[selFullAsync](targetJidObj, true, null, completion);
      send({ type: "debug", msg: "Fullsize active request triggered; polling metadata..." });
    } catch (e) {
      send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_full", error: "invoke exception: " + e });
    } finally {
      try { if (pool) pool.release(); } catch (_) {}
    }
  });

  setTimeout(poll, 800);
  return { ok: true, status: "pending", note: "fullsize active request sent; watch qqw.explore.avatar_url" };
}

function getProfilePictureUrlLinkActiveReq(jid) {
  return { ok: false, error: "disabled_for_stability" };
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };

  const targetJidStr = String(jid || "").trim();
  if (!targetJidStr) return { ok: false, error: "no jid provided" };

  let ppmRef = null;
  let jidObjRef = null;

  const selMeta = "metadataForProfilePicture:";
  const selReq = "requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:botPersonaID:";

  const startMs = nowMs();
  const maxWaitMs = 20000;

  const poll = () => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        if (!ppmRef || !jidObjRef) return;
        if (objcHasSelector(ppmRef, "bestAvailablePictureURLForIdentifierProviding:isFullSized:")) {
          try {
            const u0 = ppmRef["bestAvailablePictureURLForIdentifierProviding:isFullSized:"](jidObjRef, true);
            const s0 = _toUrlString(u0).trim();
            if (s0.startsWith("http://") || s0.startsWith("https://")) {
              send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "active_req", url: s0, source: "bestAvailablePictureURLForIdentifierProviding:isFullSized:" });
              return;
            }
          } catch (_) {}
        }
        if (objcHasSelector(ppmRef, selMeta)) {
          const meta = ppmRef[selMeta](jidObjRef);
          if (meta) {
            const out = { ok: true, jid: targetJidStr, mode: "active_req", meta: String(meta) };
            try {
              const u = meta.valueForKey_(nsString("profilePictureURLString"));
              if (u) out.url = String(u);
            } catch (_) {}
            try {
              const dp = meta.valueForKey_(nsString("directPath"));
              if (dp) out.directPath = String(dp);
            } catch (_) {}
            if (out.url || out.directPath) {
              send({ type: "qqw.explore.avatar_url", ...out });
              return;
            }
          }
        }
        const elapsed = nowMs() - startMs;
        if (elapsed >= maxWaitMs) {
          send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_req", error: "timeout waiting metadata" });
          return;
        }
        setTimeout(poll, 900);
      } catch (e) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_req", error: "poll exception: " + e });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  };

  safeObjCInvoke(() => {
    let pool = null;
    try {
      try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
      const ctxRes = _resolveCtxMainActive();
      if (!ctxRes || !ctxRes.ok) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_req", error: "no context" });
        return;
      }
      const ppm = _getProfilePictureManagerFromCtx(ctxRes.ctx);
      if (!ppm) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_req", error: "no profilePictureManager" });
        return;
      }
      let targetJidObj = null;
      try {
        const WAUserJID = ObjC.classes.WAUserJID;
        if (WAUserJID) {
          if (WAUserJID["+ jidOrLIDWithString:"]) targetJidObj = WAUserJID.jidOrLIDWithString_(nsString(targetJidStr));
          else if (WAUserJID["+ withString:"]) targetJidObj = WAUserJID.withString_(nsString(targetJidStr));
        }
      } catch (_) {
        targetJidObj = null;
      }
      if (!targetJidObj) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_req", error: "could not create JID object" });
        return;
      }
      ppmRef = ppm;
      jidObjRef = targetJidObj;
      send({ type: "debug", msg: "active_req prepared; dispatching request on JS thread" });
      setImmediate(() => {
        if (!ppmRef || !jidObjRef) return;
        let pool2 = null;
        try {
          try { pool2 = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool2 = null; }
          if (!objcHasSelector(ppmRef, selReq)) {
            send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_req", error: "request selector missing" });
            return;
          }
          ppmRef[selReq](jidObjRef, false, null);
          send({ type: "debug", msg: "active_req request invoked; polling..." });
          setTimeout(poll, 400);
        } catch (e) {
          send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_req", error: "request exception: " + e });
        } finally {
          try { if (pool2) pool2.release(); } catch (_) {}
        }
      });
    } catch (e) {
      send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_req", error: "prepare exception: " + e });
    } finally {
      try { if (pool) pool.release(); } catch (_) {}
    }
  });

  return { ok: true, status: "pending", note: "active_req sent; watch qqw.explore.avatar_url" };
}

function getProfilePictureUrlLinkActiveStable(jid) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };

  const ctxRes = _resolveCtxMainActive();
  if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
  const ctx = ctxRes.ctx;
  const ppm = _getProfilePictureManagerFromCtx(ctx);
  if (!ppm) return { ok: false, error: "no profilePictureManager" };

  const targetJidStr = String(jid || "").trim();
  if (!targetJidStr) return { ok: false, error: "no jid provided" };

  let targetJidObj = null;
  try {
    const WAUserJID = ObjC.classes.WAUserJID;
    if (WAUserJID && WAUserJID["+ jidOrLIDWithString:"]) targetJidObj = WAUserJID.jidOrLIDWithString_(nsString(targetJidStr));
  } catch (_) {
    targetJidObj = null;
  }
  if (!targetJidObj) return { ok: false, error: "could not create JID object" };
  let idpObj = targetJidObj;
  try {
    if (targetJidObj && objcHasSelector(targetJidObj, "profilePictureJID")) {
      const pjid = targetJidObj.profilePictureJID();
      if (pjid) idpObj = pjid;
    }
  } catch (_) {}

  const selReq = "requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:newPrivacyTokenAvailable:botPersonaID:previousDirectPath:";
  const selMeta = "metadataForProfilePicture:";
  const selBestUrl = "bestAvailablePictureURLForIdentifierProviding:isFullSized:";

  let prevDp = "";
  safeObjCInvoke(() => {
    try {
      if (objcHasSelector(ppm, selMeta)) {
        const meta0 = ppm[selMeta](idpObj);
        if (meta0) {
          try {
            const dp0 = meta0.valueForKey_(nsString("directPath"));
            if (dp0) prevDp = String(dp0);
          } catch (_) {}
          try {
            if (!prevDp) {
              const dp1 = meta0.valueForKey_(nsString("profilePictureDirectPath"));
              if (dp1) prevDp = String(dp1);
            }
          } catch (_) {}
        }
      }
    } catch (_) {}
  });

  if (!prevDp) {
    try {
      const db = getProfilePictureItemFromDb(targetJidStr, _dbPath);
      if (db && db.ok && db.item && db.item.directPath) prevDp = String(db.item.directPath || "");
    } catch (_) {}
  }

  prevDp = String(prevDp || "").trim();
  if (!prevDp || prevDp.length < 8 || prevDp.indexOf("/") === -1) {
    return { ok: false, error: "no usable previousDirectPath; avoid crash. Open profile once to populate cache." };
  }

  const startMs = nowMs();
  const maxWaitMs = 20000;

  safeObjCInvoke(() => {
    let pool = null;
    try {
      try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
      if (!objcHasSelector(ppm, selReq)) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_stable", error: "request selector missing" });
        return;
      }
      send({ type: "debug", msg: "active_stable invoking request... with previousDirectPath len=" + prevDp.length });
      ppm[selReq](idpObj, false, false, null, nsString(prevDp));
    } catch (e) {
      send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_stable", error: "invoke exception: " + e });
    } finally {
      try { if (pool) pool.release(); } catch (_) {}
    }
  });

  const poll = () => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        try {
          if (objcHasSelector(ppm, selBestUrl)) {
            const u0 = ppm[selBestUrl](idpObj, true);
            const s0 = _toUrlString(u0).trim();
            if (s0.startsWith("http://") || s0.startsWith("https://")) {
              send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "active_stable", url: s0, source: "bestAvailablePictureURLForIdentifierProviding:isFullSized:" });
              return;
            }
          }
        } catch (_) {}

        if (objcHasSelector(ppm, selMeta)) {
          const meta = ppm[selMeta](idpObj);
          if (meta) {
            const out = { ok: true, jid: targetJidStr, mode: "active_stable", meta: String(meta) };
            try {
              const u = meta.valueForKey_(nsString("profilePictureURLString"));
              if (u) out.url = String(u);
            } catch (_) {}
            try {
              const dp = meta.valueForKey_(nsString("directPath"));
              if (dp) out.directPath = String(dp);
            } catch (_) {}
            if (out.url || out.directPath) {
              send({ type: "qqw.explore.avatar_url", ...out });
              return;
            }
          }
        }
        const elapsed = nowMs() - startMs;
        if (elapsed >= maxWaitMs) {
          send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_stable", error: "timeout waiting metadata/url" });
          return;
        }
        setTimeout(poll, 900);
      } catch (e) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_stable", error: "poll exception: " + e });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  };

  setTimeout(poll, 900);
  return { ok: true, status: "pending", mode: "active_stable", previousDirectPathLen: prevDp.length };
}

function getProfilePictureUrlLinkActiveSafe(jid) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };

  const ctxRes = _resolveCtxMainActive();
  if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
  const ctx = ctxRes.ctx;
  const ppm = _getProfilePictureManagerFromCtx(ctx);
  if (!ppm) return { ok: false, error: "no profilePictureManager" };

  const targetJidStr = String(jid || "").trim();
  if (!targetJidStr) return { ok: false, error: "no jid provided" };

  let jidObj = null;
  try {
    const WAUserJID = ObjC.classes.WAUserJID;
    if (WAUserJID && WAUserJID["+ jidOrLIDWithString:"]) jidObj = WAUserJID.jidOrLIDWithString_(nsString(targetJidStr));
  } catch (_) {
    jidObj = null;
  }
  if (!jidObj) return { ok: false, error: "could not create JID object" };

  let idpObj = jidObj;
  try {
    if (jidObj && objcHasSelector(jidObj, "profilePictureJID")) {
      const pjid = jidObj.profilePictureJID();
      if (pjid) idpObj = pjid;
    }
  } catch (_) {}

  const selReq = "requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:botPersonaID:";
  const selMeta = "metadataForProfilePicture:";
  const selBestUrl = "bestAvailablePictureURLForIdentifierProviding:isFullSized:";

  const startMs = nowMs();
  const maxWaitMs = 30000;
  let sentCandidate = false;

  safeObjCInvoke(() => {
    let pool = null;
    try {
      try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
      if (!objcHasSelector(ppm, selReq)) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_safe", error: "request selector missing" });
        return;
      }
      send({ type: "debug", msg: "active_safe invoking request... (no previousDirectPath)" });
      ppm[selReq](idpObj, false, null);
    } catch (e) {
      send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_safe", error: "invoke exception: " + e });
    } finally {
      try { if (pool) pool.release(); } catch (_) {}
    }
  });

  const poll = () => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        try {
          if (objcHasSelector(ppm, selBestUrl)) {
            const u1 = ppm[selBestUrl](idpObj, true);
            const u2 = ppm[selBestUrl](idpObj, false);
            const tryNormalize = (s) => {
              s = String(s || "").trim();
              if (!s) return "";
              if (s.startsWith("http://") || s.startsWith("https://")) return s;
              if (s.indexOf("pps.whatsapp.net") !== -1) return "https://" + s.replace(/^https?:\/\//, "");
              if (s.startsWith("/")) return "https://pps.whatsapp.net" + s;
              return s;
            };
            const s1 = tryNormalize(_toUrlString(u1));
            const s2 = tryNormalize(_toUrlString(u2));
            const pick = (x) => x && (x.startsWith("http://") || x.startsWith("https://")) && x.indexOf("pps.") !== -1;
            if (pick(s1)) {
              send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "active_safe", url: s1, source: "bestAvailablePictureURLForIdentifierProviding:isFullSized:=true" });
              return;
            }
            if (pick(s2)) {
              send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "active_safe", url: s2, source: "bestAvailablePictureURLForIdentifierProviding:isFullSized:=false" });
              return;
            }
            if (!sentCandidate && (s1 || s2)) {
              sentCandidate = true;
              send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_safe", note: "bestAvailablePictureURL returned non-pps", candidate_full: s1, candidate_thumb: s2 });
            }
          }
        } catch (_) {}

        try {
          if (objcHasSelector(ppm, selMeta)) {
            const meta = ppm[selMeta](idpObj);
            if (meta) {
              const out = { ok: true, jid: targetJidStr, mode: "active_safe", meta: String(meta) };
              try {
                const u = meta.valueForKey_(nsString("profilePictureURLString"));
                if (u) out.url = String(u);
              } catch (_) {}
              try {
                const dp = meta.valueForKey_(nsString("directPath"));
                if (dp) out.directPath = String(dp);
              } catch (_) {}
              if (out.url || out.directPath) {
                send({ type: "qqw.explore.avatar_url", ...out });
                return;
              }
            }
          }
        } catch (_) {}

        const elapsed = nowMs() - startMs;
        if (elapsed >= maxWaitMs) {
          send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_safe", error: "timeout waiting metadata/url" });
          return;
        }
        setTimeout(poll, 900);
      } catch (e) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "active_safe", error: "poll exception: " + e });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  };

  setTimeout(poll, 900);
  return { ok: true, status: "pending", mode: "active_safe" };
}

function getProfilePictureUrlLinkViaBusinessDirectPath(jid) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };

  const ctxRes = _resolveCtxMainActive();
  if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
  const ctx = ctxRes.ctx;
  const ppm = _getProfilePictureManagerFromCtx(ctx);
  if (!ppm) return { ok: false, error: "no profilePictureManager" };

  const targetJidStr = String(jid || "").trim();
  if (!targetJidStr) return { ok: false, error: "no jid provided" };

  let jidObj = null;
  try {
    const WAUserJID = ObjC.classes.WAUserJID;
    if (WAUserJID && WAUserJID["+ jidOrLIDWithString:"]) jidObj = WAUserJID.jidOrLIDWithString_(nsString(targetJidStr));
  } catch (_) {
    jidObj = null;
  }
  if (!jidObj) return { ok: false, error: "could not create JID object" };

  let idpObj = jidObj;
  try {
    if (jidObj && objcHasSelector(jidObj, "profilePictureJID")) {
      const pjid = jidObj.profilePictureJID();
      if (pjid) idpObj = pjid;
    }
  } catch (_) {}

  const selDirectPath = "MAIN_APP_requestBusinessProfilePictureDirectPathForIdentifierProviding:completion:";
  const selReq = "requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:newPrivacyTokenAvailable:botPersonaID:previousDirectPath:";
  const selBestUrl = "bestAvailablePictureURLForIdentifierProviding:isFullSized:";
  const selMeta = "metadataForProfilePicture:";

  if (!objcHasSelector(ppm, selDirectPath)) return { ok: false, error: "selector missing: " + selDirectPath };
  if (!objcHasSelector(ppm, selReq)) return { ok: false, error: "selector missing: " + selReq };

  const startMs = nowMs();
  const maxWaitMs = 60000;
  let prevDp = "";
  let requested = false;

  const completion = new ObjC.Block({
    retType: "void",
    argTypes: ["pointer", "pointer"],
    implementation: function (p0, p1) {
      try {
        let s = "";
        try { if (!p0.isNull()) s = String(new ObjC.Object(p0)); } catch (_) { s = ""; }
        prevDp = String(s || "").trim();
        send({ type: "debug", msg: "business directPath completion directPathLen=" + prevDp.length });
      } catch (_) {}
    }
  });

  safeObjCInvoke(() => {
    let pool = null;
    try {
      try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
      send({ type: "debug", msg: "requesting business directPath..." });
      const f = ppm[selDirectPath];
      if (typeof f === "function") {
        send({ type: "debug", msg: "selDirectPath via bridge" });
        f.call(ppm, idpObj, completion);
      } else {
        send({ type: "debug", msg: "selDirectPath via objc_msgSend" });
        const pMsg = Module.findExportByName(null, "objc_msgSend");
        if (!pMsg) throw new Error("objc_msgSend not found");
        const msgSend = new NativeFunction(pMsg, "void", ["pointer", "pointer", "pointer", "pointer"]);
        const pSelReg = Module.findExportByName("libobjc.A.dylib", "sel_registerName") || Module.findExportByName(null, "sel_registerName");
        if (!pSelReg) throw new Error("sel_registerName not found");
        const selRegisterName = new NativeFunction(pSelReg, "pointer", ["pointer"]);
        const sel = selRegisterName(Memory.allocUtf8String(selDirectPath));
        const a1 = idpObj && idpObj.handle ? idpObj.handle : idpObj;
        const a2 = completion && completion.handle ? completion.handle : completion;
        msgSend(ppm.handle, sel, a1, a2);
      }
    } catch (e) {
      send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "business_directPath", error: "invoke exception: " + e });
    } finally {
      try { if (pool) pool.release(); } catch (_) {}
    }
  });

  const poll = () => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }

        if (prevDp && prevDp.length >= 8 && prevDp.indexOf("/") !== -1) {
          const url = prevDp.startsWith("http://") || prevDp.startsWith("https://") ? prevDp : ("https://pps.whatsapp.net" + (prevDp.startsWith("/") ? prevDp : ("/" + prevDp)));
          send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "business_directPath", url, directPath: prevDp, source: "MAIN_APP_requestBusinessProfilePictureDirectPathForIdentifierProviding" });
          return;
        }

        if (!requested && prevDp) {
          requested = true;
          try { ppm[selReq](idpObj, false, false, null, nsString(prevDp)); } catch (_) {}
        }

        try {
          if (objcHasSelector(ppm, selBestUrl)) {
            const u1 = ppm[selBestUrl](idpObj, true);
            const u2 = ppm[selBestUrl](idpObj, false);
            const norm = (s) => {
              s = String(s || "").trim();
              if (!s) return "";
              if (s.startsWith("http://") || s.startsWith("https://")) return s;
              if (s.indexOf("pps.whatsapp.net") !== -1) return "https://" + s.replace(/^https?:\/\//, "");
              if (s.startsWith("/")) return "https://pps.whatsapp.net" + s;
              return s;
            };
            const s1 = norm(_toUrlString(u1));
            const s2 = norm(_toUrlString(u2));
            const pick = (x) => x && (x.startsWith("http://") || x.startsWith("https://")) && x.indexOf("pps.") !== -1;
            if (pick(s1)) {
              send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "business_directPath", url: s1, source: "bestAvailablePictureURL full" });
              return;
            }
            if (pick(s2)) {
              send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "business_directPath", url: s2, source: "bestAvailablePictureURL thumb" });
              return;
            }
          }
        } catch (_) {}

        try {
          if (objcHasSelector(ppm, selMeta)) {
            const meta = ppm[selMeta](idpObj);
            if (meta) {
              const out = { ok: true, jid: targetJidStr, mode: "business_directPath", meta: String(meta) };
              if (prevDp) out.previousDirectPath = prevDp;
              try {
                const u = meta.valueForKey_(nsString("profilePictureURLString"));
                if (u) out.url = String(u);
              } catch (_) {}
              try {
                const dp = meta.valueForKey_(nsString("directPath"));
                if (dp) out.directPath = String(dp);
              } catch (_) {}
              if (out.url || out.directPath) {
                send({ type: "qqw.explore.avatar_url", ...out });
                return;
              }
            }
          }
        } catch (_) {}

        const elapsed = nowMs() - startMs;
        if (elapsed >= maxWaitMs) {
          send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "business_directPath", error: "timeout", previousDirectPath: prevDp || "" });
          return;
        }
        setTimeout(poll, 1200);
      } catch (e) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "business_directPath", error: "poll exception: " + e });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  };

  setTimeout(poll, 1200);
  return { ok: true, status: "pending", mode: "business_directPath" };
}

function getSelfCard() {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  return new Promise((resolve) => {
    let done = false;
    const finish = (o) => {
      if (done) return;
      done = true;
      try { resolve(o); } catch (_) {}
    };

    let me = null;
    try { me = getSelfNameActive(); } catch (_) { me = null; }
    if (!me || !me.ok) return finish({ ok: false, error: "self info unavailable", phone: "", selfJid: "", selfName: "", avatarUrl: "" });

    const selfJid = String(me.selfJid || "").trim();
    const selfName = String(me.selfName || "").trim();
    const phone = String(derivePhoneFromJid(selfJid) || "").trim();

    if (!selfJid) return finish({ ok: false, error: "selfJid missing", phone, selfJid, selfName, avatarUrl: "" });

    const ctxRes = _resolveCtxMainActive();
    if (!ctxRes || !ctxRes.ok) return finish({ ok: false, error: "no context", phone, selfJid, selfName, avatarUrl: "" });
    const ppm = _getProfilePictureManagerFromCtx(ctxRes.ctx);
    if (!ppm) return finish({ ok: false, error: "no profilePictureManager", phone, selfJid, selfName, avatarUrl: "" });

    let jidObj = null;
    try {
      const WAUserJID = ObjC.classes.WAUserJID;
      if (WAUserJID && WAUserJID["+ jidOrLIDWithString:"]) jidObj = WAUserJID.jidOrLIDWithString_(nsString(selfJid));
    } catch (_) {
      jidObj = null;
    }
    if (!jidObj) return finish({ ok: false, error: "could not create JID object", phone, selfJid, selfName, avatarUrl: "" });

    let idpObj = jidObj;
    try {
      if (jidObj && objcHasSelector(jidObj, "profilePictureJID")) {
        const pjid = jidObj.profilePictureJID();
        if (pjid) idpObj = pjid;
      }
    } catch (_) {}

    const selDirectPath = "MAIN_APP_requestBusinessProfilePictureDirectPathForIdentifierProviding:completion:";
    if (!objcHasSelector(ppm, selDirectPath)) return finish({ ok: false, error: "business directPath selector missing", phone, selfJid, selfName, avatarUrl: "" });

    const timer = setTimeout(() => {
      finish({ ok: false, error: "timeout waiting directPath", phone, selfJid, selfName, avatarUrl: "" });
    }, 8000);

    const completion = new ObjC.Block({
      retType: "void",
      argTypes: ["pointer", "pointer"],
      implementation: function (p0, p1) {
        let dp = "";
        try { if (!p0.isNull()) dp = String(new ObjC.Object(p0)); } catch (_) { dp = ""; }
        dp = String(dp || "").trim();
        const url = dp
          ? (dp.startsWith("http://") || dp.startsWith("https://") ? dp : ("https://pps.whatsapp.net" + (dp.startsWith("/") ? dp : ("/" + dp))))
          : "";
        try { clearTimeout(timer); } catch (_) {}
        finish({ ok: true, phone, selfJid, selfName, avatarUrl: url });
      }
    });

    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const f = ppm[selDirectPath];
        if (typeof f === "function") {
          f.call(ppm, idpObj, completion);
          return;
        }
        const pMsg = Module.findExportByName(null, "objc_msgSend");
        const pSelReg = Module.findExportByName("libobjc.A.dylib", "sel_registerName") || Module.findExportByName(null, "sel_registerName");
        if (!pMsg || !pSelReg) return;
        const msgSend = new NativeFunction(pMsg, "void", ["pointer", "pointer", "pointer", "pointer"]);
        const selRegisterName = new NativeFunction(pSelReg, "pointer", ["pointer"]);
        const sel = selRegisterName(Memory.allocUtf8String(selDirectPath));
        const a1 = idpObj && idpObj.handle ? idpObj.handle : idpObj;
        const a2 = completion && completion.handle ? completion.handle : completion;
        msgSend(ppm.handle, sel, a1, a2);
      } catch (_) {
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function getProfilePictureUrlLinkPrefetch(jid) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };

  const ctxRes = _resolveCtxMainActive();
  if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
  const ctx = ctxRes.ctx;
  const ppm = _getProfilePictureManagerFromCtx(ctx);
  if (!ppm) return { ok: false, error: "no profilePictureManager" };

  const targetJidStr = String(jid || "").trim();
  if (!targetJidStr) return { ok: false, error: "no jid provided" };

  let targetJidObj = null;
  try {
    const WAUserJID = ObjC.classes.WAUserJID;
    if (WAUserJID && WAUserJID["+ jidOrLIDWithString:"]) targetJidObj = WAUserJID.jidOrLIDWithString_(nsString(targetJidStr));
  } catch (_) {
    targetJidObj = null;
  }
  if (!targetJidObj) return { ok: false, error: "could not create JID object" };
  let idpObj = targetJidObj;
  try {
    if (targetJidObj && objcHasSelector(targetJidObj, "profilePictureJID")) {
      const pjid = targetJidObj.profilePictureJID();
      if (pjid) idpObj = pjid;
    }
  } catch (_) {}

  const selPrefetch = "prefetchProfilePictureThumbnailForIdentifiers:";
  const selMeta = "metadataForProfilePicture:";
  const selBestUrl = "bestAvailablePictureURLForIdentifierProviding:isFullSized:";

  const startMs = nowMs();
  const maxWaitMs = 60000;

  safeObjCInvoke(() => {
    let pool = null;
    try {
      try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
      if (!objcHasSelector(ppm, selPrefetch)) return;
      const NSArray = ObjC.classes.NSArray;
      const xs = NSArray && NSArray["+ arrayWithObject:"] ? NSArray.arrayWithObject_(idpObj) : null;
      if (!xs) return;
      send({ type: "debug", msg: "prefetch invoking prefetchProfilePictureThumbnailForIdentifiers" });
      ppm[selPrefetch](xs);
    } catch (_) {
    } finally {
      try { if (pool) pool.release(); } catch (_) {}
    }
  });

  const poll = () => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        try {
          if (objcHasSelector(ppm, selBestUrl)) {
            const u0 = ppm[selBestUrl](idpObj, true);
            const s0 = _toUrlString(u0).trim();
            if (s0.startsWith("http://") || s0.startsWith("https://")) {
              send({ type: "qqw.explore.avatar_url", ok: true, jid: targetJidStr, mode: "prefetch", url: s0, source: "bestAvailablePictureURLForIdentifierProviding:isFullSized:" });
              return;
            }
          }
        } catch (_) {}

        if (objcHasSelector(ppm, selMeta)) {
          const meta = ppm[selMeta](idpObj);
          if (meta) {
            const out = { ok: true, jid: targetJidStr, mode: "prefetch", meta: String(meta) };
            try {
              const u = meta.valueForKey_(nsString("profilePictureURLString"));
              if (u) out.url = String(u);
            } catch (_) {}
            try {
              const dp = meta.valueForKey_(nsString("directPath"));
              if (dp) out.directPath = String(dp);
            } catch (_) {}
            if (out.url || out.directPath) {
              send({ type: "qqw.explore.avatar_url", ...out });
              return;
            }
          }
        }

        const elapsed = nowMs() - startMs;
        if (elapsed >= maxWaitMs) {
          send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "prefetch", error: "timeout waiting metadata/url" });
          return;
        }
        setTimeout(poll, 1200);
      } catch (e) {
        send({ type: "qqw.explore.avatar_url", ok: false, jid: targetJidStr, mode: "prefetch", error: "poll exception: " + e });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  };

  setTimeout(poll, 1200);
  return { ok: true, status: "pending", mode: "prefetch" };
}

function getProfilePictureItemFromDb(jid, pathOpt) {
  jid = String(jid || "").trim();
  if (!jid) return { ok: false, error: "missing jid" };
  // Check columns first
  const info = queryDb("PRAGMA table_info(ZWAPROFILEPICTUREITEM)", [], 100, pathOpt);
  let cols = [];
  if (info.ok && info.rows) {
      cols = info.rows.map(r => r.name);
  }
  
  const r = queryDb("select * from ZWAPROFILEPICTUREITEM where lower(ZJID)=lower(?) limit 1", [jid], 1, pathOpt);
  if (!r.ok) return r;
  if (!r.rows || !r.rows.length) return { ok: false, error: "not found in DB", cols: cols };
  return { ok: true, row: r.rows[0], cols: cols };
}

function inspectClass(className) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const cls = ObjC.classes[className];
  if (!cls) return { ok: false, error: "class not found" };
  return {
    ok: true,
    methods: cls.$ownMethods,
    protocols: cls.$protocols ? Object.keys(cls.$protocols) : []
  };
}

function listClasses(filter) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const out = [];
  const f = filter ? filter.toLowerCase() : "";
  for (let name in ObjC.classes) {
    if (!f || name.toLowerCase().indexOf(f) !== -1) {
      out.push(name);
    }
  }
  return { ok: true, classes: out.sort() };
}

function listClassesConformingToProtocol(protoName, nameFilter, limit) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const p = String(protoName || "").trim();
  const nf = String(nameFilter || "").trim().toLowerCase();
  const lim = (limit | 0) || 200;
  if (!p) return { ok: false, error: "missing protoName" };
  let proto = null;
  try { proto = ObjC.protocols ? ObjC.protocols[p] : null; } catch (_) { proto = null; }
  if (!proto) return { ok: false, error: "protocol not found: " + p };
  let conformsFn = null;
  try { conformsFn = ObjC.api ? ObjC.api.class_conformsToProtocol : null; } catch (_) { conformsFn = null; }
  if (!conformsFn) {
    try {
      const pfn =
        Module.findExportByName("libobjc.A.dylib", "class_conformsToProtocol") ||
        Module.findExportByName(null, "class_conformsToProtocol");
      if (pfn) conformsFn = new NativeFunction(pfn, "bool", ["pointer", "pointer"]);
    } catch (_) {
      conformsFn = null;
    }
  }
  if (!conformsFn) return { ok: false, error: "class_conformsToProtocol unavailable" };
  const out = [];
  for (let name in ObjC.classes) {
    try {
      if (nf && String(name).toLowerCase().indexOf(nf) === -1) continue;
      const cls = ObjC.classes[name];
      if (!cls) continue;
      const ok = conformsFn(cls.handle, proto.handle);
      if (ok) {
        out.push(name);
        if (out.length >= lim) break;
      }
    } catch (_) {}
  }
  out.sort();
  return { ok: true, protocol: p, filter: nf, count: out.length, classes: out };
}

function getTables(filter) {
  if (!_dbPath) {
      const hits = findPathsByName("ChatStorage.sqlite", 5);
      if (hits && hits.length) ensureDb(hits[0]);
  }
  const q = "SELECT name FROM sqlite_master WHERE type='table'";
  const r = queryDb(q, [], 1000, _dbPath);
  if (!r.ok) return r;
  
  const tables = [];
  const f = filter ? filter.toLowerCase() : "";
  for (let row of r.rows) {
      if (!f || row.name.toLowerCase().indexOf(f) !== -1) {
          tables.push(row.name);
      }
  }
  return { ok: true, tables: tables.sort() };
}

function hookPPM() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (globalThis.__QQW_PPM_HOOK && globalThis.__QQW_PPM_HOOK.installed) {
    return { ok: true, hooked: globalThis.__QQW_PPM_HOOK.hooked || 0, note: "already installed" };
  }
  const state = { installed: true, hooked: 0, errors: [] };
  globalThis.__QQW_PPM_HOOK = state;
  try {
    const cls = ObjC.classes.WAProfilePictureManager;
    if (!cls) return { ok: false, error: "WAProfilePictureManager missing" };
    const targets = [
      "requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:botPersonaID:",
      "MAIN_APP_requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:botPersonaID:",
      "requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:newPrivacyTokenAvailable:botPersonaID:previousDirectPath:",
      "requestFullSizedProfilePictureForIdentifierProvidingAsync:unconditionallyFetchPictureData:botPersonaID:completion:",
    ];
    for (let i = 0; i < targets.length; i++) {
      const sel = targets[i];
      const ms = "- " + sel;
      const m = cls[ms];
      if (!m || !m.implementation) continue;
      const impl = ptr(m.implementation);
      try {
        Interceptor.attach(impl, {
          onEnter(args) {
            try {
              const idp = args[2].isNull() ? null : new ObjC.Object(args[2]);
              const bot = args[4] && !args[4].isNull ? (args[4].isNull() ? null : new ObjC.Object(args[4])) : null;
              const out = {
                type: "qqw.ppm.call",
                sel,
                impl: impl.toString(),
                idpClass: idp ? String(idp.$className) : "",
                idpDesc: idp ? String(idp) : "",
              };
              try {
                if (idp && objcHasSelector(idp, "jid")) out.idp_jid = objcCallNoArgString(idp, "jid");
              } catch (_) {}
              try {
                if (idp && objcHasSelector(idp, "stringRepresentation")) out.idp_str = objcCallNoArgString(idp, "stringRepresentation");
              } catch (_) {}
              try {
                if (idp && objcHasSelector(idp, "profilePictureJID")) {
                  const pj = objcCallNoArg(idp, "profilePictureJID");
                  if (pj) out.idp_ppjid = objcCallNoArgString(pj instanceof ObjC.Object ? pj : new ObjC.Object(pj), "stringRepresentation");
                }
              } catch (_) {}
              try { out.onlyIfNecessary = !!(args[3].toInt32() & 1); } catch (_) {}
              try { out.botPersona = bot ? String(bot) : ""; } catch (_) {}
              send(out);
            } catch (_) {}
          }
        });
        state.hooked++;
      } catch (e) {
        try { state.errors.push(String(e)); } catch (_) {}
      }
    }
  } catch (e) {
    return { ok: false, error: String(e) };
  }
  return { ok: true, hooked: state.hooked, errors: state.errors };
}

function getMethodImp(className, methodSig) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const cn = String(className || "").trim();
  const ms0 = String(methodSig || "").trim();
  if (!cn) return { ok: false, error: "missing className" };
  if (!ms0) return { ok: false, error: "missing methodSig" };
  const cls = ObjC.classes[cn];
  if (!cls) return { ok: false, error: "class not found: " + cn };
  const cands = [];
  if (ms0.startsWith("- ") || ms0.startsWith("+ ")) cands.push(ms0);
  else {
    cands.push("- " + ms0);
    cands.push("+ " + ms0);
    cands.push(ms0);
  }
  let m = null;
  let ms = "";
  for (let i = 0; i < cands.length; i++) {
    const k = cands[i];
    const t = cls[k];
    if (t && t.implementation) { m = t; ms = k; break; }
  }
  if (!m || !m.implementation) return { ok: false, error: "method not found: " + ms0, tried: cands };
  const p = ptr(m.implementation);
  return {
    ok: true,
    className: cn,
    method: ms,
    types: (function () { try { return String(m.types || ""); } catch (_) { return ""; } })(),
    impl: p.toString(),
    implModule: (function () { try { const mo = Process.findModuleByAddress(p); return mo ? String(mo.name) : ""; } catch (_) { return ""; } })(),
    implOffset: (function () { try { const mo = Process.findModuleByAddress(p); return mo ? p.sub(mo.base).toString() : ""; } catch (_) { return ""; } })(),
  };
}

function getProtocolMethods(protoName) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const pn = String(protoName || "").trim();
  if (!pn) return { ok: false, error: "missing protoName" };
  let proto = null;
  try { proto = ObjC.protocols ? ObjC.protocols[pn] : null; } catch (_) { proto = null; }
  if (!proto) return { ok: false, error: "protocol not found: " + pn };
  let fnCopy = null;
  let fnFree = null;
  let fnSelGetName = null;
  try {
    const p1 =
      Module.findExportByName("libobjc.A.dylib", "protocol_copyMethodDescriptionList") ||
      Module.findExportByName(null, "protocol_copyMethodDescriptionList");
    const p2 = Module.findExportByName("libsystem_malloc.dylib", "free") || Module.findExportByName(null, "free");
    const p3 = Module.findExportByName("libobjc.A.dylib", "sel_getName") || Module.findExportByName(null, "sel_getName");
    if (p1) fnCopy = new NativeFunction(p1, "pointer", ["pointer", "bool", "bool", "pointer"]);
    if (p2) fnFree = new NativeFunction(p2, "void", ["pointer"]);
    if (p3) fnSelGetName = new NativeFunction(p3, "pointer", ["pointer"]);
  } catch (_) {
    fnCopy = null;
  }
  if (!fnCopy || !fnSelGetName) return { ok: false, error: "objc protocol introspection unavailable" };

  const ptrSize = Process.pointerSize;
  const readDescList = (required, isInstance) => {
    const out = [];
    const outCount = Memory.alloc(4);
    Memory.writeU32(outCount, 0);
    let pList = NULL;
    try { pList = fnCopy(proto.handle, !!required, !!isInstance, outCount); } catch (_) { pList = NULL; }
    const n = Memory.readU32(outCount);
    try {
      for (let i = 0; i < n; i++) {
        const e = pList.add(i * (ptrSize * 2));
        const sel = Memory.readPointer(e);
        const types = Memory.readPointer(e.add(ptrSize));
        let name = "";
        try { name = Memory.readUtf8String(fnSelGetName(sel)) || ""; } catch (_) { name = ""; }
        let enc = "";
        try { enc = types.isNull() ? "" : (Memory.readUtf8String(types) || ""); } catch (_) { enc = ""; }
        out.push({ name, types: enc });
      }
    } catch (_) {}
    try { if (fnFree && !pList.isNull()) fnFree(pList); } catch (_) {}
    return out;
  };

  return {
    ok: true,
    protocol: pn,
    required_instance: readDescList(true, true),
    optional_instance: readDescList(false, true),
    required_class: readDescList(true, false),
    optional_class: readDescList(false, false),
  };
}

function installCrashSniffer() {
  if (globalThis.__QQW_CRASH_SNIFF && globalThis.__QQW_CRASH_SNIFF.installed) {
    return { ok: true, installed: true, hooks: globalThis.__QQW_CRASH_SNIFF.hooks || [] };
  }
  const st = { installed: true, hooks: [], errors: [] };
  globalThis.__QQW_CRASH_SNIFF = st;

  const attach = (name, modNames) => {
    try {
      let p = null;
      for (let i = 0; i < modNames.length; i++) {
        p = Module.findExportByName(modNames[i], name);
        if (p) break;
      }
      if (!p) p = Module.findExportByName(null, name);
      if (!p) return;
      Interceptor.attach(p, {
        onEnter(args) {
          try {
            const bt = Thread.backtrace(this.context, Backtracer.ACCURATE)
              .slice(0, 30)
              .map((a) => DebugSymbol.fromAddress(a).toString());
            let lastStep = null;
            try { lastStep = globalThis.__QQW_REACT2_LASTSTEP || null; } catch (_) { lastStep = null; }
            if (name.startsWith("swift_") && (!lastStep || String(lastStep.stage || "") === "start" || String(lastStep.stage || "") === "idle")) return;
            send({ type: "qqw.crashsniff", fn: name, at: ptr(p).toString(), lastStep, bt });
          } catch (_) {}
        }
      });
      st.hooks.push({ name, at: ptr(p).toString() });
    } catch (e) {
      try { st.errors.push(name + ": " + String(e)); } catch (_) {}
    }
  };

  attach("abort", ["libsystem_c.dylib"]);
  attach("__assert_rtn", ["libsystem_c.dylib"]);
  attach("objc_exception_throw", ["libobjc.A.dylib"]);
  attach("swift_dynamicCastFailure", ["libswiftCore.dylib"]);
  attach("swift_unexpectedError", ["libswiftCore.dylib"]);
  attach("swift_reportError", ["libswiftCore.dylib"]);
  attach("swift_willThrow", ["libswiftCore.dylib"]);

  return { ok: true, installed: true, hooks: st.hooks, errors: st.errors };
}

function installExceptionSniffer() {
  try {
    if (globalThis.__QQW_EXC_SNIFF && globalThis.__QQW_EXC_SNIFF.installed) {
      return { ok: true, installed: true };
    }
    const st = { installed: true };
    globalThis.__QQW_EXC_SNIFF = st;
    try {
      Process.setExceptionHandler((details) => {
        try {
          const bt = (details && details.context)
            ? Thread.backtrace(details.context, Backtracer.ACCURATE)
              .slice(0, 40)
              .map((a) => DebugSymbol.fromAddress(a).toString())
            : [];
          send({
            type: "qqw.exception",
            name: String(details && details.type || ""),
            address: String(details && details.address || ""),
            memory: details && details.memory ? { operation: details.memory.operation, address: String(details.memory.address || ""), size: details.memory.size } : null,
            lastStep: (function () { try { return globalThis.__QQW_REACT2_LASTSTEP || null; } catch (_) { return null; } })(),
            bt
          });
        } catch (_) {}
        return false;
      });
    } catch (e) {
      return { ok: false, error: String(e) };
    }
    return { ok: true, installed: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function probeCrashRequestThumb(jid, useMainApp) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const targetJidStr = String(jid || "").trim();
  if (!targetJidStr) return { ok: false, error: "no jid provided" };
  const useMain = !!useMainApp;
  safeObjCInvoke(() => {
    let pool = null;
    try {
      try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
      const ctxRes = _resolveCtxMainActive();
      if (!ctxRes || !ctxRes.ok) return;
      const ppm = _getProfilePictureManagerFromCtx(ctxRes.ctx);
      if (!ppm) return;
      const WAUserJID = ObjC.classes.WAUserJID;
      if (!WAUserJID || !WAUserJID["+ jidOrLIDWithString:"]) return;
      const jidObj = WAUserJID.jidOrLIDWithString_(nsString(targetJidStr));
      let idpObj = jidObj;
      try {
        if (jidObj && objcHasSelector(jidObj, "profilePictureJID")) {
          const pjid = jidObj.profilePictureJID();
          if (pjid) idpObj = pjid;
        }
      } catch (_) {}
      const sel = useMain
        ? "MAIN_APP_requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:botPersonaID:"
        : "requestProfilePictureThumbnailForIdentifierProviding:onlyIfNecessary:botPersonaID:";
      if (!objcHasSelector(ppm, sel)) return;
      send({ type: "debug", msg: "pp crash probe invoking " + sel + " with profilePictureJID" });
      ppm[sel](idpObj, false, null);
    } catch (_) {
    } finally {
      try { if (pool) pool.release(); } catch (_) {}
    }
  });
  return { ok: true, status: "triggered", jid: targetJidStr, mode: useMain ? "MAIN_APP" : "regular" };
}

function getModuleInfo(name) {
  const n = String(name || "").trim();
  if (!n) return { ok: false, error: "missing module name" };
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
      const m = mods[i];
      if (!m) continue;
      if (String(m.name).toLowerCase() === n.toLowerCase()) {
        return { ok: true, name: m.name, base: ptr(m.base).toString(), size: m.size, path: m.path };
      }
    }
    return { ok: false, error: "module not found: " + n };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function probeObjectSelectors(obj, selectors) {
  const out = {};
  try {
    const o = obj instanceof ObjC.Object ? obj : (obj ? new ObjC.Object(obj) : null);
    if (!o) return out;
    for (let i = 0; i < selectors.length; i++) {
      const sel = String(selectors[i] || "").trim();
      if (!sel) continue;
      out[sel] = false;
      try { out[sel] = objcHasSelector(o, sel); } catch (_) { out[sel] = false; }
    }
  } catch (_) {}
  return out;
}

function probeRevokeSelectors() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const ctxRes = _resolveCtxMainActive();
  if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
  const ctx = ctxRes.ctx;
  const ppm = _getProfilePictureManagerFromCtx(ctx);
  const storage = (function () { try { return ctx && objcHasSelector(ctx, "chatStorage") ? objcCallNoArg(ctx, "chatStorage") : null; } catch (_) { return null; } })();
  const sender = (function () { try { return ctx && objcHasSelector(ctx, "messageSender") ? objcCallNoArg(ctx, "messageSender") : null; } catch (_) { return null; } })();

  let txn = null;
  try {
    const sels = ["chatSessionTransactionManager", "transactionManager"];
    for (let i = 0; i < sels.length && !txn; i++) {
      const s = sels[i];
      if (objcHasSelector(ctx, s)) txn = objcCallNoArg(ctx, s);
    }
  } catch (_) { txn = null; }

  const sels = [
    "revokeMessage:session:",
    "revokeMessage:withInputs:",
    "revokeMessagesAsGroupAdmin:",
    "internalRevokeMessages:triggeredByMessageWithID:onDate:outgoing:revokedByAdminUserJID:botPluginMessagesToDelete:beginTransactions:commitTransactions:",
    "deleteMessages:reason:error:",
    "deleteMessages:withUndoSupport:",
  ];

  return {
    ok: true,
    ctxClass: String(ctx.$className || ""),
    storageClass: storage ? String(storage.$className || "") : "",
    senderClass: sender ? String(sender.$className || "") : "",
    txnClass: txn ? String(txn.$className || "") : "",
    storage: probeObjectSelectors(storage, sels),
    sender: probeObjectSelectors(sender, sels),
    txn: probeObjectSelectors(txn, sels),
    ppmClass: ppm ? String(ppm.$className || "") : "",
  };
}

function _makeWAChatJIDFromString(jidStr) {
  try {
    const s = String(jidStr || "").trim();
    if (!s) return null;
    const WAChatJID = ObjC.classes.WAChatJID;
    if (!WAChatJID) return null;
    if (WAChatJID["+ ifValidWithStringRepresentation:"]) return WAChatJID.ifValidWithStringRepresentation_(nsString(s));
    return null;
  } catch (_) {
    return null;
  }
}

function _makeAuthorUserJIDFromString(jidStr) {
  try {
    const raw = String(jidStr || "").trim();
    if (!raw || raw.indexOf("@") === -1) return null;
    let s = raw;
    const cls = s.toLowerCase().endsWith("@lid") ? ObjC.classes.WALIDUserJID : ObjC.classes.WAUserJID;
    if (!cls) return null;
    if (cls["+ ifValidWithStringRepresentation:"]) return cls.ifValidWithStringRepresentation_(nsString(s));
    return null;
  } catch (_) {
    return null;
  }
}

function _createOutgoingReactionFromUnicode(unicodeEmoji) {
  try {
    const s = String(unicodeEmoji || "").trim();
    if (!s) return { ok: false, error: "missing unicode emoji" };
    return { ok: false, error: "disabled_for_safety; use statusreactionresolve to identify exact implementor before invoking" };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _getStatusReactionUpdater() {
  try {
    const sel = "updateStatusWithOutgoingReaction:stanzaID:authorUserJID:completion:";
    const classes = listClassesRespondingToSelector(sel, 200);
    if (!classes || !classes.length) return { ok: false, error: "no class responds to " + sel };
    const pick = (name) => {
      try {
        const k = ObjC.classes[name];
        if (!k) return null;
        const inst = tryGetSingletonInstance(k);
        if (inst && objcHasSelector(inst, sel)) return inst;
        return null;
      } catch (_) { return null; }
    };
    let inst = null;
    for (let i = 0; i < classes.length; i++) {
      const n = String(classes[i] || "");
      if (n.indexOf("Status") === -1 && n.indexOf("status") === -1) continue;
      inst = pick(n);
      if (inst) return { ok: true, className: n, instance: inst };
    }
    for (let i = 0; i < classes.length; i++) {
      const n = String(classes[i] || "");
      inst = pick(n);
      if (inst) return { ok: true, className: n, instance: inst };
    }
    return { ok: false, error: "no singleton instance for updater classes", classes };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function statusreactionnative(unicodeEmoji, authorJid, statusStanzaId) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const emoji = String(unicodeEmoji || "").trim();
  const authorStr = String(authorJid || "").trim();
  const sid = String(statusStanzaId || "").trim();
  if (!emoji || !authorStr || !sid) return Promise.resolve({ ok: false, error: "missing emoji/authorJid/statusStanzaId" });
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const core = _resolveCoreForSendExplore();
        if (!core || !core.ok) return resolve({ ok: false, error: core ? core.error : "core failed" });

        const authorObj = _makeAuthorUserJIDFromString(authorStr);
        if (!authorObj) return resolve({ ok: false, error: "authorUserJID construct failed", statusAuthorJid: authorStr });

        const statusJidObj = _makeWAChatJIDFromString("status@broadcast");
        if (!statusJidObj) return resolve({ ok: false, error: "status@broadcast jid parse failed" });
        const csStatus = _fetchOrCreateChatSession(core.storage, statusJidObj, core.ctxMain);
        if (!csStatus) return resolve({ ok: false, error: "fetchChatSession status@broadcast failed" });
        const mcsStatus = _getMutableChatSession(csStatus);
        if (!mcsStatus) return resolve({ ok: false, error: "mutableChatSession status@broadcast failed" });

        const nsSid = nsString(sid);
        if (!nsSid) return resolve({ ok: false, error: "stanzaId->NSString failed" });
        const selFetch = "fetchMessageWithStanzaID:authorUserJID:";
        if (!objcHasSelector(mcsStatus, selFetch)) return resolve({ ok: false, error: "WAMutableChatSession missing selector " + selFetch });
        const msg = mcsStatus.fetchMessageWithStanzaID_authorUserJID_(nsSid, authorObj);
        if (!msg) return resolve({ ok: false, error: "fetchMessageWithStanzaID:authorUserJID returned nil", statusAuthorJid: authorStr, statusStanzaId: sid });
        const msgObj = msg instanceof ObjC.Object ? msg : new ObjC.Object(msg);
        const msgPtr = (function () { try { return ptr(msgObj).toString(); } catch (_) { return "0x0"; } })();

        const selCreate = "- createOutgoingReactionWithUnicode:metadata:error:";
        if (!msgObj[selCreate] || typeof msgObj[selCreate] !== "function") return resolve({ ok: false, error: "WAMessage missing selector " + selCreate });
        const nsU = nsString(emoji);
        if (!nsU) return resolve({ ok: false, error: "emoji->NSString failed" });
        const errOut = Memory.alloc(Process.pointerSize);
        Memory.writePointer(errOut, ptr("0x0"));
        const reactionObj = msgObj[selCreate](nsU, null, errOut);
        if (!reactionObj) {
          let errDesc = "";
          try {
            const ep = Memory.readPointer(errOut);
            if (ep && !ep.isNull()) errDesc = String(new ObjC.Object(ep));
          } catch (_) { errDesc = ""; }
          return resolve({ ok: false, error: "createOutgoingReaction returned nil", err: errDesc });
        }

        const selUpd = "- updateOutgoingReaction:";
        if (!msgObj[selUpd] || typeof msgObj[selUpd] !== "function") return resolve({ ok: false, error: "WAMessage missing selector " + selUpd });
        try { msgObj[selUpd](reactionObj); } catch (e) { return resolve({ ok: false, error: "updateOutgoingReaction failed: " + String(e) }); }
        return resolve({ ok: true, statusAuthorJid: authorStr, statusStanzaId: sid, msgPtr: msgPtr, msgClass: String(msgObj.$className || ""), reactionClass: String(reactionObj.$className || ""), coreSource: String(core.source || "") });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function statusreactionresolve(maxN) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const lim = Math.max(1, Math.min(40, Number(maxN || 10) | 0));
  const selCreate = "createOutgoingReactionWithUnicode:metadata:error:";
  const selUpdate = "updateStatusWithOutgoingReaction:stanzaID:authorUserJID:completion:";
  const get = (name, ret, args) => {
    const p = Module.findExportByName("libobjc.A.dylib", name);
    return p ? new NativeFunction(p, ret, args) : null;
  };
  const objc_copyClassNamesForImage = get("objc_copyClassNamesForImage", "pointer", ["pointer", "pointer"]);
  const objc_getClass = get("objc_getClass", "pointer", ["pointer"]);
  const sel_registerName = get("sel_registerName", "pointer", ["pointer"]);
  const class_getInstanceMethod = get("class_getInstanceMethod", "pointer", ["pointer", "pointer"]);
  const class_getClassMethod = get("class_getClassMethod", "pointer", ["pointer", "pointer"]);
  const method_getImplementation = get("method_getImplementation", "pointer", ["pointer"]);
  const method_getTypeEncoding = get("method_getTypeEncoding", "pointer", ["pointer"]);
  const freeFn = Module.findExportByName(null, "free") ? new NativeFunction(Module.findExportByName(null, "free"), "void", ["pointer"]) : null;
  if (!objc_copyClassNamesForImage || !objc_getClass || !sel_registerName || !class_getInstanceMethod || !class_getClassMethod) {
    return { ok: false, error: "libobjc exports missing (need objc_copyClassNamesForImage)" };
  }
  let imgPath = "WhatsApp";
  try {
    const m = Process.getModuleByName("WhatsApp");
    if (m && m.path) imgPath = String(m.path);
  } catch (_) {}
  const imgPathP = Memory.allocUtf8String(imgPath);
  const scanImage = (selName) => {
    const out = [];
    const outCountP = Memory.alloc(4);
    Memory.writeU32(outCountP, 0);
    const listP = objc_copyClassNamesForImage(imgPathP, outCountP);
    const n = Memory.readU32(outCountP) | 0;
    if (!listP || ptr(listP).isNull() || n <= 0) return out;
    const sel = sel_registerName(Memory.allocUtf8String(selName));
    const maxTake = Math.min(n, 60000);
    for (let i = 0; i < maxTake && out.length < lim; i++) {
      const nameP = Memory.readPointer(ptr(listP).add(i * Process.pointerSize));
      if (!nameP || nameP.isNull()) continue;
      let name = "";
      try { name = Memory.readUtf8String(nameP) || ""; } catch (_) { name = ""; }
      if (!name || name.length < 2) continue;
      const cls = objc_getClass(Memory.allocUtf8String(name));
      if (!cls || ptr(cls).isNull()) continue;
      let mth = ptr("0x0");
      let kind = "";
      try { mth = class_getClassMethod(cls, sel); } catch (_) { mth = ptr("0x0"); }
      if (mth && !mth.isNull()) kind = "class";
      if (!kind) {
        try { mth = class_getInstanceMethod(cls, sel); } catch (_) { mth = ptr("0x0"); }
        if (mth && !mth.isNull()) kind = "instance";
      }
      if (!kind) continue;
      let imp = "0x0";
      let type = "";
      try {
        if (method_getImplementation) {
          const p = method_getImplementation(mth);
          if (p && !ptr(p).isNull()) imp = ptr(p).toString();
        }
      } catch (_) { imp = "0x0"; }
      try {
        if (method_getTypeEncoding) {
          const tp = method_getTypeEncoding(mth);
          if (tp && !ptr(tp).isNull()) type = Memory.readUtf8String(ptr(tp)) || "";
        }
      } catch (_) { type = ""; }
      if (selName.indexOf(":") !== -1 && (type === "v@:" || type === "@@:")) continue;
      let ida = "";
      let moduleName = "";
      let moduleBase = "";
      let moduleOff = "";
      try {
        const info = imp !== "0x0" ? idaFromRuntimeAddr(imp) : null;
        if (info && info.ok) {
          ida = String(info.ida || "");
          moduleName = String(info.module || "");
          moduleBase = String(info.moduleBase || "");
          moduleOff = String(info.moduleOff || "");
        }
      } catch (_) {}
      out.push({ className: name, kind, imp, type, ida, moduleName, moduleBase, moduleOff });
    }
    try { if (freeFn) freeFn(ptr(listP)); } catch (_) {}
    return out;
  };
  const create = scanImage(selCreate);
  const update = scanImage(selUpdate);
  return { ok: true, image: imgPath, selCreate, selUpdate, lim, create, update };
}

function statusreactionlistimages(filter, maxN) {
  const lim = Math.max(1, Math.min(200, Number(maxN || 50) | 0));
  const flt = String(filter || "").trim().toLowerCase();
  const out = [];
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length && out.length < lim; i++) {
      const m = mods[i];
      if (!m) continue;
      const name = String(m.name || "");
      const path = String(m.path || "");
      if (flt) {
        const hay = (name + " " + path).toLowerCase();
        if (hay.indexOf(flt) === -1) continue;
      }
      out.push({ name, path, base: ptr(m.base).toString(), size: "0x" + (Number(m.size || 0) >>> 0).toString(16) });
    }
  } catch (_) {}
  return { ok: true, filter: String(filter || ""), count: out.length, images: out };
}

function statusreactionresolveimg(filter, maxN) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const lim = Math.max(1, Math.min(40, Number(maxN || 10) | 0));
  const selCreate = "createOutgoingReactionWithUnicode:metadata:error:";
  const selUpdate = "updateStatusWithOutgoingReaction:stanzaID:authorUserJID:completion:";
  const flt = String(filter || "").trim().toLowerCase();
  let imgPath = "";
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
      const m = mods[i];
      if (!m) continue;
      const name = String(m.name || "");
      const path = String(m.path || "");
      const hay = (name + " " + path).toLowerCase();
      if (!flt || hay.indexOf(flt) !== -1) { imgPath = path || name; break; }
    }
  } catch (_) {}
  if (!imgPath) return { ok: false, error: "no module matched filter", filter: String(filter || "") };

  const get = (name, ret, args) => {
    const p = Module.findExportByName("libobjc.A.dylib", name);
    return p ? new NativeFunction(p, ret, args) : null;
  };
  const objc_copyClassNamesForImage = get("objc_copyClassNamesForImage", "pointer", ["pointer", "pointer"]);
  const objc_getClass = get("objc_getClass", "pointer", ["pointer"]);
  const sel_registerName = get("sel_registerName", "pointer", ["pointer"]);
  const class_getInstanceMethod = get("class_getInstanceMethod", "pointer", ["pointer", "pointer"]);
  const class_getClassMethod = get("class_getClassMethod", "pointer", ["pointer", "pointer"]);
  const method_getImplementation = get("method_getImplementation", "pointer", ["pointer"]);
  const method_getTypeEncoding = get("method_getTypeEncoding", "pointer", ["pointer"]);
  const freeFn = Module.findExportByName(null, "free") ? new NativeFunction(Module.findExportByName(null, "free"), "void", ["pointer"]) : null;
  if (!objc_copyClassNamesForImage || !objc_getClass || !sel_registerName || !class_getInstanceMethod || !class_getClassMethod) {
    return { ok: false, error: "libobjc exports missing (need objc_copyClassNamesForImage)" };
  }
  const imgPathP = Memory.allocUtf8String(imgPath);
  const scanImage = (selName) => {
    const out = [];
    const outCountP = Memory.alloc(4);
    Memory.writeU32(outCountP, 0);
    const listP = objc_copyClassNamesForImage(imgPathP, outCountP);
    const n = Memory.readU32(outCountP) | 0;
    if (!listP || ptr(listP).isNull() || n <= 0) return out;
    const sel = sel_registerName(Memory.allocUtf8String(selName));
    const maxTake = Math.min(n, 60000);
    for (let i = 0; i < maxTake && out.length < lim; i++) {
      const nameP = Memory.readPointer(ptr(listP).add(i * Process.pointerSize));
      if (!nameP || nameP.isNull()) continue;
      let name = "";
      try { name = Memory.readUtf8String(nameP) || ""; } catch (_) { name = ""; }
      if (!name || name.length < 2) continue;
      const cls = objc_getClass(Memory.allocUtf8String(name));
      if (!cls || ptr(cls).isNull()) continue;
      let mth = ptr("0x0");
      let kind = "";
      try { mth = class_getClassMethod(cls, sel); } catch (_) { mth = ptr("0x0"); }
      if (mth && !mth.isNull()) kind = "class";
      if (!kind) {
        try { mth = class_getInstanceMethod(cls, sel); } catch (_) { mth = ptr("0x0"); }
        if (mth && !mth.isNull()) kind = "instance";
      }
      if (!kind) continue;
      let imp = "0x0";
      let type = "";
      try {
        if (method_getImplementation) {
          const p = method_getImplementation(mth);
          if (p && !ptr(p).isNull()) imp = ptr(p).toString();
        }
      } catch (_) { imp = "0x0"; }
      try {
        if (method_getTypeEncoding) {
          const tp = method_getTypeEncoding(mth);
          if (tp && !ptr(tp).isNull()) type = Memory.readUtf8String(ptr(tp)) || "";
        }
      } catch (_) { type = ""; }
      let ida = "";
      let moduleName = "";
      let moduleBase = "";
      let moduleOff = "";
      try {
        const info = imp !== "0x0" ? idaFromRuntimeAddr(imp) : null;
        if (info && info.ok) {
          ida = String(info.ida || "");
          moduleName = String(info.module || "");
          moduleBase = String(info.moduleBase || "");
          moduleOff = String(info.moduleOff || "");
        }
      } catch (_) {}
      out.push({ className: name, kind, imp, type, ida, moduleName, moduleBase, moduleOff });
    }
    try { if (freeFn) freeFn(ptr(listP)); } catch (_) {}
    return out;
  };
  const create = scanImage(selCreate);
  const update = scanImage(selUpdate);
  return { ok: true, filter: String(filter || ""), image: imgPath, selCreate, selUpdate, lim, create, update };
}

function statusreactionfindupdate(filter, maxModules, maxHitsPerImage) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const flt = String(filter || "frameworks").trim().toLowerCase();
  const modLim = Math.max(1, Math.min(80, Number(maxModules || 30) | 0));
  const hitLim = Math.max(1, Math.min(40, Number(maxHitsPerImage || 10) | 0));
  const selUpdate = "updateStatusWithOutgoingReaction:stanzaID:authorUserJID:completion:";

  const get = (name, ret, args) => {
    const p = Module.findExportByName("libobjc.A.dylib", name);
    return p ? new NativeFunction(p, ret, args) : null;
  };
  const objc_copyClassNamesForImage = get("objc_copyClassNamesForImage", "pointer", ["pointer", "pointer"]);
  const objc_getClass = get("objc_getClass", "pointer", ["pointer"]);
  const sel_registerName = get("sel_registerName", "pointer", ["pointer"]);
  const class_getInstanceMethod = get("class_getInstanceMethod", "pointer", ["pointer", "pointer"]);
  const class_getClassMethod = get("class_getClassMethod", "pointer", ["pointer", "pointer"]);
  const method_getImplementation = get("method_getImplementation", "pointer", ["pointer"]);
  const method_getTypeEncoding = get("method_getTypeEncoding", "pointer", ["pointer"]);
  const freeFn = Module.findExportByName(null, "free") ? new NativeFunction(Module.findExportByName(null, "free"), "void", ["pointer"]) : null;
  if (!objc_copyClassNamesForImage || !objc_getClass || !sel_registerName || !class_getInstanceMethod || !class_getClassMethod) {
    return { ok: false, error: "libobjc exports missing (need objc_copyClassNamesForImage)" };
  }

  const scanOneImage = (imgPath) => {
    const out = [];
    const imgPathP = Memory.allocUtf8String(String(imgPath || ""));
    const outCountP = Memory.alloc(4);
    Memory.writeU32(outCountP, 0);
    const listP = objc_copyClassNamesForImage(imgPathP, outCountP);
    const n = Memory.readU32(outCountP) | 0;
    if (!listP || ptr(listP).isNull() || n <= 0) return out;
    const sel = sel_registerName(Memory.allocUtf8String(selUpdate));
    const maxTake = Math.min(n, 80000);
    for (let i = 0; i < maxTake && out.length < hitLim; i++) {
      const nameP = Memory.readPointer(ptr(listP).add(i * Process.pointerSize));
      if (!nameP || nameP.isNull()) continue;
      let name = "";
      try { name = Memory.readUtf8String(nameP) || ""; } catch (_) { name = ""; }
      if (!name || name.length < 2) continue;
      const cls = objc_getClass(Memory.allocUtf8String(name));
      if (!cls || ptr(cls).isNull()) continue;
      let mth = ptr("0x0");
      let kind = "";
      try { mth = class_getClassMethod(cls, sel); } catch (_) { mth = ptr("0x0"); }
      if (mth && !mth.isNull()) kind = "class";
      if (!kind) {
        try { mth = class_getInstanceMethod(cls, sel); } catch (_) { mth = ptr("0x0"); }
        if (mth && !mth.isNull()) kind = "instance";
      }
      if (!kind) continue;
      let imp = "0x0";
      let type = "";
      try {
        if (method_getImplementation) {
          const p = method_getImplementation(mth);
          if (p && !ptr(p).isNull()) imp = ptr(p).toString();
        }
      } catch (_) { imp = "0x0"; }
      try {
        if (method_getTypeEncoding) {
          const tp = method_getTypeEncoding(mth);
          if (tp && !ptr(tp).isNull()) type = Memory.readUtf8String(ptr(tp)) || "";
        }
      } catch (_) { type = ""; }
      if (type === "v@:" || type === "@@:") continue;
      let ida = "";
      let moduleName = "";
      let moduleBase = "";
      let moduleOff = "";
      try {
        const info = imp !== "0x0" ? idaFromRuntimeAddr(imp) : null;
        if (info && info.ok) {
          ida = String(info.ida || "");
          moduleName = String(info.module || "");
          moduleBase = String(info.moduleBase || "");
          moduleOff = String(info.moduleOff || "");
        }
      } catch (_) {}
      out.push({ className: name, kind, imp, type, ida, moduleName, moduleBase, moduleOff });
    }
    try { if (freeFn) freeFn(ptr(listP)); } catch (_) {}
    return out;
  };

  const mods = [];
  try {
    const xs = Process.enumerateModules();
    for (let i = 0; i < xs.length && mods.length < modLim; i++) {
      const m = xs[i];
      if (!m) continue;
      const name = String(m.name || "");
      const path = String(m.path || "");
      if (flt) {
        const hay = (name + " " + path).toLowerCase();
        if (hay.indexOf(flt) === -1) continue;
      }
      mods.push({ name, path });
    }
  } catch (_) {}

  const hits = [];
  for (let i = 0; i < mods.length; i++) {
    const p = String(mods[i].path || mods[i].name || "");
    if (!p) continue;
    let out = [];
    try { out = scanOneImage(p); } catch (_) { out = []; }
    if (out && out.length) hits.push({ image: p, matches: out });
    if (hits.length >= 6) break;
  }
  return { ok: true, selector: selUpdate, filter: String(filter || ""), scanned: mods.length, hitImages: hits.length, hits };
}

function _fetchChatSession(storageObj, chatJidObj) {
  try {
    if (!storageObj || !chatJidObj) return null;
    const stor = storageObj instanceof ObjC.Object ? storageObj : new ObjC.Object(storageObj);
    const cj = chatJidObj instanceof ObjC.Object ? chatJidObj : new ObjC.Object(chatJidObj);
    if (!stor || !cj) return null;
    if (!objcHasSelector(stor, "fetchChatSessionForJID:")) return null;
    return stor.fetchChatSessionForJID_(cj);
  } catch (_) {
    return null;
  }
}

function _fetchOrCreateChatSession(storageObj, chatJidObj, ctxMainObj) {
  try {
    if (!storageObj || !chatJidObj) return null;
    const stor = storageObj instanceof ObjC.Object ? storageObj : new ObjC.Object(storageObj);
    const cj = chatJidObj instanceof ObjC.Object ? chatJidObj : new ObjC.Object(chatJidObj);
    if (!stor || !cj) return null;

    const ctxMain = ctxMainObj ? (ctxMainObj instanceof ObjC.Object ? ctxMainObj : new ObjC.Object(ctxMainObj)) : null;

    try {
      if (objcHasSelector(stor, "fetchChatSessionForJID:")) {
        const cs0 = stor.fetchChatSessionForJID_(cj);
        if (cs0) return cs0;
      }
    } catch (_) {}

    try {
      if (ctxMain && objcHasSelector(stor, "fetchChatSessionForJID:inContext:")) {
        const cs0b = stor.fetchChatSessionForJID_inContext_(cj, ctxMain);
        if (cs0b) return cs0b;
      }
    } catch (_) {}

    try {
      if (objcHasSelector(stor, "hasExistingChatSessionForJID:")) {
        const ex = stor.hasExistingChatSessionForJID_(cj);
        if (ex === 1 || ex === true || String(ex) === "1") {
          try {
            if (objcHasSelector(stor, "fetchPreferredChatSessionForJID:inContext:prefetchingRelationshipKeyPaths:error:") && ctxMain) {
              const errPtr = Memory.alloc(Process.pointerSize);
              try { Memory.writePointer(errPtr, ptr("0x0")); } catch (_) {}
              const csPref = stor.fetchPreferredChatSessionForJID_inContext_prefetchingRelationshipKeyPaths_error_(cj, ctxMain, ptr("0x0"), errPtr);
              if (csPref) return csPref;
            }
          } catch (_) {}
        }
      }
    } catch (_) {}

    try {
      if (objcHasSelector(stor, "newOrExistingChatSessionForJID:options:")) {
        const cs2 = stor.newOrExistingChatSessionForJID_options_(cj, ptr("0x0"));
        if (cs2) return cs2;
      }
    } catch (_) {}
    try {
      if (objcHasSelector(stor, "newOrExistingChatSessionForJID:configuration:")) {
        const cs3 = stor.newOrExistingChatSessionForJID_configuration_(cj, ptr("0x0"));
        if (cs3) return cs3;
      }
    } catch (_) {}
    return null;
  } catch (_) {
    return null;
  }
}

function _getMutableChatSession(chatSessionObj) {
  try {
    if (!chatSessionObj) return null;
    const cs = chatSessionObj instanceof ObjC.Object ? chatSessionObj : new ObjC.Object(chatSessionObj);
    if (!cs) return null;
    const cn = String(cs.$className || "");
    if (cn === "WAMutableChatSession" || cn.endsWith(".WAMutableChatSession")) return cs;
    if (!objcHasSelector(cs, "mutableChatSession")) return null;
    return cs.mutableChatSession();
  } catch (_) {
    return null;
  }
}

function _fetchMessageByStanzaId(mcsObj, stanzaIdStr, participantJidStr) {
  try {
    const mcs = mcsObj instanceof ObjC.Object ? mcsObj : (mcsObj ? new ObjC.Object(mcsObj) : null);
    if (!mcs) return null;
    const sid = String(stanzaIdStr || "").trim();
    if (!sid) return null;
    const nsSid = nsString(sid);
    if (!nsSid) return null;
    const pj = String(participantJidStr || "").trim();
    if (pj) {
      let author = null;
      try {
        if (pj.startsWith("0x")) author = _safeObjFromPtrStr(pj);
      } catch (_) { author = null; }
      if (!author) author = _makeAuthorUserJIDFromString(pj);
      if (author && objcHasSelector(mcs, "fetchMessageWithStanzaID:authorUserJID:")) {
        try {
          const m0 = mcs.fetchMessageWithStanzaID_authorUserJID_(nsSid, author);
          if (m0) return m0;
        } catch (_) {}
      }
      if (author && objcHasSelector(mcs, "fetchMessageWithStanzaID:participantUserJID:isFromMe:")) {
        try {
          const m0 = mcs.fetchMessageWithStanzaID_participantUserJID_isFromMe_(nsSid, author, 0);
          if (m0) return m0;
        } catch (_) {}
        try {
          const m1 = mcs.fetchMessageWithStanzaID_participantUserJID_isFromMe_(nsSid, author, 1);
          if (m1) return m1;
        } catch (_) {}
      }
      return null;
    }
    if (!objcHasSelector(mcs, "fetchMessageWithStanzaID:isFromMe:")) return null;
    try {
      const m0 = mcs.fetchMessageWithStanzaID_isFromMe_(nsSid, 0);
      if (m0) return m0;
    } catch (_) {}
    try {
      const m1 = mcs.fetchMessageWithStanzaID_isFromMe_(nsSid, 1);
      if (m1) return m1;
    } catch (_) {}
    return null;
  } catch (_) {
    return null;
  }
}

function revokeMessageForEveryone(jid, stanzaId, participantJid) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const chatJidStr = String(jid || "").trim();
  const stanzaIdStr = String(stanzaId || "").trim();
  const participantStr = String(participantJid || "").trim();
  if (!chatJidStr || !stanzaIdStr) return Promise.resolve({ ok: false, error: "missing jid/stanzaId" });

  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const core = _resolveCoreFixedExplore();
        if (!core || !core.ok) return resolve({ ok: false, error: (core && core.error) ? core.error : "no context" });
        const storage = core.storage;
        if (!storage) return resolve({ ok: false, error: "chatStorage nil" });
        if (!objcHasSelector(storage, "revokeOutgoingMessages:")) return resolve({ ok: false, error: "WAChatStorage missing revokeOutgoingMessages:" });

        const chatJidObj = _makeWAChatJIDFromString(chatJidStr);
        if (!chatJidObj) return resolve({ ok: false, error: "invalid chatJid" });
        const cs = _fetchChatSession(storage, chatJidObj);
        if (!cs) return resolve({ ok: false, error: "fetchChatSession failed" });
        const mcs = _getMutableChatSession(cs);
        if (!mcs) return resolve({ ok: false, error: "mutableChatSession missing" });
        const msg = _fetchMessageByStanzaId(mcs, stanzaIdStr, participantStr);
        if (!msg) return resolve({ ok: false, error: "message not found by stanzaId" });

        try {
          if (objcHasSelector(msg, "isFromMe")) {
            const fm = msg.isFromMe();
            if (!(fm === 1 || fm === true || String(fm) === "1")) return resolve({ ok: false, error: "target is not an outgoing message" });
          } else {
            return resolve({ ok: false, error: "cannot verify isFromMe" });
          }
        } catch (_) {
          return resolve({ ok: false, error: "cannot verify isFromMe" });
        }

        const NSArray = ObjC.classes.NSArray;
        if (!NSArray || !NSArray["+ arrayWithObject:"]) return resolve({ ok: false, error: "NSArray unavailable" });
        const messages = NSArray.arrayWithObject_(msg);
        storage.revokeOutgoingMessages_(messages);
        resolve({ ok: true, jid: chatJidStr, stanzaId: stanzaIdStr });
      } catch (e) {
        return resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function markMessageReadByStanzaId(chatJid, stanzaId, participantJid, sendReadReceipts, isMarkedByUser) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const chatJidStr = String(chatJid || "").trim();
  const stanzaIdStr = String(stanzaId || "").trim();
  const participantStr = String(participantJid || "").trim();
  const sendRR = (sendReadReceipts === undefined || sendReadReceipts === null) ? true : !!sendReadReceipts;
  const markedByUser = (isMarkedByUser === undefined || isMarkedByUser === null) ? true : !!isMarkedByUser;
  if (!chatJidStr || !stanzaIdStr) return Promise.resolve({ ok: false, error: "missing jid/stanzaId" });

  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const core = _resolveCoreFixedExplore();
        if (!core || !core.ok) return resolve({ ok: false, error: (core && core.error) ? core.error : "no context" });
        const storage = core.storage;
        if (!storage) return resolve({ ok: false, error: "chatStorage nil" });

        const chatJidObj = _makeWAChatJIDFromString(chatJidStr);
        if (!chatJidObj) return resolve({ ok: false, error: "invalid chatJid" });
        const cs = _fetchChatSession(storage, chatJidObj);
        if (!cs) return resolve({ ok: false, error: "fetchChatSession failed" });
        const mcs = _getMutableChatSession(cs);
        if (!mcs) return resolve({ ok: false, error: "mutableChatSession missing" });
        const msg = _fetchMessageByStanzaId(mcs, stanzaIdStr, participantStr);
        if (!msg) return resolve({ ok: false, error: "message not found by stanzaId" });

        const NSArray = ObjC.classes.NSArray;
        if (!NSArray || !NSArray["+ arrayWithObject:"]) return resolve({ ok: false, error: "NSArray unavailable" });
        const sessions = NSArray.arrayWithObject_(cs);

        const actions = [];
        const chatMgrRes = _resolveChatManager(core);
        const chatMgr = (chatMgrRes && chatMgrRes.ok) ? chatMgrRes.mgr : null;
        const chatMgrSource = (chatMgrRes && chatMgrRes.ok) ? String(chatMgrRes.source || "") : "";
        const chatMgrClass = (chatMgr && chatMgr.$className) ? String(chatMgr.$className || "") : "";
        const chatMgrPtr = (function () { try { return chatMgr && chatMgr.handle ? chatMgr.handle.toString() : ""; } catch (_) { return ""; } })();

        if (chatMgr) {
          const errPtr = Memory.alloc(Process.pointerSize);
          try { Memory.writePointer(errPtr, ptr("0x0")); } catch (_) {}
          try {
            if (objcHasSelector(chatMgr, "markChatSessions:read:sendReadReceipts:isMarkedByUser:error:")) {
              chatMgr.markChatSessions_read_sendReadReceipts_isMarkedByUser_error_(sessions, 1, sendRR ? 1 : 0, markedByUser ? 1 : 0, errPtr);
              actions.push("WAChatManager.markChatSessions:read:sendReadReceipts:isMarkedByUser:error:");
              let errDesc = "";
              try {
                const ep = Memory.readPointer(errPtr);
                if (ep && !ep.isNull()) errDesc = String(new ObjC.Object(ep));
              } catch (_) { errDesc = ""; }
              return resolve({ ok: true, jid: chatJidStr, stanzaId: stanzaIdStr, participantJid: participantStr, used: actions.join(","), source: chatMgrSource, chatManagerClass: chatMgrClass, chatManagerPtr: chatMgrPtr, sendReadReceipts: sendRR ? 1 : 0, isMarkedByUser: markedByUser ? 1 : 0, err: errDesc });
            }
          } catch (_) {}

          if (sendRR) {
            try {
              if (objcHasSelector(chatMgr, "sendReadReceiptsForMessagesBeforeAndIncludingMessage:inChatSession:isMarkedByUser:")) {
                chatMgr.sendReadReceiptsForMessagesBeforeAndIncludingMessage_inChatSession_isMarkedByUser_(msg, cs, markedByUser ? 1 : 0);
                actions.push("WAChatManager.sendReadReceiptsForMessagesBeforeAndIncludingMessage:inChatSession:isMarkedByUser:");
              }
            } catch (_) {}
          }
          try {
            if (objcHasSelector(chatMgr, "markChatSessionsAsRead:")) {
              chatMgr.markChatSessionsAsRead_(sessions);
              actions.push("WAChatManager.markChatSessionsAsRead:");
              return resolve({ ok: true, jid: chatJidStr, stanzaId: stanzaIdStr, participantJid: participantStr, used: actions.join(","), source: chatMgrSource, chatManagerClass: chatMgrClass, chatManagerPtr: chatMgrPtr, sendReadReceipts: sendRR ? 1 : 0, isMarkedByUser: markedByUser ? 1 : 0 });
            }
          } catch (_) {}
        }

        let vc = _findWAChatListViewControllerActive();
        let vcSource = "active_search";
        if (!vc) {
          const vcPtr = String(READ_PROBE.lastSelfPtr || "").trim();
          if (vcPtr) {
            vc = _safeObj(vcPtr);
            vcSource = "captured_last";
          }
        }
        if (!vc) return resolve({ ok: false, error: "WAChatListViewController not found; open chat list UI and retry", source: vcSource });
        if (!objcHasSelector(vc, "markChatSessionsAsRead:")) return resolve({ ok: false, error: "WAChatListViewController missing markChatSessionsAsRead:", source: vcSource });

        vc.markChatSessionsAsRead_(sessions);
        actions.push("WAChatListViewController.markChatSessionsAsRead:");
        resolve({ ok: true, jid: chatJidStr, stanzaId: stanzaIdStr, participantJid: participantStr, used: actions.join(","), source: vcSource, sendReadReceipts: sendRR ? 1 : 0, isMarkedByUser: markedByUser ? 1 : 0 });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

function _buildAttachmentsEmptyExplore() {
  try {
    const cls = ObjC.classes.WAMessageAttachments;
    if (!cls || !cls.alloc) return null;
    const inst = cls.alloc();
    if (!inst || !inst["- init"]) return null;
    return _safeObj(inst["- init"]());
  } catch (_) {
    return null;
  }
}

const STATUS_FIXED = {
  sendTextSelector: "- sendMessageWithText:multicast:attachments:messageOrigin:creationEntryPoint:inChatSession:statusContentOriginInfo:statusDistributionInfo:statusResharePolicy:statusNotificationInfo:statusCreativeToolsUsageInfo:hasTextFromURL:openedFromURL:smbAutomated:statusMentionsJIDs:statusMentionsChatSessions:isQuestion:fromViewController:beforeSendCallback:completion:",
  sendImageSelector: "- sendMessageWithImage:thumbnail:caption:statusMentionsJIDs:statusMentionsChatSessions:productDescriptor:attachments:messageOrigin:inChatSession:statusContentOriginInfo:statusDistributionInfo:statusResharePolicy:statusNotificationInfo:statusCreativeToolsUsageInfo:isViewOnce:scanLengths:optimisticUploadIdentifier:interactiveAnnotations:mediaPickerOrigin:mediaTranscodeConfig:transcodeLoggingInfo:imageSourceType:statusSourceType:accessibilityLabel:pairedMediaInfo:isPremiumMessage:isQuestion:assetIdentifier:mediaSourceMetadata:completion:",
  fetchChatSessionSelector: "- fetchChatSessionForJID:",
  mutableChatSessionSelector: "- mutableChatSession",
  msgIdInitUsingStanzaIdSelector: "- initWithMessage:usingStanzaID:",
};

const STATUS_POST = { hookInstalled: false, hookError: "", stanzaIdByMsgPtr: {}, pendByMsgPtr: {}, activePend: null };

function _statusCanCall(objOrCls, selKey) {
  try {
    if (!objcAvailable() || !objOrCls || !selKey) return false;
    const o = objOrCls instanceof ObjC.Object ? objOrCls : new ObjC.Object(objOrCls);
    const m = o[selKey];
    return !!(m && m.implementation);
  } catch (_) {
    return false;
  }
}

function _statusStripAngles(s) {
  try { return String(s || "").replace(/[<>\s]/g, ""); } catch (_) { return ""; }
}

function _statusSafeDesc(p) {
  try {
    const o = _safeObj(p);
    if (!o) return "";
    const d = String(o);
    return d && d !== "(null)" ? d : "";
  } catch (_) {
    return "";
  }
}

function _statusGetUIApplicationDelegate() {
  try {
    const UIApp = ObjC.classes.UIApplication;
    if (!UIApp || !UIApp["+ sharedApplication"]) return null;
    const app = _safeObj(UIApp["+ sharedApplication"]());
    if (!app) return null;
    try { if (app.delegate) return _safeObj(app.delegate()); } catch (_) {}
    try { if (_statusCanCall(app, "- delegate")) return _safeObj(app["- delegate"]()); } catch (_) {}
    return null;
  } catch (_) {
    return null;
  }
}

function _statusResolveCoreFixed() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const del = _statusGetUIApplicationDelegate();
  if (!del) return { ok: false, error: "UIApplication.delegate unavailable" };
  let ctx = null;
  try { if (del.$ivars) ctx = del.$ivars._userContext || null; } catch (_) { ctx = null; }
  ctx = _safeObj(ctx);
  if (!ctx) return { ok: false, error: "delegate._userContext nil" };
  const cn = String(ctx.$className || "");
  if (cn !== "WAContextMain") return { ok: false, error: "userContext not WAContextMain", className: cn };
  let storage = null;
  let sender = null;
  try { if (_statusCanCall(ctx, "- chatStorage")) storage = _safeObj(ctx["- chatStorage"]()); } catch (_) { storage = null; }
  try { if (_statusCanCall(ctx, "- messageSender")) sender = _safeObj(ctx["- messageSender"]()); } catch (_) { sender = null; }
  if (!storage) return { ok: false, error: "ctxMain.chatStorage nil" };
  if (!sender) return { ok: false, error: "ctxMain.messageSender nil" };
  return { ok: true, ctxMain: ctx, storage, sender };
}

function _statusGetMutableChatSession(chatSessionObj) {
  try {
    const cs = chatSessionObj instanceof ObjC.Object ? chatSessionObj : _safeObj(chatSessionObj);
    if (!cs) return null;
    const cn = String(cs.$className || "");
    if (cn === "WAMutableChatSession" || cn.endsWith(".WAMutableChatSession")) return cs;
    if (!_statusCanCall(cs, STATUS_FIXED.mutableChatSessionSelector)) return null;
    return _safeObj(cs[STATUS_FIXED.mutableChatSessionSelector]());
  } catch (_) {
    return null;
  }
}

function _statusInstallMsgIdHook() {
  try {
    if (STATUS_POST.hookInstalled) return { ok: true };
    if (STATUS_POST.hookError) return { ok: false, error: STATUS_POST.hookError };
    if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
    const cls = ObjC.classes.WAMessageID;
    if (!cls) return { ok: false, error: "WAMessageID missing" };
    const m = cls[STATUS_FIXED.msgIdInitUsingStanzaIdSelector];
    if (!m || !m.implementation) return { ok: false, error: "msgid selector missing" };
    Interceptor.attach(m.implementation, {
      onEnter(args) {
        try {
          const msgPtr = String(args[2] || "");
          if (!msgPtr || msgPtr === "0x0") return;
          const stanzaDesc = _statusSafeDesc(args[3]);
          const cand = _statusStripAngles(stanzaDesc);
          if (!cand || !/^[0-9A-Fa-f]{6,}$/.test(cand)) return;
          STATUS_POST.stanzaIdByMsgPtr[msgPtr] = cand;
          const pend = STATUS_POST.pendByMsgPtr[msgPtr];
          if (pend && !pend.stanzaId) pend.stanzaId = cand;
          const ap = STATUS_POST.activePend;
          if (ap && !ap.stanzaId && Date.now() <= ap.deadlineMs) {
            try {
              const mo = _safeObj(args[2]);
              if (mo && _statusCanCall(mo, "- isFromMe")) {
                const fm = mo["- isFromMe"]();
                if (!(fm === 1 || fm === true || String(fm) === "1")) return;
              }
            } catch (_) {}
            ap.stanzaId = cand;
          }
        } catch (_) {}
      }
    });
    STATUS_POST.hookInstalled = true;
    return { ok: true };
  } catch (e) {
    STATUS_POST.hookError = String(e);
    return { ok: false, error: STATUS_POST.hookError };
  }
}

function _statusPendingNew(kind, timeoutMs) {
  const tmo = Math.max(500, Math.min(30000, Number(timeoutMs || 8000) | 0));
  return { kind: String(kind || ""), deadlineMs: Date.now() + tmo, stanzaId: "", error: "", messagePtr: "", _keep: null, _block: null };
}

function _statusCaptureMessage(pend, msg) {
  try {
    const o = msg instanceof ObjC.Object ? msg : _safeObj(msg);
    if (!o) return false;
    const mp = ptr(o).toString();
    if (!mp || mp === "0x0") return false;
    pend.messagePtr = mp;
    STATUS_POST.pendByMsgPtr[mp] = pend;
    const sid = STATUS_POST.stanzaIdByMsgPtr[mp];
    if (sid && !pend.stanzaId) pend.stanzaId = String(sid);
    return true;
  } catch (_) {
    return false;
  }
}

function _statusWaitStanzaId(pend) {
  while (Date.now() < pend.deadlineMs) {
    if (pend.stanzaId) return { ok: true, stanzaId: String(pend.stanzaId || "") };
    if (pend.error) return { ok: false, error: String(pend.error || "") };
    Thread.sleep(0.02);
  }
  return { ok: false, error: "stanzaId timeout" };
}

function _statusTmpDirPath() {
  try {
    if (!objcAvailable()) return "";
    try {
      const NSFileManager = ObjC.classes.NSFileManager;
      if (NSFileManager && NSFileManager.defaultManager) {
        const fm = _safeObj(NSFileManager.defaultManager());
        if (fm && fm.temporaryDirectory) {
          const u = _safeObj(fm.temporaryDirectory());
          if (u && u.path) return String(_safeObj(u.path()) || "");
        }
      }
    } catch (_) {}
    try {
      if (ObjC.classes.NSTemporaryDirectory) {
        const p = ObjC.classes.NSTemporaryDirectory();
        if (p) return String(p);
      }
    } catch (_) {}
    return "";
  } catch (_) {
    return "";
  }
}

function _statusTmpPathForBasename(basename) {
  try {
    const bn = String(basename || "file.bin").replace(/[\\\/]/g, "_");
    const tmp = _statusTmpDirPath();
    if (!tmp) return "";
    const sep = tmp.endsWith("/") ? "" : "/";
    return tmp + sep + bn;
  } catch (_) {
    return "";
  }
}

function _statusPosixOpenWriteTrunc(pathStr) {
  try {
    const p = String(pathStr || "");
    if (!p) return { ok: false, error: "path empty" };
    const openPtr = Module.findExportByName(null, "open");
    if (!openPtr) return { ok: false, error: "open missing" };
    const openFn = new NativeFunction(openPtr, "int", ["pointer", "int", "int"]);
    const O_WRONLY = 0x0001;
    const O_CREAT = 0x0200;
    const O_TRUNC = 0x0400;
    const flags = O_WRONLY | O_CREAT | O_TRUNC;
    const mode = 0o600;
    const fd = openFn(Memory.allocUtf8String(p), flags, mode);
    if (fd < 0) return { ok: false, error: "open failed", fd };
    return { ok: true, fd };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _statusPosixWriteAll(fd, bufPtr, len) {
  try {
    const writePtr = Module.findExportByName(null, "write");
    if (!writePtr) return { ok: false, error: "write missing" };
    const writeFn = new NativeFunction(writePtr, "int", ["int", "pointer", "int"]);
    let off = 0;
    while (off < len) {
      const n = writeFn(fd, bufPtr.add(off), len - off);
      if (n <= 0) return { ok: false, error: "write failed", n, off };
      off += n;
    }
    return { ok: true, written: off };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _statusPosixClose(fd) {
  try {
    const closePtr = Module.findExportByName(null, "close");
    if (!closePtr) return { ok: false, error: "close missing" };
    const closeFn = new NativeFunction(closePtr, "int", ["int"]);
    const r = closeFn(fd);
    return { ok: r === 0, rc: r };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _statusChmod(pathStr, modeOctal) {
  try {
    const p = String(pathStr || "").trim();
    if (!p) return { ok: false, error: "path empty" };
    const chmodPtr = Module.findExportByName(null, "chmod");
    if (!chmodPtr) return { ok: false, error: "chmod missing" };
    const chmodFn = new NativeFunction(chmodPtr, "int", ["pointer", "int"]);
    const rc = chmodFn(Memory.allocUtf8String(p), Number(modeOctal) | 0);
    return { ok: rc === 0, rc };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _statusSetFileProtectionNone(pathStr) {
  try {
    if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
    const p = String(pathStr || "").trim();
    if (!p) return { ok: false, error: "path empty" };
    const fm0 = ObjC.classes.NSFileManager ? ObjC.classes.NSFileManager.defaultManager() : null;
    const fm = _safeObj(fm0);
    if (!fm) return { ok: false, error: "NSFileManager missing" };
    const sel = "- setAttributes:ofItemAtPath:error:";
    if (!fm[sel] || !fm[sel].implementation) return { ok: false, error: "setAttributes missing" };
    const nsPath = nsString(p);
    if (!nsPath) return { ok: false, error: "path->NSString failed" };
    const NSMutableDictionary = ObjC.classes.NSMutableDictionary;
    if (!NSMutableDictionary || !NSMutableDictionary.dictionary) return { ok: false, error: "NSMutableDictionary missing" };
    const d = _safeObj(NSMutableDictionary.dictionary());
    if (!d || !d["- setObject:forKey:"] || !d["- setObject:forKey:"].implementation) return { ok: false, error: "dict init failed" };
    const k = nsString("NSFileProtectionKey");
    const v = nsString("NSFileProtectionNone");
    if (!k || !v) return { ok: false, error: "NSString const failed" };
    d.setObject_forKey_(v, k);
    try {
      const kp = nsString("NSFilePosixPermissions");
      const NSNumber = ObjC.classes.NSNumber;
      if (kp && NSNumber && NSNumber.numberWithInt_) {
        const n = NSNumber.numberWithInt_(0o644);
        if (n) d.setObject_forKey_(n, kp);
      }
    } catch (_) {}
    const errp = Memory.alloc(Process.pointerSize);
    try { Memory.writePointer(errp, ptr("0x0")); } catch (_) {}
    const ok = !!fm.setAttributes_ofItemAtPath_error_(d, nsPath, errp);
    return { ok };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _statusB64ToBytes(b64) {
  try {
    const s = String(b64 || "");
    if (!s) return null;
    const bytes = [];
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const map = {};
    for (let i = 0; i < alphabet.length; i++) map[alphabet[i]] = i;
    let buffer = 0;
    let bits = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === "=") break;
      const v = map[c];
      if (v === undefined) continue;
      buffer = (buffer << 6) | v;
      bits += 6;
      if (bits >= 8) {
        bits -= 8;
        bytes.push((buffer >>> bits) & 0xff);
      }
    }
    return bytes;
  } catch (_) {
    return null;
  }
}

let STATUS_FILEPUT_NEXTID = 1;
const STATUS_FILEPUT_MAP = {};

function fileput_probe() {
  return { ok: true, tmp: String(_statusTmpDirPath() || "") };
}

function fileput_begin(basename) {
  const path = _statusTmpPathForBasename(basename);
  if (!path) return { ok: false, error: "tmp path failed" };
  const op = _statusPosixOpenWriteTrunc(path);
  if (!op || !op.ok) return { ok: false, error: op ? op.error : "open failed", path };
  const id = STATUS_FILEPUT_NEXTID++;
  STATUS_FILEPUT_MAP[String(id)] = { path, fd: Number(op.fd) };
  return { ok: true, id, path };
}

function fileput_chunk(id, b64chunk) {
  const it = STATUS_FILEPUT_MAP[String(id || "")];
  if (!it || typeof it.fd !== "number") return { ok: false, error: "unknown id" };
  const bytes = _statusB64ToBytes(b64chunk);
  if (!bytes || !bytes.length) return { ok: false, error: "base64 decode failed" };
  const buf = Memory.alloc(bytes.length);
  Memory.writeByteArray(buf, bytes);
  const wr = _statusPosixWriteAll(it.fd, buf, bytes.length);
  if (!wr || !wr.ok) return { ok: false, error: wr ? wr.error : "write failed" };
  return { ok: true, written: wr.written };
}

function fileput_end(id) {
  const k = String(id || "");
  const it = STATUS_FILEPUT_MAP[k];
  if (!it || typeof it.fd !== "number") return { ok: false, error: "unknown id" };
  const path = String(it.path || "");
  delete STATUS_FILEPUT_MAP[k];
  const cl = _statusPosixClose(it.fd);
  if (!cl || !cl.ok) return { ok: false, error: cl ? cl.error : "close failed", path };
  _statusChmod(path, 0o644);
  _statusSetFileProtectionNone(path);
  return { ok: true, path };
}

function _statusNsArray0() {
  try {
    const NSArray = ObjC.classes.NSArray;
    if (!NSArray) return null;
    if (NSArray.array) return _safeObj(NSArray.array());
    if (NSArray.alloc && NSArray.alloc().init) return _safeObj(NSArray.alloc().init());
    return null;
  } catch (_) {
    return null;
  }
}

function _statusBuildBeforeSendBlock(pend) {
  try {
    if (!objcAvailable() || !ObjC.Block) return null;
    return new ObjC.Block({ retType: "void", argTypes: ["object"], implementation: function (msg) { try { _statusCaptureMessage(pend, msg); } catch (_) {} } });
  } catch (_) {
    return null;
  }
}

function _statusBuildCompletionBlockMsgErr(pend) {
  try {
    if (!objcAvailable() || !ObjC.Block) return null;
    return new ObjC.Block({
      retType: "void",
      argTypes: ["object", "object"],
      implementation: function (a0, _a1) { try { _statusCaptureMessage(pend, a0); } catch (_) {} },
    });
  } catch (_) {
    return null;
  }
}

function _statusUIImageFromFile(pathStr) {
  try {
    const p = String(pathStr || "").trim();
    if (!p) return null;
    const ns = nsString(p);
    if (!ns) return null;
    const UIImage = ObjC.classes.UIImage;
    if (!UIImage || !UIImage.imageWithContentsOfFile_) return null;
    const img0 = UIImage.imageWithContentsOfFile_(ns);
    return img0 ? _safeObj(img0) : null;
  } catch (_) {
    return null;
  }
}

function _statusBuildImageSendable(imgObj) {
  try {
    const img = imgObj instanceof ObjC.Object ? imgObj : _safeObj(imgObj);
    if (!img) return null;
    const proto = ObjC.protocols ? ObjC.protocols.WAImageSendable : null;
    if (!proto) return null;
    const sel = "- conformsToProtocol:";
    if (!img[sel] || !img[sel].implementation) return null;
    const ok = !!img.conformsToProtocol_(proto);
    return ok ? img : null;
  } catch (_) {
    return null;
  }
}

function _statusBuildRichText(text) {
  try {
    const s = String(text || "");
    if (!s) return null;
    const cls = ObjC.classes.WARichText;
    if (!cls) return null;
    const ns = nsString(s);
    if (!ns) return null;
    if (cls.richTextWithString_) {
      const o = cls.richTextWithString_(ns);
      return o ? _safeObj(o) : null;
    }
    if (cls.alloc && cls.alloc().initWithString_) {
      const o2 = cls.alloc().initWithString_(ns);
      return o2 ? _safeObj(o2) : null;
    }
    return null;
  } catch (_) {
    return null;
  }
}

function statusposttext(text, messageOrigin, creationEntryPoint) {
  try {
    const hk = _statusInstallMsgIdHook();
    if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: hk ? hk.error : "hook failed" };
    const pend = _statusPendingNew("status_text", 8000);
    const t = String(text || "");
    if (!t) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "missing text" };
    STATUS_POST.activePend = pend;
    safeObjCInvoke(() => {
      try {
        let pool = null;
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const core = _statusResolveCoreFixed();
        if (!core || !core.ok) { pend.error = core ? core.error : "core failed"; return; }
        const nsText = nsString(t);
        if (!nsText) { pend.error = "text->NSString failed"; return; }
        const jid = _makeWAChatJIDFromString("status@broadcast");
        if (!jid) { pend.error = "status@broadcast jid parse failed"; return; }
        const stor = core.storage;
        if (!_statusCanCall(stor, STATUS_FIXED.fetchChatSessionSelector)) { pend.error = "fetchChatSession selector missing"; return; }
        const cs = stor[STATUS_FIXED.fetchChatSessionSelector](jid);
        if (!cs) { pend.error = "fetchChatSessionForJID returned nil"; return; }
        const csObj = _safeObj(cs);
        if (!csObj) { pend.error = "chatSession invalid"; return; }
        const mcsObj = _statusGetMutableChatSession(csObj);
        if (!mcsObj) { pend.error = "mutableChatSession returned nil"; return; }
        const att = _buildAttachmentsEmptyExplore();
        if (!att) { pend.error = "attachments build failed"; return; }
        const emptyArr = _statusNsArray0();
        if (!emptyArr) { pend.error = "empty NSArray failed"; return; }
        const cb = _statusBuildBeforeSendBlock(pend);
        if (!cb) { pend.error = "beforeSend block failed"; return; }
        const sender = core.sender;
        if (!_statusCanCall(sender, STATUS_FIXED.sendTextSelector)) { pend.error = "sendText selector missing"; return; }
        const mo = Number.isFinite(Number(messageOrigin)) ? (Number(messageOrigin) | 0) : 1;
        const ep = Number.isFinite(Number(creationEntryPoint)) ? Number(creationEntryPoint) : 1;
        pend._keep = [nsText, mcsObj, att, emptyArr];
        pend._block = cb;
        sender[STATUS_FIXED.sendTextSelector](nsText, false, att, mo, ep, mcsObj, ptr("0x0"), ptr("0x0"), ptr("0x0"), ptr("0x0"), ptr("0x0"), false, false, false, emptyArr, emptyArr, false, ptr("0x0"), cb, cb);
        try { if (pool) pool.release(); } catch (_) {}
      } catch (e) {
        pend.error = String(e);
      }
    });
    const w = _statusWaitStanzaId(pend);
    if (STATUS_POST.activePend === pend) STATUS_POST.activePend = null;
    if (pend.messagePtr) delete STATUS_POST.pendByMsgPtr[pend.messagePtr];
    return { ok: !!(w && w.ok), build: SCRIPT_BUILD_ID, stanzaId: w && w.ok ? String(w.stanzaId || "") : "", error: w && !w.ok ? String(w.error || "") : (pend.error ? String(pend.error) : null) };
  } catch (e) {
    return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: String(e) };
  }
}

function statuspostimage(imagePath, captionText, messageOrigin) {
  try {
    const hk = _statusInstallMsgIdHook();
    if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: hk ? hk.error : "hook failed" };
    const pend = _statusPendingNew("status_image", 20000);
    const p = String(imagePath || "").trim();
    if (!p) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "missing imagePath" };
    safeObjCInvoke(() => {
      try {
        let pool = null;
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const core = _statusResolveCoreFixed();
        if (!core || !core.ok) { pend.error = core ? core.error : "core failed"; return; }
        const jid = _makeWAChatJIDFromString("status@broadcast");
        if (!jid) { pend.error = "status@broadcast jid parse failed"; return; }
        const stor = core.storage;
        if (!_statusCanCall(stor, STATUS_FIXED.fetchChatSessionSelector)) { pend.error = "fetchChatSession selector missing"; return; }
        const cs = stor[STATUS_FIXED.fetchChatSessionSelector](jid);
        if (!cs) { pend.error = "fetchChatSessionForJID returned nil"; return; }
        const csObj = _safeObj(cs);
        if (!csObj) { pend.error = "chatSession invalid"; return; }
        const mcsObj = _statusGetMutableChatSession(csObj);
        if (!mcsObj) { pend.error = "mutableChatSession returned nil"; return; }
        const img = _statusUIImageFromFile(p);
        if (!img) { pend.error = "UIImage load failed"; return; }
        const sendable = _statusBuildImageSendable(img);
        if (!sendable) { pend.error = "UIImage not WAImageSendable"; return; }
        const capText = String(captionText || "");
        const cap = capText ? _statusBuildRichText(capText) : null;
        if (capText && !cap) { pend.error = "WARichText build failed"; return; }
        const att = _buildAttachmentsEmptyExplore();
        if (!att) { pend.error = "attachments build failed"; return; }
        const emptyArr = _statusNsArray0();
        if (!emptyArr) { pend.error = "empty NSArray failed"; return; }
        const completion = _statusBuildCompletionBlockMsgErr(pend);
        if (!completion) { pend.error = "completion block failed"; return; }
        pend._keep = [img, sendable, cap, mcsObj, att, emptyArr];
        pend._block = completion;
        const sender = core.sender;
        if (!_statusCanCall(sender, STATUS_FIXED.sendImageSelector)) { pend.error = "sendImage selector missing"; return; }
        const mo = Number.isFinite(Number(messageOrigin)) ? (Number(messageOrigin) | 0) : 1;
        sender[STATUS_FIXED.sendImageSelector](sendable, img, cap ? cap : ptr("0x0"), emptyArr, emptyArr, ptr("0x0"), att, mo, mcsObj, ptr("0x0"), ptr("0x0"), ptr("0x0"), ptr("0x0"), ptr("0x0"), false, emptyArr, ptr("0x0"), emptyArr, 0, ptr("0x0"), ptr("0x0"), 0, 0, ptr("0x0"), ptr("0x0"), false, false, ptr("0x0"), ptr("0x0"), completion);
        try { if (pool) pool.release(); } catch (_) {}
      } catch (e) {
        pend.error = String(e);
      }
    });
    const w = _statusWaitStanzaId(pend);
    if (pend.messagePtr) delete STATUS_POST.pendByMsgPtr[pend.messagePtr];
    return { ok: !!(w && w.ok), build: SCRIPT_BUILD_ID, stanzaId: w && w.ok ? String(w.stanzaId || "") : "", error: w && !w.ok ? String(w.error || "") : (pend.error ? String(pend.error) : null) };
  } catch (e) {
    return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: String(e) };
  }
}

function _buildQuotedItemFromMessageExplore(msgObj, quoteType) {
  try {
    const msg = msgObj instanceof ObjC.Object ? msgObj : _safeObj(msgObj);
    if (!msg) return null;
    const cls = ObjC.classes.WAMessageQuotedItem;
    if (!cls || !cls.alloc) return null;
    const inst = cls.alloc();
    const sel = "- initWithMessage:quoteType:";
    if (!objcHasSelector(inst, "initWithMessage:quoteType:")) return null;
    const qi = inst.initWithMessage_quoteType_(msg, Number(quoteType) || 1);
    return _safeObj(qi);
  } catch (_) {
    return null;
  }
}

function _buildAttachmentsWithQuotedItemExplore(quotedItemObj) {
  try {
    const qi = quotedItemObj instanceof ObjC.Object ? quotedItemObj : _safeObj(quotedItemObj);
    if (!qi) return null;
    const cls = ObjC.classes.WAMessageAttachments;
    if (!cls || !cls.alloc) return null;
    const inst = cls.alloc();
    if (!inst || !inst["- init"]) return null;
    const att = _safeObj(inst["- init"]());
    if (!att) return null;
    try {
      if (objcHasSelector(att, "setQuotedItem:")) att.setQuotedItem_(qi);
    } catch (_) {}
    try {
      if (objcHasSelector(att, "setContainsQuotedItem:")) att.setContainsQuotedItem_(true);
    } catch (_) {}
    return att;
  } catch (_) {
    return null;
  }
}

function _resolveCoreForSendExplore() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const ctxRes = _resolveCtxMainStableExplore();
  if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
  const ctx = ctxRes.ctx;
  let storage = null;
  let sender = null;
  try { if (objcHasSelector(ctx, "chatStorage")) storage = objcCallNoArg(ctx, "chatStorage"); } catch (_) { storage = null; }
  try { if (objcHasSelector(ctx, "messageSender")) sender = objcCallNoArg(ctx, "messageSender"); } catch (_) { sender = null; }
  if (!storage) return { ok: false, error: "ctxMain.chatStorage nil" };
  if (!sender) return { ok: false, error: "ctxMain.messageSender nil" };
  return { ok: true, ctxMain: ctx, storage, sender, source: String(ctxRes.source || "") };
}

function _sendTextWithAttachmentsExplore(senderObj, mcsObj, nsTextObj, attObj, originInt) {
  const sender = senderObj instanceof ObjC.Object ? senderObj : _safeObj(senderObj);
  const cs = mcsObj instanceof ObjC.Object ? mcsObj : _safeObj(mcsObj);
  const nsText = nsTextObj instanceof ObjC.Object ? nsTextObj : _safeObj(nsTextObj);
  const att = attObj instanceof ObjC.Object ? attObj : _safeObj(attObj);
  if (!sender || !cs || !nsText || !att) return { ok: false, error: "sender/chatSession/text/attachments missing" };
  const mo = Number.isFinite(Number(originInt)) ? (Number(originInt) | 0) : 1;
  const tried = [];
  try {
    if (objcHasSelector(sender, "sendMessageWithText:attachments:messageOrigin:inChatSession:")) {
      tried.push("sendMessageWithText:attachments:messageOrigin:inChatSession:");
      sender.sendMessageWithText_attachments_messageOrigin_inChatSession_(nsText, att, mo, cs);
      return { ok: true, used: tried[tried.length - 1] };
    }
  } catch (e) { return { ok: false, error: String(e), tried }; }
  try {
    if (objcHasSelector(sender, "sendMessageWithText:attachments:messageOrigin:inChatSession:hasTextFromURL:openedFromURL:")) {
      tried.push("sendMessageWithText:attachments:messageOrigin:inChatSession:hasTextFromURL:openedFromURL:");
      sender.sendMessageWithText_attachments_messageOrigin_inChatSession_hasTextFromURL_openedFromURL_(nsText, att, mo, cs, false, false);
      return { ok: true, used: tried[tried.length - 1] };
    }
  } catch (e) { return { ok: false, error: String(e), tried }; }
  return { ok: false, error: "no sendText selector found", tried };
}

function _parseHexPtrToInt(ptrStr, fallback) {
  try {
    const s = String(ptrStr || "").trim().toLowerCase();
    if (!s || s === "0x0") return fallback;
    if (!s.startsWith("0x")) return fallback;
    const n = parseInt(s.slice(2), 16);
    if (!Number.isFinite(n)) return fallback;
    if (n < 0 || n > 0x7fffffff) return fallback;
    return n | 0;
  } catch (_) {
    return fallback;
  }
}

function _getLastChatSessionPtrFromSendProbe() {
  try {
    const last = SEND_PROBE && SEND_PROBE.last ? SEND_PROBE.last : null;
    if (!last) return "";
    const p = String(last.a7Ptr || "").trim();
    if (!p || p === "0x0") return "";
    return p;
  } catch (_) {
    return "";
  }
}

function _getLastOriginFromSendProbe(defaultOrigin) {
  try {
    const last = SEND_PROBE && SEND_PROBE.last ? SEND_PROBE.last : null;
    if (!last) return defaultOrigin;
    const o = _parseHexPtrToInt(last.a5Ptr, defaultOrigin);
    return o;
  } catch (_) {
    return defaultOrigin;
  }
}

function sendquotetext(jid, quotedStanzaId, replyText, participantJid, origin) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const jidStr = String(jid || "").trim();
  const qsid = String(quotedStanzaId || "").trim();
  const text = String(replyText || "");
  const part = String(participantJid || "").trim();
  const moIn = Number.isFinite(Number(origin)) ? (Number(origin) | 0) : 1;
  if (!jidStr || !qsid || !text) return Promise.resolve({ ok: false, error: "missing jid/quotedStanzaId/text" });

  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      let pool = null;
      try {
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        const core = _resolveCoreForSendExplore();
        if (!core || !core.ok) return resolve({ ok: false, error: core ? core.error : "core failed" });
        const mo = _getLastOriginFromSendProbe(moIn);

        let csTarget = null;
        let mcsTarget = null;
        const lastCsPtr = _getLastChatSessionPtrFromSendProbe();
        if (lastCsPtr) {
          try {
            csTarget = new ObjC.Object(ptr(lastCsPtr));
            mcsTarget = _getMutableChatSession(csTarget);
          } catch (_) { mcsTarget = null; }
        }
        if (!mcsTarget || !csTarget) {
          const targetJidObj = _makeWAChatJIDFromString(jidStr);
          if (!targetJidObj) return resolve({ ok: false, error: "invalid target jid" });
          csTarget = _fetchOrCreateChatSession(core.storage, targetJidObj, core.ctxMain);
          if (!csTarget) return resolve({ ok: false, error: "fetchChatSession target failed (no cached chatSession; use UI reply once then retry)" });
          mcsTarget = _getMutableChatSession(csTarget);
          if (!mcsTarget) return resolve({ ok: false, error: "mutableChatSession target failed" });
        }

        let quotedMsg = null;
        try { quotedMsg = _fetchMessageByStanzaId(mcsTarget, qsid, part); } catch (_) { quotedMsg = null; }
        if (!quotedMsg) {
          const statusJidObj = _makeWAChatJIDFromString("status@broadcast");
          if (statusJidObj) {
            const csStatus = _fetchOrCreateChatSession(core.storage, statusJidObj, core.ctxMain);
            const mcsStatus = csStatus ? _getMutableChatSession(csStatus) : null;
            const part2 = part || jidStr;
            if (mcsStatus) {
              try { quotedMsg = _fetchMessageByStanzaId(mcsStatus, qsid, part2); } catch (_) { quotedMsg = null; }
            }
          }
        }
        if (!quotedMsg) return resolve({ ok: false, error: "quoted message not found", jid: jidStr, quotedStanzaId: qsid });

        const qi = _buildQuotedItemFromMessageExplore(quotedMsg, 1);
        if (!qi) return resolve({ ok: false, error: "build quotedItem failed" });
        const att = _buildAttachmentsWithQuotedItemExplore(qi) || _buildAttachmentsEmptyExplore();
        if (!att) return resolve({ ok: false, error: "build attachments failed" });
        const nsText = nsString(text);
        if (!nsText) return resolve({ ok: false, error: "text->NSString failed" });

        const sendRes = _sendTextWithAttachmentsExplore(core.sender, csTarget, nsText, att, mo);
        if (!sendRes.ok) return resolve({ ok: false, error: sendRes.error || "send failed", tried: sendRes.tried || [] });
        resolve({ ok: true, jid: jidStr, quotedStanzaId: qsid, participantJid: part, origin: mo, used: sendRes.used, usedCachedChatSession: lastCsPtr ? 1 : 0, cachedChatSessionPtr: lastCsPtr || "" });
      } catch (e) {
        resolve({ ok: false, error: String(e) });
      } finally {
        try { if (pool) pool.release(); } catch (_) {}
      }
    });
  });
}

const REVOKE_TRACE = {
  installed: false,
  err: "",
  last: null,
  count: 0,
  xmpp: { installed: false, err: "", last: null, count: 0 }
};

const REVOKE_PROBE = { installed: false, err: "", last: null, count: 0, _ls: [] };

function _safeObj(p) {
  try {
    if (!objcAvailable() || !p) return null;
    if (p instanceof ObjC.Object) return p;
    const pp = ptr(p);
    if (!pp || pp.isNull()) return null;
    return new ObjC.Object(pp);
  } catch (_) {
    return null;
  }
}

function _safeDesc(o) {
  try { return o ? String(o) : ""; } catch (_) { return ""; }
}

function installRevokeTrace() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (REVOKE_TRACE.installed) return { ok: true, installed: true, count: REVOKE_TRACE.count, err: REVOKE_TRACE.err || "" };
  REVOKE_TRACE.err = "";
  try {
    const cls = ObjC.classes.WAChatStorage;
    if (!cls) return { ok: false, error: "WAChatStorage missing" };
    const sel = "- internalRevokeMessages:triggeredByMessageWithID:onDate:outgoing:revokedByAdminUserJID:botPluginMessagesToDelete:beginTransactions:commitTransactions:";
    const m = cls[sel];
    if (!m || !m.implementation) return { ok: false, error: "method missing", selector: sel };
    Interceptor.attach(m.implementation, {
      onEnter(args) {
        try {
          const aMsgs = _safeObj(args[2]);
          const aTrig = _safeObj(args[3]);
          const aDate = _safeObj(args[4]);
          const aOut = (function () { try { return Number(args[5]) | 0; } catch (_) { return 0; } })();
          const aAdmin = _safeObj(args[6]);
          const aBot = _safeObj(args[7]);
          const aBegin = ptr(args[8]).toString();
          const aCommit = ptr(args[9]).toString();
          let msg0 = null;
          try {
            if (aMsgs && objcHasSelector(aMsgs, "count") && Number(aMsgs.count()) > 0 && objcHasSelector(aMsgs, "objectAtIndex:")) {
              msg0 = _safeObj(aMsgs.objectAtIndex_(0));
            }
          } catch (_) { msg0 = null; }
          let msg0Id = null;
          try { if (msg0 && objcHasSelector(msg0, "messageID")) msg0Id = _safeObj(msg0.messageID()); } catch (_) { msg0Id = null; }
          REVOKE_TRACE.last = {
            ts: nowMs(),
            msgsCount: (function () { try { return aMsgs && objcHasSelector(aMsgs, "count") ? Number(aMsgs.count()) : -1; } catch (_) { return -1; } })(),
            msg0: msg0 ? String(msg0.$className || "") : "",
            msg0Desc: _safeDesc(msg0),
            msg0MessageId: _safeDesc(msg0Id),
            triggeredByMessageID: _safeDesc(aTrig),
            onDate: _safeDesc(aDate),
            outgoing: aOut,
            revokedByAdminUserJID: _safeDesc(aAdmin),
            botPluginMessagesToDelete: _safeDesc(aBot),
            beginTxPtr: aBegin,
            commitTxPtr: aCommit
          };
          REVOKE_TRACE.count++;
          send({ type: "qqw.explore.revoke_trace", ok: true, ...REVOKE_TRACE.last });
        } catch (e) {
          try { send({ type: "qqw.explore.revoke_trace", ok: false, error: String(e) }); } catch (_) {}
        }
      }
    });
    REVOKE_TRACE.installed = true;
    return { ok: true, installed: true };
  } catch (e) {
    REVOKE_TRACE.err = String(e);
    return { ok: false, error: REVOKE_TRACE.err };
  }
}

function installXMPPTrace() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (REVOKE_TRACE.xmpp.installed) return { ok: true, installed: true, count: REVOKE_TRACE.xmpp.count, err: REVOKE_TRACE.xmpp.err || "" };
  REVOKE_TRACE.xmpp.err = "";
  try {
    const cls = ObjC.classes.XMPPConnectionMain;
    if (!cls) return { ok: false, error: "XMPPConnectionMain missing" };
    const sel = "- sendMessageStanza:";
    const m = cls[sel];
    if (!m || !m.implementation) return { ok: false, error: "method missing", selector: sel };
    Interceptor.attach(m.implementation, {
      onEnter(args) {
        try {
          const stanza = _safeObj(args[2]);
          const desc = _safeDesc(stanza);
          REVOKE_TRACE.xmpp.last = { ts: nowMs(), stanzaDesc: desc };
          REVOKE_TRACE.xmpp.count++;
          if (desc && desc.toLowerCase().indexOf("revoke") !== -1) send({ type: "qqw.explore.xmpp_send", ok: true, desc });
        } catch (_) {}
      }
    });
    REVOKE_TRACE.xmpp.installed = true;
    return { ok: true, installed: true };
  } catch (e) {
    REVOKE_TRACE.xmpp.err = String(e);
    return { ok: false, error: REVOKE_TRACE.xmpp.err };
  }
}

function getRevokeTraceLast() {
  return { ok: true, installed: REVOKE_TRACE.installed, count: REVOKE_TRACE.count, last: REVOKE_TRACE.last, xmpp: REVOKE_TRACE.xmpp };
}

function selResponders(selectorName, maxN) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const selName = String(selectorName || "").trim();
  if (!selName) return { ok: false, error: "missing selector" };
  const lim = Math.max(1, Math.min(500, Number(maxN || 50) | 0));
  const sel = ObjC.selector(selName);
  const out = [];
  try {
    for (const k in ObjC.classes) {
      if (!Object.prototype.hasOwnProperty.call(ObjC.classes, k)) continue;
      if (k.length < 2 || k[0] !== "W" || k[1] !== "A") continue;
      const cls = ObjC.classes[k];
      if (!cls) continue;
      try {
        if (cls.respondsToSelector_(ObjC.selector("instancesRespondToSelector:"))) {
          if (cls.instancesRespondToSelector_(sel)) {
            out.push(k);
            if (out.length >= lim) break;
          }
        }
      } catch (_) {}
    }
  } catch (_) {}
  return { ok: true, selector: selName, count: out.length, classes: out };
}

function _filterMethods(methods, regex, maxN) {
  const lim = Math.max(1, Math.min(800, Number(maxN || 120) | 0));
  const rx = String(regex || "").trim();
  let re = null;
  if (rx) {
    try { re = new RegExp(rx, "i"); } catch (_) { re = null; }
  }
  const out = [];
  try {
    for (let i = 0; i < methods.length; i++) {
      const m = String(methods[i] || "");
      if (!m) continue;
      if (re && !re.test(m)) continue;
      out.push(m);
      if (out.length >= lim) break;
    }
  } catch (_) {}
  return out;
}

function quotedSelectors(className, regex, maxN) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const cn = String(className || "").trim();
  const cls = cn ? ObjC.classes[cn] : null;
  if (!cls) return { ok: false, error: "class not found" };
  const methods = (cls.$methods || cls.$ownMethods || []);
  return { ok: true, className: cn, count: methods.length, matched: _filterMethods(methods, regex, maxN) };
}

function objSelectors(ptrStr, regex, maxN, safe) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  const p = ptr(String(ptrStr || "").trim() || "0x0");
  if (p.isNull()) return { ok: false, error: "null ptr" };
  let obj = null;
  try { obj = new ObjC.Object(p); } catch (e) { return { ok: false, error: "bad objc ptr: " + String(e) }; }
  const cn = String(obj.$className || "");
  const cls = obj.$class || (cn ? ObjC.classes[cn] : null);
  const methods = cls ? (cls.$methods || cls.$ownMethods || []) : [];
  const matched = _filterMethods(methods, regex, maxN);
  if (!safe) return { ok: true, ptr: p.toString(), className: cn, matched };
  const selMethods = [];
  try {
    for (let i = 0; i < matched.length; i++) {
      const sig = String(matched[i] || "").trim();
      if (!sig) continue;
      const selName = sig.replace(/^[-+]\s*/, "").trim();
      if (!selName) continue;
      let ok = false;
      try { ok = !!obj.respondsToSelector_(ObjC.selector(selName)); } catch (_) { ok = false; }
      if (ok) selMethods.push(sig);
    }
  } catch (_) {}
  return { ok: true, ptr: p.toString(), className: cn, matched: selMethods };
}

function objcStr(ptrStr, maxChars) {
  if (!objcAvailable()) return Promise.resolve({ ok: false, error: "objc_unavailable" });
  const p = ptr(String(ptrStr || "").trim() || "0x0");
  if (p.isNull()) return Promise.resolve({ ok: false, error: "null ptr" });
  const lim = Math.max(16, Math.min(16000, Number(maxChars || 4000) | 0));
  return new Promise((resolve) => {
    safeObjCInvoke(() => {
      try {
        try { Memory.readPointer(p); } catch (_) { return resolve({ ok: false, error: "unreadable ptr", ptr: p.toString() }); }
        try {
          const o = new ObjC.Object(p);
          const cn = String(o.$className || "");
          let text = "";
          try {
            const NSString = ObjC.classes.NSString;
            if (NSString && o.isKindOfClass_ && o.isKindOfClass_(NSString)) text = String(o);
          } catch (_) {}
          if (!text) {
            try { if (objcHasSelector(o, "stringRepresentation")) text = objcCallNoArgString(o, "stringRepresentation"); } catch (_) { text = ""; }
          }
          if (!text) {
            try { if (objcHasSelector(o, "description")) text = objcCallNoArgString(o, "description"); } catch (_) { text = ""; }
          }
          if (text) return resolve({ ok: true, ptr: p.toString(), kind: "objc", className: cn, text: text.slice(0, lim) });
          return resolve({ ok: true, ptr: p.toString(), kind: "objc", className: cn, text: "" });
        } catch (_) {}
        try {
          const s = Memory.readCString(p, 256);
          const t = String(s || "");
          if (t && t.length <= 256) return resolve({ ok: true, ptr: p.toString(), kind: "cstring", text: t.slice(0, lim) });
        } catch (_) {}
        resolve({ ok: true, ptr: p.toString(), kind: "unknown", text: "" });
      } catch (e) {
        resolve({ ok: false, error: String(e), ptr: p.toString() });
      }
    });
  });
}

function _idaFromPtr(p) {
  try {
    const m = Process.getModuleByName("WhatsApp");
    const base = m.base;
    const off = ptr(p).sub(base);
    return ptr("0x100000000").add(off).toString();
  } catch (_) {
    return "0x0";
  }
}

function idaFromRuntimeAddr(addrStr) {
  const a = ptr(String(addrStr || "").trim() || "0x0");
  if (a.isNull()) return { ok: false, error: "null addr" };
  try {
    const m = Process.findModuleByAddress(a) || Process.getModuleByName("WhatsApp");
    if (!m) return { ok: false, error: "module not found" };
    const off = a.sub(m.base);
    const ida = ptr("0x100000000").add(off);
    return { ok: true, addr: a.toString(), module: String(m.name || ""), moduleBase: ptr(m.base).toString(), moduleOff: off.toString(), ida: ida.toString() };
  } catch (e) {
    return { ok: false, error: String(e), addr: a.toString() };
  }
}

function xavMethods(filter, maxN) {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  try {
    const C = ObjC.classes.XMPPAttributeValue;
    if (!C) return { ok: false, error: "XMPPAttributeValue missing" };
    const rx = String(filter || "").trim();
    const re = rx ? new RegExp(rx, "i") : null;
    const lim = Math.max(10, Math.min(500, Number(maxN || 200) | 0));
    const ms = (C.$methods || []).filter(m => typeof m === "string");
    const out = [];
    for (let i = 0; i < ms.length && out.length < lim; i++) {
      const m = ms[i];
      if (re && !re.test(m)) continue;
      out.push(m);
    }
    return { ok: true, count: out.length, methods: out };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _analyzeBlockPtr(p) {
  try {
    const bp = ptr(p);
    if (bp.isNull()) return null;
    const isa = Memory.readPointer(bp);
    const flags = Memory.readU32(bp.add(8));
    const invoke = Memory.readPointer(bp.add(16));
    const desc = Memory.readPointer(bp.add(24));
    let sig = "";
    let sigPtr = ptr("0x0");
    let layoutPtr = ptr("0x0");
    let size = 0;
    let copyFn = ptr("0x0");
    let disposeFn = ptr("0x0");
    if (!desc.isNull()) {
      try { size = Number(Memory.readU64(desc.add(8))); } catch (_) { size = 0; }
      let off = 16;
      if (flags & 0x02000000) {
        copyFn = Memory.readPointer(desc.add(off));
        disposeFn = Memory.readPointer(desc.add(off + 8));
        off += 16;
      }
      if (flags & 0x40000000) {
        sigPtr = Memory.readPointer(desc.add(off));
        if (!sigPtr.isNull()) { try { sig = Memory.readCString(sigPtr); } catch (_) { sig = ""; } }
        off += 8;
      }
      if (flags & 0x80000000) {
        try { layoutPtr = Memory.readPointer(desc.add(off)); } catch (_) { layoutPtr = ptr("0x0"); }
      }
    }
    const cap = [];
    try {
      const n = (size && size >= 40) ? Math.min(8, Math.max(0, ((size - 32) / 8) | 0)) : 0;
      for (let i = 0; i < n; i++) {
        const cp = Memory.readPointer(bp.add(32 + 8 * i));
        cap.push({ i, ptr: cp.toString(), ptrIda: _idaFromPtr(cp) });
      }
    } catch (_) {}
    return {
      ptr: bp.toString(),
      isa: isa.toString(),
      isaIda: _idaFromPtr(isa),
      className: (function () { try { const o = _safeObj(bp); return o ? String(o.$className || "") : ""; } catch (_) { return ""; } })(),
      flags: "0x" + (flags >>> 0).toString(16),
      invoke: invoke.toString(),
      invokeIda: _idaFromPtr(invoke),
      descriptor: desc.toString(),
      descriptorIda: _idaFromPtr(desc),
      size,
      signature: sig,
      signaturePtr: sigPtr.toString(),
      signaturePtrIda: _idaFromPtr(sigPtr),
      layoutPtr: layoutPtr.toString(),
      layoutPtrIda: _idaFromPtr(layoutPtr),
      copy: copyFn.toString(),
      copyIda: copyFn.isNull() ? "0x0" : _idaFromPtr(copyFn),
      dispose: disposeFn.toString(),
      disposeIda: disposeFn.isNull() ? "0x0" : _idaFromPtr(disposeFn),
      captures: cap,
    };
  } catch (_) {
    return null;
  }
}

function _dumpByrefPtr(p) {
  try {
    const bp = ptr(p);
    if (bp.isNull()) return null;
    const qs = [];
    for (let i = 0; i < 8; i++) {
      const q = Memory.readPointer(bp.add(i * 8));
      qs.push({ i, ptr: q.toString(), ptrIda: _idaFromPtr(q) });
    }
    let flags = 0;
    let size = 0;
    let forwarding = ptr("0x0");
    try { forwarding = Memory.readPointer(bp.add(8)); } catch (_) { forwarding = ptr("0x0"); }
    try { flags = Memory.readU32(bp.add(16)); } catch (_) { flags = 0; }
    try { size = Memory.readU32(bp.add(20)); } catch (_) { size = 0; }
    const bytes = [];
    try {
      const n = Math.min(96, Math.max(24, size ? size : 96));
      const ba = Memory.readByteArray(bp, n);
      const u8 = new Uint8Array(ba);
      for (let i = 0; i < u8.length; i++) bytes.push(u8[i]);
    } catch (_) {}
    return {
      ptr: bp.toString(),
      forwarding: forwarding.toString(),
      forwardingIda: _idaFromPtr(forwarding),
      flags: "0x" + (flags >>> 0).toString(16),
      size,
      qwords: qs,
      bytes
    };
  } catch (_) {
    return null;
  }
}

function installRevokeProbe() {
  if (!objcAvailable()) return { ok: false, error: "objc_unavailable" };
  if (REVOKE_PROBE.installed) return { ok: true, installed: true, count: REVOKE_PROBE.count, err: REVOKE_PROBE.err || "" };
  REVOKE_PROBE.err = "";
  REVOKE_PROBE._ls = [];
  try {
    const cls = ObjC.classes.WAChatStorage;
    if (!cls) return { ok: false, error: "WAChatStorage missing" };
    const sel = "- internalRevokeMessages:triggeredByMessageWithID:onDate:outgoing:revokedByAdminUserJID:botPluginMessagesToDelete:beginTransactions:commitTransactions:";
    const m = cls[sel];
    if (!m || !m.implementation) return { ok: false, error: "method missing", selector: sel };
    const l0 = Interceptor.attach(m.implementation, {
      onEnter(args) {
        try {
          const aMsgs = _safeObj(args[2]);
          const aTrig = _safeObj(args[3]);
          const aDate = _safeObj(args[4]);
          const aOut = (function () { try { return Number(args[5]) | 0; } catch (_) { return 0; } })();
          const aAdmin = _safeObj(args[6]);
          const aBot = _safeObj(args[7]);
          const aBegin = ptr(args[8]);
          const aCommit = ptr(args[9]);
          let msg0 = null;
          try {
            if (aMsgs && objcHasSelector(aMsgs, "count") && Number(aMsgs.count()) > 0 && objcHasSelector(aMsgs, "objectAtIndex:")) msg0 = _safeObj(aMsgs.objectAtIndex_(0));
          } catch (_) { msg0 = null; }
          let msg0Id = null;
          try { if (msg0 && objcHasSelector(msg0, "messageID")) msg0Id = _safeObj(msg0.messageID()); } catch (_) { msg0Id = null; }
          REVOKE_PROBE.last = {
            ts: nowMs(),
            callerIda: _idaFromPtr(this.returnAddress),
            msgsCount: (function () { try { return aMsgs && objcHasSelector(aMsgs, "count") ? Number(aMsgs.count()) : -1; } catch (_) { return -1; } })(),
            msg0Class: msg0 ? String(msg0.$className || "") : "",
            msg0Desc: _safeDesc(msg0),
            msg0IsFromMe: (function () { try { return msg0 && objcHasSelector(msg0, "isFromMe") ? ((msg0.isFromMe() === 1 || msg0.isFromMe() === true || String(msg0.isFromMe()) === "1") ? 1 : 0) : -1; } catch (_) { return -1; } })(),
            msg0MessageId: _safeDesc(msg0Id),
            triggeredByMessageID: _safeDesc(aTrig),
            onDate: _safeDesc(aDate),
            outgoing: aOut,
            revokedByAdminUserJID: _safeDesc(aAdmin),
            botPluginMessagesToDelete: _safeDesc(aBot),
            beginBlock: _analyzeBlockPtr(aBegin),
            commitBlock: _analyzeBlockPtr(aCommit),
          };
          try {
            const bb = REVOKE_PROBE.last.beginBlock;
            const cb = REVOKE_PROBE.last.commitBlock;
            const bLast = bb && bb.captures && bb.captures.length ? bb.captures[bb.captures.length - 1] : null;
            const cLast = cb && cb.captures && cb.captures.length ? cb.captures[cb.captures.length - 1] : null;
            if (bLast && cLast && bLast.ptr && cLast.ptr && bLast.ptr === cLast.ptr) REVOKE_PROBE.last.sharedByref = _dumpByrefPtr(bLast.ptr);
          } catch (_) {}
          REVOKE_PROBE.count++;
          send({ type: "qqw.explore.revoke_probe", ok: true, ...REVOKE_PROBE.last });
        } catch (e) {
          try { send({ type: "qqw.explore.revoke_probe", ok: false, error: String(e) }); } catch (_) {}
        }
      }
    });
    REVOKE_PROBE._ls.push(l0);
    REVOKE_PROBE.installed = true;
    return { ok: true, installed: true };
  } catch (e) {
    REVOKE_PROBE.err = String(e);
    return { ok: false, error: REVOKE_PROBE.err };
  }
}

function revokeProbeStatus() {
  return { ok: true, installed: REVOKE_PROBE.installed, count: REVOKE_PROBE.count, last: REVOKE_PROBE.last, err: REVOKE_PROBE.err || "" };
}

function revokeProbeOff() {
  try {
    const ls = REVOKE_PROBE._ls || [];
    for (let i = 0; i < ls.length; i++) {
      try { ls[i].detach(); } catch (_) {}
    }
  } catch (_) {}
  REVOKE_PROBE._ls = [];
  REVOKE_PROBE.installed = false;
  return { ok: true };
}

function crashsnifflaststep() {
  try { return { ok: true, lastStep: globalThis.__QQW_REACT2_LASTSTEP || null }; } catch (_) { return { ok: true, lastStep: null }; }
}

rpc.exports = {
  entries: () => ({ ok: true, build: SCRIPT_BUILD_ID, exports: Object.keys(rpc.exports).sort() }),
  build: () => SCRIPT_BUILD_ID,
  ping: () => ({ ok: true, ts: nowMs(), objc: objcAvailable(), sqlite: SQLITE.ok, sqliteErr: SQLITE.err || "" }),
  homedir: () => ({ ok: true, home: getHomeDir() }),
  findchatstoragepaths: (maxHits) => ({ ok: true, paths: findPathsByName("ChatStorage.sqlite", maxHits | 0) }),
  findpathscontains: (substr, maxHits) => ({ ok: true, paths: findPathsContaining(substr, maxHits | 0) }),
  opendb: (path) => ensureDb(path),
  closedb: () => { closeDb(); return { ok: true }; },
  query: (sql, params, limitRows, path) => queryDb(sql, params || [], limitRows | 0, path),
  getpushname: (jid, path) => getPushName(jid, path),
  getprofilepictureid: (jid, path) => getProfilePictureId(jid, path),
  getchatsessionpartnername: (jid, path) => getChatSessionPartnerName(jid, path),
  resolvedisplayname: (jid, path) => resolveDisplayName(jid, path),
  findselfcandidates: (path) => findSelfCandidates(path),
  listclassesrespondingtoselector: (sel, limit) => ({ ok: true, selector: String(sel || ""), classes: listClassesRespondingToSelector(sel, limit | 0) }),
  getselfprofile: (path) => getSelfProfile(path),
  selfhookinstall: () => installSelfGetterHooks(),
  selfhookstatus: () => ({ ok: true, installed: SELF_SNIFF.installed, installedAt: SELF_SNIFF.installedAt, hookedCount: SELF_SNIFF.hookedCount, last: SELF_SNIFF.last, errors: SELF_SNIFF.errors || [] }),
  getselfnameactive: () => getSelfNameActive(),
  getselfruntimeprofile: (includeAvatar) => getSelfRuntimeProfile(!!includeAvatar),
  getselfruntimename: () => getSelfRuntimeName(),
  inspectppm: () => {
    const ctxRes = _resolveCtxMainActive();
    if (!ctxRes || !ctxRes.ok) return { ok: false, error: "no context" };
    const ppm = _getProfilePictureManagerFromCtx(ctxRes.ctx);
    if (!ppm) return { ok: false, error: "no ppm" };
    const methods = ObjC.classes[String(ppm.$className)].$ownMethods;
    return { ok: true, className: String(ppm.$className), methods: methods };
  },
  listclasses: (f) => listClasses(f),
  listclassesconforming: (proto, filter, limit) => listClassesConformingToProtocol(proto, filter, limit | 0),
  gettables: (f) => getTables(f),
  inspectclass: (name) => inspectClass(name),
  getimp: (className, methodSig) => getMethodImp(className, methodSig),
  getprotomethods: (protoName) => getProtocolMethods(protoName),
  sendquotetext: (jid, quotedStanzaId, replyText, participantJid, origin) => sendquotetext(jid, quotedStanzaId, replyText, participantJid, origin),
  fileput_begin,
  fileput_chunk,
  fileput_end,
  fileput_probe,
  fileputBegin: fileput_begin,
  fileputChunk: fileput_chunk,
  fileputEnd: fileput_end,
  fileputProbe: fileput_probe,
  fileputbegin: fileput_begin,
  fileputchunk: fileput_chunk,
  fileputend: fileput_end,
  fileputprobe: fileput_probe,
  statusposttext: (text, messageOrigin, creationEntryPoint) => statusposttext(text, messageOrigin, creationEntryPoint),
  statuspostimage: (imagePath, captionText, messageOrigin) => statuspostimage(imagePath, captionText, messageOrigin),
  crashsniff: () => installCrashSniffer(),
  crashsnifflaststep: () => crashsnifflaststep(),
  impof: (className, selName) => impof(className, selName),
  ppcrashprobe: (jid, useMainApp) => probeCrashRequestThumb(jid, !!useMainApp),
  ppsniffprobe: (jid, useMainApp) => {
    installCrashSniffer();
    return probeCrashRequestThumb(jid, !!useMainApp);
  },
  moduleinfo: (name) => getModuleInfo(name),
  proberevokesels: () => probeRevokeSelectors(),
  revokemessage: (jid, stanzaId, participantJid) => revokeMessageForEveryone(jid, stanzaId, participantJid),
  revoketraceon: () => ({ ok: true, revoke: installRevokeTrace(), xmpp: installXMPPTrace() }),
  revoketracelast: () => getRevokeTraceLast(),
  revokeprobeon: () => installRevokeProbe(),
  revokeprobeget: () => revokeProbeStatus(),
  revokeprobeoff: () => revokeProbeOff(),
  selresponders: (selectorName, maxN) => selResponders(selectorName, maxN),
  quotedselectors: (className, regex, maxN) => quotedSelectors(className, regex, maxN),
  objselectors: (ptrStr, regex, maxN) => objSelectors(ptrStr, regex, maxN, false),
  objselectors_safe: (ptrStr, regex, maxN) => objSelectors(ptrStr, regex, maxN, true),
  objselectorsSafe: (ptrStr, regex, maxN) => objSelectors(ptrStr, regex, maxN, true),
  markread: (jid, stanzaId, participantJid, sendReadReceipts, isMarkedByUser) => markMessageReadByStanzaId(jid, stanzaId, participantJid, sendReadReceipts, isMarkedByUser),
  sendprobeon: (maxHooks) => installSendProbe(maxHooks),
  sendprobeget: () => sendProbeStatus(),
  sendprobeinspect: (ptrStr) => sendProbeInspect(ptrStr),
  sendprobeclear: () => sendProbeClear(),
  sendprobeoff: () => sendProbeOff(),
  likeprobeon: () => likeProbeOn(),
  likeprobeget: () => likeProbeGet(),
  likeprobeinspect: (ptrStr) => likeProbeInspect(ptrStr),
  likeprobestanzasummary: (ptrStr, maxChars) => likeProbeStanzaSummary(ptrStr, maxChars),
  likeprobestanzalast: (maxChars) => likeProbeStanzaLast(maxChars),
  likeprobestanzamethodslast: (regex, maxN) => likeProbeStanzaMethodsLast(regex, maxN),
  likeprobestanzacalllast: (selName, maxChars) => likeProbeStanzaCallNoArgLast(selName, maxChars),
  likeprobestanzacall1last: (selName, argStr, maxChars) => likeProbeStanzaCall1ArgLast(selName, argStr, maxChars),
  likestanzadumplast: () => likeStanzaDumpLast(),
  likebuildarm: (ms) => likeBuildArm(ms),
  likebuildget: (maxEvents) => likeBuildGet(maxEvents),
  likebuildextract: (maxEvents) => likeBuildExtract(maxEvents),
  likebuildoff: () => likeBuildOff(),
  likeresendlast: () => likeResendLast(),
  xmppsendstanzaptr: (ptrStr) => xmppSendStanzaPtr(ptrStr),
  objcstr: (ptrStr, maxChars) => objcStr(ptrStr, maxChars),
  idafrom: (addrStr) => idaFromRuntimeAddr(addrStr),
  xavmethods: (filter, maxN) => xavMethods(filter, maxN),
  likeprobeclear: () => likeProbeClear(),
  likeprobeoff: () => likeProbeOff(),
  statuslikecapture: () => statusLikeCapture(),
  statuslikearm: (ms) => statusLikeArm(ms),
  statuslike: (emojiText, authorJid, statusStanzaId) => statuslike(emojiText, authorJid, statusStanzaId),
  statuslikepure: (authorJid, statusStanzaId, emojiCode) => statuslikepure(authorJid, statusStanzaId, emojiCode),
  statuslikefind: (authorJid, statusStanzaId) => statuslikefind(authorJid, statusStanzaId),
  statuslikeinspect: (authorJid, statusStanzaId, regex, maxN) => statuslikeinspect(authorJid, statusStanzaId, regex, maxN),
  statuslikebuild: (authorJid, statusStanzaId, emojiCode) => statuslikebuild(authorJid, statusStanzaId, emojiCode),
  statuslikereact: (statusStanzaId, emojiCode, authorJid) => statuslikereact(statusStanzaId, emojiCode, authorJid),
  statuslikereact2: (statusStanzaId, emojiCode, authorJid) => statuslikereact2(statusStanzaId, emojiCode, authorJid),
  statuslikereact2build: (statusStanzaId, emojiCode, authorJid) => statuslikereact2build(statusStanzaId, emojiCode, authorJid),
  statuslikereact2send: () => statuslikereact2send(),
  statusreactionnative: (emojiText, authorJid, statusStanzaId) => statusreactionnative(emojiText, authorJid, statusStanzaId),
  statusreactionresolve: (maxN) => statusreactionresolve(maxN),
  statusreactionlistimages: (filter, maxN) => statusreactionlistimages(filter, maxN),
  statusreactionresolveimg: (filter, maxN) => statusreactionresolveimg(filter, maxN),
  statusreactionfindupdate: (filter, maxModules, maxHitsPerImage) => statusreactionfindupdate(filter, maxModules, maxHitsPerImage),
  readprobeon: () => installReadProbe(),
  readprobeget: () => readProbeStatus(),
  readprobeoff: () => readProbeOff(),
  readtraceon: (ms, maxHits) => readTraceOn(ms, maxHits),
  readtraceget: (maxN) => readTraceGet(maxN),
  readtraceclear: () => readTraceClear(),
  readtraceoff: () => readTraceOff(),
  rxpinnedon: () => rxPinnedOn(),
  rxpinnedoff: () => rxPinnedOff(),
  rxpinnedstatus: () => rxPinnedStatus(),
  rxpinnedlast: (maxN) => rxPinnedLast(maxN),
  statusmsgprobeon: () => statusMsgProbeOn(),
  statusmsgprobeoff: () => statusMsgProbeOff(),
  statusmsgprobestatus: () => statusMsgProbeStatus(),
  statusmsgprobelast: (maxN) => statusMsgProbeLast(maxN),
  statusreplyargslast: () => statusReplyArgsLast(),
  hookppm: () => hookPPM(),
  getprofilepictureitem: (jid) => {
    // try to find path automatically if not set
    if (!_dbPath) {
        const hits = findPathsByName("ChatStorage.sqlite", 5);
        if (hits && hits.length) ensureDb(hits[0]);
    }
    // ensureDb sets _dbPath global
    return getProfilePictureItemFromDb(jid, _dbPath);
  },
  getprofilepictureurl: (jid, pictureId) => getProfilePictureUrlLink(jid, pictureId),
  getprofilepictureurlasync: (jid) => getProfilePictureUrlLinkAsync(jid),
  getprofilepictureurlactive: (jid) => getProfilePictureUrlLinkActive(jid),
  getprofilepictureurlactivesafe: (jid) => getProfilePictureUrlLinkActiveSafe(jid),
  getprofilepictureurlbusiness: (jid) => getProfilePictureUrlLinkViaBusinessDirectPath(jid),
  getprofilepictureurlactivestable: (jid) => getProfilePictureUrlLinkActiveStable(jid),
  getprofilepictureurlprefetch: (jid) => getProfilePictureUrlLinkPrefetch(jid),
  getprofilepictureurlactivefull: (jid) => getProfilePictureUrlLinkActiveFull(jid),
  getprofilepictureurlactivereq: (jid) => getProfilePictureUrlLinkActiveReq(jid),
  inspectmetadata: (jid) => getProfilePictureUrlLinkAsync(jid),
  getselfcard: () => getSelfCard(),
  getselfavatar: (includeThumb, hint) => {
    const h = String(hint || "").trim();
    const me = getSelfNameActive();
    const selfJid = me && me.ok ? String(me.selfJid || "").trim() : "";
    const selfDigits = derivePhoneFromJid(selfJid);
    const key = h || selfDigits || "";

    const spot = _getSelfAvatarViaSpotlightProfileV2(key, 20);
    if (spot && spot.ok) return { ok: true, mode: "spotlight_profile_v2", selfJid, hint: key, ...spot };

    const safe = _getSelfAvatarViaFileSearch(key);
    if (safe && safe.ok) return { ok: true, mode: "file_search", selfJid, hint: key, ...safe };

    if (includeThumb) {
      const info = tryGetMyProfilePictureInfo(true);
      if (info && info.ok) return { ok: true, mode: "provider", selfJid, ...info };
      return { ok: false, mode: "none", selfJid, fileSearch: safe, spotlight: spot, provider: info };
    }

    const info2 = { ok: false, skipped: true, reason: "provider disabled unless thumb requested" };
    return { ok: false, mode: "none", selfJid, spotlight: spot, fileSearch: safe, provider: info2 };
  },
};

safeObjCInvoke(() => {
  try {
    send({ type: "qqw.explore.ready", build: SCRIPT_BUILD_ID, ts: nowMs(), objc: objcAvailable(), sqlite: SQLITE.ok, sqliteErr: SQLITE.err || "" });
  } catch (_) {}
});

refreshSelfCacheAsync();
