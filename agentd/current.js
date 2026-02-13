/*
  wa_txrx_stable_unified_pinned_output_v1.js

  来源：wa_txrx_stable_unified_pinned.js（发送/接收全功能脚本）
  目标：不更改功能与逻辑，仅把“接收侧 send() 输出”改为长期稳定事件格式（与 qqw-contracts/device-events.md 对齐）
*/
const SCRIPT_BUILD_ID = "2026-02-12.txrx.stable_unified_pinned.output_v1";

function _tid() {
  try { return Process.getCurrentThreadId(); } catch (_) { return 0; }
}

function _toPtr(p) {
  try {
    if (!p) return ptr("0x0");
    if (p.isNull !== undefined) return p;
    return ptr(String(p));
  } catch (_) {
    return ptr("0x0");
  }
}

function _safeObj(p) {
  try {
    if (!ObjC.available) return null;
    const pp = _toPtr(p);
    if (!pp || pp.isNull()) return null;
    return new ObjC.Object(pp);
  } catch (_) {
    return null;
  }
}

function _objcCanCall(objOrCls, sel) {
  try {
    if (!ObjC.available) return false;
    if (!objOrCls || !sel) return false;
    const f = objOrCls[sel];
    return !!(f && f.implementation);
  } catch (_) {
    return false;
  }
}

function _ns(s) {
  try {
    if (!ObjC.available) return null;
    const NSString = ObjC.classes.NSString;
    if (!NSString || !NSString.stringWithUTF8String_) return null;
    return NSString.stringWithUTF8String_(Memory.allocUtf8String(String(s || "")));
  } catch (_) {
    return null;
  }
}

function _safeDescValue(v) {
  try {
    if (!ObjC.available) return "";
    const o = _safeObj(v);
    if (!o) return "";
    const d = String(o);
    if (!d || d === "(null)") return "";
    return d;
  } catch (_) {
    return "";
  }
}

function _normJid(s) {
  try {
    const t = String(s || "").trim();
    if (!t) return "";
    return t.replace(/[<>]/g, "").trim();
  } catch (_) {
    return "";
  }
}

function _stripAngles(s) {
  try { return String(s || "").replace(/[<>\\s]/g, ""); } catch (_) { return ""; }
}

function _parseTextStanzaDesc(desc) {
  try {
    const s = String(desc || "");
    if (!s) return { id: "", to: "", encLen: -1 };
    const mId = s.match(/\bid=([0-9A-Fa-f]+)/);
    const id = mId ? String(mId[1] || "") : "";
    const mTo1 = s.match(/\bto=<([^>]+)>/);
    const mTo2 = s.match(/\bto=([^\s\]]+)/);
    const mTo3 = s.match(/\bt=<([^>]+)>/);
    const mTo4 = s.match(/\bt=([^\s\]]+)/);
    const to = mTo1 ? String(mTo1[1] || "") : (mTo2 ? String(mTo2[1] || "") : (mTo3 ? String(mTo3[1] || "") : (mTo4 ? String(mTo4[1] || "") : "")));
    const mEnc = s.match(/\[enc\s*\{(\d+)b\}\]/i);
    const encLen = mEnc ? Math.trunc(Number(mEnc[1])) : -1;
    return { id, to, encLen };
  } catch (_) {
    return { id: "", to: "", encLen: -1 };
  }
}

function _tmpDirPath() {
  try {
    if (!ObjC.available) return "";
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
      const p = ObjC.classes.NSTemporaryDirectory ? ObjC.classes.NSTemporaryDirectory() : null;
      if (p) return String(p);
    } catch (_) {}
    return "";
  } catch (_) {
    return "";
  }
}

function _tmpPathForBasename(basename) {
  try {
    const bn = String(basename || "file.bin").replace(/[\\\/]/g, "_");
    const tmp = _tmpDirPath();
    if (!tmp) return "";
    const sep = tmp.endsWith("/") ? "" : "/";
    return tmp + sep + bn;
  } catch (_) {
    return "";
  }
}

function _posixOpenWriteTrunc(pathStr) {
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

function _posixWriteAll(fd, bufPtr, len) {
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

function _posixClose(fd) {
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

function _chmod(pathStr, modeOctal) {
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

function _setFileProtectionNone(pathStr) {
  try {
    if (!ObjC.available) return { ok: false, error: "ObjC not available" };
    const p = String(pathStr || "").trim();
    if (!p) return { ok: false, error: "path empty" };
    const fm0 = ObjC.classes.NSFileManager ? ObjC.classes.NSFileManager.defaultManager() : null;
    const fm = _safeObj(fm0);
    if (!fm) return { ok: false, error: "NSFileManager missing" };
    if (!_objcCanCall(fm, "- setAttributes:ofItemAtPath:error:")) return { ok: false, error: "setAttributes missing" };
    const nsPath = _ns(p);
    if (!nsPath) return { ok: false, error: "path->NSString failed" };
    const NSMutableDictionary = ObjC.classes.NSMutableDictionary;
    if (!NSMutableDictionary || !NSMutableDictionary.dictionary) return { ok: false, error: "NSMutableDictionary missing" };
    const d = _safeObj(NSMutableDictionary.dictionary());
    if (!d || !_objcCanCall(d, "- setObject:forKey:")) return { ok: false, error: "dict init failed" };
    const k = _ns("NSFileProtectionKey");
    const v = _ns("NSFileProtectionNone");
    if (!k || !v) return { ok: false, error: "NSString const failed" };
    d.setObject_forKey_(v, k);
    try {
      const kp = _ns("NSFilePosixPermissions");
      const NSNumber = ObjC.classes.NSNumber;
      if (kp && NSNumber && NSNumber.numberWithInt_) {
        const n = NSNumber.numberWithInt_(0o644);
        if (n) d.setObject_forKey_(n, kp);
      }
    } catch (_) {}
    const errp = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errp, ptr("0x0"));
    const ok = !!fm.setAttributes_ofItemAtPath_error_(d, nsPath, errp);
    return { ok };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function _b64ToBytes(b64) {
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

let _filePutNextId = 1;
const _filePutMap = {};

function fileput_probe() {
  return { ok: true, tmp: String(_tmpDirPath() || "") };
}

function fileput_begin(basename) {
  const path = _tmpPathForBasename(basename);
  if (!path) return { ok: false, error: "tmp path failed" };
  const op = _posixOpenWriteTrunc(path);
  if (!op || !op.ok) return { ok: false, error: op ? op.error : "open failed", path };
  const id = _filePutNextId++;
  _filePutMap[String(id)] = { path, fd: Number(op.fd) };
  return { ok: true, id, path };
}

function fileput_chunk(id, b64chunk) {
  const it = _filePutMap[String(id || "")];
  if (!it || typeof it.fd !== "number") return { ok: false, error: "unknown id" };
  const bytes = _b64ToBytes(b64chunk);
  if (!bytes || !bytes.length) return { ok: false, error: "base64 decode failed" };
  const buf = Memory.alloc(bytes.length);
  Memory.writeByteArray(buf, bytes);
  const wr = _posixWriteAll(it.fd, buf, bytes.length);
  if (!wr || !wr.ok) return { ok: false, error: wr ? wr.error : "write failed" };
  return { ok: true, written: wr.written };
}

function fileput_end(id) {
  const k = String(id || "");
  const it = _filePutMap[k];
  if (!it || typeof it.fd !== "number") return { ok: false, error: "unknown id" };
  const path = String(it.path || "");
  delete _filePutMap[k];
  const cl = _posixClose(it.fd);
  if (!cl || !cl.ok) return { ok: false, error: cl ? cl.error : "close failed", path };
  _chmod(path, 0o644);
  _setFileProtectionNone(path);
  return { ok: true, path };
}

function _isMainThread() {
  try {
    const NSThread = ObjC.classes.NSThread;
    if (!NSThread || !NSThread["+ isMainThread"]) return false;
    const r = NSThread["+ isMainThread"]();
    return r === 1 || r === true || String(r) === "1";
  } catch (_) {
    return false;
  }
}

function _runOnMainQueueSync(fn, timeoutMs) {
  const tmo = Math.max(50, Math.min(30000, Number(timeoutMs) || 1500));
  if (!ObjC.available) return { ok: false, error: "ObjC not available" };
  if (_isMainThread()) {
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

function _scheduleOnMainQueue(fn) {
  try {
    if (!ObjC.available) return { ok: false, error: "ObjC not available" };
    ObjC.schedule(ObjC.mainQueue, () => { try { fn(); } catch (_) {} });
    return { ok: true };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

const FIXED = {
  sendTextSelector: "- sendMessageWithText:multicast:attachments:messageOrigin:creationEntryPoint:inChatSession:statusContentOriginInfo:statusDistributionInfo:statusResharePolicy:statusNotificationInfo:statusCreativeToolsUsageInfo:hasTextFromURL:openedFromURL:smbAutomated:statusMentionsJIDs:statusMentionsChatSessions:isQuestion:fromViewController:beforeSendCallback:completion:",
  sendImageSelector: "- sendMessageWithImage:thumbnail:caption:statusMentionsJIDs:statusMentionsChatSessions:productDescriptor:attachments:messageOrigin:inChatSession:statusContentOriginInfo:statusDistributionInfo:statusResharePolicy:statusNotificationInfo:statusCreativeToolsUsageInfo:isViewOnce:scanLengths:optimisticUploadIdentifier:interactiveAnnotations:mediaPickerOrigin:mediaTranscodeConfig:transcodeLoggingInfo:imageSourceType:statusSourceType:accessibilityLabel:pairedMediaInfo:isPremiumMessage:isQuestion:assetIdentifier:mediaSourceMetadata:completion:",
  sendVideoSelector: "- sendVideoAtURL:thumbnail:videoType:isViewOnce:isQuestion:contentProvider:caption:statusMentionsJIDs:statusMentionsChatSessions:mediaCachingInfo:attachments:messageOrigin:inChatSession:statusContentOriginInfo:statusDistributionInfo:statusResharePolicy:statusNotificationInfo:statusCreativeToolsUsageInfo:openedFromURL:interactiveAnnotations:mediaPickerOrigin:mediaTranscodeConfig:transcodeLoggingInfo:statusSourceType:videoSourceType:accessibilityLabel:pairedMediaInfo:assetIdentifier:mediaSourceMetadata:completion:",
  sendAudioSelector: "- sendMessageWithAudioFilePath:outgoingWaveform:draftMetrics:attachments:toChatSessions:mediaOrigin:statusContentOriginInfo:statusDistributionInfo:statusCreativeToolsUsageInfo:duration:isViewOnce:backgroundColor:openedFromURL:statusMentionsJIDs:statusMentionsChatSessions:fromViewController:audienceSheetCompletion:completion:",
  fetchChatSessionSelector: "- fetchChatSessionForJID:",
  mutableChatSessionSelector: "- mutableChatSession",
  fetchMessageSelector: "- fetchMessageWithStanzaID:isFromMe:",
  fetchMessageWithParticipantSelector: "- fetchMessageWithStanzaID:participantUserJID:isFromMe:",
  attachmentsSetQuotedItemSelector: "- setQuotedItem:",
  attachmentsSetContainsQuotedItemSelector: "- setContainsQuotedItem:",
  quotedItemInitSelector: "- initWithMessage:quoteType:",
  msgIdInitUsingStanzaIdSelector: "- initWithMessage:usingStanzaID:",
};

let _hookInstalled = false;
let _hookError = null;
const _stanzaIdByMessagePtr = new Map();
const _pendingByRqTag = new Map();
const _pendingByMessagePtr = new Map();
const _pendingByAttachmentsPtr = new Map();
let _activePending = null;

function _installMsgIdHook() {
  if (_hookInstalled) return { ok: true, installed: true };
  if (_hookError) return { ok: false, error: _hookError };
  if (!ObjC.available) return { ok: false, error: "ObjC not available" };
  const cls = ObjC.classes.WAMessageID;
  if (!cls) return { ok: false, error: "WAMessageID missing" };
  const m = cls[FIXED.msgIdInitUsingStanzaIdSelector];
  if (!m || !m.implementation) return { ok: false, error: "msgid selector missing", selector: FIXED.msgIdInitUsingStanzaIdSelector };
  try {
    Interceptor.attach(m.implementation, {
      onEnter(args) {
        try {
          const msgPtr = String(args[2]);
          const stanzaDesc = _safeDescValue(args[3]);
          const cand = _stripAngles(stanzaDesc);
          if (!msgPtr || msgPtr === "0x0") return;
          if (!cand || !/^[0-9A-Fa-f]{6,}$/.test(cand)) return;
          _stanzaIdByMessagePtr.set(msgPtr, cand);
          const pend = _pendingByMessagePtr.get(msgPtr);
          if (pend && !pend.stanzaId) pend.stanzaId = cand;
          try {
            const ap = _activePending;
            if (!ap || ap.stanzaId) return;
            if (typeof ap.deadlineMs === "number" && Date.now() > ap.deadlineMs) return;
            const mo = _safeObj(args[2]);
            if (!mo) return;
            if (_objcCanCall(mo, "- isFromMe")) {
              const fm = mo["- isFromMe"]();
              if (!(fm === 1 || fm === true || String(fm) === "1")) return;
            }
            ap.stanzaId = cand;
          } catch (_) {}
        } catch (_) {}
      },
    });
    _hookInstalled = true;
    return { ok: true, installed: true };
  } catch (e) {
    _hookError = String(e);
    return { ok: false, error: _hookError };
  }
}

function _newRqTag(prefix) {
  return `${String(prefix || "rq")}.${String(Date.now())}.${String(Math.floor(Math.random() * 1e9))}`;
}

function _pendingNew(kind, jidStr, timeoutMs) {
  const rqTag = _newRqTag(`min.${kind}`);
  const tmo = Math.max(500, Math.min(30000, Number(timeoutMs) || 8000));
  const now = Date.now();
  const p = { rqTag, kind: String(kind || ""), jid: String(jidStr || ""), jidNorm: _normJid(jidStr), deadlineMs: now + tmo, messagePtr: "", attachmentsPtr: "", stanzaId: "", error: "" };
  _pendingByRqTag.set(rqTag, p);
  return p;
}

function _captureMessageForPending(pend, msgObjOrPtr) {
  try {
    const msg = msgObjOrPtr && msgObjOrPtr.handle ? msgObjOrPtr : _safeObj(msgObjOrPtr);
    if (!msg) return false;
    const mp = String(msg.handle);
    if (!mp || mp === "0x0") return false;
    pend.messagePtr = mp;
    _pendingByMessagePtr.set(mp, pend);
    const sid = _stanzaIdByMessagePtr.get(mp);
    if (sid && !pend.stanzaId) pend.stanzaId = String(sid);
    return true;
  } catch (_) {
    return false;
  }
}

function _waitStanzaId(pend) {
  const start = Date.now();
  while (Date.now() < pend.deadlineMs) {
    if (pend.stanzaId) return { ok: true, stanzaId: String(pend.stanzaId) };
    if (pend.error) return { ok: false, error: String(pend.error) };
    Thread.sleep(0.02);
  }
  const waited = Date.now() - start;
  return { ok: false, error: "stanzaId timeout", waitedMs: waited };
}

function _cleanupPending(pend) {
  try {
    _pendingByRqTag.delete(pend.rqTag);
    if (pend.messagePtr) _pendingByMessagePtr.delete(pend.messagePtr);
    if (pend.attachmentsPtr) _pendingByAttachmentsPtr.delete(pend.attachmentsPtr);
  } catch (_) {}
}

function _buildNoopBoolBlock() {
  try {
    if (!ObjC.available || !ObjC.Block) return null;
    return new ObjC.Block({ retType: "void", argTypes: ["bool"], implementation: function (_b) {} });
  } catch (_) {
    return null;
  }
}

function _buildBeforeSendBlockCaptureMessage(pend) {
  try {
    if (!ObjC.available || !ObjC.Block) return null;
    return new ObjC.Block({
      retType: "void",
      argTypes: ["object"],
      implementation: function (msg) { try { _captureMessageForPending(pend, msg); } catch (_) {} },
    });
  } catch (_) {
    return null;
  }
}

function _buildCompletionBlockCaptureMsgErr(pend) {
  try {
    if (!ObjC.available || !ObjC.Block) return null;
    return new ObjC.Block({
      retType: "void",
      argTypes: ["object", "object"],
      implementation: function (a0, a1) {
        try {
          const o0 = _safeObj(a0);
          if (!o0) return;
          const cn = String(o0.$className || "");
          if (cn && cn.indexOf("WAMessage") !== -1 && cn.indexOf("WAMessageID") === -1) { _captureMessageForPending(pend, o0); return; }
          if (cn.indexOf("Array") !== -1) {
            try {
              const arr = o0;
              if (!_objcCanCall(arr, "- count") || !_objcCanCall(arr, "- objectAtIndex:")) return;
              const c = Number(arr.count());
              if (c !== 1) { pend.error = "completion NSArray count != 1"; return; }
              const msg = _safeObj(arr.objectAtIndex_(0));
              if (!msg) { pend.error = "completion NSArray[0] nil"; return; }
              const mcn = String(msg.$className || "");
              if (mcn && mcn.indexOf("WAMessage") !== -1 && mcn.indexOf("WAMessageID") === -1) {
                _captureMessageForPending(pend, msg);
                return;
              }
              if (mcn && mcn.indexOf("WAMessageID") !== -1) {
                const d = _safeDescValue(msg);
                const m1 = String(d || "").match(/\bstanzaId=([0-9A-Fa-f]{6,})/);
                const m2 = String(d || "").match(/\bid=([0-9A-Fa-f]{6,})/);
                const sid = m1 ? String(m1[1]) : (m2 ? String(m2[1]) : "");
                if (sid) { pend.stanzaId = sid; return; }
                pend.error = "completion WAMessageID stanzaId parse failed";
                return;
              }
              pend.error = "completion NSArray[0] unexpected class";
              return;
            } catch (_) {
              pend.error = "completion NSArray decode failed";
              return;
            }
          }
        } catch (_) {}
        try {
          const err = _safeObj(a1);
          if (err) pend.error = String(err);
        } catch (_) {}
      },
    });
  } catch (_) {
    return null;
  }
}

function _nsArray0() {
  try {
    if (!ObjC.available) return null;
    const NSArray = ObjC.classes.NSArray;
    if (!NSArray) return null;
    if (NSArray.array) return _safeObj(NSArray.array());
    if (NSArray.alloc && NSArray.alloc().init) return _safeObj(NSArray.alloc().init());
    return null;
  } catch (_) {
    return null;
  }
}

function _nsArray1(obj) {
  try {
    if (!ObjC.available) return null;
    const o = obj && obj.handle ? obj : _safeObj(obj);
    if (!o) return null;
    const NSArray = ObjC.classes.NSArray;
    if (!NSArray || !NSArray.arrayWithObject_) return null;
    return _safeObj(NSArray.arrayWithObject_(o));
  } catch (_) {
    return null;
  }
}

function _fileURLFromPath(pathStr) {
  try {
    if (!ObjC.available) return null;
    const p = String(pathStr || "").trim();
    if (!p) return null;
    const ns = _ns(p);
    if (!ns) return null;
    const NSURL = ObjC.classes.NSURL;
    if (!NSURL || !NSURL.fileURLWithPath_) return null;
    return _safeObj(NSURL.fileURLWithPath_(ns));
  } catch (_) {
    return null;
  }
}

function _uiImageFromFile(pathStr) {
  try {
    if (!ObjC.available) return null;
    const p = String(pathStr || "").trim();
    if (!p) return null;
    const ns = _ns(p);
    if (!ns) return null;
    const UIImage = ObjC.classes.UIImage;
    if (!UIImage) return null;
    if (UIImage.imageWithContentsOfFile_) {
      const img0 = UIImage.imageWithContentsOfFile_(ns);
      if (img0) return _safeObj(img0);
    }
    return null;
  } catch (_) {
    return null;
  }
}

function _buildRichTextMaybe(text) {
  try {
    if (!ObjC.available) return null;
    const s = String(text || "");
    if (!s) return null;
    const cls = ObjC.classes.WARichText;
    if (!cls) return null;
    const ns = _ns(s);
    if (!ns) return null;
    if (cls.richTextWithString_) {
      const o = cls.richTextWithString_(ns);
      if (o) return _safeObj(o);
    }
    if (cls.alloc && cls.alloc().initWithString_) {
      const o2 = cls.alloc().initWithString_(ns);
      if (o2) return _safeObj(o2);
    }
    return null;
  } catch (_) {
    return null;
  }
}

function _buildImageSendablePinned(imgObj) {
  try {
    if (!ObjC.available) return null;
    const img = imgObj && imgObj.handle ? imgObj : _safeObj(imgObj);
    if (!img) return null;
    const proto = ObjC.protocols ? ObjC.protocols.WAImageSendable : null;
    if (!proto) return null;
    if (!_objcCanCall(img, "- conformsToProtocol:")) return null;
    const ok = !!img.conformsToProtocol_(proto);
    return ok ? img : null;
  } catch (_) {
    return null;
  }
}

function _buildAttachmentsEmpty() {
  try {
    if (!ObjC.available) return null;
    const cls = ObjC.classes.WAMessageAttachments;
    if (!cls || !cls.alloc) return null;
    const inst = cls.alloc();
    if (!inst || !inst.init) return null;
    return _safeObj(inst.init());
  } catch (_) {
    return null;
  }
}

function _getUIApplicationDelegate() {
  try {
    const UIApp = ObjC.classes.UIApplication;
    if (!UIApp || !UIApp["+ sharedApplication"]) return null;
    const app = _safeObj(UIApp["+ sharedApplication"]());
    if (!app) return null;
    try { if (app.delegate) return _safeObj(app.delegate()); } catch (_) {}
    try { if (_objcCanCall(app, "- delegate")) return _safeObj(app["- delegate"]()); } catch (_) {}
    return null;
  } catch (_) {
    return null;
  }
}

function _resolveCoreFixed() {
  if (!ObjC.available) return { ok: false, error: "ObjC not available" };
  const del = _getUIApplicationDelegate();
  if (!del) return { ok: false, error: "UIApplication.delegate unavailable" };
  let ctx = null;
  try { if (del.$ivars) ctx = del.$ivars._userContext || null; } catch (_) { ctx = null; }
  ctx = _safeObj(ctx);
  if (!ctx) return { ok: false, error: "delegate._userContext nil" };
  const cn = String(ctx.$className || "");
  if (cn !== "WAContextMain") return { ok: false, error: "userContext not WAContextMain", className: cn };
  let storage = null;
  let sender = null;
  try { if (_objcCanCall(ctx, "- chatStorage")) storage = _safeObj(ctx["- chatStorage"]()); } catch (_) { storage = null; }
  try { if (_objcCanCall(ctx, "- messageSender")) sender = _safeObj(ctx["- messageSender"]()); } catch (_) { sender = null; }
  if (!storage) return { ok: false, error: "ctxMain.chatStorage nil" };
  if (!sender) return { ok: false, error: "ctxMain.messageSender nil" };
  return { ok: true, ctxMain: ctx, storage: storage, sender: sender };
}

function _makeWAChatJIDFromString(jidStr) {
  const s = String(jidStr || "").trim();
  if (!s) return null;
  const ns = _ns(s);
  if (!ns) return null;
  const cls = ObjC.classes.WAChatJID;
  if (!cls) return null;
  const sel = "+ ifValidWithStringRepresentation:";
  if (!_objcCanCall(cls, sel)) return null;
  return _safeObj(cls[sel](ns));
}

function _makeAuthorUserJIDFromString(jidStr) {
  const s = String(jidStr || "").trim();
  if (!s || s.indexOf("@") === -1) return null;
  const ns = _ns(s);
  if (!ns) return null;
  const isLid = s.indexOf("@lid") !== -1;
  const cls = isLid ? ObjC.classes.WALIDUserJID : ObjC.classes.WAUserJID;
  if (!cls) return null;
  const sel = "+ ifValidWithStringRepresentation:";
  if (!_objcCanCall(cls, sel)) return null;
  return _safeObj(cls[sel](ns));
}

function _fetchChatSession(storageObj, chatJidObj) {
  const stor = storageObj && storageObj.handle ? storageObj : _safeObj(storageObj);
  const cj = chatJidObj && chatJidObj.handle ? chatJidObj : _safeObj(chatJidObj);
  if (!stor || !cj) return null;
  if (!_objcCanCall(stor, FIXED.fetchChatSessionSelector)) return null;
  return _safeObj(stor[FIXED.fetchChatSessionSelector](cj));
}

function _getMutableChatSession(chatSessionObj) {
  const cs = chatSessionObj && chatSessionObj.handle ? chatSessionObj : _safeObj(chatSessionObj);
  if (!cs) return null;
  const cn = String(cs.$className || "");
  if (cn === "WAMutableChatSession" || cn.endsWith(".WAMutableChatSession")) return cs;
  if (!_objcCanCall(cs, FIXED.mutableChatSessionSelector)) return null;
  return _safeObj(cs[FIXED.mutableChatSessionSelector]());
}

function _fetchMessageByStanzaId(mcsObj, stanzaIdStr, participantJidStr) {
  const mcs = mcsObj && mcsObj.handle ? mcsObj : _safeObj(mcsObj);
  if (!mcs) return null;
  const sid = String(stanzaIdStr || "").trim();
  if (!sid) return null;
  const nsSid = _ns(sid);
  if (!nsSid) return null;
  const pj = String(participantJidStr || "").trim();
  if (pj) {
    const author = _makeAuthorUserJIDFromString(pj);
    if (!author) return null;
    if (!_objcCanCall(mcs, FIXED.fetchMessageWithParticipantSelector)) return null;
    try {
      const m0 = _safeObj(mcs[FIXED.fetchMessageWithParticipantSelector](nsSid, author, 0));
      if (m0) return m0;
      const m1 = _safeObj(mcs[FIXED.fetchMessageWithParticipantSelector](nsSid, author, 1));
      if (m1) return m1;
    } catch (_) {}
    return null;
  }
  if (!_objcCanCall(mcs, FIXED.fetchMessageSelector)) return null;
  try {
    const m0 = _safeObj(mcs[FIXED.fetchMessageSelector](nsSid, 0));
    if (m0) return m0;
    const m1 = _safeObj(mcs[FIXED.fetchMessageSelector](nsSid, 1));
    if (m1) return m1;
  } catch (_) {}
  return null;
}

function _buildQuotedItemFromMessage(msgObj, quoteType) {
  const msg = msgObj && msgObj.handle ? msgObj : _safeObj(msgObj);
  if (!msg) return null;
  const cls = ObjC.classes.WAMessageQuotedItem;
  if (!cls || !cls.alloc) return null;
  const inst = cls.alloc();
  if (!_objcCanCall(inst, FIXED.quotedItemInitSelector)) return null;
  return _safeObj(inst[FIXED.quotedItemInitSelector](msg, Number(quoteType) || 1));
}

function _buildAttachmentsWithQuotedItem(quotedItemObj) {
  const qi = quotedItemObj && quotedItemObj.handle ? quotedItemObj : _safeObj(quotedItemObj);
  if (!qi) return null;
  const cls = ObjC.classes.WAMessageAttachments;
  if (!cls || !cls.alloc) return null;
  const inst = cls.alloc();
  if (!_objcCanCall(inst, "- init")) return null;
  const att = _safeObj(inst["- init"]());
  if (!att) return null;
  try { if (_objcCanCall(att, FIXED.attachmentsSetQuotedItemSelector)) att[FIXED.attachmentsSetQuotedItemSelector](qi); } catch (_) {}
  try { if (_objcCanCall(att, FIXED.attachmentsSetContainsQuotedItemSelector)) att[FIXED.attachmentsSetContainsQuotedItemSelector](true); } catch (_) {}
  return att;
}

function _audioDurationSecondsFromOggOpus(pathStr) {
  try {
    const p = String(pathStr || "").trim();
    if (!p) return 0;
    const openPtr = Module.findExportByName(null, "open");
    const readPtr = Module.findExportByName(null, "read");
    const closePtr = Module.findExportByName(null, "close");
    if (!openPtr || !readPtr || !closePtr) return 0;
    const openFn = new NativeFunction(openPtr, "int", ["pointer", "int", "int"]);
    const readFn = new NativeFunction(readPtr, "int", ["int", "pointer", "int"]);
    const closeFn = new NativeFunction(closePtr, "int", ["int"]);
    const O_RDONLY = 0;
    const fd = openFn(Memory.allocUtf8String(p), O_RDONLY, 0);
    if (fd < 0) return 0;

    const _readU32 = (b, off) => (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
    const _readU64 = (b, off) => {
      const lo = _readU32(b, off);
      const hi = _readU32(b, off + 4);
      try { if (typeof BigInt !== "undefined") return (BigInt(hi) << 32n) | BigInt(lo); } catch (_) {}
      return hi * 4294967296 + lo;
    };

    const chunkSize = 8192;
    const tmp = Memory.alloc(chunkSize);
    let buf = new Uint8Array(0);
    let lastGranule = null;
    let preSkip = null;

    const _concat = (a, b) => {
      if (!a || a.length === 0) return b;
      const out = new Uint8Array(a.length + b.length);
      out.set(a, 0);
      out.set(b, a.length);
      return out;
    };
    const _indexOfOggS = (arr, start) => {
      for (let i = Math.max(0, start | 0); i + 3 < arr.length; i++) {
        if (arr[i] === 0x4f && arr[i + 1] === 0x67 && arr[i + 2] === 0x67 && arr[i + 3] === 0x53) return i;
      }
      return -1;
    };

    while (true) {
      const r = readFn(fd, tmp, chunkSize);
      if (r <= 0) break;
      const chunk = new Uint8Array(Memory.readByteArray(tmp, r));
      buf = _concat(buf, chunk);
      let pos = 0;
      while (true) {
        const idx = _indexOfOggS(buf, pos);
        if (idx < 0) {
          if (buf.length > 64) buf = buf.slice(buf.length - 64);
          break;
        }
        if (idx + 27 > buf.length) { buf = buf.slice(idx); break; }
        const nsegs = buf[idx + 26];
        const hdrSize = 27 + nsegs;
        if (idx + hdrSize > buf.length) { buf = buf.slice(idx); break; }
        let dataLen = 0;
        for (let i = 0; i < nsegs; i++) dataLen += buf[idx + 27 + i];
        const pageSize = hdrSize + dataLen;
        if (idx + pageSize > buf.length) { buf = buf.slice(idx); break; }
        lastGranule = _readU64(buf, idx + 6);
        if (preSkip === null) {
          let pktStart = idx + hdrSize;
          let pktLen = 0;
          for (let i = 0; i < nsegs; i++) {
            const l = buf[idx + 27 + i];
            pktLen += l;
            if (l < 255) {
              if (pktLen >= 12) {
                if (buf[pktStart] === 0x4f && buf[pktStart + 1] === 0x70 && buf[pktStart + 2] === 0x75 && buf[pktStart + 3] === 0x73 && buf[pktStart + 4] === 0x48 && buf[pktStart + 5] === 0x65 && buf[pktStart + 6] === 0x61 && buf[pktStart + 7] === 0x64) {
                  preSkip = (buf[pktStart + 10] | (buf[pktStart + 11] << 8)) >>> 0;
                  break;
                }
              }
              pktStart += pktLen;
              pktLen = 0;
            }
          }
        }
        pos = idx + pageSize;
        if (pos >= buf.length) { buf = new Uint8Array(0); break; }
      }
    }
    closeFn(fd);
    if (lastGranule === null) return 0;
    let samples = 0;
    try {
      if (typeof lastGranule === "bigint") {
        let g = lastGranule;
        if (preSkip !== null) g = g - BigInt(preSkip);
        if (g <= 0n) return 0;
        const s = Number(g) / 48000;
        return Number.isFinite(s) && s > 0 ? s : 0;
      }
      samples = Number(lastGranule);
    } catch (_) {
      samples = 0;
    }
    if (preSkip !== null) samples -= Number(preSkip) || 0;
    if (!(samples > 0)) return 0;
    const sec = samples / 48000;
    return Number.isFinite(sec) && sec > 0 ? sec : 0;
  } catch (_) {
    return 0;
  }
}

function _sendTextCore(senderObj, mcsObj, nsTextObj, attachmentsObj, messageOrigin, creationEntryPoint, pend) {
  const sender = senderObj && senderObj.handle ? senderObj : _safeObj(senderObj);
  const cs = mcsObj && mcsObj.handle ? mcsObj : _safeObj(mcsObj);
  const nsText = nsTextObj && nsTextObj.handle ? nsTextObj : _safeObj(nsTextObj);
  const att = attachmentsObj && attachmentsObj.handle ? attachmentsObj : _safeObj(attachmentsObj);
  if (!sender || !cs || !nsText) return { ok: false, error: "sender/chatSession/text nil" };
  if (!_objcCanCall(sender, FIXED.sendTextSelector)) return { ok: false, error: "send selector missing" };
  const mo = Number.isFinite(Number(messageOrigin)) ? Number(messageOrigin) : 1;
  const ep = Number.isFinite(Number(creationEntryPoint)) ? Number(creationEntryPoint) : 1;

  if (att && att.handle && !att.handle.isNull()) {
    pend.attachmentsPtr = String(att.handle);
    _pendingByAttachmentsPtr.set(pend.attachmentsPtr, pend);
  }

  const emptyArr = _nsArray0();
  if (!emptyArr) return { ok: false, error: "empty NSArray build failed" };
  const cb = _buildBeforeSendBlockCaptureMessage(pend);
  if (!cb) return { ok: false, error: "beforeSendCallback block create failed" };
  pend._block_keep = cb;

  sender[FIXED.sendTextSelector](
    nsText,
    false,
    att ? att : ptr("0x0"),
    mo,
    ep,
    cs,
    ptr("0x0"),
    ptr("0x0"),
    0,
    ptr("0x0"),
    ptr("0x0"),
    false,
    false,
    false,
    emptyArr,
    emptyArr,
    false,
    ptr("0x0"),
    cb,
    cb
  );
  return { ok: true };
}

function waitready() {
  return _runOnMainQueueSync(() => {
    const hk = _installMsgIdHook();
    if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, error: hk ? hk.error : "hook failed" };
    const core = _resolveCoreFixed();
    if (!core || !core.ok) return { ok: false, build: SCRIPT_BUILD_ID, error: core ? core.error : "core failed" };
    return { ok: true, build: SCRIPT_BUILD_ID };
  }, 2500);
}

function sendtext(jidStr, text, messageOrigin, creationEntryPoint) {
  const pend = _pendingNew("text", jidStr, 8000);
  const hk = _installMsgIdHook();
  if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "hook install failed" };
  const sch = _scheduleOnMainQueue(() => {
    try {
      const core = _resolveCoreFixed();
      if (!core || !core.ok) { pend.error = core ? core.error : "core failed"; return; }
      const nsText = _ns(text);
      if (!nsText) { pend.error = "text->NSString failed"; return; }
      const jid = _makeWAChatJIDFromString(jidStr);
      if (!jid) { pend.error = "WAChatJID parse failed"; return; }
      const cs = _fetchChatSession(core.storage, jid);
      if (!cs) { pend.error = "fetchChatSessionForJID returned nil"; return; }
      const mcs = _getMutableChatSession(cs);
      if (!mcs) { pend.error = "mutableChatSession returned nil"; return; }
      const att = _buildAttachmentsEmpty();
      if (!att) { pend.error = "build attachments failed"; return; }
      pend._keep = [nsText, att, mcs];
      _activePending = pend;
      _sendTextCore(core.sender, mcs, nsText, att, messageOrigin, creationEntryPoint, pend);
    } catch (e) {
      pend.error = String(e);
    }
  });
  if (!sch || !sch.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: sch ? sch.error : "schedule failed" };
  const w = _waitStanzaId(pend);
  const sid = w && w.ok ? String(w.stanzaId || "") : "";
  const err = w && !w.ok ? String(w.error || "failed") : (pend.error ? String(pend.error) : null);
  if (_activePending === pend) _activePending = null;
  _cleanupPending(pend);
  return { ok: !!(w && w.ok), build: SCRIPT_BUILD_ID, stanzaId: sid, error: err };
}

function sendquotetext(jidStr, stanzaIdStr, replyText, participantJidStr, messageOrigin, creationEntryPoint) {
  const pend = _pendingNew("quote", jidStr, 12000);
  const hk = _installMsgIdHook();
  if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "hook install failed" };
  const sch = _scheduleOnMainQueue(() => {
    try {
      const core = _resolveCoreFixed();
      if (!core || !core.ok) { pend.error = core ? core.error : "core failed"; return; }
      const jid = _makeWAChatJIDFromString(jidStr);
      if (!jid) { pend.error = "WAChatJID parse failed"; return; }
      const cs = _fetchChatSession(core.storage, jid);
      if (!cs) { pend.error = "fetchChatSessionForJID returned nil"; return; }
      const mcs = _getMutableChatSession(cs);
      if (!mcs) { pend.error = "mutableChatSession returned nil"; return; }
      const msg = _fetchMessageByStanzaId(mcs, stanzaIdStr, participantJidStr);
      if (!msg) { pend.error = "fetchMessage returned nil"; return; }
      const qi = _buildQuotedItemFromMessage(msg, 1);
      if (!qi) { pend.error = "build quotedItem failed"; return; }
      const att = _buildAttachmentsWithQuotedItem(qi);
      if (!att) { pend.error = "build attachments failed"; return; }
      const nsText = _ns(replyText);
      if (!nsText) { pend.error = "text->NSString failed"; return; }
      pend._keep = [msg, qi, att, nsText, mcs];
      _activePending = pend;
      _sendTextCore(core.sender, mcs, nsText, att, messageOrigin, creationEntryPoint, pend);
    } catch (e) {
      pend.error = String(e);
    }
  });
  if (!sch || !sch.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: sch ? sch.error : "schedule failed" };
  const w = _waitStanzaId(pend);
  const sid = w && w.ok ? String(w.stanzaId || "") : "";
  const err = w && !w.ok ? String(w.error || "failed") : (pend.error ? String(pend.error) : null);
  if (_activePending === pend) _activePending = null;
  _cleanupPending(pend);
  return { ok: !!(w && w.ok), build: SCRIPT_BUILD_ID, stanzaId: sid, error: err };
}

function sendimage(jidStr, captionText, imagePath, messageOrigin) {
  const pend = _pendingNew("image", jidStr, 20000);
  const hk = _installMsgIdHook();
  if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "hook install failed" };
  const coreRes = _runOnMainQueueSync(() => _resolveCoreFixed(), 2500);
  if (!coreRes || !coreRes.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: coreRes ? coreRes.error : "core failed" };
  const core = coreRes;
  const jid = _makeWAChatJIDFromString(jidStr);
  if (!jid) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "WAChatJID parse failed" };
  const cs = _runOnMainQueueSync(() => _fetchChatSession(core.storage, jid), 2500);
  if (!cs) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "fetchChatSessionForJID returned nil" };
  const mcs = _runOnMainQueueSync(() => _getMutableChatSession(cs), 2500);
  if (!mcs) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "mutableChatSession returned nil" };
  const img = _uiImageFromFile(imagePath);
  if (!img) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "UIImage load failed" };
  const sendable = _buildImageSendablePinned(img);
  if (!sendable) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "UIImage not WAImageSendable" };
  if (!_objcCanCall(core.sender, FIXED.sendImageSelector)) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "send image selector missing" };
  const att = _buildAttachmentsEmpty();
  if (!att) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "build attachments failed" };
  const emptyArr = _nsArray0();
  if (!emptyArr) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "empty NSArray build failed" };
  const completion = _buildCompletionBlockCaptureMsgErr(pend);
  if (!completion) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "completion block create failed" };
  const mo = Number.isFinite(Number(messageOrigin)) ? Number(messageOrigin) : 1;
  pend._block_keep = completion;
  const sch = _scheduleOnMainQueue(() => {
    try {
      core.sender[FIXED.sendImageSelector](
        sendable,
        img,
        ptr("0x0"),
        emptyArr,
        emptyArr,
        ptr("0x0"),
        att,
        mo,
        mcs,
        ptr("0x0"),
        ptr("0x0"),
        ptr("0x0"),
        ptr("0x0"),
        ptr("0x0"),
        false,
        emptyArr,
        ptr("0x0"),
        emptyArr,
        0,
        ptr("0x0"),
        ptr("0x0"),
        0,
        0,
        ptr("0x0"),
        ptr("0x0"),
        false,
        false,
        ptr("0x0"),
        ptr("0x0"),
        completion
      );
    } catch (e) {
      pend.error = String(e);
    }
  });
  if (!sch || !sch.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: sch ? sch.error : "schedule failed" };
  const w = _waitStanzaId(pend);
  const sid = w && w.ok ? String(w.stanzaId || "") : "";
  const err = w && !w.ok ? String(w.error || "failed") : (pend.error ? String(pend.error) : null);
  _cleanupPending(pend);
  return { ok: !!(w && w.ok), build: SCRIPT_BUILD_ID, stanzaId: sid, error: err };
}

function sendvideo(jidStr, captionText, videoPath, thumbnailPath, messageOrigin) {
  const pend = _pendingNew("video", jidStr, 30000);
  const hk = _installMsgIdHook();
  if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "hook install failed" };
  const coreRes = _runOnMainQueueSync(() => _resolveCoreFixed(), 2500);
  if (!coreRes || !coreRes.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: coreRes ? coreRes.error : "core failed" };
  const core = coreRes;
  const jid = _makeWAChatJIDFromString(jidStr);
  if (!jid) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "WAChatJID parse failed" };
  const cs = _runOnMainQueueSync(() => _fetchChatSession(core.storage, jid), 2500);
  if (!cs) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "fetchChatSessionForJID returned nil" };
  const mcs = _runOnMainQueueSync(() => _getMutableChatSession(cs), 2500);
  if (!mcs) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "mutableChatSession returned nil" };
  try { _chmod(String(videoPath || ""), 0o644); } catch (_) {}
  try { _setFileProtectionNone(String(videoPath || "")); } catch (_) {}
  const url = _fileURLFromPath(videoPath);
  if (!url) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "NSURL fileURL failed" };
  const tp = String(thumbnailPath || "").trim();
  if (tp) {
    try { _chmod(tp, 0o644); } catch (_) {}
    try { _setFileProtectionNone(tp); } catch (_) {}
  }
  const thumb = tp ? _uiImageFromFile(tp) : null;
  if (tp && !thumb) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "thumbnail UIImage load failed" };
  const capText = String(captionText || "");
  const cap = capText ? _buildRichTextMaybe(capText) : null;
  if (capText && !cap) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "WARichText build failed" };
  if (!_objcCanCall(core.sender, FIXED.sendVideoSelector)) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "send video selector missing" };
  const att = _buildAttachmentsEmpty();
  if (!att) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "build attachments failed" };
  const emptyArr = _nsArray0();
  if (!emptyArr) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "empty NSArray build failed" };
  const completion = _buildCompletionBlockCaptureMsgErr(pend);
  if (!completion) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "completion block create failed" };
  const mo = Number.isFinite(Number(messageOrigin)) ? Number(messageOrigin) : 1;
  pend._block_keep = completion;
  const sch = _scheduleOnMainQueue(() => {
    try {
      core.sender[FIXED.sendVideoSelector](
        url,
        thumb ? thumb : ptr("0x0"),
        uint64(0),
        false,
        false,
        int64(0),
        cap ? cap : ptr("0x0"),
        emptyArr,
        emptyArr,
        ptr("0x0"),
        att,
        mo,
        mcs,
        ptr("0x0"),
        ptr("0x0"),
        ptr("0x0"),
        ptr("0x0"),
        ptr("0x0"),
        false,
        emptyArr,
        uint64(0),
        ptr("0x0"),
        ptr("0x0"),
        0,
        0,
        ptr("0x0"),
        ptr("0x0"),
        ptr("0x0"),
        ptr("0x0"),
        completion
      );
    } catch (e) {
      pend.error = String(e);
    }
  });
  if (!sch || !sch.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: sch ? sch.error : "schedule failed" };
  const w = _waitStanzaId(pend);
  const sid = w && w.ok ? String(w.stanzaId || "") : "";
  const err = w && !w.ok ? String(w.error || "failed") : (pend.error ? String(pend.error) : null);
  _cleanupPending(pend);
  return { ok: !!(w && w.ok), build: SCRIPT_BUILD_ID, stanzaId: sid, error: err };
}

function sendaudio(jidStr, audioPath, durationSec, messageOrigin) {
  const pend = _pendingNew("audio", jidStr, 30000);
  const hk = _installMsgIdHook();
  if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "hook install failed" };
  const coreRes = _runOnMainQueueSync(() => _resolveCoreFixed(), 2500);
  if (!coreRes || !coreRes.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: coreRes ? coreRes.error : "core failed" };
  const core = coreRes;
  const jid = _makeWAChatJIDFromString(jidStr);
  if (!jid) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "WAChatJID parse failed" };
  const cs = _runOnMainQueueSync(() => _fetchChatSession(core.storage, jid), 2500);
  if (!cs) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "fetchChatSessionForJID returned nil" };
  const mcs = _runOnMainQueueSync(() => _getMutableChatSession(cs), 2500);
  if (!mcs) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "mutableChatSession returned nil" };
  try { _chmod(String(audioPath || ""), 0o644); } catch (_) {}
  try { _setFileProtectionNone(String(audioPath || "")); } catch (_) {}
  const nsPath = _ns(String(audioPath || ""));
  if (!nsPath) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "path->NSString failed" };
  const att = _buildAttachmentsEmpty();
  if (!att) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "build attachments failed" };
  const toChatSessions = _nsArray1(mcs);
  if (!toChatSessions) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "NSArray(1) build failed" };
  const emptyArr = _nsArray0();
  if (!emptyArr) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "empty NSArray build failed" };
  const audience = _buildNoopBoolBlock();
  if (!audience) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "audienceSheetCompletion block create failed" };
  const completion = _buildCompletionBlockCaptureMsgErr(pend);
  if (!completion) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "completion block create failed" };
  const mo = Number.isFinite(Number(messageOrigin)) ? Number(messageOrigin) : 1;
  let dur = Number.isFinite(Number(durationSec)) ? Number(durationSec) : 0;
  if (!(dur > 0)) {
    try { dur = _audioDurationSecondsFromOggOpus(String(audioPath || "")); } catch (_) { dur = 0; }
  }
  if (!_objcCanCall(core.sender, FIXED.sendAudioSelector)) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "send audio selector missing" };
  pend._block_keep = [audience, completion];
  const sch = _scheduleOnMainQueue(() => {
    try {
      core.sender[FIXED.sendAudioSelector](
        nsPath,
        ptr("0x0"),
        ptr("0x0"),
        att,
        toChatSessions,
        mo,
        ptr("0x0"),
        ptr("0x0"),
        ptr("0x0"),
        dur,
        false,
        ptr("0x0"),
        false,
        emptyArr,
        emptyArr,
        ptr("0x0"),
        audience,
        completion
      );
    } catch (e) {
      pend.error = String(e);
    }
  });
  if (!sch || !sch.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: sch ? sch.error : "schedule failed" };
  const w = _waitStanzaId(pend);
  const sid = w && w.ok ? String(w.stanzaId || "") : "";
  const err = w && !w.ok ? String(w.error || "failed") : (pend.error ? String(pend.error) : null);
  _cleanupPending(pend);
  return { ok: !!(w && w.ok), build: SCRIPT_BUILD_ID, stanzaId: sid, error: err };
}

function entries() {
  return { ok: true, build: SCRIPT_BUILD_ID, exports: Object.keys(rpc.exports || {}).sort() };
}

rpc.exports = {
  entries,
  waitready,
  sendtext,
  sendquotetext,
  sendimage,
  sendvideo,
  sendaudio,
  fileput_begin,
  fileput_chunk,
  fileput_end,
  fileput_probe,
  fileputbegin: fileput_begin,
  fileputchunk: fileput_chunk,
  fileputend: fileput_end,
  fileputprobe: fileput_probe,
  fileputBegin: fileput_begin,
  fileputChunk: fileput_chunk,
  fileputEnd: fileput_end,
  fileputProbe: fileput_probe,
};

const RX_STATE = { installed: false, error: null, installedAt: null };

function RX_objcAvailable() { try { return !!(ObjC && ObjC.available); } catch (_) { return false; } }

function RX_safeObjCInvoke(fn) {
  try {
    if (!RX_objcAvailable()) return;
    try { ObjC.schedule(ObjC.mainQueue, fn); return; } catch (_) {}
    try { fn(); } catch (_) {}
  } catch (_) {}
}

function RX_pickModuleByHints(hints) {
  try {
    const hs = (hints || []).map(s => String(s)).filter(Boolean);
    const mods = Process.enumerateModules();
    for (const h of hs) {
      const m = mods.find(x => String(x.name).indexOf(h) !== -1);
      if (m) return m;
    }
    return mods.length ? mods[0] : null;
  } catch (_) {
    return null;
  }
}

function RX_isReadable(p, size) {
  try {
    if (!p || p.isNull()) return false;
    const r = Process.findRangeByAddress(p);
    if (!r) return false;
    const prot = String(r.protection || "");
    if (prot.indexOf("r") === -1) return false;
    const n = Math.max(1, Number(size) || 1);
    const base = r.base;
    const end = r.base.add(r.size);
    return p.compare(base) >= 0 && p.add(n).compare(end) <= 0;
  } catch (_) {
    return false;
  }
}

function RX_isLikelyTaggedPointer(p) {
  try {
    if (!p || p.isNull()) return false;
    if (Process.pointerSize !== 8) return false;
    const s = p.toString();
    if (!s) return false;
    const n = BigInt(s);
    return (n & 0x8000000000000000n) !== 0n;
  } catch (_) {
    return false;
  }
}

function RX_isLikelyObjCPointer(p) {
  try {
    if (!p || p.isNull()) return false;
    if (RX_isLikelyTaggedPointer(p)) return true;
    const r = Process.findRangeByAddress(p);
    if (!r) return false;
    const prot = String(r.protection || "");
    return prot.indexOf("r") !== -1;
  } catch (_) {
    return false;
  }
}

function RX_tryObjCObject(p) {
  try {
    if (!RX_objcAvailable()) return null;
    if (!p || p.isNull()) return null;
    if (!RX_isLikelyObjCPointer(p)) return null;
    return new ObjC.Object(p);
  } catch (_) {
    return null;
  }
}

function RX_tryObjCObjectDeep(ptrValue, maxDeref) {
  try {
    if (!RX_objcAvailable()) return null;
    const max = Math.max(0, Math.min(3, Number(maxDeref) || 0));
    let cur = ptrValue;
    for (let i = 0; i <= max; i++) {
      const o = RX_tryObjCObject(cur);
      if (o) return o;
      if (!cur || cur.isNull()) return null;
      if (!RX_isReadable(cur, Process.pointerSize)) return null;
      let next = null;
      try { next = Memory.readPointer(cur); } catch (_) { next = null; }
      if (!next || next.isNull()) return null;
      if (String(next) === String(cur)) return null;
      cur = next;
    }
    return null;
  } catch (_) {
    return null;
  }
}

function RX_tryInvokeNoArg(obj, sel) {
  try {
    if (!obj) return null;
    const name = String(sel || "");
    if (!name || name.indexOf(":") !== -1) return null;
    const fn = obj[name];
    if (typeof fn !== "function") return null;
    return fn.call(obj);
  } catch (_) {
    return null;
  }
}

function RX_tryCallBoolNoArg(obj, sel) {
  try {
    const v = RX_tryInvokeNoArg(obj, sel);
    if (v === null || v === undefined) return null;
    if (typeof v === "boolean") return v;
    if (typeof v === "number") return v !== 0;
    if (!RX_objcAvailable()) return null;
    if (!(v instanceof ObjC.Object)) return null;
    if (ObjC.classes.NSNumber && v.isKindOfClass_(ObjC.classes.NSNumber)) {
      try { return Number(v) !== 0; } catch (_) { return null; }
    }
    return null;
  } catch (_) {
    return null;
  }
}

function RX_tryReadNSDataAll(ptrValue, hardCapBytes) {
  try {
    if (!RX_objcAvailable()) return null;
    const obj = RX_tryObjCObject(ptrValue);
    if (!obj) return null;
    if (!ObjC.classes.NSData || !obj.isKindOfClass_(ObjC.classes.NSData)) return null;
    let len = 0;
    try { len = Number(obj.length()); } catch (_) { len = 0; }
    const cap = Math.max(0, Number(hardCapBytes) || 0);
    const n = cap > 0 ? Math.min(len, cap) : len;
    if (n <= 0) return { bytes: new Uint8Array([]), totalLen: len, truncated: false };
    let bytesPtr = null;
    try { bytesPtr = obj.bytes(); } catch (_) { bytesPtr = null; }
    if (!bytesPtr || bytesPtr.isNull()) return null;
    if (!RX_isReadable(bytesPtr, Math.min(16, n))) return null;
    const ab = Memory.readByteArray(bytesPtr, n);
    if (!ab) return null;
    return { bytes: new Uint8Array(ab), totalLen: len, truncated: (cap > 0 && len > cap) };
  } catch (_) {
    return null;
  }
}

function RX_bytesToHexChunks(u8, chunkChars) {
  try {
    if (!u8 || u8.length === 0) return [];
    const perChunkBytes = Math.max(1, Math.floor((Number(chunkChars) || 12000) / 2));
    const out = [];
    for (let off = 0; off < u8.length; off += perChunkBytes) {
      const end = Math.min(u8.length, off + perChunkBytes);
      let s = "";
      for (let i = off; i < end; i++) {
        const b = u8[i] & 0xff;
        s += (b < 16 ? "0" : "") + b.toString(16);
      }
      out.push(s);
    }
    return out;
  } catch (_) {
    return [];
  }
}

function RX_jidToString(anyObj) {
  try {
    if (!RX_objcAvailable()) return null;
    const o = (anyObj instanceof ObjC.Object) ? anyObj : RX_tryObjCObjectDeep(anyObj, 1);
    if (!o) return null;
    if (ObjC.classes.NSString && o.isKindOfClass_(ObjC.classes.NSString)) return String(o);
    const jidString = RX_tryInvokeNoArg(o, "jidString");
    if (jidString !== null && jidString !== undefined) return String(jidString);
    const rawString = RX_tryInvokeNoArg(o, "rawString");
    if (rawString !== null && rawString !== undefined) return String(rawString);
    const s = String(o);
    if (s.indexOf("@") !== -1) return s;
    return null;
  } catch (_) {
    return null;
  }
}

function RX_deriveIsFromMeFromUniqueKey(uniqueKeyStr) {
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

function RX_isGroupJidString(jidStr) {
  try {
    const s = String(jidStr || "");
    if (!s) return false;
    return s.indexOf("@g.us") !== -1 || s.indexOf("@group") !== -1;
  } catch (_) {
    return false;
  }
}

function RX_deriveChatJidFromUniqueKey(uniqueKeyStr) {
  try {
    const s = String(uniqueKeyStr || "");
    const idx = s.indexOf("_");
    if (idx <= 0) return null;
    const jid = s.slice(0, idx);
    return jid && jid.indexOf("@") !== -1 ? jid : null;
  } catch (_) {
    return null;
  }
}

function RX_extractStanzaFieldsFromContext(ctxPtr) {
  const out = { stanzaId: null, uniqueKey: null, chatJID: null, senderJID: null, isGroup: null, isFromMe: null };
  try {
    const ctxObj = RX_tryObjCObjectDeep(ctxPtr, 2);
    if (!ctxObj) return out;
    const stanzaObj = RX_tryInvokeNoArg(ctxObj, "orderedMessageStanza") || RX_tryInvokeNoArg(ctxObj, "messageStanza");
    if (!stanzaObj || !(stanzaObj instanceof ObjC.Object)) return out;

    const stanzaId = RX_tryInvokeNoArg(stanzaObj, "uniqueStanzaID");
    if (stanzaId !== null && stanzaId !== undefined) out.stanzaId = String(stanzaId);
    const uniqueKey = RX_tryInvokeNoArg(stanzaObj, "uniqueKey");
    if (uniqueKey !== null && uniqueKey !== undefined) out.uniqueKey = String(uniqueKey);

    const chatCand =
      RX_tryInvokeNoArg(stanzaObj, "chatJID") ||
      RX_tryInvokeNoArg(stanzaObj, "chatJid") ||
      RX_tryInvokeNoArg(stanzaObj, "remoteJID") ||
      RX_tryInvokeNoArg(stanzaObj, "remoteJid");
    out.chatJID = RX_jidToString(chatCand);
    if (!out.chatJID && out.uniqueKey) out.chatJID = RX_deriveChatJidFromUniqueKey(out.uniqueKey);

    const senderCand =
      RX_tryInvokeNoArg(stanzaObj, "threadMsgSenderJID") ||
      RX_tryInvokeNoArg(stanzaObj, "incomingOriginalAuthorUserJID") ||
      RX_tryInvokeNoArg(stanzaObj, "participant");
    out.senderJID = RX_jidToString(senderCand);

    if (out.chatJID) out.isGroup = RX_isGroupJidString(out.chatJID);
    const isFromMe = RX_tryCallBoolNoArg(stanzaObj, "isFromMe");
    out.isFromMe = (isFromMe !== null && isFromMe !== undefined) ? isFromMe : RX_tryCallBoolNoArg(stanzaObj, "fromMe");
    if (out.isFromMe === null && out.uniqueKey) out.isFromMe = RX_deriveIsFromMeFromUniqueKey(out.uniqueKey);
    return out;
  } catch (_) {
    return out;
  }
}

const RX_CONFIG = {
  moduleNameHints: ["WhatsApp", "WhatsAppDecrypted", "WhatsApp_Decrypted"],
  rva: 0x35B1CE4,
  cmdSelectors: [
    "reallyProcessResultsAfterSignalForContext:plaintextProtobuf:originalMessageData:notificationBehavior:journalID:error:retryCount:origin:reportEmptyPlaintextError:",
    "processResultsAfterSignalForContext:plaintextProtobuf:originalMessageData:notificationBehavior:journalID:error:retryCount:origin:reportEmptyPlaintextError:",
  ],
  limits: { maxEvents: 800, maxLinesPerSecond: 60 },
  protobuf: { hardCapBytes: 4 * 1024 * 1024, hexChunkChars: 12000, alwaysEmitHex: true },
};

function RX_install() {
  try {
    if (!RX_objcAvailable()) throw new Error("ObjC unavailable");
    const mod = RX_pickModuleByHints(RX_CONFIG.moduleNameHints);
    if (!mod || !mod.base) throw new Error("module not found");
    const addr = mod.base.add(ptr(Number(RX_CONFIG.rva) || 0));
    const reentry = {};
    let events = 0;
    let winStart = 0;
    let winLines = 0;

    Interceptor.attach(addr, {
      onEnter(args) {
        try {
          if (events >= RX_CONFIG.limits.maxEvents) return;
          const tid = Process.getCurrentThreadId();
          if (reentry[tid]) return;
          reentry[tid] = 1;
          events += 1;

          const now = Date.now();
          const maxLps = Number(RX_CONFIG.limits.maxLinesPerSecond) || 0;
          if (maxLps > 0) {
            if (!winStart || now - winStart >= 1000) { winStart = now; winLines = 0; }
            if (winLines >= maxLps) return;
            winLines += 1;
          }

          let cmdSel = null;
          try { cmdSel = ObjC.selectorAsString(args[1]); } catch (_) { cmdSel = null; }
          if (RX_CONFIG.cmdSelectors && RX_CONFIG.cmdSelectors.length) {
            if (!cmdSel || RX_CONFIG.cmdSelectors.indexOf(String(cmdSel)) === -1) return;
          }

          const ctxPtr = args[2];
          const arg4Ptr = args[4];
          const arg5Ptr = args[5];

          const doWork = () => {
            try {
              const stanza = RX_extractStanzaFieldsFromContext(ctxPtr);
              let data = RX_tryReadNSDataAll(arg4Ptr, RX_CONFIG.protobuf.hardCapBytes);
              let source = "arg4";
              if (!data) {
                data = RX_tryReadNSDataAll(arg5Ptr, RX_CONFIG.protobuf.hardCapBytes);
                source = "arg5";
              }
              const proto = data ? {
                len: data.totalLen,
                truncated: data.truncated,
                hexChunks: RX_CONFIG.protobuf.alwaysEmitHex ? RX_bytesToHexChunks(data.bytes, RX_CONFIG.protobuf.hexChunkChars) : null,
              } : null;

              const chatJID = stanza.chatJID ? String(stanza.chatJID) : "";
              const stanzaId = stanza.stanzaId ? String(stanza.stanzaId) : "";
              const senderJID = stanza.senderJID ? String(stanza.senderJID) : "";
              const isGroup = (stanza.isGroup === true || stanza.isGroup === false) ? stanza.isGroup : null;
              const fromMe = (stanza.isFromMe === true || stanza.isFromMe === false) ? stanza.isFromMe : null;
              const uniqueKey = stanza.uniqueKey ? String(stanza.uniqueKey) : "";

              send({
                type: "wa.recv.update",
                build: SCRIPT_BUILD_ID,
                ts: Date.now(),
                phase: "native_post_decrypt_pinned_style",
                data: {
                  stanzaId: stanzaId,
                  route: {
                    via: "native_post_decrypt",
                    chatJID: chatJID,
                    remoteChat: chatJID,
                    participantJID: senderJID,
                    fromMe: fromMe === true,
                    isGroup: isGroup,
                    uniqueKey: uniqueKey,
                  },
                  protobuf: proto,
                  diag: { cmdSel: cmdSel ? String(cmdSel) : null, protobufSource: proto ? source : null },
                  rawType: "wa.recv.native_post_decrypt.pinned_style",
                },
              });
            } catch (_) {}
          };

          try { doWork(); } catch (_) { RX_safeObjCInvoke(doWork); }
        } catch (_) {}
      },
      onLeave() {
        try {
          const tid = Process.getCurrentThreadId();
          if (reentry[tid]) delete reentry[tid];
        } catch (_) {}
      },
    });

    RX_STATE.installed = true;
    RX_STATE.installedAt = String(addr);
    RX_STATE.error = null;
  } catch (e) {
    RX_STATE.installed = false;
    RX_STATE.error = String(e);
  }
}

setImmediate(() => {
  try { RX_install(); } catch (_) {}
});

