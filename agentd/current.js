/*
  wa_txrx_stable_unified_pinned_output_v1.js

  来源：wa_txrx_stable_unified_pinned.js（发送/接收全功能脚本）
  目标：不更改功能与逻辑，仅把“接收侧 send() 输出”改为长期稳定事件格式（与 qqw-contracts/device-events.md 对齐）
*/
const SCRIPT_BUILD_ID = "2026-04-08.txrx_stable_unified_pinned_output_v2_rx_enabled_default";

const _keepAliveBlocks = [];

function _keepAliveBlock(b, ttlMs) {
  try {
    if (!b) return;
    _keepAliveBlocks.push(b);
    const ms = Number(ttlMs || 30000) | 0;
    if (typeof setTimeout !== "function") return;
    setTimeout(function () {
      try {
        const i = _keepAliveBlocks.indexOf(b);
        if (i >= 0) _keepAliveBlocks.splice(i, 1);
      } catch (_) {}
    }, ms);
  } catch (_) {}
}

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

function _normalizePhoneE164Like(phoneStr) {
  try {
    const s0 = String(phoneStr || "").trim();
    if (!s0) return "";
    let s = s0.replace(/[^\d+]/g, "");
    if (!s) return "";
    if (s.startsWith("00")) s = "+" + s.slice(2);
    if (s.startsWith("+")) return "+" + s.slice(1).replace(/[^\d]/g, "");
    return "+" + s.replace(/[^\d]/g, "");
  } catch (_) {
    return "";
  }
}

function _writeOSContactNameByPhoneDigits(phoneDigits, fullName) {
  const out = { ok: false, attempted: false, error: "", matches: 0, chosenId: "", chosenGivenName: "", chosenFamilyName: "", usedPredicate: "", wroteGivenName: "", wroteFamilyName: "" };
  try {
    out.attempted = true;
    if (!ObjC.available) {
      out.error = "ObjC not available";
      return out;
    }
    const CNContactStore = ObjC.classes.CNContactStore;
    const CNContact = ObjC.classes.CNContact;
    const CNPhoneNumber = ObjC.classes.CNPhoneNumber;
    const CNSaveRequest = ObjC.classes.CNSaveRequest;
    const NSArray = ObjC.classes.NSArray;
    if (!CNContactStore || !CNContact || !CNPhoneNumber || !CNSaveRequest || !NSArray) {
      out.error = "Contacts.framework classes missing";
      return out;
    }
    if (!CNPhoneNumber.phoneNumberWithStringValue_) {
      out.error = "CNPhoneNumber.phoneNumberWithStringValue_ missing";
      return out;
    }
    const pn = CNPhoneNumber.phoneNumberWithStringValue_(_ns(String(phoneDigits || "")));
    if (!pn) {
      out.error = "CNPhoneNumber alloc failed";
      return out;
    }
    if (!CNContact.predicateForContactsMatchingPhoneNumber_) {
      out.error = "CNContact.predicateForContactsMatchingPhoneNumber_ missing";
      return out;
    }
    const pred = CNContact.predicateForContactsMatchingPhoneNumber_(pn);
    if (!pred) {
      out.error = "predicate nil";
      return out;
    }
    out.usedPredicate = "predicateForContactsMatchingPhoneNumber";
    const kId = _ns("identifier");
    const kGiven = _ns("givenName");
    const kFamily = _ns("familyName");
    if (!kId || !kGiven || !kFamily) {
      out.error = "NSString alloc failed for keys";
      return out;
    }
    const keys = NSArray.arrayWithObjects_(kId, kGiven, kFamily, ptr("0x0"));
    const store = CNContactStore.alloc().init();
    const errPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errPtr, ptr("0x0"));
    const contacts = _safeObj(store.unifiedContactsMatchingPredicate_keysToFetch_error_(pred, keys, errPtr));
    const errObj = _safeObj(Memory.readPointer(errPtr));
    if (!contacts) {
      out.error = errObj ? _safeDescValue(errObj) : "unifiedContactsMatchingPredicate returned nil";
      return out;
    }
    const count = Number(contacts.count());
    out.matches = count;
    if (count <= 0) {
      out.error = "no match";
      return out;
    }
    const c0 = _safeObj(contacts.objectAtIndex_(0));
    if (!c0) {
      out.error = "first contact nil";
      return out;
    }
    try {
      const idv = _safeObj(c0.identifier());
      if (idv) out.chosenId = String(idv);
    } catch (_) {}
    try {
      const gv = _safeObj(c0.givenName());
      if (gv) out.chosenGivenName = String(gv);
    } catch (_) {}
    try {
      const fv = _safeObj(c0.familyName());
      if (fv) out.chosenFamilyName = String(fv);
    } catch (_) {}
    const mc = _safeObj(c0.mutableCopy());
    if (!mc) {
      out.error = "mutableCopy nil";
      return out;
    }
    const newGiven = _ns(String(fullName || ""));
    if (!newGiven) {
      out.error = "NSString alloc failed for name";
      return out;
    }
    mc.setGivenName_(newGiven);
    mc.setFamilyName_(_ns(""));
    out.wroteGivenName = String(fullName || "");
    out.wroteFamilyName = "";
    const req = CNSaveRequest.alloc().init();
    req.updateContact_(mc);
    const errPtr2 = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errPtr2, ptr("0x0"));
    const ok = !!store.executeSaveRequest_error_(req, errPtr2);
    const errObj2 = _safeObj(Memory.readPointer(errPtr2));
    out.ok = ok;
    out.error = ok ? "" : (errObj2 ? _safeDescValue(errObj2) : "executeSaveRequest failed");
    return out;
  } catch (e) {
    out.ok = false;
    out.error = String(e);
    return out;
  }
}

function csabcncreatephone(phoneStr, givenNameStr) {
  try {
    if (!ObjC.available) return { ok: false, build: SCRIPT_BUILD_ID, error: "ObjC not available" };
    const phone = _normalizePhoneE164Like(phoneStr);
    const givenName = String(givenNameStr || "");
    if (!phone) return { ok: false, build: SCRIPT_BUILD_ID, error: "missing phone" };

    const CNContactStore = ObjC.classes.CNContactStore;
    const CNContact = ObjC.classes.CNContact;
    const CNPhoneNumber = ObjC.classes.CNPhoneNumber;
    const CNSaveRequest = ObjC.classes.CNSaveRequest;
    const CNMutableContact = ObjC.classes.CNMutableContact;
    const CNLabeledValue = ObjC.classes.CNLabeledValue;
    const NSArray = ObjC.classes.NSArray;
    const NSMutableArray = ObjC.classes.NSMutableArray;
    if (!CNContactStore || !CNContact || !CNPhoneNumber || !CNSaveRequest || !CNMutableContact || !CNLabeledValue || !NSArray || !NSMutableArray) {
      return { ok: false, build: SCRIPT_BUILD_ID, error: "Contacts.framework classes missing" };
    }
    if (!CNPhoneNumber.alloc || !CNPhoneNumber.alloc().initWithStringValue_) return { ok: false, build: SCRIPT_BUILD_ID, error: "CNPhoneNumber initWithStringValue missing", phone };
    const pn = CNPhoneNumber.alloc().initWithStringValue_(_ns(phone));
    if (!pn) return { ok: false, build: SCRIPT_BUILD_ID, error: "CNPhoneNumber alloc failed", phone };
    if (!CNContact.predicateForContactsMatchingPhoneNumber_) return { ok: false, build: SCRIPT_BUILD_ID, error: "predicate missing", phone };
    const pred = CNContact.predicateForContactsMatchingPhoneNumber_(pn);
    if (!pred) return { ok: false, build: SCRIPT_BUILD_ID, error: "predicate nil", phone };

    const kId = _ns("identifier");
    if (!kId) return { ok: false, build: SCRIPT_BUILD_ID, error: "NSString alloc failed for keys", phone };
    const keys = NSMutableArray.alloc().init();
    try { keys.addObject_(kId); } catch (_) {}
    const store = CNContactStore.alloc().init();

    const errPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errPtr, ptr("0x0"));
    const arr0 = store.unifiedContactsMatchingPredicate_keysToFetch_error_(pred, keys, errPtr);
    const errObj = _safeObj(Memory.readPointer(errPtr));
    const contacts = arr0 ? _safeObj(arr0) : null;
    if (!contacts) return { ok: false, build: SCRIPT_BUILD_ID, error: errObj ? _safeDescValue(errObj) : "query failed", phone };
    const count = Number(contacts.count());
    if (count > 0) {
      let identifier = "";
      try {
        const c0 = _safeObj(contacts.objectAtIndex_(0));
        const idv = c0 ? _safeObj(c0.identifier()) : null;
        if (idv) identifier = String(idv);
      } catch (_) {}
      return { ok: false, build: SCRIPT_BUILD_ID, error: "already exists", phone, existed: true, count, identifier };
    }

    const mc = CNMutableContact.alloc().init();
    if (!mc) return { ok: false, build: SCRIPT_BUILD_ID, error: "CNMutableContact alloc failed", phone };
    try { if (mc.setGivenName_) mc.setGivenName_(_ns(givenName)); } catch (_) {}
    try {
      const lv = CNLabeledValue.labeledValueWithLabel_value_(_ns("mobile"), pn);
      const phones = NSArray.arrayWithObject_(lv);
      if (mc.setPhoneNumbers_) mc.setPhoneNumbers_(phones);
    } catch (_) {}

    const req = CNSaveRequest.alloc().init();
    if (!req || !req.addContact_toContainerWithIdentifier_) return { ok: false, build: SCRIPT_BUILD_ID, error: "CNSaveRequest missing addContact", phone };
    req.addContact_toContainerWithIdentifier_(mc, ptr("0x0"));

    const errPtr2 = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errPtr2, ptr("0x0"));
    const ok = !!store.executeSaveRequest_error_(req, errPtr2);
    const errObj2 = _safeObj(Memory.readPointer(errPtr2));
    if (!ok) return { ok: false, build: SCRIPT_BUILD_ID, error: errObj2 ? _safeDescValue(errObj2) : "executeSaveRequest failed", phone };

    let identifier2 = "";
    try { const idv2 = _safeObj(mc.identifier()); if (idv2) identifier2 = String(idv2); } catch (_) {}
    return { ok: true, build: SCRIPT_BUILD_ID, phone, existed: false, saved: true, identifier: identifier2, givenName };
  } catch (e) {
    return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) };
  }
}

function csabcnupsertgivenphone(phoneStr, givenNameStr, phoneRawStr) {
  try {
    if (!ObjC.available) return { ok: false, build: SCRIPT_BUILD_ID, error: "ObjC not available" };
    const phone = _normalizePhoneE164Like(phoneStr);
    const givenName = String(givenNameStr || "");
    if (!phone) return { ok: false, build: SCRIPT_BUILD_ID, error: "missing phone" };
    const digits = phone.replace(/[^\d]/g, "");
    const phoneRaw = String(phoneRawStr || "").trim();
    let phoneForStore = phone;
    try {
      if (phoneRaw && digits) {
        const d2 = String(phoneRaw).replace(/[^\d]/g, "");
        if (d2 && d2 === digits && /[\s\-()]/.test(phoneRaw) && (/^\+/.test(phoneRaw) || /^00/.test(phoneRaw))) {
          phoneForStore = phoneRaw.startsWith("00") ? ("+" + phoneRaw.slice(2).trim()) : phoneRaw;
        }
      }
    } catch (_) {}
    try {
      if (phoneForStore === phone && phone.startsWith("+62") && !/[\s\-()]/.test(phone) && phone.length > 3) {
        phoneForStore = "+62 " + phone.slice(3);
      }
    } catch (_) {}

    const CNContactStore = ObjC.classes.CNContactStore;
    const CNContact = ObjC.classes.CNContact;
    const CNPhoneNumber = ObjC.classes.CNPhoneNumber;
    const CNSaveRequest = ObjC.classes.CNSaveRequest;
    const NSMutableArray = ObjC.classes.NSMutableArray;
    const NSArray = ObjC.classes.NSArray;
    const CNLabeledValue = ObjC.classes.CNLabeledValue;
    if (!CNContactStore || !CNContact || !CNPhoneNumber || !CNSaveRequest || !NSMutableArray || !NSArray || !CNLabeledValue) {
      return { ok: false, build: SCRIPT_BUILD_ID, error: "Contacts.framework classes missing" };
    }
    if (!CNPhoneNumber.alloc || !CNPhoneNumber.alloc().initWithStringValue_) return { ok: false, build: SCRIPT_BUILD_ID, error: "CNPhoneNumber initWithStringValue missing", phone };
    const pn = CNPhoneNumber.alloc().initWithStringValue_(_ns(phone));
    if (!pn) return { ok: false, build: SCRIPT_BUILD_ID, error: "CNPhoneNumber alloc failed", phone };
    if (!CNContact.predicateForContactsMatchingPhoneNumber_) return { ok: false, build: SCRIPT_BUILD_ID, error: "predicate missing", phone };
    const pred = CNContact.predicateForContactsMatchingPhoneNumber_(pn);
    if (!pred) return { ok: false, build: SCRIPT_BUILD_ID, error: "predicate nil", phone };

    const store = CNContactStore.alloc().init();
    const keys = NSMutableArray.alloc().init();
    try { keys.addObject_(_ns("identifier")); } catch (_) {}
    try { keys.addObject_(_ns("givenName")); } catch (_) {}
    try { keys.addObject_(_ns("familyName")); } catch (_) {}
    try { keys.addObject_(_ns("phoneNumbers")); } catch (_) {}

    const errPtr = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errPtr, ptr("0x0"));
    const arr0 = store.unifiedContactsMatchingPredicate_keysToFetch_error_(pred, keys, errPtr);
    const errObj = _safeObj(Memory.readPointer(errPtr));
    const arr = arr0 ? _safeObj(arr0) : null;
    if (!arr) return { ok: false, build: SCRIPT_BUILD_ID, error: errObj ? _safeDescValue(errObj) : "query failed", phone };
    const n = Number(arr.count());

    if (n <= 0) {
      const created = csabcncreatephone(phoneForStore, givenName);
      if (!created || !created.ok) return created || { ok: false, build: SCRIPT_BUILD_ID, error: "create failed", phone };
      return { ok: true, build: SCRIPT_BUILD_ID, phone, phoneForStore, existed: false, saved: true, identifier: String(created.identifier || ""), givenName };
    }

    const c0 = _safeObj(arr.objectAtIndex_(0));
    if (!c0) return { ok: false, build: SCRIPT_BUILD_ID, error: "first contact nil", phone };
    let identifier = "";
    let beforeGivenName = "";
    let beforePhone = "";
    try { const idv = _safeObj(c0.identifier()); if (idv) identifier = String(idv); } catch (_) {}
    try { const gv = _safeObj(c0.givenName()); if (gv) beforeGivenName = String(gv); } catch (_) {}
    try {
      if (c0.phoneNumbers && c0.phoneNumbers()) {
        const pns = _safeObj(c0.phoneNumbers());
        const pnCount = pns && pns.count ? Number(pns.count()) : 0;
        if (pnCount > 0) {
          const lv = _safeObj(pns.objectAtIndex_(0));
          const v = lv && lv.value ? _safeObj(lv.value()) : null;
          const sv = v && v.stringValue ? _safeObj(v.stringValue()) : null;
          if (sv) beforePhone = String(sv);
        }
      }
    } catch (_) {}
    const mc = _safeObj(c0.mutableCopy());
    if (!mc) return { ok: false, build: SCRIPT_BUILD_ID, error: "mutableCopy nil", phone, identifier };
    try { if (mc.setGivenName_) mc.setGivenName_(_ns(givenName)); } catch (_) {}
    try {
      const beforeDigits = String(beforePhone || "").replace(/[^\d]/g, "");
      if (phoneForStore !== phone && beforeDigits && beforeDigits === digits && /[\s\-()]/.test(phoneForStore)) {
        let label = _ns("mobile");
        try {
          if (c0.phoneNumbers && c0.phoneNumbers()) {
            const pns = _safeObj(c0.phoneNumbers());
            const pnCount = pns && pns.count ? Number(pns.count()) : 0;
            if (pnCount > 0) {
              const lv0 = _safeObj(pns.objectAtIndex_(0));
              const lb = lv0 && lv0.label ? _safeObj(lv0.label()) : null;
              if (lb) label = lb;
            }
          }
        } catch (_) {}
        const pnStore = CNPhoneNumber.alloc().initWithStringValue_(_ns(String(phoneForStore)));
        const lv2 = CNLabeledValue.labeledValueWithLabel_value_(label, pnStore);
        const phones2 = NSArray.arrayWithObject_(lv2);
        if (mc.setPhoneNumbers_) mc.setPhoneNumbers_(phones2);
      }
    } catch (_) {}

    const req = CNSaveRequest.alloc().init();
    if (!req || !req.updateContact_) return { ok: false, build: SCRIPT_BUILD_ID, error: "CNSaveRequest missing updateContact", phone, identifier };
    req.updateContact_(mc);

    const errPtr2 = Memory.alloc(Process.pointerSize);
    Memory.writePointer(errPtr2, ptr("0x0"));
    const ok = !!store.executeSaveRequest_error_(req, errPtr2);
    const errObj2 = _safeObj(Memory.readPointer(errPtr2));
    if (!ok) return { ok: false, build: SCRIPT_BUILD_ID, error: errObj2 ? _safeDescValue(errObj2) : "executeSaveRequest failed", phone, identifier };

    return { ok: true, build: SCRIPT_BUILD_ID, phone, phoneForStore, existed: true, saved: true, identifier, beforeGivenName, givenName, beforePhone };
  } catch (e) {
    return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) };
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
  fetchMessageWithAuthorSelector: "- fetchMessageWithStanzaID:authorUserJID:",
  fetchMessageWithParticipantSelector: "- fetchMessageWithStanzaID:participantUserJID:isFromMe:",
  fetchMessageWithContextSelector: "- fetchMessageWithStanzaID:isFromMe:context:",
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

function _resolveManagedObjectContext(core) {
  try {
    if (!ObjC.available) return null;
    if (!core || !core.ok) return null;
    const ctx = core.ctxMain;
    const st = core.storage;
    const isMoc = o => {
      try {
        if (!o) return false;
        const cn = String(o.$className || "");
        return cn.indexOf("NSManagedObjectContext") !== -1;
      } catch (_) {
        return false;
      }
    };
    const cands = ["managedObjectContext", "mainManagedObjectContext", "mainQueueContext", "viewContext", "context"];
    for (let i = 0; i < cands.length; i++) {
      const k = cands[i];
      const v1 = ctx ? RX_tryInvokeNoArg(ctx, k) : null;
      const o1 = v1 && v1.handle ? v1 : _safeObj(v1);
      if (o1 && isMoc(o1)) return o1;
      const v2 = st ? RX_tryInvokeNoArg(st, k) : null;
      const o2 = v2 && v2.handle ? v2 : _safeObj(v2);
      if (o2 && isMoc(o2)) return o2;
    }
    const pickIvarLike = obj => {
      try {
        if (!obj || !obj.$ivars) return null;
        const ks = Object.keys(obj.$ivars || {});
        for (let i = 0; i < ks.length; i++) {
          const k = ks[i];
          const kl = String(k || "").toLowerCase();
          if (kl.indexOf("managedobjectcontext") === -1 && kl.indexOf("mainqueuecontext") === -1 && kl.indexOf("viewcontext") === -1 && kl !== "context" && kl.indexOf("moc") === -1) continue;
          const v = _safeObj(obj.$ivars[k]);
          if (v && isMoc(v)) return v;
        }
      } catch (_) {}
      return null;
    };
    const iv1 = pickIvarLike(ctx);
    if (iv1) return iv1;
    const iv2 = pickIvarLike(st);
    if (iv2) return iv2;
    return null;
  } catch (_) {
    return null;
  }
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

function _fetchMessageByStanzaId(mcsObj, stanzaIdStr, participantJidStr, mocObj) {
  const mcs = mcsObj && mcsObj.handle ? mcsObj : _safeObj(mcsObj);
  if (!mcs) return null;
  const sid = String(stanzaIdStr || "").trim();
  if (!sid) return null;
  const nsSid = _ns(sid);
  if (!nsSid) return null;
  const pj = String(participantJidStr || "").trim();
  if (pj) {
    try {
      const author = _makeAuthorUserJIDFromString(pj);
      if (author && _objcCanCall(mcs, FIXED.fetchMessageWithAuthorSelector)) {
        try {
          const m2 = _safeObj(mcs[FIXED.fetchMessageWithAuthorSelector](nsSid, author));
          if (m2) return { msg: m2, via: "mcs.fetchMessageWithStanzaID:authorUserJID:" };
        } catch (_) {}
      }
      if (author && _objcCanCall(mcs, FIXED.fetchMessageWithParticipantSelector)) {
        const m0 = _safeObj(mcs[FIXED.fetchMessageWithParticipantSelector](nsSid, author, 0));
        if (m0) return { msg: m0, via: "mcs.fetchMessageWithStanzaID:participantUserJID:isFromMe:(0)" };
        const m1 = _safeObj(mcs[FIXED.fetchMessageWithParticipantSelector](nsSid, author, 1));
        if (m1) return { msg: m1, via: "mcs.fetchMessageWithStanzaID:participantUserJID:isFromMe:(1)" };
      }
    } catch (_) {}
  }
  if (_objcCanCall(mcs, FIXED.fetchMessageSelector)) {
    try {
      const m0 = _safeObj(mcs[FIXED.fetchMessageSelector](nsSid, 0));
      if (m0) return { msg: m0, via: "mcs.fetchMessageWithStanzaID:isFromMe:(0)" };
      const m1 = _safeObj(mcs[FIXED.fetchMessageSelector](nsSid, 1));
      if (m1) return { msg: m1, via: "mcs.fetchMessageWithStanzaID:isFromMe:(1)" };
    } catch (_) {}
  }
  const moc = mocObj && mocObj.handle ? mocObj : _safeObj(mocObj);
  if (moc && _objcCanCall(mcs, FIXED.fetchMessageWithContextSelector)) {
    try {
      const m0 = _safeObj(mcs[FIXED.fetchMessageWithContextSelector](nsSid, 0, moc));
      if (m0) return { msg: m0, via: "mcs.fetchMessageWithStanzaID:isFromMe:context:(0)" };
      const m1 = _safeObj(mcs[FIXED.fetchMessageWithContextSelector](nsSid, 1, moc));
      if (m1) return { msg: m1, via: "mcs.fetchMessageWithStanzaID:isFromMe:context:(1)" };
    } catch (_) {}
  }
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

function _sendTextCoreStatus(senderObj, mcsObj, nsTextObj, attachmentsObj, messageOrigin, creationEntryPoint, pend) {
  const sender = senderObj && senderObj.handle ? senderObj : _safeObj(senderObj);
  const cs = mcsObj && mcsObj.handle ? mcsObj : _safeObj(mcsObj);
  const nsText = nsTextObj && nsTextObj.handle ? nsTextObj : _safeObj(nsTextObj);
  const att = attachmentsObj && attachmentsObj.handle ? attachmentsObj : _safeObj(attachmentsObj);
  if (!sender || !cs || !nsText) return { ok: false, error: "sender/chatSession/text nil" };
  if (!_objcCanCall(sender, FIXED.sendTextSelector)) return { ok: false, error: "send selector missing" };
  let mo = Number.isFinite(Number(messageOrigin)) ? (Number(messageOrigin) | 0) : 1;
  let ep = Number.isFinite(Number(creationEntryPoint)) ? (Number(creationEntryPoint) | 0) : 1;
  if (!(mo > 0)) mo = 1;
  if (!(ep > 0)) ep = 1;

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
    ptr("0x0"),
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

function sendstatustext(text, messageOrigin, creationEntryPoint) {
  const pend = _pendingNew("status_text", "status@broadcast", 8000);
  const hk = _installMsgIdHook();
  if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "hook install failed" };
  const sch = _scheduleOnMainQueue(() => {
    try {
      const core = _resolveCoreFixed();
      if (!core || !core.ok) { pend.error = core ? core.error : "core failed"; return; }
      const nsText = _ns(text);
      if (!nsText) { pend.error = "text->NSString failed"; return; }
      const jid = _makeWAChatJIDFromString("status@broadcast");
      if (!jid) { pend.error = "WAChatJID parse failed"; return; }
      const cs = _fetchChatSession(core.storage, jid);
      if (!cs) { pend.error = "fetchChatSessionForJID returned nil"; return; }
      const mcs = _getMutableChatSession(cs);
      if (!mcs) { pend.error = "mutableChatSession returned nil"; return; }
      const att = _buildAttachmentsEmpty();
      if (!att) { pend.error = "build attachments failed"; return; }
      pend._keep = [nsText, att, mcs];
      _activePending = pend;
      _sendTextCoreStatus(core.sender, mcs, nsText, att, messageOrigin, creationEntryPoint, pend);
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
      const moc = _resolveManagedObjectContext(core);
      const fm = _fetchMessageByStanzaId(mcs, stanzaIdStr, participantJidStr, moc);
      if (!fm || !fm.msg) { pend.error = "fetchMessage returned nil"; return; }
      const msg = fm.msg;
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
  try { _chmod(String(imagePath || ""), 0o644); } catch (_) {}
  try { _setFileProtectionNone(String(imagePath || "")); } catch (_) {}
  const img = _uiImageFromFile(imagePath);
  if (!img) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "UIImage load failed" };
  const sendable = _buildImageSendablePinned(img);
  if (!sendable) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "UIImage not WAImageSendable" };
  const capText = String(captionText || "");
  const cap = capText ? _buildRichTextMaybe(capText) : null;
  if (capText && !cap) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "WARichText build failed" };
  if (!_objcCanCall(core.sender, FIXED.sendImageSelector)) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "send image selector missing" };
  const att = _buildAttachmentsEmpty();
  if (!att) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "build attachments failed" };
  const emptyArr = _nsArray0();
  if (!emptyArr) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "empty NSArray build failed" };
  const completion = _buildCompletionBlockCaptureMsgErr(pend);
  if (!completion) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "completion block create failed" };
  let mo = Number.isFinite(Number(messageOrigin)) ? (Number(messageOrigin) | 0) : 1;
  if (!(mo > 0)) mo = 1;
  pend._keep = [img, sendable, cap, mcs, att, emptyArr];
  pend._block_keep = completion;
  const sch = _scheduleOnMainQueue(() => {
    try {
      core.sender[FIXED.sendImageSelector](
        sendable,
        img,
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

function sendstatusimage(imagePath, captionText, messageOrigin) {
  const pend = _pendingNew("status_image", "status@broadcast", 20000);
  const hk = _installMsgIdHook();
  if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "hook install failed" };
  const coreRes = _runOnMainQueueSync(() => _resolveCoreFixed(), 2500);
  if (!coreRes || !coreRes.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: coreRes ? coreRes.error : "core failed" };
  const core = coreRes;
  const jid = _makeWAChatJIDFromString("status@broadcast");
  if (!jid) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "WAChatJID parse failed" };
  const cs = _runOnMainQueueSync(() => _fetchChatSession(core.storage, jid), 2500);
  if (!cs) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "fetchChatSessionForJID returned nil" };
  const mcs = _runOnMainQueueSync(() => _getMutableChatSession(cs), 2500);
  if (!mcs) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "mutableChatSession returned nil" };
  try { _chmod(String(imagePath || ""), 0o644); } catch (_) {}
  try { _setFileProtectionNone(String(imagePath || "")); } catch (_) {}
  const img = _uiImageFromFile(imagePath);
  if (!img) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "UIImage load failed" };
  const sendable = _buildImageSendablePinned(img);
  if (!sendable) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "UIImage not WAImageSendable" };
  const capText = String(captionText || "");
  const cap = capText ? _buildRichTextMaybe(capText) : null;
  if (capText && !cap) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "WARichText build failed" };
  if (!_objcCanCall(core.sender, FIXED.sendImageSelector)) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "send image selector missing" };
  const att = _buildAttachmentsEmpty();
  if (!att) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "build attachments failed" };
  const emptyArr = _nsArray0();
  if (!emptyArr) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "empty NSArray build failed" };
  const completion = _buildCompletionBlockCaptureMsgErr(pend);
  if (!completion) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "completion block create failed" };
  let mo = Number.isFinite(Number(messageOrigin)) ? (Number(messageOrigin) | 0) : 1;
  if (!(mo > 0)) mo = 1;
  pend._keep = [img, sendable, cap, mcs, att, emptyArr];
  pend._block_keep = completion;
  const sch = _scheduleOnMainQueue(() => {
    try {
      core.sender[FIXED.sendImageSelector](
        sendable,
        img,
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
  let mo = Number.isFinite(Number(messageOrigin)) ? (Number(messageOrigin) | 0) : 1;
  if (!(mo > 0)) mo = 1;
  pend._keep = [url, thumb, cap, mcs, att, emptyArr];
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

function sendstatusvideo(videoPath, captionText, thumbnailPath, messageOrigin) {
  const pend = _pendingNew("status_video", "status@broadcast", 30000);
  const hk = _installMsgIdHook();
  if (!hk || !hk.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: "hook install failed" };
  const coreRes = _runOnMainQueueSync(() => _resolveCoreFixed(), 2500);
  if (!coreRes || !coreRes.ok) return { ok: false, build: SCRIPT_BUILD_ID, stanzaId: "", error: coreRes ? coreRes.error : "core failed" };
  const core = coreRes;
  const jid = _makeWAChatJIDFromString("status@broadcast");
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
  let mo = Number.isFinite(Number(messageOrigin)) ? (Number(messageOrigin) | 0) : 1;
  if (!(mo > 0)) mo = 1;
  pend._keep = [url, thumb, cap, mcs, att, emptyArr];
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
  let p0 = String(audioPath || "").trim();
  try { _chmod(p0, 0o644); } catch (_) {}
  try { _setFileProtectionNone(p0); } catch (_) {}
  const ext0 = (function () { try { const s = p0.toLowerCase(); const i = s.lastIndexOf("."); return i >= 0 ? s.slice(i) : ""; } catch (_) { return ""; } })();
  if (ext0 === ".ogg" || ext0 === ".opus") {
    try {
      const tmp = _tmpPathForBasename("qqw_voice_" + String(Date.now()) + ".ogg");
      if (tmp) {
        const ok = _runOnMainQueueSync(() => {
          const NSFileManager = ObjC.classes.NSFileManager;
          if (!NSFileManager || !NSFileManager.defaultManager) return { ok: false, error: "NSFileManager missing" };
          const fm = NSFileManager.defaultManager();
          if (!fm || !fm["- copyItemAtPath:toPath:error:"]) return { ok: false, error: "copyItemAtPath missing" };
          const nsSrc = _ns(p0);
          const nsDst = _ns(tmp);
          if (!nsSrc || !nsDst) return { ok: false, error: "path->NSString failed" };
          const errp = Memory.alloc(Process.pointerSize);
          Memory.writePointer(errp, ptr("0x0"));
          try { if (fm["- fileExistsAtPath:"](nsDst)) { fm["- removeItemAtPath:error:"](nsDst, errp); } } catch (_) {}
          const r = !!fm["- copyItemAtPath:toPath:error:"](nsSrc, nsDst, errp);
          return { ok: r };
        }, 2500);
        if (ok && ok.ok) {
          p0 = String(tmp);
          try { _chmod(p0, 0o644); } catch (_) {}
          try { _setFileProtectionNone(p0); } catch (_) {}
        }
      }
    } catch (_) {}
  }
  const nsPath = _ns(p0);
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
  if (ext0 === ".ogg" || ext0 === ".opus") {
    try {
      const d2 = _audioDurationSecondsFromOggOpus(p0);
      if (Number.isFinite(Number(d2)) && Number(d2) > 0) dur = Math.ceil(Number(d2));
    } catch (_) {}
  } else if (!(dur > 0)) {
    try { dur = _audioDurationSecondsFromOggOpus(p0); } catch (_) { dur = 0; }
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

function csabsetgivennamejid(chatJidStr, givenNameStr, saveAfter) {
  try {
    if (!ObjC.available) return { ok: false, build: SCRIPT_BUILD_ID, error: "ObjC not available" };
    const chatJid = String(chatJidStr || "").trim();
    const givenName = String(givenNameStr || "");
    const doSave = (saveAfter === undefined) ? 1 : ((Number(saveAfter) | 0) ? 1 : 0);
    if (!chatJid) return { ok: false, build: SCRIPT_BUILD_ID, error: "missing chatJid" };

    const r = _runOnMainQueueSync(function () {
      const core = _resolveCoreFixed();
      if (!core || !core.ok) return { ok: false, build: SCRIPT_BUILD_ID, error: core ? core.error : "core failed" };
      const ctxMain = core.ctxMain;
      const chatManager = (_objcCanCall(ctxMain, "- chatManager")) ? _safeObj(ctxMain["- chatManager"]()) : null;
      if (!chatManager) return { ok: false, build: SCRIPT_BUILD_ID, error: "ctxMain.chatManager nil" };

      const jidObj = _makeAuthorUserJIDFromString(chatJid);
      if (!jidObj) return { ok: false, build: SCRIPT_BUILD_ID, error: "invalid chatJid" };
      const isLid = chatJid.indexOf("@lid") !== -1;

      let contactToSave = null;
      const mcsSel = "- mappedContactsStorage";
      const mcs = _objcCanCall(ctxMain, mcsSel) ? _safeObj(ctxMain[mcsSel]()) : null;
      if (mcs) {
        const s2 = isLid ? "- contactForLID:includeUnknownContacts:" : "- contactForJID:includeUnknownContacts:";
        const s1 = isLid ? "- contactForLID:" : "- contactForJID:";
        if (_objcCanCall(mcs, s2)) contactToSave = _safeObj(mcs[s2](jidObj, 1));
        if (!contactToSave && _objcCanCall(mcs, s1)) contactToSave = _safeObj(mcs[s1](jidObj));
      }
      if (!contactToSave) return { ok: false, build: SCRIPT_BUILD_ID, error: "contact not found", chatJid };

      const setGivenSel = "- setGivenName:";
      if (!_objcCanCall(contactToSave, setGivenSel)) return { ok: false, build: SCRIPT_BUILD_ID, error: "missing setGivenName:", chatJid };
      const beforeGiven = _objcCanCall(contactToSave, "- givenName") ? String(_safeObj(contactToSave["- givenName"]()) || "") : "";
      try { contactToSave[setGivenSel](_ns(givenName)); } catch (e) { return { ok: false, build: SCRIPT_BUILD_ID, error: "setGivenName failed: " + String(e), chatJid }; }
      const afterGiven = _objcCanCall(contactToSave, "- givenName") ? String(_safeObj(contactToSave["- givenName"]()) || "") : "";

      let saved = false;
      let saveError = "";
      if (doSave) {
        const saveSel = "- saveChangesInContact:originalContact:saveToOSAddressBook:completion:";
        if (!_objcCanCall(chatManager, saveSel)) return { ok: false, build: SCRIPT_BUILD_ID, error: "chatManager missing saveChangesInContact:*", chatJid };
        if (!_objcCanCall(contactToSave, "- copy")) return { ok: false, build: SCRIPT_BUILD_ID, error: "contact missing copy", chatJid };
        const originalContact = _safeObj(contactToSave["- copy"]());
        if (!originalContact) return { ok: false, build: SCRIPT_BUILD_ID, error: "contact copy nil", chatJid };
        try { chatManager[saveSel](contactToSave, originalContact, 0, ptr("0x0")); saved = true; } catch (e) { saved = false; saveError = String(e); }
      }

      let osId = "";
      try {
        const osIdSel = "- osAddressBookContactID";
        const osIdObj = _objcCanCall(contactToSave, osIdSel) ? _safeObj(contactToSave[osIdSel]()) : null;
        osId = osIdObj ? String(osIdObj) : "";
      } catch (_) {}

      let osSaved = null;
      let osBefore = "";
      let osAfter = "";
      let osError = "";
      if (osId && doSave) {
        try {
          const CNContactStore = ObjC.classes.CNContactStore;
          const CNSaveRequest = ObjC.classes.CNSaveRequest;
          const NSMutableArray = ObjC.classes.NSMutableArray;
          if (CNContactStore && CNSaveRequest && NSMutableArray) {
            const store = CNContactStore.alloc().init();
            const keys = NSMutableArray.alloc().init();
            try { keys.addObject_(_ns("givenName")); } catch (_) {}
            const errPtr = Memory.alloc(Process.pointerSize);
            Memory.writePointer(errPtr, ptr("0x0"));
            const cn0 = store.unifiedContactWithIdentifier_keysToFetch_error_(_ns(osId), keys, errPtr);
            const eobj = _safeObj(Memory.readPointer(errPtr));
            const cn = cn0 ? _safeObj(cn0) : null;
            if (cn) {
              try { osBefore = String(_safeObj(cn.givenName()) || "") || ""; } catch (_) {}
              const m = _safeObj(cn.mutableCopy());
              try { if (m && m.setGivenName_) m.setGivenName_(_ns(givenName)); } catch (_) {}
              const req = CNSaveRequest.alloc().init();
              if (req && req.updateContact_) {
                req.updateContact_(m);
                const err2 = Memory.alloc(Process.pointerSize);
                Memory.writePointer(err2, ptr("0x0"));
                const ok2 = !!store.executeSaveRequest_error_(req, err2);
                const e2 = _safeObj(Memory.readPointer(err2));
                osSaved = ok2;
                if (e2) osError = _safeDescValue(e2);
                Memory.writePointer(errPtr, ptr("0x0"));
                const cn1 = store.unifiedContactWithIdentifier_keysToFetch_error_(_ns(osId), keys, errPtr);
                const cnAfter = cn1 ? _safeObj(cn1) : null;
                if (cnAfter) {
                  try { osAfter = String(_safeObj(cnAfter.givenName()) || "") || ""; } catch (_) {}
                }
              } else {
                osSaved = false;
                osError = "CNSaveRequest missing updateContact:";
              }
            } else {
              osSaved = false;
              osError = eobj ? _safeDescValue(eobj) : "CNContact nil";
            }
          }
        } catch (e) {
          osSaved = false;
          osError = String(e);
        }
      }

      return { ok: true, build: SCRIPT_BUILD_ID, chatJid, beforeGivenName: beforeGiven, afterGivenName: afterGiven, saved: !!saved, saveError, osAddressBookContactID: osId, osSaved, osBeforeGivenName: osBefore, osAfterGivenName: osAfter, osSaveError: osError };
    }, 8000);
    return r && r.ok !== undefined ? r : { ok: false, build: SCRIPT_BUILD_ID, error: (r && r.error) ? r.error : "failed" };
  } catch (e) {
    return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) };
  }
}

function csabsetgivennamejid_writecontext(chatJidStr, givenNameStr, saveToOSAddressBook) {
  try {
    if (!ObjC.available) return { ok: false, build: SCRIPT_BUILD_ID, error: "ObjC not available" };
    const targetJidStr = String(chatJidStr || "").trim();
    if (!targetJidStr) return { ok: false, build: SCRIPT_BUILD_ID, error: "missing chatJid" };
    const givenName = String(givenNameStr || "");
    const doSyncOS = (saveToOSAddressBook === undefined) ? 1 : ((Number(saveToOSAddressBook) | 0) ? 1 : 0);

    const core = _runOnMainQueueSync(() => _resolveCoreFixed(), 2500);
    if (!core || !core.ok) return { ok: false, build: SCRIPT_BUILD_ID, error: core ? String(core.error || "core failed") : "core failed" };
    const ctxMain = core.ctxMain;
    const chatManager = (_objcCanCall(ctxMain, "- chatManager")) ? _safeObj(ctxMain["- chatManager"]()) : null;

    const getIvar = (obj, keys) => {
      try {
        const o = obj && obj.handle ? obj : _safeObj(obj);
        if (!o || !o.$ivars) return null;
        for (let i = 0; i < keys.length; i++) {
          const k = keys[i];
          try {
            const v = _safeObj(o.$ivars[k]);
            if (v) return v;
          } catch (_) {}
        }
      } catch (_) {}
      return null;
    };
    const getPropOrIvar = (owner, selNoArg, ivarKeys) => {
      try {
        const o = owner && owner.handle ? owner : _safeObj(owner);
        if (!o) return null;
        if (selNoArg && _objcCanCall(o, selNoArg)) {
          const v = _safeObj(o[selNoArg]());
          if (v) return v;
        }
        const iv = getIvar(o, ivarKeys || []);
        if (iv) return iv;
      } catch (_) {}
      return null;
    };

    const cs = getPropOrIvar(ctxMain, "- contactsStorage", ["_contactsStorage", "contactsStorage"])
      || getPropOrIvar(chatManager, "- contactsStorage", ["_contactsStorage", "contactsStorage"])
      || getIvar(ctxMain, ["_contactsManager", "contactsManager"]);
    const csq = getPropOrIvar(ctxMain, "- contactsStorageQueries", ["_contactsStorageQueries", "contactsStorageQueries"])
      || getPropOrIvar(chatManager, "- contactsStorageQueries", ["_contactsStorageQueries", "contactsStorageQueries"]);
    const contactsStorage = (cs && cs.handle && String(cs.$className || "").indexOf("Contacts") !== -1) ? cs : getPropOrIvar(cs, "- contactsStorage", ["_contactsStorage", "contactsStorage"]) || cs;
    if (!contactsStorage) return { ok: false, build: SCRIPT_BUILD_ID, error: "contactsStorage missing" };
    if (!csq) return { ok: false, build: SCRIPT_BUILD_ID, error: "contactsStorageQueries missing" };

    const wc = getIvar(contactsStorage, ["_writeContext", "writeContext"]) || getPropOrIvar(contactsStorage, "- writeContext", ["_writeContext", "writeContext"]);
    if (!wc) return { ok: false, build: SCRIPT_BUILD_ID, error: "contactsStorage writeContext missing" };
    if (!_objcCanCall(wc, "- performBlockAndWait:") || !ObjC.Block) return { ok: false, build: SCRIPT_BUILD_ID, error: "writeContext missing performBlockAndWait:" };

    const jidObj = (function () {
      try {
        const s = String(targetJidStr || "").trim();
        if (!s) return null;
        const ns = _ns(s);
        if (!ns) return null;
        const WAUserJID = ObjC.classes.WAUserJID;
        const WAJID = ObjC.classes.WAJID;
        let o = null;
        if (WAUserJID) {
          if (_objcCanCall(WAUserJID, "+ jidOrLIDWithString:")) o = _safeObj(WAUserJID["+ jidOrLIDWithString:"](ns));
          else if (_objcCanCall(WAUserJID, "+ withString:")) o = _safeObj(WAUserJID["+ withString:"](ns));
          else if (_objcCanCall(WAUserJID, "+ withJIDString:")) o = _safeObj(WAUserJID["+ withJIDString:"](ns));
          else if (_objcCanCall(WAUserJID, "+ userJIDWithString:")) o = _safeObj(WAUserJID["+ userJIDWithString:"](ns));
          else if (_objcCanCall(WAUserJID, "+ jidWithString:")) o = _safeObj(WAUserJID["+ jidWithString:"](ns));
        }
        if (!o && WAJID && _objcCanCall(WAJID, "+ withString:")) o = _safeObj(WAJID["+ withString:"](ns));
        if (!o) o = _makeAuthorUserJIDFromString(s);
        return o || null;
      } catch (_) {
        return null;
      }
    })();
    if (!jidObj) return { ok: false, build: SCRIPT_BUILD_ID, error: "invalid chatJid" };

    const out = {
      ok: false,
      build: SCRIPT_BUILD_ID,
      chatJid: targetJidStr,
      givenName: givenName,
      saveToOSAddressBook: doSyncOS,
      osAddressBookContactID: "",
      osSaved: null,
      osSaveError: "",
      beforeGivenName: "",
      afterGivenName: ""
    };

    let result = null;
    const blk = new ObjC.Block({
      retType: "void",
      argTypes: [],
      implementation: function () {
        let pool = null;
        try { pool = ObjC.classes.NSAutoreleasePool.alloc().init(); } catch (_) { pool = null; }
        try {
          const preferred = _ns("");
          let ab0 = null;
          const isLid = targetJidStr.toLowerCase().endsWith("@lid");
          const sL = "- addressBookContactForLID:preferredFullName:";
          const sJ = "- addressBookContactForJID:preferredFullName:";
          if (isLid && _objcCanCall(csq, sL)) {
            try { ab0 = _safeObj(csq[sL](jidObj, preferred)); } catch (_) { ab0 = null; }
          }
          if (!ab0 && _objcCanCall(csq, sJ)) {
            try { ab0 = _safeObj(csq[sJ](jidObj, preferred)); } catch (_) { ab0 = null; }
          }
          const ab = ab0 ? (ab0 instanceof ObjC.Object ? ab0 : new ObjC.Object(ab0)) : null;
          if (!ab) { result = { ok: false, error: "addressBookContactFor* returned nil" }; return; }

          let uid = "";
          try {
            if (_objcCanCall(ab, "- uniqueID")) uid = String(_safeObj(ab["- uniqueID"]()) || "");
            else if (_objcCanCall(ab, "- persistedUniqueID")) uid = String(_safeObj(ab["- persistedUniqueID"]()) || "");
          } catch (_) {}
          if (!uid) { result = { ok: false, error: "uniqueID empty" }; return; }

          const fetchSel = "- fetchAddressBookContactsForUniqueIDs:inContext:filteringPredicate:";
          if (!_objcCanCall(contactsStorage, fetchSel)) { result = { ok: false, error: "contactsStorage missing fetchAddressBookContactsForUniqueIDs" }; return; }
          const NSArray = ObjC.classes.NSArray;
          if (!NSArray || !_objcCanCall(NSArray, "+ arrayWithObject:")) { result = { ok: false, error: "NSArray missing arrayWithObject" }; return; }
          const uids = NSArray.arrayWithObject_(_ns(uid));
          const dict0 = _safeObj(contactsStorage[fetchSel](uids, wc, ptr("0x0")));
          if (!dict0) { result = { ok: false, error: "fetch returned nil dict" }; return; }
          if (!_objcCanCall(dict0, "- objectForKey:")) { result = { ok: false, error: "dict missing objectForKey" }; return; }
          const vv = _safeObj(dict0["- objectForKey:"](_ns(uid)));
          const c = vv ? (vv instanceof ObjC.Object ? vv : new ObjC.Object(vv)) : null;
          if (!c) { result = { ok: false, error: "dict missing value for uniqueID" }; return; }

          try {
            const osIdSel = "- osAddressBookContactID";
            if (_objcCanCall(c, osIdSel)) out.osAddressBookContactID = String(_safeObj(c[osIdSel]()) || "");
          } catch (_) {}

          try { if (_objcCanCall(c, "- givenName")) out.beforeGivenName = String(_safeObj(c["- givenName"]()) || ""); } catch (_) {}
          if (!_objcCanCall(c, "- setGivenName:")) { result = { ok: false, error: "missing setGivenName:" }; return; }
          try { c["- setGivenName:"](_ns(givenName)); } catch (e) { result = { ok: false, error: "set failed: " + String(e) }; return; }
          try { if (_objcCanCall(c, "- givenName")) out.afterGivenName = String(_safeObj(c["- givenName"]()) || ""); } catch (_) {}

          if (_objcCanCall(wc, "- save:")) {
            const errPtr = Memory.alloc(Process.pointerSize);
            Memory.writePointer(errPtr, ptr("0x0"));
            const okSave = !!wc["- save:"](errPtr);
            const eobj = _safeObj(Memory.readPointer(errPtr));
            out.saved = okSave;
            if (eobj) out.saveError = String(eobj);
          }
          result = { ok: true };
        } finally {
          try { if (pool) pool.release(); } catch (_) {}
        }
      }
    });

    wc["- performBlockAndWait:"](blk);

    if (result && result.ok && doSyncOS && out.osAddressBookContactID) {
      try {
        const CNContactStore = ObjC.classes.CNContactStore;
        const CNSaveRequest = ObjC.classes.CNSaveRequest;
        const NSMutableArray = ObjC.classes.NSMutableArray;
        if (CNContactStore && CNSaveRequest && NSMutableArray) {
          const store = CNContactStore.alloc().init();
          const keys = NSMutableArray.alloc().init();
          try { keys.addObject_(_ns("givenName")); } catch (_) {}
          try { keys.addObject_(_ns("familyName")); } catch (_) {}
          try { keys.addObject_(_ns("nickname")); } catch (_) {}
          const errPtr = Memory.alloc(Process.pointerSize);
          Memory.writePointer(errPtr, ptr("0x0"));
          const cn0 = store.unifiedContactWithIdentifier_keysToFetch_error_(_ns(out.osAddressBookContactID), keys, errPtr);
          const eobj = _safeObj(Memory.readPointer(errPtr));
          const cn = cn0 ? _safeObj(cn0) : null;
          if (cn) {
            const m = _safeObj(cn.mutableCopy());
            try { if (m && m.setGivenName_) m.setGivenName_(_ns(givenName)); } catch (_) {}
            const req = CNSaveRequest.alloc().init();
            if (req && req.updateContact_) {
              req.updateContact_(m);
              const err2 = Memory.alloc(Process.pointerSize);
              Memory.writePointer(err2, ptr("0x0"));
              const okSave = !!store.executeSaveRequest_error_(req, err2);
              const e2 = _safeObj(Memory.readPointer(err2));
              out.osSaved = okSave;
              if (e2) out.osSaveError = String(e2);
            } else {
              out.osSaved = false;
              out.osSaveError = "CNSaveRequest missing updateContact:";
            }
          } else {
            out.osSaved = false;
            out.osSaveError = eobj ? _safeDescValue(eobj) : "CNContact nil";
          }
        } else {
          out.osSaved = false;
          out.osSaveError = "Contacts.framework classes missing";
        }
      } catch (e) {
        out.osSaved = false;
        out.osSaveError = String(e);
      }
    }

    out.ok = !!(result && result.ok);
    return out;
  } catch (e) {
    return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) };
  }
}

rpc.exports = {
  entries,
  waitready,
  sendtext,
  sendquotetext,
  sendimage,
  sendvideo,
  sendaudio,
  sendstatustext,
  sendstatusimage,
  sendstatusvideo,
  notifycontactstoredidchange: _contactsNotifyContactStoreDidChange,
  csabsetgivennamejidwc: csabsetgivennamejid_writecontext,
  statusposttext(text, messageOrigin, creationEntryPoint) {
    let mo = Number(messageOrigin);
    let ep = Number(creationEntryPoint);
    if (!(mo > 0)) mo = 1;
    if (!(ep > 0)) ep = 1;
    return sendstatustext(String(text || ""), mo | 0, ep | 0);
  },
  statuspostimage(imagePath, captionText, messageOrigin) {
    let mo = Number(messageOrigin);
    if (!(mo > 0)) mo = 1;
    return sendstatusimage(String(imagePath || ""), String(captionText || ""), mo | 0);
  },
  statuspostvideo(videoPath, captionText, messageOrigin) {
    let mo = Number(messageOrigin);
    if (!(mo > 0)) mo = 1;
    return sendstatusvideo(String(videoPath || ""), String(captionText || ""), "", mo | 0);
  },
  avatarurl,
  selfnameactive,
  selfcard,
  makeread(jid, stanzaId, participantJid, timeoutMs) {
    try {
      const j = String(jid || "").trim();
      const sid = String(stanzaId || "").trim();
      const pj = String(participantJid || "").trim();
      if (!j || !sid) return { ok: false, build: SCRIPT_BUILD_ID, error: "missing jid/stanzaId" };
      const res = _runOnMainQueueSync(() => RX_markMessageReadByStanzaId(j, sid, pj), Math.max(500, Number(timeoutMs) || 5000));
      if (res && res.ok) return { ok: true, build: SCRIPT_BUILD_ID, jid: j, stanzaId: sid, participantJid: pj, used: String(res.used || ""), fetchVia: String(res.fetchVia || "") };
      return { ok: false, build: SCRIPT_BUILD_ID, jid: j, stanzaId: sid, participantJid: pj, error: res && res.error ? String(res.error) : "failed", used: String(res && res.used ? res.used : ""), fetchVia: String(res && res.fetchVia ? res.fetchVia : "") };
    } catch (e) {
      return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) };
    }
  },
  markread(jid, stanzaId, participantJid, timeoutMs) {
    return rpc.exports.makeread(jid, stanzaId, participantJid, timeoutMs);
  },
  autoreadstats() {
    try { return { ok: true, build: SCRIPT_BUILD_ID, stats: RX_AUTO_READ_STATS }; } catch (e) { return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) }; }
  },
  autoreadreset() {
    try {
      RX_AUTO_READ_STATS.recv = 0;
      RX_AUTO_READ_STATS.filtered = 0;
      RX_AUTO_READ_STATS.filtered_reason = {};
      RX_AUTO_READ_STATS.scheduled = 0;
      RX_AUTO_READ_STATS.attempts = 0;
      RX_AUTO_READ_STATS.ok = 0;
      RX_AUTO_READ_STATS.fail = 0;
      RX_AUTO_READ_STATS.fail_reason = {};
      RX_AUTO_READ_STATS.last = null;
      return { ok: true, build: SCRIPT_BUILD_ID };
    } catch (e) {
      return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) };
    }
  },
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
  sampleseton(meta) {
    try {
      const o = (typeof meta === "string") ? JSON.parse(meta) : (meta || {});
      RX_SAMPLE.enabled = true;
      RX_SAMPLE.msg_kind = String(o.msg_kind || o.msgKind || RX_SAMPLE.msg_kind || "unknown");
      RX_SAMPLE.quoted_kind = String(o.quoted_kind || o.quotedKind || RX_SAMPLE.quoted_kind || "none");
      RX_SAMPLE.quoted_stanza_id = String(o.quoted_stanza_id || o.quotedStanzaId || RX_SAMPLE.quoted_stanza_id || "");
      return { ok: true, build: SCRIPT_BUILD_ID, enabled: true, sample: RX_SAMPLE };
    } catch (e) {
      return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) };
    }
  },
  sampleset(msg_kind, quoted_kind, quoted_stanza_id) {
    try {
      RX_SAMPLE.enabled = true;
      RX_SAMPLE.msg_kind = String(msg_kind || "unknown");
      RX_SAMPLE.quoted_kind = String(quoted_kind || "none");
      RX_SAMPLE.quoted_stanza_id = String(quoted_stanza_id || "");
      return { ok: true, build: SCRIPT_BUILD_ID, enabled: true, sample: RX_SAMPLE };
    } catch (e) {
      return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) };
    }
  },
  sampleoff() {
    RX_SAMPLE.enabled = false;
    RX_SAMPLE.msg_kind = "unknown";
    RX_SAMPLE.quoted_kind = "none";
    RX_SAMPLE.quoted_stanza_id = "";
    return { ok: true, build: SCRIPT_BUILD_ID, enabled: false };
  },
  csabcncreatephone,
  csabcnupsertgivenphone,
  csabsetgivennamejid,
};

function _txEmitResult(opId, kind, jid, res, extraErr, mediaRef) {
  try {
    const ok = !!(res && res.ok);
    const stanzaId = res && res.stanzaId ? String(res.stanzaId) : "";
    const err = ok ? "" : String((res && res.error) ? res.error : (extraErr ? extraErr : "failed"));
    const retryable = !!(res && res.retryable);
    const errorCode = res && res.errorCode ? String(res.errorCode) : "";
    const out = {
      type: "wa.tx.send.result",
      build: SCRIPT_BUILD_ID,
      ts: Date.now(),
      op_id: String(opId || ""),
      opId: String(opId || ""),
      kind: String(kind || ""),
      jid: String(jid || ""),
      ok: ok,
      stanzaId: stanzaId,
      error: err,
      retryable: retryable,
      errorCode: errorCode
    };
    try {
      if (mediaRef && typeof mediaRef === "object") {
        out.mediaRef = mediaRef;
      }
    } catch (_) {}
    send(out);
  } catch (_) {}
}

function _toUrlString(obj) {
  try {
    if (obj === null || obj === undefined) return "";
    const o = obj && obj.handle ? obj : _safeObj(obj);
    if (!o) return "";
    try {
      const s1 = String(o["absoluteString"] ? o["absoluteString"]() : (o["- absoluteString"] ? o["- absoluteString"]() : "")).trim();
      if (s1.startsWith("http://") || s1.startsWith("https://")) return s1;
    } catch (_) {}
    try {
      const s2 = String(o).trim();
      if (s2.startsWith("http://") || s2.startsWith("https://")) return s2;
      return s2;
    } catch (_) {
      return "";
    }
  } catch (_) {
    return "";
  }
}

function _getProfilePictureManagerFromCtx(ctxMain) {
  try {
    const ctx = ctxMain && ctxMain.handle ? ctxMain : _safeObj(ctxMain);
    if (!ctx) return null;
    if (_objcCanCall(ctx, "profilePictureManager")) {
      const v = _safeObj(ctx["profilePictureManager"]());
      if (v) return v;
    }
    try {
      if (ctx.$ivars) {
        const keys = Object.keys(ctx.$ivars || {});
        for (let i = 0; i < keys.length; i++) {
          const k = keys[i];
          const kl = String(k || "").toLowerCase();
          if (kl.indexOf("profilepicture") === -1 && kl.indexOf("profile_picture") === -1) continue;
          const v = _safeObj(ctx.$ivars[k]);
          if (v) return v;
        }
      }
    } catch (_) {}
  } catch (_) {}
  return null;
}

function _makeAnyJIDFromString(jidStr) {
  const s = String(jidStr || "").trim();
  if (!s || s.indexOf("@") === -1) return null;
  const ns = _ns(s);
  if (!ns) return null;
  try {
    const WAUserJID = ObjC.classes.WAUserJID;
    if (WAUserJID) {
      if (WAUserJID["+ jidOrLIDWithString:"]) {
        const r0 = _safeObj(WAUserJID.jidOrLIDWithString_(ns));
        if (r0) return r0;
      }
      if (WAUserJID["+ withString:"]) {
        const r1 = _safeObj(WAUserJID.withString_(ns));
        if (r1) return r1;
      }
      if (WAUserJID["+ withJIDString:"]) {
        const r2 = _safeObj(WAUserJID.withJIDString_(ns));
        if (r2) return r2;
      }
      if (WAUserJID["+ userJIDWithString:"]) {
        const r3 = _safeObj(WAUserJID.userJIDWithString_(ns));
        if (r3) return r3;
      }
      if (WAUserJID["+ jidWithString:"]) {
        const r4 = _safeObj(WAUserJID.jidWithString_(ns));
        if (r4) return r4;
      }
    }
  } catch (_) {}
  try {
    const WAJID = ObjC.classes.WAJID;
    if (WAJID && _objcCanCall(WAJID, "+ ifValidWithStringRepresentation:")) {
      const r = _safeObj(WAJID["+ ifValidWithStringRepresentation:"](ns));
      if (r) return r;
    }
  } catch (_) {}
  try {
    const isLid = s.indexOf("@lid") !== -1;
    const cls = isLid ? ObjC.classes.WALIDUserJID : ObjC.classes.WAUserJID;
    if (cls && _objcCanCall(cls, "+ ifValidWithStringRepresentation:")) {
      const r = _safeObj(cls["+ ifValidWithStringRepresentation:"](ns));
      if (r) return r;
    }
  } catch (_) {}
  return null;
}

function avatarurl(jid, fullSize, timeoutMsOpt) {
  if (!ObjC.available) return { ok: false, build: SCRIPT_BUILD_ID, jid: String(jid || "").trim(), url: "", error: "objc_unavailable" };
  const target = String(jid || "").trim();
  if (!target) return { ok: false, build: SCRIPT_BUILD_ID, jid: "", url: "", error: "jid required" };
  const timeoutMs = Number.isFinite(timeoutMsOpt) ? (timeoutMsOpt | 0) : 20000;
  const deadlineMs = Date.now() + Math.max(1500, timeoutMs);
  const core = _runOnMainQueueSync(() => _resolveCoreFixed(), 2500);
  if (!core || !core.ok) return { ok: false, build: SCRIPT_BUILD_ID, jid: target, url: "", error: core ? core.error : "no context" };
  const ppm = _getProfilePictureManagerFromCtx(core.ctxMain);
  if (!ppm) return { ok: false, build: SCRIPT_BUILD_ID, jid: target, url: "", error: "profilePictureManager nil" };
  const jidObj = _makeAnyJIDFromString(target);
  if (!jidObj) return { ok: false, build: SCRIPT_BUILD_ID, jid: target, url: "", error: "invalid jid" };
  let idpObj = jidObj;
  try {
    if (_objcHasSelector(jidObj, "profilePictureJID")) {
      const pjid = _objcCallNoArg(jidObj, "profilePictureJID");
      if (pjid) idpObj = pjid;
    }
  } catch (_) {}

  const selDirectPath = "MAIN_APP_requestBusinessProfilePictureDirectPathForIdentifierProviding:completion:";
  let directPath = "";
  let invokeErr = "";
  let done = false;

  let completion = null;
  try {
    completion = new ObjC.Block({
      retType: "void",
      argTypes: ["pointer", "pointer"],
      implementation: function (p0, _p1) {
        try {
          let s = "";
          try { if (p0 && !p0.isNull()) s = String(new ObjC.Object(p0)); } catch (_) { s = ""; }
          directPath = String(s || "").trim();
          done = true;
        } catch (_) {
          done = true;
        }
      }
    });
  } catch (e) {
    return { ok: false, build: SCRIPT_BUILD_ID, jid: target, url: "", error: "ObjC.Block unavailable: " + String(e) };
  }

  try {
    _runOnMainQueueSync(() => {
      try {
        const f = ppm[selDirectPath];
        if (typeof f === "function") {
          f.call(ppm, idpObj, completion);
          return true;
        }
        const pMsg = Module.findExportByName(null, "objc_msgSend");
        const pSelReg = Module.findExportByName("libobjc.A.dylib", "sel_registerName") || Module.findExportByName(null, "sel_registerName");
        if (!pMsg || !pSelReg) {
          invokeErr = "objc_msgSend/sel_registerName not found";
          return true;
        }
        const msgSend = new NativeFunction(pMsg, "void", ["pointer", "pointer", "pointer", "pointer"]);
        const selRegisterName = new NativeFunction(pSelReg, "pointer", ["pointer"]);
        const sel = selRegisterName(Memory.allocUtf8String(selDirectPath));
        const a1 = idpObj && idpObj.handle ? idpObj.handle : idpObj;
        const a2 = completion && completion.handle ? completion.handle : completion;
        msgSend(ppm.handle, sel, a1, a2);
        return true;
      } catch (e) {
        invokeErr = String(e);
        return true;
      }
    }, 2500);
  } catch (e) {
    invokeErr = String(e);
  }

  if (invokeErr) return { ok: false, build: SCRIPT_BUILD_ID, jid: target, url: "", error: "directPath invoke error: " + invokeErr };

  while (!done && Date.now() < deadlineMs) {
    Thread.sleep(0.03);
  }
  if (!directPath) return { ok: false, build: SCRIPT_BUILD_ID, jid: target, url: "", error: done ? "directPath empty" : "directPath timeout" };
  const url = directPath.startsWith("http://") || directPath.startsWith("https://") ? directPath : ("https://pps.whatsapp.net" + (directPath.startsWith("/") ? directPath : ("/" + directPath)));
  return { ok: true, build: SCRIPT_BUILD_ID, jid: target, url: url, fullSize: !!fullSize };
}

function _extractDigits(s) {
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

function _derivePhoneFromJid(jid) {
  try {
    const s = String(jid || "").trim();
    if (!s) return "";
    const at = s.indexOf("@");
    const left = at >= 0 ? s.slice(0, at) : s;
    if (!left) return "";
    if (left.startsWith("a_")) return _extractDigits(left.slice(2));
    const d = _extractDigits(left);
    return d.length >= 8 ? d : "";
  } catch (_) {
    return "";
  }
}

function _objcHasSelector(o, sel) {
  try {
    if (!ObjC.available || !o) return false;
    const s = String(sel || "").trim();
    if (!s) return false;
    return _objcCanCall(o, s) || _objcCanCall(o, "- " + s) || _objcCanCall(o, "+ " + s);
  } catch (_) {
    return false;
  }
}

function _objcCallNoArg(o, sel) {
  try {
    if (!ObjC.available || !o) return null;
    const s = String(sel || "").trim();
    if (!s) return null;
    if (_objcCanCall(o, s)) return _safeObj(o[s]());
    if (_objcCanCall(o, "- " + s)) return _safeObj(o["- " + s]());
    if (_objcCanCall(o, "+ " + s)) return _safeObj(o["+ " + s]());
  } catch (_) {}
  return null;
}

function _objcCallNoArgString(o, sel) {
  try {
    const v = _objcCallNoArg(o, sel);
    return String(v || "").trim();
  } catch (_) {
    return "";
  }
}

function _normalizeJidString(s) {
  try {
    let v = String(s || "").trim();
    if (!v) return "";
    if (v[0] === "<" && v[v.length - 1] === ">") v = v.slice(1, -1).trim();
    if (!v) return "";
    if (v.indexOf("*") !== -1) return "";
    if (v.indexOf("@") === -1) return "";
    if (v.length > 128) return "";
    return v;
  } catch (_) {
    return "";
  }
}

function _extractJidStringFromMaybeObj(x) {
  try {
    if (x === null || x === undefined) return "";
    if (!ObjC.available) return _normalizeJidString(String(x || ""));
    const o = x instanceof ObjC.Object ? x : new ObjC.Object(x);
    if (!o) return "";
    try {
      const uj = _objcCallNoArg(o, "userJID");
      if (uj) {
        const s0 = _objcCallNoArgString(uj instanceof ObjC.Object ? uj : new ObjC.Object(uj), "stringRepresentation");
        const n0 = _normalizeJidString(s0);
        if (n0) return n0;
      }
    } catch (_) {}
    try {
      const dj = _objcCallNoArg(o, "deviceJID");
      if (dj) {
        const djObj = dj instanceof ObjC.Object ? dj : new ObjC.Object(dj);
        const uj = _objcCallNoArg(djObj, "userJID");
        if (uj) {
          const s0 = _objcCallNoArgString(uj instanceof ObjC.Object ? uj : new ObjC.Object(uj), "stringRepresentation");
          const n0 = _normalizeJidString(s0);
          if (n0) return n0;
        }
      }
    } catch (_) {}
    const s1 = _normalizeJidString(_objcCallNoArgString(o, "stringRepresentation"));
    if (s1) return s1;
    const sJid = _normalizeJidString(_objcCallNoArgString(o, "jid"));
    if (sJid) return sJid;
    const sJid2 = _normalizeJidString(_objcCallNoArgString(o, "jidString"));
    if (sJid2) return sJid2;
    const s2 = _normalizeJidString(String(o).trim());
    return s2;
  } catch (_) {
    try { return _normalizeJidString(String(x || "").trim()); } catch (_) { return ""; }
  }
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

function _extractPhoneFromMaybeObj(x) {
  try {
    if (x === null || x === undefined) return "";
    const s0 = String(x).trim();
    const d0 = _extractDigits(s0);
    if (d0.length >= 8) return d0;
    if (!ObjC.available) return "";
    const o = x instanceof ObjC.Object ? x : new ObjC.Object(x);
    if (!o) return "";
    const cands = ["phoneNumber", "rawPhoneNumber", "nationalNumber", "number"];
    for (let i = 0; i < cands.length; i++) {
      const sel = cands[i];
      if (!_objcHasSelector(o, sel)) continue;
      const v = _objcCallNoArgString(o, sel);
      const d = _extractDigits(v);
      if (d.length >= 8) return d;
    }
  } catch (_) {}
  return "";
}

function _scanIvarsForHints(obj, tags) {
  const out = { jid: "", phone: "", username: "", name: "" };
  try {
    if (!ObjC.available || !obj || !obj.$ivars) return out;
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
        if (s) out.jid = s;
      }
      if (!out.phone && (kl.indexOf("phone") !== -1 || kl.indexOf("msisdn") !== -1)) {
        const p = _extractPhoneFromMaybeObj(v);
        if (p) out.phone = p;
      }
      if (!out.username && kl.indexOf("username") !== -1) {
        const u = _cleanMaybeUsername(v);
        if (u) out.username = u;
      }
      if (!out.name && (kl.indexOf("name") !== -1 || kl.indexOf("profilename") !== -1)) {
        const n = String(v).trim();
        if (n && n.length <= 64) out.name = n;
      }
      if (out.jid && out.phone && out.username && out.name) break;
    }
  } catch (_) {}
  return out;
}

function selfnameactive() {
  if (!ObjC.available) return { ok: false, build: SCRIPT_BUILD_ID, selfJid: "", selfName: "", selfUsername: "", phone: "", error: "objc_unavailable" };
  const core = _runOnMainQueueSync(() => _resolveCoreFixed(), 2500);
  if (!core || !core.ok) return { ok: false, build: SCRIPT_BUILD_ID, selfJid: "", selfName: "", selfUsername: "", phone: "", error: core ? core.error : "no context" };
  const ctx = core.ctxMain;
  let selfName = "";
  try {
    const helpers = ObjC.classes.WAProfileNameHelpers;
    const sel = "currentProfileNameWithUseDeviceNameIfNeeded:userContext:";
    if (helpers && helpers["+ " + sel]) {
      selfName = String(helpers["+ " + sel](1, ctx) || "").trim();
    }
  } catch (_) {}
  let selfJid = "";
  let selfUsername = "";
  let phone = "";
  try {
    if (!selfJid || !phone || !selfUsername) {
      const h = _scanIvarsForHints(ctx, ["jid", "userjid", "phone", "msisdn", "username"]);
      if (!selfJid && h.jid) {
        selfJid = h.jid;
        phone = _derivePhoneFromJid(selfJid) || phone;
      }
      if (!phone && h.phone) phone = h.phone;
      if (!selfUsername && h.username) selfUsername = h.username;
      if (!selfName && h.name) selfName = h.name;
    }
  } catch (_) {}
  const probes = [];
  probes.push({ obj: ctx, tag: "ctx" });
  try {
    if (_objcHasSelector(ctx, "messageSender")) {
      const sender = _objcCallNoArg(ctx, "messageSender");
      if (sender) probes.push({ obj: sender, tag: "messageSender" });
    }
  } catch (_) {}
  try {
    if (_objcHasSelector(ctx, "accountService")) {
      const as = _objcCallNoArg(ctx, "accountService");
      if (as) probes.push({ obj: as, tag: "accountService" });
    }
  } catch (_) {}
  try {
    if (_objcHasSelector(ctx, "accountProvider")) {
      const ap = _objcCallNoArg(ctx, "accountProvider");
      if (ap) probes.push({ obj: ap, tag: "accountProvider" });
    }
  } catch (_) {}
  try {
    if (_objcHasSelector(ctx, "ownUserJIDFetcher")) {
      const f = _objcCallNoArg(ctx, "ownUserJIDFetcher");
      if (f) probes.push({ obj: f, tag: "ownUserJIDFetcher" });
    }
  } catch (_) {}
  const jidSelectors = ["ownUserJID", "userJID", "currentUserJID", "myUserJID", "deviceJID"];
  const nameSelectors = ["currentUserName", "currentProfileName", "profileName", "displayName", "pushName", "name"];
  const usernameSelectors = ["currentUserUsername", "username", "currentUsername", "userName"];
  for (let pi = 0; pi < probes.length; pi++) {
    const o = probes[pi].obj;
    if (!o) continue;
    try {
      if (!selfJid || !phone || !selfUsername) {
        const h = _scanIvarsForHints(o, ["jid", "userjid", "phone", "msisdn", "username"]);
        if (!selfJid && h.jid) {
          selfJid = h.jid;
          phone = _derivePhoneFromJid(selfJid) || phone;
        }
        if (!phone && h.phone) phone = h.phone;
        if (!selfUsername && h.username) selfUsername = h.username;
        if (!selfName && h.name) selfName = h.name;
      }
    } catch (_) {}
    try {
      if (!selfJid) {
        for (let si = 0; si < jidSelectors.length; si++) {
          const sel = jidSelectors[si];
          if (!_objcHasSelector(o, sel)) continue;
          const jidStr = _extractJidStringFromMaybeObj(_objcCallNoArg(o, sel));
          if (jidStr) {
            selfJid = jidStr;
            phone = _derivePhoneFromJid(jidStr) || phone;
            break;
          }
        }
      }
    } catch (_) {}
    try {
      if (!selfUsername) {
        for (let si = 0; si < usernameSelectors.length; si++) {
          const sel = usernameSelectors[si];
          if (!_objcHasSelector(o, sel)) continue;
          const v = _cleanMaybeUsername(_objcCallNoArgString(o, sel));
          if (v) {
            selfUsername = v;
            break;
          }
        }
      }
    } catch (_) {}
    try {
      if (!selfName) {
        for (let si = 0; si < nameSelectors.length; si++) {
          const sel = nameSelectors[si];
          if (!_objcHasSelector(o, sel)) continue;
          const v = String(_objcCallNoArgString(o, sel) || "").trim();
          if (v) {
            selfName = v;
            break;
          }
        }
      }
    } catch (_) {}
    if (selfJid && phone && selfName && selfUsername) break;
  }
  if (!phone) phone = _derivePhoneFromJid(selfJid);
  return { ok: true, build: SCRIPT_BUILD_ID, selfJid: selfJid, selfName: selfName, selfUsername: selfUsername, phone: phone };
}

function selfcard() {
  const h = selfnameactive();
  if (!h || !h.ok) return { ok: false, build: SCRIPT_BUILD_ID, selfCard: null, error: h && h.error ? String(h.error) : "selfname failed" };
  const selfJid = String(h.selfJid || "").trim();
  if (!selfJid) return { ok: false, build: SCRIPT_BUILD_ID, selfCard: null, error: "selfJid empty" };
  const a = avatarurl(selfJid, false, 20000);
  const avatarUrl = a && a.ok ? String(a.url || "").trim() : "";
  const err = (a && !a.ok) ? String(a.error || "avatarurl failed") : "";
  const selfUsername = _cleanMaybeUsername(String(h.selfUsername || "").trim());
  return {
    ok: true,
    build: SCRIPT_BUILD_ID,
    selfCard: {
      selfJid: selfJid,
      selfName: String(h.selfName || "").trim(),
      selfUsername: selfUsername,
      phone: String(h.phone || "").trim(),
      avatarUrl: avatarUrl
    },
    error: err
  };
}

function _avatarEmitResult(opId, jid, res, extraErr) {
  try {
    const ok = !!(res && res.ok);
    const url = res && res.url ? String(res.url) : "";
    const err = ok ? "" : String((res && res.error) ? res.error : (extraErr ? extraErr : "failed"));
    send({
      type: "wa.tx.avatar_url.result",
      build: SCRIPT_BUILD_ID,
      ts: Date.now(),
      op_id: String(opId || ""),
      opId: String(opId || ""),
      jid: String(jid || ""),
      ok: ok,
      avatarUrl: url,
      error: err
    });
  } catch (_) {}
}

function _avatarHandleMsg(message) {
  const p = message && message.payload ? message.payload : (message || {});
  const opId = String(p.opId || p.op_id || "");
  const jid = String(p.jid || p.chatJid || "");
  const fullSize = !!(p.fullSize || p.fullsize || p.isFullSized || p.full);
  if (!opId || !jid) {
    _avatarEmitResult(opId, jid, { ok: false, url: "", error: "missing opId/jid" }, null);
    return;
  }
  try { waitready(); } catch (_) {}
  try {
    const timeoutMs = Number(p.timeoutMs || 20000) | 0;
    const res = avatarurl(jid, fullSize, timeoutMs);
    _avatarEmitResult(opId, jid, res, null);
  } catch (e) {
    _avatarEmitResult(opId, jid, { ok: false, url: "", error: String(e) }, null);
  }
}

function _avatarLoop() {
  recv("qqw.avatar_url", function (message) {
    try { _avatarHandleMsg(message); } catch (_) {}
    _avatarLoop();
  }).wait();
}

try { setImmediate(_avatarLoop); } catch (_) {}

function _selfCardEmitResult(opId, res, extraErr) {
  try {
    const ok = !!(res && res.ok);
    const selfCard = (res && res.selfCard) ? res.selfCard : null;
    const err = String((res && res.error) ? res.error : (extraErr ? extraErr : ""));
    send({
      type: "wa.tx.self_card.result",
      build: SCRIPT_BUILD_ID,
      ts: Date.now(),
      op_id: String(opId || ""),
      opId: String(opId || ""),
      ok: ok,
      selfCard: selfCard,
      error: err
    });
  } catch (_) {}
}

function _selfCardHandleMsg(message) {
  const p = message && message.payload ? message.payload : (message || {});
  const opId = String(p.opId || p.op_id || "");
  if (!opId) {
    _selfCardEmitResult(opId, { ok: false, selfCard: null, error: "missing opId" }, null);
    return;
  }
  try { waitready(); } catch (_) {}
  try {
    const res = selfcard();
    _selfCardEmitResult(opId, res, null);
  } catch (e) {
    _selfCardEmitResult(opId, { ok: false, selfCard: null, error: String(e) }, null);
  }
}

function _selfCardLoop() {
  recv("qqw.self_card", function (message) {
    try { _selfCardHandleMsg(message); } catch (_) {}
    _selfCardLoop();
  }).wait();
}

try { setImmediate(_selfCardLoop); } catch (_) {}

function _contactsNoteEmitResult(opId, chatJid, contactPhoneJid, phoneDigits, res, extraErr) {
  try {
    const ok = !!(res && res.ok);
    const status = String((res && res.status) ? res.status : (ok ? "ok" : "failed"));
    const err = ok ? "" : String((res && res.error) ? res.error : (extraErr ? extraErr : "failed"));
    send({
      type: "wa.tx.contact_note_upsert.result",
      build: SCRIPT_BUILD_ID,
      ts: Date.now(),
      opId: String(opId || ""),
      op_id: String(opId || ""),
      chatJid: String(chatJid || ""),
      contactPhoneJid: String(contactPhoneJid || ""),
      phoneDigits: String(phoneDigits || ""),
      ok: ok,
      status: status,
      error: err,
      waOk: !!(res && res.waOk),
      osOk: !!(res && res.osOk)
    });
  } catch (_) {}
}

const ENABLE_CONTACTS_STORAGE_FETCH = true;
const ENABLE_SAFE_CONTACTS_STORAGE_FETCH = true;
const ENABLE_CN_DIRECT_WRITE = false;
const ENABLE_DELAYED_READ_6000MS = false;

function _contactsNoteUpsertFullNameOnMain(p) {
  if (1) {
  const opId = String((p && (p.opId || p.op_id)) ? (p.opId || p.op_id) : "").trim();
  const chatJid = String((p && p.chatJid) ? p.chatJid : "").trim();
  const contactPhoneJid = String((p && p.contactPhoneJid) ? p.contactPhoneJid : "").trim();
  const phoneDigits = String((p && p.phoneDigits) ? p.phoneDigits : "").trim();
  const noteText = String((p && p.noteText) ? p.noteText : "").trim();
  const saveToOSAddressBook = (p && p.saveToOSAddressBook !== undefined) ? ((Number(p.saveToOSAddressBook) | 0) ? 1 : 0) : 1;
  if (!chatJid || !phoneDigits) {
    return { ok: false, status: "failed", error: "missing chatJid/phoneDigits", waOk: false, osOk: false };
  }

  const r = csabsetgivennamejid_writecontext(chatJid, noteText, saveToOSAddressBook);
  const waOk = !!(r && r.ok);
  let osSaved = !!(r && r.osSaved === true);
  let osMethod = "";
  let osErr = String((r && r.osSaveError) ? r.osSaveError : "");
  try {
    if (r && r.osAddressBookContactID) osMethod = "id";
    else osMethod = "id_missing";
  } catch (_) {}
  let osFallback = null;
  try {
    if (saveToOSAddressBook && (!osSaved || osMethod === "id_missing")) {
      osFallback = csabcnupsertgivenphone("+" + phoneDigits, noteText);
      if (osFallback && osFallback.ok) {
        osSaved = true;
        osMethod = "phone";
        osErr = "";
      } else if (!osErr) {
        osErr = String((osFallback && osFallback.error) ? osFallback.error : "failed");
        osMethod = (osMethod === "id_missing") ? "id_missing+phone_failed" : "id+phone_failed";
      }
    }
  } catch (e) {
    if (!osErr) osErr = String(e);
    osMethod = (osMethod === "id_missing") ? "id_missing+phone_exception" : "id+phone_exception";
  }
  const osOk = saveToOSAddressBook ? !!osSaved : true;
  const ok = waOk && osOk;
  const status = ok ? "success" : (waOk ? "wa_only" : "failed");
  const error = ok ? "" : String((r && r.error) ? r.error : (waOk ? ("os=" + (osErr || "failed") + " method=" + (osMethod || "")) : "failed"));
  return {
    ok: ok,
    status: status,
    error: error,
    opId: opId,
    chatJid: chatJid,
    contactPhoneJid: contactPhoneJid,
    phoneDigits: phoneDigits,
    noteText: noteText,
    saveToOSAddressBook: saveToOSAddressBook,
    waOk: waOk,
    osOk: osOk,
    debug: Object.assign({}, r || {}, { osMethod: osMethod, osFallback: osFallback })
  };
  }
  const core = _resolveCoreFixed();
  if (!core || !core.ok) return { ok: false, status: "failed", error: core ? core.error : "core failed" };
  const ctxMain = core.ctxMain;
  const chatManager = (_objcCanCall(ctxMain, "- chatManager")) ? _safeObj(ctxMain["- chatManager"]()) : null;
  if (!chatManager) return { ok: false, status: "failed", error: "ctxMain.chatManager nil" };

  const opId = String((p && (p.opId || p.op_id)) ? (p.opId || p.op_id) : "");
  const chatJid = String(p.chatJid || "");
  const contactPhoneJid = String(p.contactPhoneJid || "");
  const targetFullName = String(p.noteText || "");
  const saveToOSAddressBook = (p && p.saveToOSAddressBook !== undefined) ? ((Number(p.saveToOSAddressBook) | 0) ? 1 : 0) : 1;
  const preferLid = (chatJid && chatJid.indexOf("@lid") !== -1) ? chatJid : "";
  const preferPn = contactPhoneJid || "";
  const prefer = (saveToOSAddressBook && preferPn) ? preferPn : (preferLid || preferPn);
  if (!prefer) return { ok: false, status: "failed", error: "missing chatJid/contactPhoneJid" };
  const isLid = prefer.indexOf("@lid") !== -1;
  let debug = {};
  let contactToSave = null;
  let fetchSel = "";
  let retrSel = "";
  let abPropsFrom = "";
  let abPropsClass = "";
  let altPn = null;
  let altPnFetchSel = "";
  let mcsFetchFrom = null;

  if (!contactToSave) {
    const pickRetriever = () => {
      const out = {
        ok: false,
        retriever: null,
        retrSel: "",
        abPropsFrom: "",
        abPropsClass: "",
        debug: {}
      };

      const retrSels = [
        "- username_contact_lid_based_retrieving",
        "- username_contact_lid_based_retrieving_usync"
      ];

      const abPropsSel = "- abProperties";
      const ucSel = "- userContext";

      const cands = [
        { k: "ctxMain.abProperties", owner: ctxMain, viaUserContext: false },
        { k: "ctxMain.userContext.abProperties", owner: ctxMain, viaUserContext: true },
        { k: "chatManager.userContext.abProperties", owner: chatManager, viaUserContext: true }
      ];

      for (let i = 0; i < cands.length; i++) {
        const c = cands[i];
        const o0 = c.owner && c.owner.handle ? c.owner : _safeObj(c.owner);
        const ownerClass = o0 ? String(o0.$className || "") : "";
        out.debug[c.k] = { ownerClassName: ownerClass, hasUserContext: false, userContextClass: "", hasAbProperties: false, abPropsClass: "", retrSels: {} };
        if (!o0) continue;

        let owner2 = o0;
        if (c.viaUserContext) {
          out.debug[c.k].hasUserContext = _objcCanCall(owner2, ucSel);
          if (!out.debug[c.k].hasUserContext) continue;
          const uc = _safeObj(owner2[ucSel]());
          out.debug[c.k].userContextClass = uc ? String(uc.$className || "") : "";
          if (!uc) continue;
          owner2 = uc;
        }

        out.debug[c.k].hasAbProperties = _objcCanCall(owner2, abPropsSel);
        if (!out.debug[c.k].hasAbProperties) continue;
        const ab = _safeObj(owner2[abPropsSel]());
        out.debug[c.k].abPropsClass = ab ? String(ab.$className || "") : "";
        if (!ab) continue;

        for (let si = 0; si < retrSels.length; si++) {
          const rs = retrSels[si];
          const hasSel = _objcCanCall(ab, rs);
          out.debug[c.k].retrSels[rs] = { hasSel: hasSel, retrieverNil: true };
          if (!hasSel) continue;
          const r = _safeObj(ab[rs]());
          out.debug[c.k].retrSels[rs].retrieverNil = !r;
          if (!r) continue;
          out.ok = true;
          out.retriever = r;
          out.retrSel = rs;
          out.abPropsFrom = c.k;
          out.abPropsClass = out.debug[c.k].abPropsClass;
          return out;
        }
      }
      return out;
    };

    const picked = pickRetriever();
    const retriever = (picked && picked.ok) ? picked.retriever : null;
    retrSel = (picked && picked.ok) ? picked.retrSel : "";
    abPropsFrom = (picked && picked.ok) ? picked.abPropsFrom : "";
    abPropsClass = (picked && picked.ok) ? picked.abPropsClass : "";
    if (picked && picked.debug) debug = Object.assign({}, debug, picked.debug);

    if (retriever) {
      const jidObj = _makeAuthorUserJIDFromString(prefer);
      const retrFetchSel = isLid ? "- contactForLID:includeUnknownContacts:" : "- contactForJID:includeUnknownContacts:";
      debug.uiLike = debug.uiLike || {};
      debug.uiLike.retrFetchSel = retrFetchSel;
      debug.uiLike.includeUnknown = 0;
      debug.uiLike.retrSel = retrSel;
      debug.uiLike.abPropsFrom = abPropsFrom;
      if (_objcCanCall(retriever, retrFetchSel) && jidObj) {
        const c = _safeObj(retriever[retrFetchSel](jidObj, 0));
        if (c) {
          contactToSave = c;
          fetchSel = retrFetchSel;
        } else {
          debug.uiLike.retrieverReturnedNil = true;
        }
      } else {
        debug.uiLike.retrieverMissingSelOrJid = true;
      }
    }
  }

  const mcsSel = "- mappedContactsStorage";
  const mcsHasSel = _objcCanCall(ctxMain, mcsSel);
  debug["ctxMain.mappedContactsStorage"] = { className: "WAContextMain", hasSel: mcsHasSel, storageNil: true, storageClass: "", fetchSels: {} };
  if (mcsHasSel) {
    const mcs = _safeObj(ctxMain[mcsSel]());
    debug["ctxMain.mappedContactsStorage"].storageNil = !mcs;
    debug["ctxMain.mappedContactsStorage"].storageClass = mcs ? String(mcs.$className || "") : "";
    if (mcs) {
      const includeUnknown = 0;
      const fetchFrom = (jidStr) => {
        const u = _makeAuthorUserJIDFromString(jidStr);
        if (!u) return { c: null, usedSel: "" };
        const isL = jidStr.indexOf("@lid") !== -1;
        const s2 = isL ? "- contactForLID:includeUnknownContacts:" : "- contactForJID:includeUnknownContacts:";
        const has2 = _objcCanCall(mcs, s2);
        debug["ctxMain.mappedContactsStorage"].fetchSels[s2] = debug["ctxMain.mappedContactsStorage"].fetchSels[s2] || { hasSel: has2, contactNil: true };
        debug["ctxMain.mappedContactsStorage"].fetchSels[s2].hasSel = has2;
        if (has2) {
          const c2 = _safeObj(mcs[s2](u, includeUnknown));
          debug["ctxMain.mappedContactsStorage"].fetchSels[s2].contactNil = !c2;
          if (c2) return { c: c2, usedSel: s2 };
        }
        const s1 = isL ? "- contactForLID:" : "- contactForJID:";
        const has1 = _objcCanCall(mcs, s1);
        debug["ctxMain.mappedContactsStorage"].fetchSels[s1] = debug["ctxMain.mappedContactsStorage"].fetchSels[s1] || { hasSel: has1, contactNil: true };
        debug["ctxMain.mappedContactsStorage"].fetchSels[s1].hasSel = has1;
        if (has1) {
          const c1 = _safeObj(mcs[s1](u));
          debug["ctxMain.mappedContactsStorage"].fetchSels[s1].contactNil = !c1;
          if (c1) return { c: c1, usedSel: s1 };
        }
        return { c: null, usedSel: "" };
      };
      mcsFetchFrom = fetchFrom;

      if (saveToOSAddressBook && preferPn) {
        const rpn0 = fetchFrom(preferPn);
        altPn = rpn0.c;
        altPnFetchSel = rpn0.usedSel;
        if (rpn0.c) {
          contactToSave = rpn0.c;
          fetchSel = rpn0.usedSel;
          retrSel = "ctxMain.mappedContactsStorage." + rpn0.usedSel;
          abPropsFrom = "ctxMain.mappedContactsStorage";
          abPropsClass = "";
        }
      }
      if (!contactToSave && preferLid) {
        const r = fetchFrom(preferLid);
        if (r.c) {
          contactToSave = r.c;
          fetchSel = r.usedSel;
          retrSel = "ctxMain.mappedContactsStorage." + r.usedSel;
          abPropsFrom = "ctxMain.mappedContactsStorage";
          abPropsClass = "";
        }
      }
    }
  }

  if (!contactToSave) {
    return {
      ok: false,
      status: "failed",
      error: "no contact fetch path available",
      retrSel: retrSel,
      debug: debug
    };
  }

  let wrapperClass = String(contactToSave.$className || "");

  try {
    debug.osab = debug.osab || {};
    debug.osab.altPn = { hasAlt: !!altPn, fetchSel: String(altPnFetchSel || ""), osAddressBookContactID: "" };
    if (altPn) {
      const osIdSelAlt = "- osAddressBookContactID";
      if (_objcCanCall(altPn, osIdSelAlt)) {
        const v = _safeObj(altPn[osIdSelAlt]());
        if (v) debug.osab.altPn.osAddressBookContactID = String(v);
      }
    }
  } catch (_) {}

  if (!_objcCanCall(contactToSave, "- copy")) {
    return { ok: false, status: "failed", error: "contact missing copy", fetchSel: fetchSel, retrSel: retrSel, abPropsFrom: abPropsFrom, abPropsClass: abPropsClass, debug: debug, prefer: prefer, wrapperClass: wrapperClass };
  }
  let originalContact = _safeObj(contactToSave["- copy"]());
  if (!originalContact) {
    return { ok: false, status: "failed", error: "contact copy returned nil", fetchSel: fetchSel, retrSel: retrSel, abPropsFrom: abPropsFrom, abPropsClass: abPropsClass, debug: debug, prefer: prefer, wrapperClass: wrapperClass };
  }

  try {
    if (saveToOSAddressBook) {
      debug.osab = debug.osab || {};
      debug.osab.abSync = debug.osab.abSync || { attempted: false, hasAbSync: false, abSyncClass: "", hasFetch: false, hasObjectForKey: false, fetched: false, uid: "", gotProxy: false, proxyClass: "", error: "", via: "" };
      debug.osab.abSync.attempted = true;
      const abSyncSel = "- addressBookSynchronizer";
      debug.osab.abSync.hasAbSync = _objcCanCall(chatManager, abSyncSel);
      if (debug.osab.abSync.hasAbSync) {
        const abSync = _safeObj(chatManager[abSyncSel]());
        debug.osab.abSync.abSyncClass = abSync ? String(abSync.$className || "") : "";
        const ucSel = "- userContext";
        const hasUc = _objcCanCall(chatManager, ucSel);
        const uc = hasUc ? _safeObj(chatManager[ucSel]()) : null;
        const puSel = "- persistedUniqueID";
        const hasPuid = _objcCanCall(contactToSave, puSel);
        const puidObj = hasPuid ? _safeObj(contactToSave[puSel]()) : null;
        const puid = puidObj ? String(puidObj) : "";
        debug.osab.abSync.uid = puid;
        const fetchSel2 = "- fetchAddressBookContactsForUniqueIDs:inContext:filteringPredicate:";

        let csCtxMain = null;
        let csChatManager = null;
        try {
          const csSel = "- contactsStorage";
          if (_objcCanCall(ctxMain, csSel)) csCtxMain = _safeObj(ctxMain[csSel]());
          if (_objcCanCall(chatManager, csSel)) csChatManager = _safeObj(chatManager[csSel]());
        } catch (_) {}

      try {
        debug.osab.abSync.fetchOwnerCandidates = [];
        const addCand = (label, obj) => {
          try {
            if (!obj) return;
            debug.osab.abSync.fetchOwnerCandidates.push({
              label: String(label || ""),
              className: String(obj.$className || ""),
              hasFetch: _objcCanCall(obj, fetchSel2),
              hasCDM: _objcCanCall(obj, "- contactsDownloadManager"),
              hasMainMoc: _objcCanCall(obj, "- mainManagedObjectContext"),
              hasMoc: _objcCanCall(obj, "- managedObjectContext")
            });
          } catch (_) {}
        };
        addCand("chatManager", chatManager);
        addCand("chatManager.userContext", uc);
        addCand("chatManager.addressBookSynchronizer", abSync);
        addCand("ctxMain", ctxMain);
        addCand("ctxMain.contactsStorage", csCtxMain);
        const csqSel = "- contactsStorageQueries";
        if (_objcCanCall(ctxMain, csqSel)) addCand("ctxMain.contactsStorageQueries", _safeObj(ctxMain[csqSel]()));
        addCand("chatManager.contactsStorage", csChatManager);
        if (_objcCanCall(chatManager, csqSel)) addCand("chatManager.contactsStorageQueries", _safeObj(chatManager[csqSel]()));
      } catch (_) {}

        const tryFetchFrom = (owner, ownerLabel, inContext) => {
          try {
            if (!owner || !puidObj) return null;
            if (!inContext) return null;
            const can = _objcCanCall(owner, fetchSel2);
            if (!can) return null;
            const arr = ObjC.classes.NSArray.arrayWithObject_(puidObj);
            const dict = _safeObj(owner[fetchSel2](arr, inContext, ptr("0x0")));
            if (!dict) return null;
            if (!_objcCanCall(dict, "- objectForKey:")) return null;
            const proxy = _safeObj(dict["- objectForKey:"](puidObj));
            if (!proxy) return null;
            return { ownerLabel, proxy, dict };
          } catch (_) {
            return null;
          }
        };

        const tryFetchFromContactsStorageSafe = (csObj, ownerLabel) => {
          try {
            if (!csObj || !puidObj) return null;
            if (!_objcCanCall(csObj, "- managedObjectContext")) return null;
            const moc = _safeObj(csObj["- managedObjectContext"]());
            debug.osab.abSync.csMoc = debug.osab.abSync.csMoc || {};
            debug.osab.abSync.csMoc[ownerLabel] = { nil: !moc, className: moc ? String(moc.$className || "") : "" };
            if (!moc) return null;
            const pbwSel = "- performBlockAndWait:";
            const hasPBW = _objcCanCall(moc, pbwSel);
            debug.osab.abSync.csMoc[ownerLabel].hasPerformBlockAndWait = !!hasPBW;
            if (!hasPBW || !ObjC.Block) return null;

            let outProxy = null;
            let outProxyClass = "";
            let outProxyHasCopy = false;
            let outErr = "";
            const blk = new ObjC.Block({
              retType: "void",
              argTypes: [],
              implementation: function () {
                try {
                  if (!_objcCanCall(csObj, fetchSel2)) return;
                  const arr = ObjC.classes.NSArray.arrayWithObject_(puidObj);
                  const dict = _safeObj(csObj[fetchSel2](arr, moc, ptr("0x0")));
                  if (!dict) return;
                  if (!_objcCanCall(dict, "- objectForKey:")) return;
                  const proxy = _safeObj(dict["- objectForKey:"](puidObj));
                  if (!proxy) return;
                  outProxyClass = String(proxy.$className || "");
                  outProxyHasCopy = _objcCanCall(proxy, "- copy");
                  if (outProxyHasCopy) {
                    outProxy = _safeObj(proxy["- copy"]());
                  } else {
                    outProxy = proxy;
                  }
                } catch (e) {
                  outErr = String(e);
                }
              }
            });
            _keepAliveBlock(blk, 15000);
            moc[pbwSel](blk);
            if (!outProxy) {
              debug.osab.abSync.csMoc[ownerLabel].fetchError = outErr;
              return null;
            }
            debug.osab.abSync.csMoc[ownerLabel].proxyClass = outProxyClass;
            debug.osab.abSync.csMoc[ownerLabel].proxyHasCopy = outProxyHasCopy;
            return { ownerLabel, proxy: outProxy, dict: null };
          } catch (e) {
            try {
              debug.osab.abSync.csMoc = debug.osab.abSync.csMoc || {};
              debug.osab.abSync.csMoc[ownerLabel] = debug.osab.abSync.csMoc[ownerLabel] || {};
              debug.osab.abSync.csMoc[ownerLabel].outerError = String(e);
            } catch (_) {}
            return null;
          }
        };

        debug.osab.abSync.hasFetch = abSync ? _objcCanCall(abSync, fetchSel2) : false;
        let got = null;
        if (abSync && uc && puid) got = tryFetchFrom(abSync, "chatManager.addressBookSynchronizer", uc);

        if (ENABLE_CONTACTS_STORAGE_FETCH) {
          if (ENABLE_SAFE_CONTACTS_STORAGE_FETCH) {
            if (!got && csCtxMain) got = tryFetchFromContactsStorageSafe(csCtxMain, "ctxMain.contactsStorage");
            if (!got && csChatManager) got = tryFetchFromContactsStorageSafe(csChatManager, "chatManager.contactsStorage");
          } else {
            try {
              debug.osab.abSync.csMoc = debug.osab.abSync.csMoc || {};
              if (!got && csCtxMain && _objcCanCall(csCtxMain, "- managedObjectContext")) {
                const moc = _safeObj(csCtxMain["- managedObjectContext"]());
                debug.osab.abSync.csMoc.ctxMain = { nil: !moc, className: moc ? String(moc.$className || "") : "" };
                if (moc) got = tryFetchFrom(csCtxMain, "ctxMain.contactsStorage", moc);
              }
              if (!got && csChatManager && _objcCanCall(csChatManager, "- managedObjectContext")) {
                const moc2 = _safeObj(csChatManager["- managedObjectContext"]());
                debug.osab.abSync.csMoc.chatManager = { nil: !moc2, className: moc2 ? String(moc2.$className || "") : "" };
                if (moc2) got = tryFetchFrom(csChatManager, "chatManager.contactsStorage", moc2);
              }
            } catch (_) {}
          }
        }

        if (!got) {
          let cdm = null;
          const cdmSel = "- contactsDownloadManager";
          const tryGetByIvars = (owner) => {
            try {
              const o = owner && owner.handle ? owner : _safeObj(owner);
              if (!o || !o.$ivars) return null;
              const iv = o.$ivars;
              const names = [
                "contactsDownloadManager",
                "_contactsDownloadManager",
                "$__lazy_storage_$_contactsDownloadManager",
                "$__lazy_storage_$_contactsDownloadManager_0",
                "$__lazy_storage_$_contactsDownloadManager_1",
                "$__lazy_storage_$_contactsDownloadManager_2"
              ];
              for (let i = 0; i < names.length; i++) {
                const k = names[i];
                if (!(k in iv)) continue;
                const v = _safeObj(iv[k]);
                if (v) return { key: k, obj: v };
              }
              return null;
            } catch (_) {
              return null;
            }
          };

          debug.osab.abSync.hasContactsDownloadManager = _objcCanCall(ctxMain, cdmSel) || (uc ? _objcCanCall(uc, cdmSel) : false) || _objcCanCall(chatManager, cdmSel);
          if (_objcCanCall(ctxMain, cdmSel)) cdm = _safeObj(ctxMain[cdmSel]());
          if (!cdm && uc && _objcCanCall(uc, cdmSel)) cdm = _safeObj(uc[cdmSel]());
          if (!cdm && _objcCanCall(chatManager, cdmSel)) cdm = _safeObj(chatManager[cdmSel]());

          debug.osab.abSync.contactsDownloadManagerViaIvar = "";
          if (!cdm) {
            let r = tryGetByIvars(ctxMain);
            if (!r && uc) r = tryGetByIvars(uc);
            if (!r) r = tryGetByIvars(chatManager);
            if (r && r.obj) {
              cdm = r.obj;
              debug.osab.abSync.contactsDownloadManagerViaIvar = String(r.key || "");
            }
          }

          debug.osab.abSync.contactsDownloadManagerClass = cdm ? String(cdm.$className || "") : "";
          debug.osab.abSync.contactsDownloadManagerHasFetch = cdm ? _objcCanCall(cdm, fetchSel2) : false;
          if (cdm && uc && puid) got = tryFetchFrom(cdm, "contactsDownloadManager", uc);
        }

        debug.osab.abSync.fetched = !!got;
        debug.osab.abSync.hasObjectForKey = got ? true : false;
        if (got && got.proxy) {
          debug.osab.abSync.via = String(got.ownerLabel || "");
          const proxy = got.proxy;
          debug.osab.abSync.gotProxy = true;
          debug.osab.abSync.proxyClass = proxy ? String(proxy.$className || "") : "";
          debug.osab.abSync.proxyCaps = {
            hasCopy: proxy ? _objcCanCall(proxy, "- copy") : false,
            hasMutableCopy: proxy ? _objcCanCall(proxy, "- mutableCopy") : false,
            hasFullNameSel: proxy ? _objcCanCall(proxy, "- fullName") : false
          };
          if (proxy && _objcCanCall(proxy, "- copy")) {
            contactToSave = proxy;
            originalContact = _safeObj(proxy["- copy"]());
            wrapperClass = String(contactToSave.$className || "");
            fetchSel = String("abFetch:" + got.ownerLabel);
          }
        }
      }
    }
  } catch (e) {
    try {
      debug.osab = debug.osab || {};
      debug.osab.abSync = debug.osab.abSync || {};
      debug.osab.abSync.error = String(e);
    } catch (_) {}
  }

  if (!originalContact) {
    return { ok: false, status: "failed", error: "contact/originalContact nil after abSync", fetchSel: fetchSel, retrSel: retrSel, abPropsFrom: abPropsFrom, abPropsClass: abPropsClass, debug: debug, prefer: prefer, wrapperClass: wrapperClass };
  }

  try {
    if (saveToOSAddressBook && ENABLE_CN_DIRECT_WRITE) {
      debug.osab = debug.osab || {};
      const phoneDigits2 = _derivePhoneFromJid(contactPhoneJid);
      debug.osab.cnWriteName = _writeOSContactNameByPhoneDigits(phoneDigits2, targetFullName);
    }
  } catch (e) {
    try {
      debug.osab = debug.osab || {};
      debug.osab.cnWriteName = { ok: false, attempted: true, error: String(e) };
    } catch (_) {}
  }
  const contactClass = String(originalContact.$className || "");
  let fullNameClass = "";
  let setterUsed = "";

  let beforeFullName = "";
  try {
    if (_objcCanCall(originalContact, "- fullName")) {
      const n = _safeObj(originalContact["- fullName"]());
      if (n) {
        fullNameClass = String(n.$className || "");
        if (_objcCanCall(n, "- fullName")) {
          const s = _safeObj(n["- fullName"]());
          if (s) beforeFullName = String(s);
        } else if (_objcCanCall(n, "- description")) {
          const s = _safeObj(n["- description"]());
          if (s) beforeFullName = String(s);
        } else {
          beforeFullName = String(n);
        }
      }
    } else if (_objcCanCall(originalContact, "- cachedFullName")) {
      const s = _safeObj(originalContact["- cachedFullName"]());
      if (s) beforeFullName = String(s);
    } else if (_objcCanCall(originalContact, "- businessName")) {
      const s = _safeObj(originalContact["- businessName"]());
      if (s) beforeFullName = String(s);
    }
  } catch (_) {}

  try {
    debug.nameObjProbe = debug.nameObjProbe || {};
    const sFn = "- fullName";
    debug.nameObjProbe.hasContactFullNameSel = _objcCanCall(contactToSave, sFn);
    debug.nameObjProbe.contactFullNameObjNil = true;
    if (debug.nameObjProbe.hasContactFullNameSel) {
      const fnObj = _safeObj(contactToSave[sFn]());
      debug.nameObjProbe.contactFullNameObjNil = !fnObj;
      if (fnObj) {
        debug.nameObjProbe.contactFullNameObjClass = String(fnObj.$className || "");
        debug.nameObjProbe.contactFullNameObjDesc = _safeDescValue(fnObj);
        const selAllow = "- setFullName:allowExternalSideEffects:";
        const selSet = "- setFullName:";
        debug.nameObjProbe.contactFullNameObjHasSetAllow = _objcCanCall(fnObj, selAllow);
        debug.nameObjProbe.contactFullNameObjHasSet = _objcCanCall(fnObj, selSet);
      }
    }

    debug.nameObjProbe.hasOriginalFullNameSel = _objcCanCall(originalContact, sFn);
    debug.nameObjProbe.originalFullNameObjNil = true;
    if (debug.nameObjProbe.hasOriginalFullNameSel) {
      const ofnObj = _safeObj(originalContact[sFn]());
      debug.nameObjProbe.originalFullNameObjNil = !ofnObj;
      if (ofnObj) {
        debug.nameObjProbe.originalFullNameObjClass = String(ofnObj.$className || "");
        debug.nameObjProbe.originalFullNameObjDesc = _safeDescValue(ofnObj);
        const selAllow = "- setFullName:allowExternalSideEffects:";
        const selSet = "- setFullName:";
        debug.nameObjProbe.originalFullNameObjHasSetAllow = _objcCanCall(ofnObj, selAllow);
        debug.nameObjProbe.originalFullNameObjHasSet = _objcCanCall(ofnObj, selSet);
      }
    }
  } catch (_) {}

  try {
    debug.osab = debug.osab || {};
    const osIdSel = "- osAddressBookContactID";
    debug.osab.hasOsAddressBookContactID = _objcCanCall(contactToSave, osIdSel);
    debug.osab.osAddressBookContactID = "";
    if (debug.osab.hasOsAddressBookContactID) {
      const v = _safeObj(contactToSave[osIdSel]());
      if (v) debug.osab.osAddressBookContactID = String(v);
    }
    const syncPolicySel = "- syncPolicy";
    debug.osab.hasSyncPolicy = _objcCanCall(contactToSave, syncPolicySel);
    debug.osab.syncPolicy = debug.osab.hasSyncPolicy ? Number(contactToSave[syncPolicySel]()) : -1;
    const phoneStatusSel = "- phoneStatus";
    debug.osab.hasPhoneStatus = _objcCanCall(contactToSave, phoneStatusSel);
    debug.osab.phoneStatus = debug.osab.hasPhoneStatus ? Number(contactToSave[phoneStatusSel]()) : -1;
    const pnSel = "- pnJID";
    debug.osab.hasPnJID = _objcCanCall(contactToSave, pnSel);
    debug.osab.pnJid = "";
    if (debug.osab.hasPnJID) {
      const pj = _safeObj(contactToSave[pnSel]());
      if (pj && _objcCanCall(pj, "- stringRepresentation")) {
        const s = _safeObj(pj["- stringRepresentation"]());
        if (s) debug.osab.pnJid = String(s);
      } else if (pj) {
        debug.osab.pnJid = String(pj);
      }
    }
  } catch (_) {}

  const nsName = _ns(targetFullName);
  if (!nsName) return { ok: false, status: "failed", error: "NSString alloc failed", fetchSel: fetchSel, retrSel: retrSel, abPropsFrom: abPropsFrom, abPropsClass: abPropsClass, debug: debug, prefer: prefer, wrapperClass: wrapperClass, contactClass: contactClass };

  try {
    debug.uiLike = debug.uiLike || {};
    const setLidSel = "- setLidJID:";
    const setChatSel = "- setChatJID:";
    const setSrcSel = "- setSource:";
    const setUpdSel = "- setLastUpdated:";
    debug.uiLike.hasSetLidJID = _objcCanCall(contactToSave, setLidSel);
    debug.uiLike.hasSetChatJID = _objcCanCall(contactToSave, setChatSel);
    debug.uiLike.hasSetSource = _objcCanCall(contactToSave, setSrcSel);
    debug.uiLike.hasSetLastUpdated = _objcCanCall(contactToSave, setUpdSel);
    if (debug.uiLike.hasSetLidJID && preferLid) {
      const lidObj = _makeAuthorUserJIDFromString(preferLid);
      if (lidObj) contactToSave[setLidSel](lidObj);
    }
    if (debug.uiLike.hasSetChatJID) {
      const chatObj = _makeAuthorUserJIDFromString(preferPn || prefer);
      if (chatObj) contactToSave[setChatSel](chatObj);
    }
    if (debug.uiLike.hasSetSource) {
      contactToSave[setSrcSel](1);
    }
    if (debug.uiLike.hasSetLastUpdated && ObjC.available && ObjC.classes.NSDate && ObjC.classes.NSDate.date) {
      const d = ObjC.classes.NSDate.date();
      if (d) contactToSave[setUpdSel](d);
    }
  } catch (_) {}

  const trySetName = () => {
    try { debug.nameSetterCaps = debug.nameSetterCaps || {}; } catch (_) {}
    try {
      if (_objcCanCall(contactToSave, "- fullName")) {
        const nameObj = _safeObj(contactToSave["- fullName"]());
        if (nameObj) {
          fullNameClass = fullNameClass || String(nameObj.$className || "");
          const setNameSel = "- setFullName:allowExternalSideEffects:";
          try { debug.nameSetterCaps[setNameSel] = _objcCanCall(nameObj, setNameSel); } catch (_) {}
          if (_objcCanCall(nameObj, setNameSel)) {
            nameObj[setNameSel](nsName, 1);
            setterUsed = "contact.fullName.setFullName:allowExternalSideEffects:";
            return true;
          }
        }
      }
    } catch (_) {}
    try {
      const cnNoSideSel = "- setContactNameWithoutExternalSideEffects:";
      try { debug.nameSetterCaps[cnNoSideSel] = _objcCanCall(contactToSave, cnNoSideSel); } catch (_) {}
      if (_objcCanCall(contactToSave, cnNoSideSel)) {
        contactToSave[cnNoSideSel](nsName);
        setterUsed = "contact.setContactNameWithoutExternalSideEffects:";
        return true;
      }
    } catch (_) {}
    try {
      const cnSel = "- setContactName:";
      try { debug.nameSetterCaps[cnSel] = _objcCanCall(contactToSave, cnSel); } catch (_) {}
      if (_objcCanCall(contactToSave, cnSel)) {
        contactToSave[cnSel](nsName);
        setterUsed = "contact.setContactName:";
        return true;
      }
    } catch (_) {}
    try {
      const directSel = "- setFullName:";
      try { debug.nameSetterCaps[directSel] = _objcCanCall(contactToSave, directSel); } catch (_) {}
      if (_objcCanCall(contactToSave, directSel)) {
        contactToSave[directSel](nsName);
        setterUsed = "contact.setFullName:";
        return true;
      }
    } catch (_) {}
    try {
      const cachedSel = "- setCachedFullName:";
      try { debug.nameSetterCaps[cachedSel] = _objcCanCall(contactToSave, cachedSel); } catch (_) {}
      if (_objcCanCall(contactToSave, cachedSel)) {
        contactToSave[cachedSel](nsName);
        setterUsed = "contact.setCachedFullName:";
        return true;
      }
    } catch (_) {}
    try {
      const bizSel = "- setBusinessName:";
      try { debug.nameSetterCaps[bizSel] = _objcCanCall(contactToSave, bizSel); } catch (_) {}
      if (_objcCanCall(contactToSave, bizSel)) {
        contactToSave[bizSel](nsName);
        setterUsed = "contact.setBusinessName:";
        return true;
      }
    } catch (_) {}
    try {
      const givenSel = "- setGivenName:";
      try { debug.nameSetterCaps[givenSel] = _objcCanCall(contactToSave, givenSel); } catch (_) {}
      if (_objcCanCall(contactToSave, givenSel)) {
        contactToSave[givenSel](nsName);
        setterUsed = "contact.setGivenName:";
        return true;
      }
    } catch (_) {}
    try {
      const famSel = "- setFamilyName:";
      try { debug.nameSetterCaps[famSel] = _objcCanCall(contactToSave, famSel); } catch (_) {}
      if (_objcCanCall(contactToSave, famSel)) {
        contactToSave[famSel](nsName);
        setterUsed = "contact.setFamilyName:";
        return true;
      }
    } catch (_) {}
    try {
      const hiSel = "- setHighlightedName:";
      try { debug.nameSetterCaps[hiSel] = _objcCanCall(contactToSave, hiSel); } catch (_) {}
      if (_objcCanCall(contactToSave, hiSel)) {
        contactToSave[hiSel](nsName);
        setterUsed = "contact.setHighlightedName:";
        return true;
      }
    } catch (_) {}
    try {
      const secSel = "- setSectionTitle:";
      try { debug.nameSetterCaps[secSel] = _objcCanCall(contactToSave, secSel); } catch (_) {}
      if (_objcCanCall(contactToSave, secSel)) {
        contactToSave[secSel](nsName);
        setterUsed = "contact.setSectionTitle:";
        return true;
      }
    } catch (_) {}
    return false;
  };
  if (!trySetName()) {
    return { ok: false, status: "failed", error: "no supported name setter", fetchSel: fetchSel, retrSel: retrSel, abPropsFrom: abPropsFrom, abPropsClass: abPropsClass, debug: debug, prefer: prefer, wrapperClass: wrapperClass, contactClass: contactClass, fullNameClass: fullNameClass };
  }

  try {
    debug.afterSetter = debug.afterSetter || {};
    try {
      const s9 = "- contactName";
      debug.afterSetter.hasContactName = _objcCanCall(contactToSave, s9);
      if (debug.afterSetter.hasContactName) {
        const v = _safeObj(contactToSave[s9]());
        if (v) debug.afterSetter.contactName = String(v);
      }
    } catch (_) {}
    const s1 = "- givenName";
    debug.afterSetter.hasGivenName = _objcCanCall(contactToSave, s1);
    if (debug.afterSetter.hasGivenName) {
      const v = _safeObj(contactToSave[s1]());
      if (v) debug.afterSetter.givenName = String(v);
    }
    const s0 = "- cachedFullName";
    debug.afterSetter.hasCachedFullName = _objcCanCall(contactToSave, s0);
    if (debug.afterSetter.hasCachedFullName) {
      const v = _safeObj(contactToSave[s0]());
      if (v) debug.afterSetter.cachedFullName = String(v);
    }
  } catch (_) {}

  try {
    const syncSel = "- setSyncWithServerState:";
    debug.osab = debug.osab || {};
    debug.osab.hasSetSyncWithServerState = _objcCanCall(contactToSave, syncSel);
    if (debug.osab.hasSetSyncWithServerState) {
      contactToSave[syncSel](1);
    }
  } catch (_) {}

  const saveSel = "- saveChangesInContact:originalContact:saveToOSAddressBook:completion:";
  if (!_objcCanCall(chatManager, saveSel)) {
    return { ok: false, status: "failed", error: "chatManager missing saveChangesInContact:*", fetchSel: fetchSel, retrSel: retrSel, abPropsFrom: abPropsFrom, abPropsClass: abPropsClass, debug: debug, prefer: prefer, wrapperClass: wrapperClass, contactClass: contactClass, fullNameClass: fullNameClass, setterUsed: setterUsed };
  }
  chatManager[saveSel](contactToSave, originalContact, saveToOSAddressBook, ptr("0x0"));

  try {
    debug.osab = debug.osab || {};
    debug.osab.persist = debug.osab.persist || { attempted: false, called: false, error: "", hasPersistSel: false, hasPersistedUniqueID: false, persistedUniqueID: "" };
    if (saveToOSAddressBook) {
      debug.osab.persist.attempted = true;
      const persistSel1 = "- persistEditsToContact:completion:";
      const persistSel2 = "- persistEditsToSyncedContact:completion:";
      const has1 = _objcCanCall(chatManager, persistSel1);
      const has2 = _objcCanCall(chatManager, persistSel2);
      debug.osab.persist.hasPersistEditsToContact = has1;
      debug.osab.persist.hasPersistEditsToSyncedContact = has2;
      const persistSel = has2 ? persistSel2 : persistSel1;
      debug.osab.persist.hasPersistSel = _objcCanCall(chatManager, persistSel);
      debug.osab.persist.persistSel = String(persistSel || "");
      const puSel = "- persistedUniqueID";
      debug.osab.persist.hasPersistedUniqueID = _objcCanCall(contactToSave, puSel);
      if (debug.osab.persist.hasPersistedUniqueID) {
        const v = _safeObj(contactToSave[puSel]());
        if (v) debug.osab.persist.persistedUniqueID = String(v);
      }
      if (debug.osab.persist.hasPersistSel && debug.osab.persist.hasPersistedUniqueID) {
        try {
          let cb = null;
          try {
            if (ObjC.available && ObjC.Block) {
              cb = new ObjC.Block({
                retType: "void",
                argTypes: ["pointer", "pointer"],
                implementation: function (a0, a1) {
                  try {
                    const o0 = _safeObj(a0);
                    const o1 = _safeObj(a1);
                    send({
                      ok: true,
                      ts: Date.now(),
                      op_id: String(opId || ""),
                      opId: String(opId || ""),
                      type: "wa.tx.contact_note_upsert.result",
                      build: SCRIPT_BUILD_ID,
                      status: "debug",
                      debugPhase: "persist_completion",
                      chatJid: String(chatJid || ""),
                      contactPhoneJid: String(contactPhoneJid || ""),
                      prefer: String(prefer || ""),
                      debug: {
                        osab: {
                          persist: {
                            persistSel: String(debug.osab && debug.osab.persist ? (debug.osab.persist.persistSel || "") : ""),
                            persistedUniqueID: String(debug.osab && debug.osab.persist ? (debug.osab.persist.persistedUniqueID || "") : "")
                          }
                        },
                        persistCompletion: {
                          a0Ptr: String(_toPtr(a0)),
                          a0Class: o0 ? String(o0.$className || "") : "",
                          a0: o0 ? _safeDescValue(o0) : "",
                          a1Ptr: String(_toPtr(a1)),
                          a1Class: o1 ? String(o1.$className || "") : "",
                          a1: o1 ? _safeDescValue(o1) : ""
                        }
                      }
                    });
                  } catch (_) {}
                }
              });
              try { _keepAliveBlock(cb, 30000); } catch (_) {}
            }
          } catch (_) { cb = null; }
          chatManager[persistSel](contactToSave, cb ? cb : ptr("0x0"));
          debug.osab.persist.called = true;
          debug.osab.persist.cb = { scheduled: !!cb, note: "completion async (no wait on main)" };
        } catch (e) {
          debug.osab.persist.error = String(e);
        }
      }
      const notifySel = "- notifyContactStoreDidChange";
      debug.osab.hasNotifyContactStoreDidChange = _objcCanCall(chatManager, notifySel);
      if (debug.osab.hasNotifyContactStoreDidChange) {
        try {
          chatManager[notifySel]();
          debug.osab.didNotifyContactStoreDidChange = true;
        } catch (_) {
          debug.osab.didNotifyContactStoreDidChange = false;
        }
      }
    }
  } catch (_) {}

  try {
    if (typeof setTimeout === "function" && mcsFetchFrom) {
      const opId2 = String(opId || "");
      const chatJid2 = String(chatJid || "");
      const contactPhoneJid2 = String(contactPhoneJid || "");
      const prefer2 = String(prefer || "");
      const build2 = String(SCRIPT_BUILD_ID || "");
      const puid2 = debug && debug.osab && debug.osab.persist ? String(debug.osab.persist.persistedUniqueID || "") : "";
      const delayRead = function (delayMs) {
        try {
          const rr = mcsFetchFrom(prefer2);
          if (!rr || !rr.c) return;
          const c = rr.c;
          const out = { delayMs: Number(delayMs) | 0, refetchSel: String(rr.usedSel || "") };
          try {
            const s1 = "- givenName";
            if (_objcCanCall(c, s1)) {
              const v = _safeObj(c[s1]());
              if (v) out.givenName = String(v);
            }
          } catch (_) {}
          try {
            const s0 = "- cachedFullName";
            if (_objcCanCall(c, s0)) {
              const v = _safeObj(c[s0]());
              if (v) out.cachedFullName = String(v);
            }
          } catch (_) {}
          try {
            const osIdSel = "- osAddressBookContactID";
            if (_objcCanCall(c, osIdSel)) {
              const v = _safeObj(c[osIdSel]());
              if (v) out.osAddressBookContactID = String(v);
            }
          } catch (_) {}
          send({
            ok: true,
            ts: Date.now(),
            op_id: opId2,
            opId: opId2,
            type: "wa.tx.contact_note_upsert.result",
            build: build2,
            status: "debug",
            debugPhase: "delayed_read",
            chatJid: chatJid2,
            contactPhoneJid: contactPhoneJid2,
            prefer: prefer2,
            debug: {
              osab: { persist: { persistedUniqueID: puid2 } },
              afterDelay: out
            }
          });
        } catch (_) {}
      };
      setTimeout(function () { delayRead(1200); }, 1200);
      if (ENABLE_DELAYED_READ_6000MS) setTimeout(function () { delayRead(6000); }, 6000);
    }
  } catch (_) {}

  try {
    if (saveToOSAddressBook && altPn && altPn.handle && contactToSave.handle && !altPn.handle.equals(contactToSave.handle)) {
      const altClass = String(altPn.$className || "");
      const altOrig = (_objcCanCall(altPn, "- copy")) ? _safeObj(altPn["- copy"]()) : null;
      if (altOrig) {
        let altBefore = "";
        try {
          if (_objcCanCall(altPn, "- givenName")) {
            const v = _safeObj(altPn["- givenName"]());
            if (v) altBefore = String(v);
          }
        } catch (_) {}
        try {
          debug.osab = debug.osab || {};
          debug.osab.altPn = debug.osab.altPn || {};
          const setGivenSel = "- setGivenName:";
          debug.osab.altPn.hasSetGivenName = _objcCanCall(altPn, setGivenSel);
          if (debug.osab.altPn.hasSetGivenName) {
            altPn[setGivenSel](nsName);
            debug.osab.altPn.setterUsed = "altPn.setGivenName:";
          }
        } catch (_) {}
        try {
          debug.osab = debug.osab || {};
          debug.osab.altPn = debug.osab.altPn || {};
          const syncSelAlt = "- setSyncWithServerState:";
          debug.osab.altPn.hasSetSyncWithServerState = _objcCanCall(altPn, syncSelAlt);
          if (debug.osab.altPn.hasSetSyncWithServerState) {
            altPn[syncSelAlt](1);
          }
        } catch (_) {}
        chatManager[saveSel](altPn, altOrig, 1, ptr("0x0"));
        debug.osab.altPn.saved = true;
        debug.osab.altPn.altClass = altClass;
        debug.osab.altPn.altBeforeGivenName = altBefore;
      } else {
        debug.osab.altPn.saved = false;
        debug.osab.altPn.error = "altPn copy nil";
      }
    }
  } catch (_) {}

  let afterRead = {};
  try {
    try {
      if (saveToOSAddressBook && ObjC.available && ObjC.classes.NSThread && ObjC.classes.NSThread.sleepForTimeInterval_) {
        ObjC.classes.NSThread.sleepForTimeInterval_(0.2);
      }
    } catch (_) {}
    try {
      const s9 = "- contactName";
      if (_objcCanCall(contactToSave, s9)) {
        const v = _safeObj(contactToSave[s9]());
        if (v) afterRead.contactName = String(v);
      }
    } catch (_) {}
    const s1 = "- givenName";
    if (_objcCanCall(contactToSave, s1)) {
      const v = _safeObj(contactToSave[s1]());
      if (v) afterRead.givenName = String(v);
    }
    const s2 = "- familyName";
    if (_objcCanCall(contactToSave, s2)) {
      const v = _safeObj(contactToSave[s2]());
      if (v) afterRead.familyName = String(v);
    }
    const s3 = "- businessName";
    if (_objcCanCall(contactToSave, s3)) {
      const v = _safeObj(contactToSave[s3]());
      if (v) afterRead.businessName = String(v);
    }
    const s4 = "- sectionTitle";
    if (_objcCanCall(contactToSave, s4)) {
      const v = _safeObj(contactToSave[s4]());
      if (v) afterRead.sectionTitle = String(v);
    }
    const s5 = "- cachedFullName";
    if (_objcCanCall(contactToSave, s5)) {
      const v = _safeObj(contactToSave[s5]());
      if (v) afterRead.cachedFullName = String(v);
    }
    const s6 = "- fullName";
    if (_objcCanCall(contactToSave, s6)) {
      const n = _safeObj(contactToSave[s6]());
      if (n) afterRead.fullNameObjClass = String(n.$className || "");
    }
    if (saveToOSAddressBook && mcsFetchFrom) {
      const rr = mcsFetchFrom(prefer);
      if (rr && rr.c) {
        afterRead.refetchSel = String(rr.usedSel || "");
        try {
          if (_objcCanCall(rr.c, s1)) {
            const v = _safeObj(rr.c[s1]());
            if (v) afterRead.refetchGivenName = String(v);
          }
        } catch (_) {}
        try {
          const s0 = "- cachedFullName";
          if (_objcCanCall(rr.c, s0)) {
            const v = _safeObj(rr.c[s0]());
            if (v) afterRead.refetchCachedFullName = String(v);
          }
        } catch (_) {}
      }
    }
  } catch (_) {}

  return {
    ok: true,
    status: "success",
    matched: { prefer: prefer, fetchSel: fetchSel },
    before: { fullName: beforeFullName },
    after: { fullName: targetFullName },
    fetchSel: fetchSel,
    retrSel: retrSel,
    abPropsFrom: abPropsFrom,
    abPropsClass: abPropsClass,
    debug: debug,
    prefer: prefer,
    saveToOSAddressBook: saveToOSAddressBook,
    afterRead: afterRead,
    wrapperClass: wrapperClass,
    contactClass: contactClass,
    fullNameClass: fullNameClass,
    setterUsed: setterUsed
  };
}

function _contactsNoteHandleMsg(message) {
  const p = message && message.payload ? message.payload : (message || {});
  try { waitready(); } catch (_) {}
  const opId = String(p.opId || p.op_id || "").trim();
  const chatJid = String(p.chatJid || "").trim();
  const contactPhoneJid = String(p.contactPhoneJid || "").trim();
  const phoneDigits = String(p.phoneDigits || "").trim();
  let res = null;
  try {
    res = _contactsNoteUpsertFullNameOnMain(p);
  } catch (e) {
    res = { ok: false, status: "failed", error: String(e) };
  }
  try {
    const r = (res && typeof res === "object") ? Object.assign({}, res) : { ok: false, status: "failed", error: "no result" };
    if (r.waOk === undefined) r.waOk = !!(r && r.ok);
    if (r.osOk === undefined) {
      const saveToOS = (r && r.saveToOSAddressBook !== undefined) ? ((Number(r.saveToOSAddressBook) | 0) ? 1 : 0) : 1;
      const osSaved = !!(r && r.debug && r.debug.osSaved === true);
      r.osOk = saveToOS ? osSaved : true;
    }
    _contactsNoteEmitResult(opId, chatJid, contactPhoneJid, phoneDigits, r, null);
  } catch (_) {}
}

function _contactsNoteLoop() {
  recv("qqw.contacts_note_upsert", function (message) {
    try { _contactsNoteHandleMsg(message); } catch (_) {}
    _contactsNoteLoop();
  }).wait();
}

try { setImmediate(_contactsNoteLoop); } catch (_) {}

function _contactsAddEmitResult(opId, chatJid, phoneE164, givenName, res, extraErr) {
  try {
    const ok = !!(res && res.ok);
    const status = String((res && res.status) ? res.status : (ok ? "ok" : "failed"));
    const err = ok ? "" : String((res && res.error) ? res.error : (extraErr ? extraErr : "failed"));
    const refresh = (res && res.refresh && typeof res.refresh === "object") ? res.refresh : null;
    send({
      type: "wa.tx.contact_add.result",
      build: SCRIPT_BUILD_ID,
      ts: Date.now(),
      opId: String(opId || ""),
      op_id: String(opId || ""),
      jid: String(chatJid || ""),
      chatJid: String(chatJid || ""),
      phoneE164: String(phoneE164 || ""),
      givenName: String(givenName || ""),
      ok: ok,
      status: status,
      error: err,
      existed: !!(res && res.existed),
      identifier: String((res && res.identifier) ? res.identifier : ""),
      refresh: refresh
    });
  } catch (_) {}
}

function _contactsNotifyContactStoreDidChange() {
  try {
    if (!ObjC.available) return { ok: false, build: SCRIPT_BUILD_ID, error: "ObjC not available" };
    const r = _runOnMainQueueSync(function () {
      const core = _resolveCoreFixed();
      if (!core || !core.ok) return { ok: false, build: SCRIPT_BUILD_ID, error: core ? core.error : "core failed" };
      const ctxMain = core.ctxMain;
      const chatManager = (_objcCanCall(ctxMain, "- chatManager")) ? _safeObj(ctxMain["- chatManager"]()) : null;
      if (!chatManager) return { ok: false, build: SCRIPT_BUILD_ID, error: "ctxMain.chatManager nil" };
      const selNotify = "- notifyContactStoreDidChange";
      if (!_objcCanCall(chatManager, selNotify)) return { ok: false, build: SCRIPT_BUILD_ID, error: "chatManager missing notifyContactStoreDidChange" };
      let before = null;
      let after = null;
      try {
        if (_objcCanCall(chatManager, "- ignoreAddressBookChangeNotifications")) before = !!chatManager["- ignoreAddressBookChangeNotifications"]();
      } catch (_) { before = null; }
      try { chatManager[selNotify](); } catch (e) { return { ok: false, build: SCRIPT_BUILD_ID, error: "notifyContactStoreDidChange failed: " + String(e) }; }
      try {
        if (_objcCanCall(chatManager, "- ignoreAddressBookChangeNotifications")) after = !!chatManager["- ignoreAddressBookChangeNotifications"]();
      } catch (_) { after = null; }
      return { ok: true, build: SCRIPT_BUILD_ID, invoked: true, beforeIgnore: before, afterIgnore: after };
    }, 2500);
    return r && r.ok !== undefined ? r : { ok: false, build: SCRIPT_BUILD_ID, error: (r && r.error) ? r.error : "failed" };
  } catch (e) {
    return { ok: false, build: SCRIPT_BUILD_ID, error: String(e) };
  }
}

function _contactsAddHandleMsg(message) {
  const p = message && message.payload ? message.payload : (message || {});
  try { waitready(); } catch (_) {}
  const opId = String(p.opId || p.op_id || "").trim();
  const chatJid = String(p.chatJid || p.jid || "").trim();
  const phoneRaw = String(p.phoneRaw || p.phone_raw || "").trim();
  const phoneE164 = String(p.phoneE164 || p.phone || "").trim();
  const givenName = String(p.givenName || "").trim();
  if (!opId || !phoneE164) {
    _contactsAddEmitResult(opId, chatJid, phoneE164, givenName, { ok: false, status: "failed", error: "missing opId/phoneE164" }, null);
    return;
  }
  let res = null;
  try {
    res = csabcnupsertgivenphone(phoneE164, givenName || "联系人", phoneRaw || phoneE164);
  } catch (e) {
    res = { ok: false, status: "failed", error: String(e) };
  }
  try {
    if (res && res.ok) {
      const digits = _normalizePhoneE164Like(phoneE164).replace(/[^\d]/g, "");
      const phoneJid = digits ? (digits + "@s.whatsapp.net") : "";
      const rr = _contactsNotifyContactStoreDidChange();
      const wr = phoneJid ? csabsetgivennamejid_writecontext(phoneJid, givenName || "联系人", 1) : { ok: false, build: SCRIPT_BUILD_ID, error: "phoneJid empty", chatJid: "" };
      res.refresh = { notifyContactStoreDidChange: rr, writeContext: wr, phoneJid: phoneJid };
    }
  } catch (_) {}
  _contactsAddEmitResult(opId, chatJid, phoneE164, givenName, res, null);
}

function _contactsAddLoop() {
  recv("qqw.contacts_add", function (message) {
    try { _contactsAddHandleMsg(message); } catch (_) {}
    _contactsAddLoop();
  }).wait();
}

try { setImmediate(_contactsAddLoop); } catch (_) {}

function _txHandleMsg(message) {
  const p = message && message.payload ? message.payload : (message || {});
  const opId = String(p.opId || p.op_id || "");
  const kind = String(p.kind || "");
  const jid = String(p.jid || p.chatJid || "");
  const text = String(p.text || "");
  const quoteStanzaId = String(p.quoteStanzaId || p.quote_stanza_id || "");
  const participantJid = String(p.participantJid || p.participant_jid || "");
  const mediaRef = (p && p.mediaRef && typeof p.mediaRef === "object") ? p.mediaRef : null;
  let messageOrigin = Number.isFinite(p.messageOrigin) ? Number(p.messageOrigin) : 1;
  let creationEntryPoint = Number.isFinite(p.creationEntryPoint) ? Number(p.creationEntryPoint) : 1;
  if (!(messageOrigin > 0)) messageOrigin = 1;
  if (!(creationEntryPoint > 0)) creationEntryPoint = 1;
  if (!opId || !kind || !jid) {
    _txEmitResult(opId, kind, jid, { ok: false, stanzaId: "", error: "missing opId/kind/jid" }, null, mediaRef);
    return;
  }
  try { waitready(); } catch (_) {}
  try {
    let res = null;
    if (kind === "text") {
      res = sendtext(jid, text, messageOrigin, creationEntryPoint);
    } else if (kind === "status_text") {
      res = sendstatustext(text, messageOrigin, creationEntryPoint);
    } else if (kind === "quote") {
      res = sendquotetext(jid, quoteStanzaId, text, participantJid, messageOrigin, creationEntryPoint);
    } else if (kind === "image") {
      res = sendimage(jid, String(p.caption || ""), String(p.path || p.imagePath || ""), messageOrigin);
    } else if (kind === "status_image") {
      res = sendstatusimage(String(p.path || p.imagePath || ""), String(p.caption || ""), messageOrigin);
    } else if (kind === "status_video") {
      res = sendstatusvideo(String(p.path || p.videoPath || ""), String(p.caption || ""), String(p.thumbnailPath || ""), messageOrigin);
    } else if (kind === "video") {
      res = sendvideo(jid, String(p.caption || ""), String(p.path || p.videoPath || ""), String(p.thumbnailPath || ""), messageOrigin);
    } else if (kind === "audio") {
      res = sendaudio(jid, String(p.path || p.audioPath || ""), Number(p.durationSec || 0), messageOrigin);
    } else if (kind === "product_asset") {
      const pth = String(p.path || p.imagePath || p.videoPath || p.audioPath || "");
      const pthLower = String(pth || "").toLowerCase();
      const dot = pthLower.lastIndexOf(".");
      const ext = dot >= 0 ? pthLower.slice(dot) : "";
      const isVideo = (ext === ".mp4" || ext === ".mov" || ext === ".m4v");
      const isAudio = (ext === ".ogg" || ext === ".opus" || ext === ".m4a" || ext === ".aac" || ext === ".mp3" || ext === ".wav" || ext === ".amr");
      if (isVideo) {
        res = sendvideo(jid, String(p.caption || ""), pth, String(p.thumbnailPath || ""), messageOrigin);
      } else if (isAudio) {
        res = sendaudio(jid, pth, Number(p.durationSec || 0), messageOrigin);
      } else {
        res = sendimage(jid, String(p.caption || ""), pth, messageOrigin);
      }
    } else {
      res = { ok: false, stanzaId: "", error: "unknown kind" };
    }
    _txEmitResult(opId, kind, jid, res, null, mediaRef);
  } catch (e) {
    _txEmitResult(opId, kind, jid, { ok: false, stanzaId: "", error: String(e) }, null, mediaRef);
  }
}

function _txLoop() {
  recv("qqw.tx_send", function (message) {
    try { _txHandleMsg(message); } catch (_) {}
    _txLoop();
  }).wait();
}

try { setImmediate(_txLoop); } catch (_) {}

function _msgEmitResult(opId, action, jid, stanzaId, res, extraErr) {
  try {
    const ok = !!(res && res.ok);
    const err = ok ? "" : String((res && res.error) ? res.error : (extraErr ? extraErr : "failed"));
    send({
      type: "wa.tx.msg_action.result",
      build: SCRIPT_BUILD_ID,
      ts: Date.now(),
      op_id: String(opId || ""),
      opId: String(opId || ""),
      action: String(action || ""),
      jid: String(jid || ""),
      stanzaId: String(stanzaId || ""),
      ok: ok,
      error: err
    });
  } catch (_) {}
}

function _msgFetchMessageOnMain(chatJidStr, stanzaIdStr, participantJidStr) {
  const core = _resolveCoreFixed();
  if (!core || !core.ok) return { ok: false, error: core ? core.error : "core failed" };
  const jid = _makeWAChatJIDFromString(chatJidStr);
  if (!jid) return { ok: false, error: "WAChatJID parse failed" };
  const cs = _fetchChatSession(core.storage, jid);
  if (!cs) return { ok: false, error: "fetchChatSessionForJID returned nil" };
  const mcs = _getMutableChatSession(cs);
  if (!mcs) return { ok: false, error: "mutableChatSession returned nil" };
  const moc = _resolveManagedObjectContext(core);
  const fm = _fetchMessageByStanzaId(mcs, stanzaIdStr, participantJidStr, moc);
  if (!fm || !fm.msg) return { ok: false, error: "message not found by stanzaId", fetchVia: fm ? fm.via : "" };
  return { ok: true, core: core, msg: fm.msg, fetchVia: fm.via };
}

function _msgActionRevoke(chatJidStr, stanzaIdStr, participantJidStr) {
  const j = String(chatJidStr || "").trim();
  const sid = String(stanzaIdStr || "").trim();
  const pj = String(participantJidStr || "").trim();
  if (!j || !sid) return { ok: false, error: "missing jid/stanzaId" };
  const res = _runOnMainQueueSync(() => {
    const fm = _msgFetchMessageOnMain(j, sid, pj);
    if (!fm || !fm.ok) return { ok: false, error: fm ? fm.error : "message fetch failed" };
    const storage = fm.core.storage;
    if (!_objcCanCall(storage, "- revokeOutgoingMessages:")) return { ok: false, error: "chatStorage missing revokeOutgoingMessages:" };
    const msg = fm.msg;
    if (_objcCanCall(msg, "- isFromMe")) {
      const v = msg["- isFromMe"]();
      const ok = (v === 1 || v === true || String(v) === "1");
      if (!ok) return { ok: false, error: "target is not an outgoing message" };
    } else {
      return { ok: false, error: "cannot verify isFromMe" };
    }
    const NSArray = ObjC.classes.NSArray;
    if (!NSArray || !NSArray["+ arrayWithObject:"]) return { ok: false, error: "NSArray unavailable" };
    const messages = NSArray["+ arrayWithObject:"](msg);
    storage["- revokeOutgoingMessages:"](messages);
    return { ok: true };
  }, 8000);
  if (res && res.ok) return { ok: true };
  return { ok: false, error: res && res.error ? String(res.error) : "failed" };
}

function _msgActionDeleteLocal(chatJidStr, stanzaIdStr, participantJidStr) {
  const j = String(chatJidStr || "").trim();
  const sid = String(stanzaIdStr || "").trim();
  const pj = String(participantJidStr || "").trim();
  if (!j || !sid) return { ok: false, error: "missing jid/stanzaId" };
  const res = _runOnMainQueueSync(() => {
    const fm = _msgFetchMessageOnMain(j, sid, pj);
    if (!fm || !fm.ok) return { ok: false, error: fm ? fm.error : "message fetch failed" };
    const storage = fm.core.storage;
    const msg = fm.msg;
    const NSArray = ObjC.classes.NSArray;
    if (!NSArray || !NSArray["+ arrayWithObject:"]) return { ok: false, error: "NSArray unavailable" };
    const messages = NSArray["+ arrayWithObject:"](msg);
    if (_objcCanCall(storage, "- deleteMessages:reason:error:")) {
      storage["- deleteMessages:reason:error:"](messages, 0, ptr("0x0"));
      return { ok: true };
    }
    if (_objcCanCall(storage, "- deleteMessages:withUndoSupport:")) {
      storage["- deleteMessages:withUndoSupport:"](messages, false);
      return { ok: true };
    }
    return { ok: false, error: "chatStorage missing deleteMessages:* selector" };
  }, 8000);
  if (res && res.ok) return { ok: true };
  return { ok: false, error: res && res.error ? String(res.error) : "failed" };
}

function _msgHandle(message) {
  const p = message && message.payload ? message.payload : (message || {});
  const opId = String(p.opId || p.op_id || "");
  const action = String(p.action || "");
  const jid = String(p.jid || p.chatJid || "");
  const stanzaId = String(p.stanzaId || p.targetStanzaId || "");
  const text = String(p.text || "");
  const participantJid = String(p.participantJid || p.participant_jid || "");
  if (!opId || !action || !jid || !stanzaId) {
    _msgEmitResult(opId, action, jid, stanzaId, { ok: false, error: "missing opId/action/jid/stanzaId" }, null);
    return;
  }
  try { waitready(); } catch (_) {}
  try {
    let res = null;
    if (action === "edit") {
      res = { ok: false, error: "not_implemented" };
    } else if (action === "delete") {
      res = _msgActionDeleteLocal(jid, stanzaId, participantJid);
    } else if (action === "revoke") {
      res = _msgActionRevoke(jid, stanzaId, participantJid);
    } else {
      res = { ok: false, error: "unknown action" };
    }
    _msgEmitResult(opId, action, jid, stanzaId, res, null);
  } catch (e) {
    _msgEmitResult(opId, action, jid, stanzaId, { ok: false, error: String(e) }, null);
  }
}

function _msgLoop() {
  recv("qqw.msg_action", function (message) {
    try { _msgHandle(message); } catch (_) {}
    _msgLoop();
  }).wait();
}

try { setImmediate(_msgLoop); } catch (_) {}

const RX_STATE = { installed: false, error: null, installedAt: null, waVersion: null, mode: "", objcHooks: null };
const RX_SAMPLE = { enabled: false, msg_kind: "unknown", quoted_kind: "none", quoted_stanza_id: "" };

function RX_objcAvailable() { try { return !!(ObjC && ObjC.available); } catch (_) { return false; } }

function RX_getMainBundleVersionString() {
  try {
    if (!RX_objcAvailable()) return null;
    const NSBundle = ObjC.classes.NSBundle;
    if (!NSBundle) return null;
    const b = NSBundle.mainBundle();
    if (!b) return null;
    const info = b.infoDictionary();
    if (!info) return null;
    const shortV = info.objectForKey_("CFBundleShortVersionString");
    const buildV = info.objectForKey_("CFBundleVersion");
    const s = shortV ? String(shortV) : "";
    const bld = buildV ? String(buildV) : "";
    if (s && bld) return s + "(" + bld + ")";
    if (s) return s;
    if (bld) return bld;
    return null;
  } catch (_) {
    return null;
  }
}

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

function RX_bytesToBase64(u8) {
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

function RX_normalizeJidString(s) {
  try {
    let v = String(s || "").trim();
    if (!v) return "";
    if (v[0] === "<" && v[v.length - 1] === ">") v = v.slice(1, -1).trim();
    if (!v) return "";
    if (v.indexOf("@") === -1) return "";
    if (v.indexOf("*") !== -1) return "";
    return v;
  } catch (_) {
    return "";
  }
}

function RX_jidToString(anyObj) {
  try {
    if (!RX_objcAvailable()) return null;
    const o = (anyObj instanceof ObjC.Object) ? anyObj : RX_tryObjCObjectDeep(anyObj, 1);
    if (!o) return null;
    if (ObjC.classes.NSString && o.isKindOfClass_(ObjC.classes.NSString)) {
      const s = RX_normalizeJidString(o);
      return s || null;
    }

    const tryObj = (obj) => {
      if (!obj) return "";
      const sels = ["stringRepresentation", "jid", "jidString", "rawString"];
      for (let i = 0; i < sels.length; i++) {
        const v = RX_tryInvokeNoArg(obj, sels[i]);
        const s = RX_normalizeJidString(v);
        if (s) return s;
      }
      return "";
    };

    const direct = tryObj(o);
    if (direct) return direct;

    try {
      const uj = RX_tryInvokeNoArg(o, "userJID");
      const ujObj = uj ? (uj instanceof ObjC.Object ? uj : RX_tryObjCObjectDeep(uj, 1)) : null;
      const s = tryObj(ujObj);
      if (s) return s;
    } catch (_) {}

    try {
      const dj = RX_tryInvokeNoArg(o, "deviceJID");
      const djObj = dj ? (dj instanceof ObjC.Object ? dj : RX_tryObjCObjectDeep(dj, 1)) : null;
      const uj = djObj ? RX_tryInvokeNoArg(djObj, "userJID") : null;
      const ujObj = uj ? (uj instanceof ObjC.Object ? uj : RX_tryObjCObjectDeep(uj, 1)) : null;
      const s = tryObj(ujObj);
      if (s) return s;
    } catch (_) {}

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

function RX_extractTailJidFromUniqueKey(uniqueKeyStr) {
  try {
    const s = String(uniqueKeyStr || "");
    if (!s) return "";
    const parts = s.split("_");
    for (let i = parts.length - 1; i >= 0; i--) {
      const p = String(parts[i] || "").trim();
      if (!p) continue;
      const low = p.toLowerCase();
      if (low === "status@broadcast" || low.indexOf("@broadcast") !== -1) continue;
      if (p.indexOf("@") !== -1) return p;
    }
    return "";
  } catch (_) {
    return "";
  }
}

function RX_extractStanzaFieldsFromContext(ctxPtr) {
  const out = { stanzaId: null, uniqueKey: null, chatJID: null, senderJID: null, statusAuthorJID: null, isGroup: null, isFromMe: null };
  try {
    const ctxObj = RX_tryObjCObject(ctxPtr) || RX_tryObjCObjectDeep(ctxPtr, 2);
    if (!ctxObj) return out;
    const stanzaObj =
      RX_tryInvokeNoArg(ctxObj, "orderedMessageStanza") ||
      RX_tryInvokeNoArg(ctxObj, "messageStanza") ||
      (RX_tryObjCObjectDeep(ctxPtr, 2) ? (RX_tryInvokeNoArg(RX_tryObjCObjectDeep(ctxPtr, 2), "orderedMessageStanza") || RX_tryInvokeNoArg(RX_tryObjCObjectDeep(ctxPtr, 2), "messageStanza")) : null);
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
      RX_tryInvokeNoArg(stanzaObj, "participant") ||
      RX_tryInvokeNoArg(stanzaObj, "incomingOriginalAuthorUserJID");
    out.senderJID = RX_jidToString(senderCand);

    const pickAuthorJid = () => {
      const sels = [
        "incomingOriginalAuthorUserJID", "incomingOriginalAuthorUserJid", "incomingOriginalAuthorJID", "incomingOriginalAuthorJid",
        "authorUserJID", "authorUserJid", "participantUserJID", "participantUserJid",
        "authorJID", "authorJid", "participantJID", "participantJid",
        "threadMsgSenderJID", "threadMsgSenderJid",
        "participant", "author",
        "senderJID", "senderJid", "fromJID", "fromJid",
      ];
      for (let i = 0; i < sels.length; i++) {
        const v = RX_tryInvokeNoArg(stanzaObj, sels[i]);
        const s = RX_jidToString(v);
        if (s) return s;
      }
      if (out.uniqueKey) {
        const d = RX_deriveChatJidFromUniqueKey(out.uniqueKey);
        if (d && d.toLowerCase() !== "status@broadcast" && d.toLowerCase().indexOf("@broadcast") === -1) return d;
      }
      return "";
    };
    const authorJid = pickAuthorJid();
    const isStatus = (String(out.chatJID || "").toLowerCase() === "status@broadcast");
    if (isStatus) {
      out.chatJID = "status@broadcast";
      const derivedAuthor = authorJid || RX_extractTailJidFromUniqueKey(out.uniqueKey);
      if (derivedAuthor) {
        out.statusAuthorJID = derivedAuthor;
        out.senderJID = derivedAuthor;
      }
    }

    if (out.chatJID) out.isGroup = RX_isGroupJidString(out.chatJID);
    const isFromMe = RX_tryCallBoolNoArg(stanzaObj, "isFromMe");
    out.isFromMe = (isFromMe !== null && isFromMe !== undefined) ? isFromMe : RX_tryCallBoolNoArg(stanzaObj, "fromMe");
    if (out.isFromMe === null && out.uniqueKey) out.isFromMe = RX_deriveIsFromMeFromUniqueKey(out.uniqueKey);
    return out;
  } catch (_) {
    return out;
  }
}

function RX_readVarint(buf, i) {
  let x = 0;
  let shift = 0;
  while (i < buf.length) {
    const c = buf[i] & 0xff;
    i += 1;
    x |= (c & 0x7f) << shift;
    if ((c & 0x80) === 0) return { v: x, i };
    shift += 7;
    if (shift > 70) break;
  }
  return { v: 0, i: buf.length, err: "badvarint" };
}

function RX_decodeUtf8(bytes) {
  try {
    let s = "";
    let i = 0;
    while (i < bytes.length) {
      const b0 = bytes[i] & 0xff;
      if (b0 < 0x80) {
        s += String.fromCharCode(b0);
        i += 1;
        continue;
      }
      if ((b0 & 0xe0) === 0xc0 && i + 1 < bytes.length) {
        const b1 = bytes[i + 1] & 0x3f;
        const cp = ((b0 & 0x1f) << 6) | b1;
        s += String.fromCharCode(cp);
        i += 2;
        continue;
      }
      if ((b0 & 0xf0) === 0xe0 && i + 2 < bytes.length) {
        const b1 = bytes[i + 1] & 0x3f;
        const b2 = bytes[i + 2] & 0x3f;
        const cp = ((b0 & 0x0f) << 12) | (b1 << 6) | b2;
        s += String.fromCharCode(cp);
        i += 3;
        continue;
      }
      i += 1;
    }
    return s;
  } catch (_) {
    return "";
  }
}

function RX_isMostlyPrintable(bytes) {
  try {
    if (!bytes || bytes.length <= 0) return false;
    let good = 0;
    for (let i = 0; i < bytes.length; i++) {
      const x = bytes[i] & 0xff;
      if (x === 9 || x === 10 || x === 13 || (x >= 32 && x < 127)) good += 1;
    }
    return (good / bytes.length) > 0.9;
  } catch (_) {
    return false;
  }
}

function RX_dumpProto(buf, depth, maxFields) {
  const out = [];
  try {
    const lim = Math.max(50, Math.min(20000, Number(maxFields) || 2000));
    let i = 0;
    let n = 0;
    const d = Math.max(0, Math.min(8, Number(depth) || 0));
    while (i < buf.length && n < lim) {
      const t = RX_readVarint(buf, i);
      if (t.err) break;
      const tag = t.v >>> 0;
      i = t.i;
      const field = tag >>> 3;
      const wire = tag & 7;
      const item = { field, wire };
      if (wire === 0) {
        const v = RX_readVarint(buf, i);
        i = v.i;
        item.varint = v.v;
      } else if (wire === 1) {
        if (i + 8 > buf.length) { item.error = "truncated64"; break; }
        item.fixed64hex = buf.slice(i, i + 8).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
        i += 8;
      } else if (wire === 2) {
        const ln0 = RX_readVarint(buf, i);
        if (ln0.err) break;
        const ln = ln0.v >>> 0;
        i = ln0.i;
        if (i + ln > buf.length) { item.error = "truncatedLen"; break; }
        const data = buf.slice(i, i + ln);
        i += ln;
        item.len = ln;
        if (RX_isMostlyPrintable(data)) item.utf8 = RX_decodeUtf8(data);
        item.hexHead = data.slice(0, 32).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
        if (ln >= 2 && d < 4) {
          const nested = RX_dumpProto(data, d + 1, 300);
          if (nested && nested.length) item.nested = nested;
        }
      } else if (wire === 5) {
        if (i + 4 > buf.length) { item.error = "truncated32"; break; }
        item.fixed32hex = buf.slice(i, i + 4).map(b => (b & 0xff).toString(16).padStart(2, "0")).join("");
        i += 4;
      } else {
        item.error = "unsupportedWire:" + String(wire);
        break;
      }
      out.push(item);
      n += 1;
    }
  } catch (_) {}
  return out;
}

function RX_findFirstFieldUtf8(fields, fieldNo) {
  try {
    for (let i = 0; i < fields.length; i++) {
      const it = fields[i];
      if (it && it.field === fieldNo && it.wire === 2 && typeof it.utf8 === "string" && it.utf8.length) return it.utf8;
    }
  } catch (_) {}
  return "";
}

function RX_findFirstNested(fields, fieldNo) {
  try {
    for (let i = 0; i < fields.length; i++) {
      const it = fields[i];
      if (it && it.field === fieldNo && it.wire === 2 && it.nested && it.nested.length) return it.nested;
    }
  } catch (_) {}
  return null;
}

function RX_extractPbFromProtoBytes(bytes) {
  const pb = { kind: "", text: "", caption: "", directPath: "", mediaKey: "", fileEncSha256: "", fileSha256: "" };
  const extra = { bytes32: [], mime: "", url: "", directPath: "", quoted: null, strings: [] };
  try {
    const top = RX_dumpProto(bytes, 0, 2000);
    let text = RX_findFirstFieldUtf8(top, 1);
    let quoted = null;
    if (!text) {
      const f6 = RX_findFirstNested(top, 6);
      if (f6) {
        const rt = RX_findFirstFieldUtf8(f6, 1);
        if (rt) text = rt;
        const f17 = RX_findFirstNested(f6, 17);
        if (f17) {
          const qStanza = RX_findFirstFieldUtf8(f17, 1);
          const qChat = RX_findFirstFieldUtf8(f17, 2);
          const f3 = RX_findFirstNested(f17, 3);
          const qText = f3 ? RX_findFirstFieldUtf8(f3, 1) : "";
          if (qStanza || qChat || qText) quoted = { stanzaId: qStanza, chatJid: qChat, text: qText };
        }
      }
    }
    if (text) {
      pb.kind = "text";
      pb.text = text;
    }
    if (quoted) extra.quoted = quoted;

    const bytes32 = [];
    const strings = [];
    const scan = (fields) => {
      for (let i = 0; i < fields.length; i++) {
        const it = fields[i];
        if (!it || it.wire !== 2) continue;
        if (typeof it.utf8 === "string" && it.utf8.length) {
          if (strings.length < 50) strings.push(it.utf8);
        }
        if (typeof it.len === "number" && it.len === 32 && typeof it.hexHead === "string" && it.hexHead.length >= 64) {
          if (bytes32.length < 20) bytes32.push(it.hexHead);
        }
        if (it.nested && it.nested.length) scan(it.nested);
      }
    };
    scan(top);
    extra.bytes32 = bytes32;
    extra.strings = strings.slice(0, 20);

    const pick = (pred) => {
      for (let i = 0; i < strings.length; i++) {
        const s = String(strings[i] || "");
        if (pred(s)) return s;
      }
      return "";
    };
    const mime = pick(s => s.indexOf("/") !== -1 && s.length <= 40 && (s.startsWith("image/") || s.startsWith("video/") || s.startsWith("audio/") || s.startsWith("application/")));
    if (mime) extra.mime = mime;
    const url = pick(s => s.startsWith("https://mmg.whatsapp.net/") || s.startsWith("http://mmg.whatsapp.net/"));
    if (url) extra.url = url;
    const directPath = pick(s => s.startsWith("/o1/v/") || s.startsWith("/v/t62") || s.indexOf("/o1/v/") !== -1 || s.indexOf("/v/t62") !== -1);
    if (directPath) extra.directPath = directPath;

    if (!pb.kind) {
      if (mime.startsWith("image/")) pb.kind = "image";
      else if (mime.startsWith("video/")) pb.kind = "video";
      else if (mime.startsWith("audio/")) pb.kind = "audio";
    }
    if (!pb.directPath && extra.directPath) pb.directPath = extra.directPath;
    if (!pb.directPath && extra.url) {
      try {
        const u = String(extra.url);
        const p = u.replace(/^https?:\/\/mmg\.whatsapp\.net\//, "/");
        const q = p.indexOf("?");
        pb.directPath = q >= 0 ? p.slice(0, q) : p;
      } catch (_) {}
    }
  } catch (_) {}
  return { pb, extra };
}

function RX_scoreProtoBytes(bytes) {
  try {
    if (!bytes || !bytes.length) return { score: -1, parsed: null, hasField35: false };
    const top = RX_dumpProto(bytes, 0, 800);
    const has35 = !!RX_findFirstNested(top, 35);
    const parsed = RX_extractPbFromProtoBytes(bytes);
    let score = 0;
    if (parsed && parsed.pb && parsed.pb.kind) score += 10;
    if (parsed && parsed.pb && parsed.pb.text) score += 6;
    if (parsed && parsed.extra && parsed.extra.quoted) score += 6;
    if (parsed && parsed.extra && parsed.extra.mime) score += 4;
    if (parsed && parsed.extra && (parsed.extra.directPath || parsed.extra.url)) score += 4;
    if (has35) score += 2;
    return { score, parsed, hasField35: has35 };
  } catch (_) {
    return { score: -1, parsed: null, hasField35: false };
  }
}

function RX_pickBestNSDataCandidate(cands) {
  try {
    let best = null;
    for (let i = 0; i < cands.length; i++) {
      const c = cands[i];
      if (!c || !c.data || !c.data.bytes || !c.data.bytes.length) continue;
      const scored = RX_scoreProtoBytes(c.data.bytes);
      const len = c.data.bytes.length | 0;
      const key = { score: scored.score, len, source: c.source, data: c.data, bytes: c.data.bytes, parsed: scored.parsed };
      if (!best) {
        best = key;
        continue;
      }
      if (key.score > best.score) {
        best = key;
        continue;
      }
      if (key.score === best.score && key.len > 0 && best.len > 0 && key.len < best.len) {
        best = key;
      }
    }
    return best;
  } catch (_) {
    return null;
  }
}

const RX_CONFIG = {
  moduleNameHints: ["WhatsApp", "WhatsAppDecrypted", "WhatsApp_Decrypted"],
  rva: 0x3aeeef0,
  cmdSelectors: [
    "reallyProcessResultsAfterSignalForContext:plaintextProtobuf:originalMessageData:notificationBehavior:journalID:error:retryCount:origin:reportEmptyPlaintextError:",
    "processResultsAfterSignalForContext:plaintextProtobuf:originalMessageData:notificationBehavior:journalID:error:retryCount:origin:reportEmptyPlaintextError:",
  ],
  enableObjcFallback: false,
  limits: { maxEvents: 0, maxLinesPerSecond: 60 },
  protobuf: { hardCapBytes: 256 * 1024, alwaysEmitB64: true },
};

const RX_ENABLED_DEFAULT = true;

const RX_AUTO_READ = { enabled: true, minIntervalMs: 3000, lastByChat: new Map() };
const RX_AUTO_READ_INFLIGHT = new Map();
const RX_AUTO_READ_WAIT = {
  maxWaitMs: 7000,
  stepsMs: [200, 400, 800, 1400, 2200, 3000],
};
const RX_AUTO_READ_STATS = {
  recv: 0,
  filtered: 0,
  filtered_reason: {},
  scheduled: 0,
  attempts: 0,
  ok: 0,
  fail: 0,
  fail_reason: {},
  last: null,
};

function RX_shouldAutoRead(chatJid, stanzaId, senderJid, isGroup, fromMe) {
  try {
    const cj = String(chatJid || "").trim();
    if (!cj) return false;
    if (cj === "status@broadcast") return false;
    if (cj.indexOf("@broadcast") !== -1) return false;
    const sid = String(stanzaId || "").trim();
    if (!sid) return false;
    if (isGroup === true) return false;
    if (fromMe === true) return false;
    const sj = String(senderJid || "").trim();
    if (sj && sj === "status@broadcast") return false;
    if (sj && sj.indexOf("@") === -1) return false;
    return true;
  } catch (_) {
    return false;
  }
}

function RX_markMessageReadByStanzaId(chatJidStr, stanzaIdStr, participantJidStr) {
  try {
    const core = _resolveCoreFixed();
    if (!core || !core.ok) return { ok: false, error: core && core.error ? String(core.error) : "no context" };
    const ctxMain = core.ctxMain;
    const storage = core.storage;
    let chatManager = null;
    try { if (_objcCanCall(ctxMain, "- chatManager")) chatManager = _safeObj(ctxMain["- chatManager"]()); } catch (_) { chatManager = null; }
    if (!chatManager) return { ok: false, error: "ctxMain.chatManager nil" };
    const sid = String(stanzaIdStr || "").trim();
    if (!sid) return { ok: false, error: "missing stanzaId" };
    const chatJid = _makeWAChatJIDFromString(chatJidStr);
    if (!chatJid) return { ok: false, error: "invalid chatJid" };
    const cs = _fetchChatSession(storage, chatJid);
    if (!cs) return { ok: false, error: "fetchChatSession failed" };
    const mcs = _getMutableChatSession(cs);
    if (!mcs) return { ok: false, error: "mutableChatSession missing" };
    const pj = String(participantJidStr || "").trim();
    const moc = _resolveManagedObjectContext(core);
    const fm = _fetchMessageByStanzaId(mcs, sid, pj, moc);
    if (!fm || !fm.msg) return { ok: false, error: "message not found by stanzaId" };
    const msg = fm.msg;
    const fetchVia = String(fm.via || "");
    const NSArray = ObjC.classes.NSArray;
    if (!NSArray || !NSArray["+ arrayWithObject:"]) return { ok: false, error: "NSArray unavailable" };
    const sessions = NSArray.arrayWithObject_(cs);
    const actions = [];
    const selRR = "- sendReadReceiptsForMessagesBeforeAndIncludingMessage:inChatSession:isMarkedByUser:";
    let rrOk = false;
    if (_objcCanCall(chatManager, selRR)) {
      try {
        chatManager[selRR](msg, cs, true);
        rrOk = true;
        actions.push("WAChatManager.sendReadReceiptsForMessagesBeforeAndIncludingMessage:inChatSession:isMarkedByUser:");
      } catch (_) {}
    }
    const selMark = "- markChatSessions:read:sendReadReceipts:isMarkedByUser:error:";
    if (_objcCanCall(chatManager, selMark)) {
      try {
        const errPtr = Memory.alloc(Process.pointerSize);
        Memory.writePointer(errPtr, ptr("0x0"));
        const ok = chatManager[selMark](sessions, true, false, true, errPtr);
        let errText = "";
        try {
          const ep = Memory.readPointer(errPtr);
          const eo = ep && !ep.isNull() ? _safeObj(ep) : null;
          if (eo) errText = String(eo);
        } catch (_) {}
        actions.push("WAChatManager.markChatSessions:read:sendReadReceipts:isMarkedByUser:error:");
        if (!!ok || rrOk) return { ok: true, used: actions.join(","), error: errText, fetchVia: fetchVia };
      } catch (_) {}
    }
    const selAsRead = "- markChatSessionsAsRead:";
    if (_objcCanCall(chatManager, selAsRead)) {
      try {
        chatManager[selAsRead](sessions);
        actions.push("WAChatManager.markChatSessionsAsRead:");
        if (rrOk) return { ok: true, used: actions.join(",") };
      } catch (_) {}
    }
    if (rrOk) return { ok: true, used: actions.join(","), fetchVia: fetchVia };
    return { ok: false, error: actions.length ? "read call failed" : "WAChatManager read selectors missing", used: actions.join(","), fetchVia: fetchVia };
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function RX_recordStat(mapObj, key) {
  try {
    const k = String(key || "").trim() || "unknown";
    mapObj[k] = (mapObj[k] || 0) + 1;
  } catch (_) {}
}

function RX_tryAutoReadOnMain(chatJid, stanzaId, senderJid, attemptIdx) {
  try {
    const cj = String(chatJid || "").trim();
    const sid = String(stanzaId || "").trim();
    let sj = String(senderJid || "").trim();
    if (!sj && cj && cj.indexOf("@") !== -1 && cj !== "status@broadcast" && cj.indexOf("@broadcast") === -1) {
      sj = cj;
    }
    const inflightKey = cj + "|" + sid;
    try {
      const st = RX_AUTO_READ_INFLIGHT.get(inflightKey);
      if (st && st.done === true) return { done: true, ok: true };
    } catch (_) {}
    RX_AUTO_READ_STATS.attempts += 1;
    const res = RX_markMessageReadByStanzaId(cj, sid, sj);
    if (res && res.ok) {
      RX_AUTO_READ_STATS.ok += 1;
      try {
        const st = RX_AUTO_READ_INFLIGHT.get(inflightKey) || {};
        st.done = true;
        RX_AUTO_READ_INFLIGHT.set(inflightKey, st);
      } catch (_) {}
      RX_AUTO_READ_STATS.last = { ok: true, atMs: Date.now(), chatJid: cj, stanzaId: sid, senderJid: sj, attempt: attemptIdx, used: String(res.used || ""), fetchVia: String(res.fetchVia || "") };
      return { done: true, ok: true };
    }
    const err = res && res.error ? String(res.error) : "failed";
    RX_AUTO_READ_STATS.fail += 1;
    RX_recordStat(RX_AUTO_READ_STATS.fail_reason, err);
    RX_AUTO_READ_STATS.last = { ok: false, atMs: Date.now(), chatJid: cj, stanzaId: sid, senderJid: sj, attempt: attemptIdx, error: err, used: String(res && res.used ? res.used : ""), fetchVia: String(res && res.fetchVia ? res.fetchVia : "") };
    const retryable = err.indexOf("message not found") !== -1 || err.indexOf("fetchChatSession failed") !== -1 || err.indexOf("mutableChatSession missing") !== -1;
    return { done: !retryable, ok: false };
  } catch (_) {
    return { done: true, ok: false };
  }
}

function RX_scheduleAutoRead(chatJid, stanzaId, senderJid, isGroup, fromMe) {
  try {
    RX_AUTO_READ_STATS.recv += 1;
    if (!RX_AUTO_READ.enabled) return;
    if (!RX_shouldAutoRead(chatJid, stanzaId, senderJid, isGroup, fromMe)) {
      RX_AUTO_READ_STATS.filtered += 1;
      let reason = "unknown";
      const cj = String(chatJid || "").trim();
      const sid = String(stanzaId || "").trim();
      const sj = String(senderJid || "").trim();
      if (!cj) reason = "no_chat";
      else if (!sid) reason = "no_stanza";
      else if (isGroup === true) reason = "group";
      else if (fromMe === true) reason = "from_me";
      else if (!sj || sj.indexOf("@") === -1) reason = "no_sender";
      else if (cj === "status@broadcast" || cj.indexOf("@broadcast") !== -1) reason = "broadcast";
      RX_recordStat(RX_AUTO_READ_STATS.filtered_reason, reason);
      RX_AUTO_READ_STATS.last = { ok: false, atMs: Date.now(), stage: "filtered", chatJid: cj, stanzaId: sid, senderJid: sj, reason: reason };
      return;
    }
    const key = String(chatJid || "").trim();
    const now = Date.now();
    const last = RX_AUTO_READ.lastByChat.get(key) || 0;
    if (now - last < RX_AUTO_READ.minIntervalMs) return;
    RX_AUTO_READ.lastByChat.set(key, now);
    RX_AUTO_READ_STATS.scheduled += 1;
    const sid = String(stanzaId || "").trim();
    const pj = String(senderJid || "").trim();
    const inflightKey = key + "|" + sid;
    try {
      const st = RX_AUTO_READ_INFLIGHT.get(inflightKey);
      if (st && st.atMs && now - Number(st.atMs) < 120000) return;
      RX_AUTO_READ_INFLIGHT.set(inflightKey, { atMs: now, done: false, tries: 0 });
      setTimeout(() => { try { RX_AUTO_READ_INFLIGHT.delete(inflightKey); } catch (_) {} }, 180000);
    } catch (_) {}
    const fire = () => {
      try {
        const st = RX_AUTO_READ_INFLIGHT.get(inflightKey);
        if (!st || st.done === true) return;
        st.tries = (Number(st.tries) || 0) + 1;
        RX_AUTO_READ_INFLIGHT.set(inflightKey, st);
        const r = _runOnMainQueueSync(() => { try { return RX_tryAutoReadOnMain(key, sid, pj, st.tries - 1); } catch (_) { return null; } }, 1500);
        const done = !!(r && r.done === true);
        const ok = !!(r && r.ok === true);
        if (done || ok) {
          st.done = true;
          RX_AUTO_READ_INFLIGHT.set(inflightKey, st);
          return;
        }
        const elapsed = Date.now() - (Number(st.atMs) || now);
        if (elapsed >= RX_AUTO_READ_WAIT.maxWaitMs) {
          st.done = true;
          RX_AUTO_READ_INFLIGHT.set(inflightKey, st);
          return;
        }
        const idx = Math.min((Number(st.tries) || 1) - 1, RX_AUTO_READ_WAIT.stepsMs.length - 1);
        const d = RX_AUTO_READ_WAIT.stepsMs[idx] || 3000;
        setTimeout(fire, d);
      } catch (_) {}
    };
    setTimeout(fire, RX_AUTO_READ_WAIT.stepsMs[0] || 3000);
  } catch (_) {}
}

function RX_installObjCBySelectors(selectors) {
  try {
    if (!RX_objcAvailable()) throw new Error("ObjC unavailable");
    const sels = (selectors || []).map(s => String(s)).filter(Boolean);
    if (!sels.length) throw new Error("no selectors");
    const loaded = ObjC.enumerateLoadedClassesSync();
    const classNames = [];
    for (const k of Object.keys(loaded || {})) {
      const arr = loaded[k] || [];
      for (let i = 0; i < arr.length; i++) classNames.push(String(arr[i] || ""));
    }
    const hooks = [];
    for (let i = 0; i < classNames.length; i++) {
      const cn = classNames[i];
      if (!cn || !(cn.startsWith("WA") || cn.indexOf("WA") !== -1)) continue;
      const cls = ObjC.classes[cn];
      if (!cls) continue;
      for (let j = 0; j < sels.length; j++) {
        const sel = sels[j];
        const m = cls["- " + sel];
        if (!m || !m.implementation) continue;
        const impl = m.implementation;
        if (hooks.find(h => h.impl && h.impl.equals && h.impl.equals(impl))) continue;
        Interceptor.attach(impl, {
          onEnter(args) {
            try {
              RX_STATE.hitsTotal = (Number(RX_STATE.hitsTotal) || 0) + 1;
              RX_STATE.lastHitTs = Date.now();
              let cmdSel = null;
              try { cmdSel = ObjC.selectorAsString(args[1]); } catch (_) { cmdSel = null; }
              RX_STATE.lastCmdSel = cmdSel ? String(cmdSel) : "";
              const ctxPtr = args[2];
              const arg3Ptr = args[3];
              const arg4Ptr = args[4];
              const arg5Ptr = args[5];
              const stanza = RX_extractStanzaFieldsFromContext(ctxPtr);
              const cand3 = RX_tryReadNSDataAll(arg3Ptr, RX_CONFIG.protobuf.hardCapBytes);
              const cand4 = RX_tryReadNSDataAll(arg4Ptr, RX_CONFIG.protobuf.hardCapBytes);
              const best = RX_pickBestNSDataCandidate([
                { source: "arg3", data: cand3 },
                { source: "arg4", data: cand4 },
              ]);
              const data = best ? best.data : (cand3 || cand4);
              const source = best ? best.source : (cand3 ? "arg3" : (cand4 ? "arg4" : null));
              const bytes = best && best.bytes ? best.bytes : (data ? data.bytes : null);
              const b64 = (bytes && RX_CONFIG.protobuf.alwaysEmitB64) ? RX_bytesToBase64(bytes) : "";
              const proto = data ? {
                len: data.totalLen,
                truncated: data.truncated,
                b64: b64 || null,
                hexChunks: null,
              } : null;
              const parsed = best && best.parsed ? best.parsed : ((bytes && bytes.length) ? RX_extractPbFromProtoBytes(bytes) : null);
              const chatJID = stanza.chatJID ? String(stanza.chatJID) : "";
              const stanzaId = stanza.stanzaId ? String(stanza.stanzaId) : "";
              const senderJID = stanza.senderJID ? String(stanza.senderJID) : "";
              const statusAuthorJID = stanza.statusAuthorJID ? String(stanza.statusAuthorJID) : "";
              const isGroup = (stanza.isGroup === true || stanza.isGroup === false) ? stanza.isGroup : null;
              const fromMe = (stanza.isFromMe === true || stanza.isFromMe === false) ? stanza.isFromMe : null;
              const uniqueKey = stanza.uniqueKey ? String(stanza.uniqueKey) : "";
              const isStatus = (chatJID || "").toLowerCase() === "status@broadcast";
              const participantJID = isStatus ? statusAuthorJID : senderJID;
              send({
                type: "wa.recv.update",
                build: SCRIPT_BUILD_ID,
                ts: Date.now(),
                phase: "objc_post_decrypt_pinned_style",
                data: {
                  stanzaId: stanzaId,
                  route: {
                    via: "objc_post_decrypt",
                    chatJID: chatJID,
                    remoteChat: chatJID,
                    participantJID: participantJID,
                    statusAuthorJID: statusAuthorJID,
                    isStatus: isStatus,
                    fromMe: fromMe === true,
                    isGroup: isGroup,
                    uniqueKey: uniqueKey,
                  },
                  protobuf: proto,
                  pb: parsed,
                  diag: { cmdSel: cmdSel ? String(cmdSel) : null, protobufSource: proto ? source : null, waVersion: RX_STATE.waVersion ? String(RX_STATE.waVersion) : null },
                  rawType: "wa.recv.objc_post_decrypt.pinned_style",
                },
              });
              RX_STATE.hitsEmitted = (Number(RX_STATE.hitsEmitted) || 0) + 1;
            } catch (_) {}
          },
        });
        hooks.push({ className: cn, selector: sel, impl: impl });
        if (hooks.length >= 6) break;
      }
      if (hooks.length >= 6) break;
    }
    RX_STATE.objcHooks = hooks;
    RX_STATE.mode = hooks.length ? "objc" : (RX_STATE.mode || "");
    return hooks.length;
  } catch (e) {
    RX_STATE.objcHooks = RX_STATE.objcHooks || [];
    return 0;
  }
}

function RX_install() {
  try {
    if (!RX_objcAvailable()) throw new Error("ObjC unavailable");
    if (!RX_STATE.waVersion) {
      try { RX_STATE.waVersion = RX_getMainBundleVersionString(); } catch (_) {}
    }
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
          RX_STATE.hitsTotal = (Number(RX_STATE.hitsTotal) || 0) + 1;
          RX_STATE.lastHitTs = Date.now();
          const maxEvents = Number(RX_CONFIG.limits.maxEvents) || 0;
          if (maxEvents > 0 && events >= maxEvents) return;
          const tid = Process.getCurrentThreadId();
          if (reentry[tid]) return;
          reentry[tid] = { tid: tid };
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
          RX_STATE.lastCmdSel = cmdSel ? String(cmdSel) : "";
          if (RX_CONFIG.cmdSelectors && RX_CONFIG.cmdSelectors.length) {
            if (!cmdSel || RX_CONFIG.cmdSelectors.indexOf(String(cmdSel)) === -1) {
              RX_STATE.hitsFiltered = (Number(RX_STATE.hitsFiltered) || 0) + 1;
              return;
            }
          }

          const ctxPtr = args[2];
          const arg3Ptr = args[3];
          const arg4Ptr = args[4];
          const arg5Ptr = args[5];

          const doWork = () => {
            try {
              const stanza = RX_extractStanzaFieldsFromContext(ctxPtr);
          const cand3 = RX_tryReadNSDataAll(arg3Ptr, RX_CONFIG.protobuf.hardCapBytes);
          const cand4 = RX_tryReadNSDataAll(arg4Ptr, RX_CONFIG.protobuf.hardCapBytes);
              const best = RX_pickBestNSDataCandidate([
                { source: "arg3", data: cand3 },
                { source: "arg4", data: cand4 },
              ]);
          const data = best ? best.data : (cand3 || cand4);
          const source = best ? best.source : (cand3 ? "arg3" : (cand4 ? "arg4" : null));
              const bytes = best && best.bytes ? best.bytes : (data ? data.bytes : null);
              const b64 = (bytes && RX_CONFIG.protobuf.alwaysEmitB64) ? RX_bytesToBase64(bytes) : "";
              const proto = data ? {
                len: data.totalLen,
                truncated: data.truncated,
                b64: b64 || null,
                hexChunks: null,
              } : null;
              const parsed = best && best.parsed ? best.parsed : ((bytes && bytes.length) ? RX_extractPbFromProtoBytes(bytes) : null);

              const chatJID = stanza.chatJID ? String(stanza.chatJID) : "";
              const stanzaId = stanza.stanzaId ? String(stanza.stanzaId) : "";
              const senderJID = stanza.senderJID ? String(stanza.senderJID) : "";
              const statusAuthorJID = stanza.statusAuthorJID ? String(stanza.statusAuthorJID) : "";
              const isGroup = (stanza.isGroup === true || stanza.isGroup === false) ? stanza.isGroup : null;
              const fromMe = (stanza.isFromMe === true || stanza.isFromMe === false) ? stanza.isFromMe : null;
              const uniqueKey = stanza.uniqueKey ? String(stanza.uniqueKey) : "";
              const isStatus = (chatJID || "").toLowerCase() === "status@broadcast";
              const participantJID = isStatus ? statusAuthorJID : senderJID;

              try {
                const tid = Process.getCurrentThreadId();
            if (reentry[tid] && typeof reentry[tid] === "object") {
              reentry[tid].autoRead = { chatJID: chatJID, stanzaId: stanzaId, senderJID: senderJID, isGroup: isGroup, fromMe: fromMe };
                }
              } catch (_) {}
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
                    participantJID: participantJID,
                    statusAuthorJID: statusAuthorJID,
                    isStatus: isStatus,
                    fromMe: fromMe === true,
                    isGroup: isGroup,
                    uniqueKey: uniqueKey,
                  },
                  protobuf: proto,
                  diag: { cmdSel: cmdSel ? String(cmdSel) : null, protobufSource: proto ? source : null, waVersion: RX_STATE.waVersion ? String(RX_STATE.waVersion) : null },
                  rawType: "wa.recv.native_post_decrypt.pinned_style",
                },
              });
              RX_STATE.hitsEmitted = (Number(RX_STATE.hitsEmitted) || 0) + 1;
              if (RX_SAMPLE.enabled) {
                send({
                  type: "qqw.sample",
                  event_id: 0,
                  device_id: "",
                  wa_version: RX_STATE.waVersion ? String(RX_STATE.waVersion) : "",
                  script_build: SCRIPT_BUILD_ID,
                  wa_event_type: "wa.recv.update",
                  chat_jid: chatJID,
                  stanza_id: stanzaId,
                  msg_kind: String(RX_SAMPLE.msg_kind || "unknown"),
                  quoted_kind: String(RX_SAMPLE.quoted_kind || "none"),
                  quoted_stanza_id: String(RX_SAMPLE.quoted_stanza_id || ""),
                  protobuf_len: data ? (data.totalLen | 0) : 0,
                  protobuf_truncated: !!(data && data.truncated),
                  protobuf_b64: b64 || ""
                });
              }
            } catch (_) {}
          };

          try { doWork(); } catch (_) { RX_safeObjCInvoke(doWork); }
        } catch (_) {}
      },
      onLeave() {
        try {
          const tid = Process.getCurrentThreadId();
          const st = reentry[tid];
          if (st && typeof st === "object" && st.autoRead) {
            try {
              const a = st.autoRead;
              RX_scheduleAutoRead(a.chatJID, a.stanzaId, a.senderJID, a.isGroup, a.fromMe);
            } catch (_) {}
          }
          if (reentry[tid]) delete reentry[tid];
        } catch (_) {}
      },
    });

    RX_STATE.installed = true;
    RX_STATE.installedAt = String(addr);
    RX_STATE.error = null;
    RX_STATE.mode = "rva";
    setTimeout(() => {
      try {
        if (!RX_STATE.installed) return;
        if ((Number(RX_STATE.hitsTotal) || 0) > 0) return;
        if (RX_STATE.mode === "objc") return;
        if (!RX_CONFIG.enableObjcFallback) return;
        RX_installObjCBySelectors(RX_CONFIG.cmdSelectors);
      } catch (_) {}
    }, 5000);
  } catch (e) {
    RX_STATE.installed = false;
    RX_STATE.error = String(e);
  }
}

setImmediate(() => {
  try { if (RX_ENABLED_DEFAULT) RX_install(); } catch (_) {}
});

setInterval(() => {
  try {
    send({
      type: "qqw.pong",
      build: SCRIPT_BUILD_ID,
      ts: Date.now(),
      ok: true,
      rxInstalled: !!RX_STATE.installed,
      rxErr: RX_STATE.error ? String(RX_STATE.error) : "",
      waVersion: RX_STATE.waVersion ? String(RX_STATE.waVersion) : "",
      rxHit: {
        total: Number(RX_STATE.hitsTotal) || 0,
        emitted: Number(RX_STATE.hitsEmitted) || 0,
        filtered: Number(RX_STATE.hitsFiltered) || 0,
        lastTs: Number(RX_STATE.lastHitTs) || 0,
        lastCmdSel: RX_STATE.lastCmdSel ? String(RX_STATE.lastCmdSel) : "",
        mode: RX_STATE.mode ? String(RX_STATE.mode) : "",
        objcHooks: (RX_STATE.objcHooks && RX_STATE.objcHooks.length) ? RX_STATE.objcHooks.length : 0,
        rva: Number(RX_CONFIG.rva) || 0,
      },
      autoRead: {
        recv: RX_AUTO_READ_STATS.recv | 0,
        filtered: RX_AUTO_READ_STATS.filtered | 0,
        scheduled: RX_AUTO_READ_STATS.scheduled | 0,
        attempts: RX_AUTO_READ_STATS.attempts | 0,
        ok: RX_AUTO_READ_STATS.ok | 0,
        fail: RX_AUTO_READ_STATS.fail | 0,
        last: RX_AUTO_READ_STATS.last || null,
      },
    });
  } catch (_) {}
}, 15000);
