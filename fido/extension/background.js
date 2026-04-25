"use strict";

// ============================================================
// JPKI FIDO2 Authenticator - Service Worker (background.js)
// ============================================================

const NATIVE_HOST = "com.github.jpki.fido2";

const POPUP_APPROVAL = "approval";
const POPUP_ACCOUNT_SELECT = "account-select";

const POPUP_TIMEOUT_MS = 60000;

// --- 排他制御 ---
let activeRequestId = null;
let activeRequestCanceled = false;

// --- ポップアップ制御 ---
// kind => { resolve, reject, windowId, timeoutId, data }
const popups = new Map();

// ============================================================
// エラー型
// ============================================================

/// プロキシリクエスト処理用のエラー。
/// errorName: WebAuthn 側に返す DOMException 名（"NotAllowedError" など）
/// silent:    true の場合 error popup を表示しない（期待されたエラー）
class ProxyError extends Error {
  constructor(message, { errorName = "NotAllowedError", silent = false } = {}) {
    super(message);
    this.errorName = errorName;
    this.silent = silent;
  }
}

/// ユーザーがポップアップを閉じた／拒否した／タイムアウトした
class UserCancelledError extends ProxyError {
  constructor(message) {
    super(message, { silent: true });
  }
}

// ============================================================
// Base64 / Base64URL
// ============================================================
//
// Native Messaging プロトコル: 標準 base64 (mpa の慣習に揃える)
// WebAuthn API:                base64url (仕様)

function bytesToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function base64urlEncode(buffer) {
  return bytesToBase64(buffer).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(str) {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  return base64ToBytes(base64);
}

// ============================================================
// CBOR 最小エンコーダ
// ============================================================

function cborEncodeUint(major, value) {
  const majorBits = major << 5;
  if (value < 24) return [majorBits | value];
  if (value < 0x100) return [majorBits | 24, value];
  if (value < 0x10000) return [majorBits | 25, (value >> 8) & 0xff, value & 0xff];
  return [majorBits | 26, (value >> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff];
}

function cborEncodeNegInt(value) {
  return cborEncodeUint(1, -(value + 1));
}

function cborEncodeBytes(data) {
  return [...cborEncodeUint(2, data.length), ...data];
}

function cborEncodeText(str) {
  const bytes = new TextEncoder().encode(str);
  return [...cborEncodeUint(3, bytes.length), ...bytes];
}

function cborEncodeIntKey(key) {
  return key < 0 ? cborEncodeNegInt(key) : cborEncodeUint(0, key);
}

function cborEncodeValue(value) {
  if (value instanceof Uint8Array) return cborEncodeBytes(value);
  if (typeof value === "string") return cborEncodeText(value);
  if (typeof value === "number") return value < 0 ? cborEncodeNegInt(value) : cborEncodeUint(0, value);
  throw new Error("Unsupported CBOR value type");
}

/// 整数キーのCBORマップ。entries: [[key, value], ...]
function cborEncodeIntMap(entries) {
  const out = [...cborEncodeUint(5, entries.length)];
  for (const [key, value] of entries) {
    out.push(...cborEncodeIntKey(key));
    out.push(...cborEncodeValue(value));
  }
  return new Uint8Array(out);
}

// ============================================================
// COSE 公開鍵 (Ed25519)
// ============================================================

function encodeCoseEd25519PublicKey(publicKey) {
  return cborEncodeIntMap([
    [1, 1],          // kty: OKP
    [3, -8],         // alg: EdDSA
    [-1, 6],         // crv: Ed25519
    [-2, publicKey], // x
  ]);
}

// ============================================================
// SubjectPublicKeyInfo (Ed25519)
// ============================================================

function buildEd25519Spki(publicKey) {
  const prefix = new Uint8Array([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x03, 0x21, 0x00,
  ]);
  const spki = new Uint8Array(prefix.length + 32);
  spki.set(prefix);
  spki.set(publicKey, prefix.length);
  return spki;
}

// ============================================================
// Authenticator データ構築
// ============================================================

async function rpIdHash(rpId) {
  return new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId))
  );
}

/// 登録時 (AT=1)
async function buildAttestedAuthenticatorData(rpId, credentialId, publicKey) {
  const hash = await rpIdHash(rpId);
  const flags = 0x45; // UP=1, UV=1, AT=1
  const aaguid = new Uint8Array(16); // nil UUID
  const credIdLen = new Uint8Array([
    (credentialId.length >> 8) & 0xff,
    credentialId.length & 0xff,
  ]);
  const coseKey = encodeCoseEd25519PublicKey(publicKey);

  const totalLen = 32 + 1 + 4 + 16 + 2 + credentialId.length + coseKey.length;
  const authData = new Uint8Array(totalLen);
  let offset = 0;
  authData.set(hash, offset); offset += 32;
  authData[offset] = flags; offset += 1;
  // signCount (4B) は 0 のまま
  offset += 4;
  authData.set(aaguid, offset); offset += 16;
  authData.set(credIdLen, offset); offset += 2;
  authData.set(credentialId, offset); offset += credentialId.length;
  authData.set(coseKey, offset);
  return authData;
}

/// 認証時 (AT=0)
async function buildAssertionAuthenticatorData(rpId) {
  const hash = await rpIdHash(rpId);
  const authData = new Uint8Array(37);
  authData.set(hash, 0);
  authData[32] = 0x05; // UP=1, UV=1, AT=0
  // signCount (4B) は 0 のまま
  return authData;
}

// ============================================================
// clientDataJSON
// ============================================================

/// Chrome は requestDetailsJson の extensions.remoteDesktopClientOverride に
/// 呼び出し元 origin を注入する。Web ページ側からは設定不可（信頼できる）。
function extractCallerContext(options) {
  const override = options.extensions?.remoteDesktopClientOverride;
  if (!override || typeof override.origin !== "string") {
    throw new ProxyError(
      "remoteDesktopClientOverride.origin missing in requestDetailsJson"
    );
  }
  return {
    origin: override.origin,
    crossOrigin: override.sameOriginWithAncestors === false,
  };
}

function buildClientDataJSON(type, challenge, origin, crossOrigin) {
  return JSON.stringify({ type, challenge, origin, crossOrigin });
}

// ============================================================
// attestationObject
// ============================================================

function buildAttestationObject(authData) {
  const out = [];
  out.push(...cborEncodeUint(5, 3));
  out.push(...cborEncodeText("fmt"));
  out.push(...cborEncodeText("none"));
  out.push(...cborEncodeText("attStmt"));
  out.push(...cborEncodeUint(5, 0)); // empty map
  out.push(...cborEncodeText("authData"));
  out.push(...cborEncodeBytes(authData));
  return new Uint8Array(out);
}

// ============================================================
// Native Messaging
// ============================================================

function sendNative(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new ProxyError(chrome.runtime.lastError.message || "Native messaging failed"));
        return;
      }
      if (!response) {
        reject(new ProxyError("Native host returned no response"));
        return;
      }
      if (response.result !== "0") {
        reject(new ProxyError(response.message || "Native host error"));
        return;
      }
      resolve(response);
    });
  });
}

async function nativeDerive(pin, rpId, userId) {
  const res = await sendNative({
    mode: "derive",
    pin,
    rpId,
    userId: bytesToBase64(userId),
  });
  return {
    publicKey: base64ToBytes(res.publicKey),
    credentialId: base64ToBytes(res.credentialId),
  };
}

async function nativeSign(pin, rpId, userId, message) {
  const res = await sendNative({
    mode: "sign",
    pin,
    rpId,
    userId: bytesToBase64(userId),
    message: bytesToBase64(message),
  });
  return {
    publicKey: base64ToBytes(res.publicKey),
    credentialId: base64ToBytes(res.credentialId),
    signature: base64ToBytes(res.signature),
  };
}

// ============================================================
// ストレージ操作
// ============================================================

async function loadCredentials() {
  const result = await chrome.storage.local.get("credentials");
  return result.credentials || {};
}

async function saveCredential(rpId, userId, userDisplayName, credentialId) {
  const credentials = await loadCredentials();
  if (!credentials[rpId]) credentials[rpId] = [];

  const userIdB64 = base64urlEncode(userId);
  const credIdB64 = base64urlEncode(credentialId);

  const displayName =
    userDisplayName && userDisplayName.trim()
      ? userDisplayName
      : userIdB64.substring(0, 8);

  const entry = {
    userId: userIdB64,
    userDisplayName: displayName,
    credentialId: credIdB64,
    createdAt: Math.floor(Date.now() / 1000),
  };

  // 同一 (rpId, userId) は上書き、なければ追加
  const idx = credentials[rpId].findIndex((c) => c.userId === userIdB64);
  if (idx >= 0) {
    credentials[rpId][idx] = entry;
  } else {
    credentials[rpId].push(entry);
  }

  await chrome.storage.local.set({ credentials });
}

async function findCredentialsByRpId(rpId) {
  const credentials = await loadCredentials();
  return credentials[rpId] || [];
}

async function findCredentialInRp(rpId, credentialIdB64) {
  const entries = await findCredentialsByRpId(rpId);
  return entries.find((c) => c.credentialId === credentialIdB64) || null;
}

// ============================================================
// ポップアップ制御
// ============================================================

function openPopup(kind, url, data, { width = 420, height = 420 } = {}) {
  return new Promise((resolve, reject) => {
    chrome.windows.create(
      {
        url: chrome.runtime.getURL(url),
        type: "popup",
        width,
        height,
        focused: true,
      },
      (win) => {
        const windowId = win.id;
        const timeoutId = setTimeout(() => {
          rejectPopup(kind, new UserCancelledError("Timeout"));
        }, POPUP_TIMEOUT_MS);

        const onRemoved = (removedId) => {
          if (removedId !== windowId) return;
          chrome.windows.onRemoved.removeListener(onRemoved);
          rejectPopup(kind, new UserCancelledError("Window closed"));
        };
        chrome.windows.onRemoved.addListener(onRemoved);

        popups.set(kind, { resolve, reject, windowId, timeoutId, data });
      }
    );
  });
}

function resolvePopup(kind, value) {
  const p = popups.get(kind);
  if (!p) return;
  popups.delete(kind);
  clearTimeout(p.timeoutId);
  chrome.windows.remove(p.windowId).catch(() => {});
  p.resolve(value);
}

function rejectPopup(kind, error) {
  const p = popups.get(kind);
  if (!p) return;
  popups.delete(kind);
  clearTimeout(p.timeoutId);
  chrome.windows.remove(p.windowId).catch(() => {});
  p.reject(error);
}

function getPopupData(kind) {
  return popups.get(kind)?.data;
}

function showApprovalPopup(rpId, userDisplayName, operationType) {
  return openPopup(POPUP_APPROVAL, "approval/approval.html", {
    rpId,
    userDisplayName,
    operationType,
  });
}

function showAccountSelectPopup(rpId, accounts) {
  return openPopup(POPUP_ACCOUNT_SELECT, "account-select/account-select.html", {
    rpId,
    accounts,
  });
}

function showErrorPopup(message) {
  const url = `error/error.html?message=${encodeURIComponent(message)}`;
  chrome.windows.create({
    url: chrome.runtime.getURL(url),
    type: "popup",
    width: 420,
    height: 220,
    focused: true,
  });
}

// ============================================================
// プロキシリクエスト共通処理
// ============================================================

/// 排他ロック・エラーハンドリング・complete*Request の呼び出しをまとめる。
/// body は responseJson 文字列を返す。失敗時は例外（ProxyError 推奨）を投げる。
async function handleProxyRequest(request, completeFn, body) {
  if (activeRequestId !== null) {
    completeFn({
      requestId: request.requestId,
      error: { name: "InvalidStateError", message: "Authenticator is busy" },
    });
    return;
  }

  activeRequestId = request.requestId;
  activeRequestCanceled = false;

  try {
    const responseJson = await body();
    if (!activeRequestCanceled) {
      completeFn({ requestId: request.requestId, responseJson });
    }
  } catch (e) {
    if (activeRequestCanceled) return; // Chrome 側がキャンセル済み
    console.error("proxy request error:", e);
    if (!e.silent && e.message) {
      showErrorPopup(e.message);
    }
    completeFn({
      requestId: request.requestId,
      error: {
        name: e.errorName || "NotAllowedError",
        message: e.message || "User rejected",
      },
    });
  } finally {
    activeRequestId = null;
  }
}

// ============================================================
// 登録リクエスト処理 (onCreateRequest)
// ============================================================

async function handleCreateRequest(request) {
  await handleProxyRequest(
    request,
    chrome.webAuthenticationProxy.completeCreateRequest,
    async () => {
      const options = JSON.parse(request.requestDetailsJson);

      if (!options.pubKeyCredParams.some((p) => p.alg === -8)) {
        throw new ProxyError("Only EdDSA (Ed25519) is supported", {
          errorName: "NotSupportedError",
          silent: true,
        });
      }

      const rpId = options.rp.id || options.rpId;
      const userId = base64urlDecode(options.user.id);
      const userDisplayName = options.user.displayName || options.user.name || "";
      const challenge = options.challenge;
      const { origin, crossOrigin } = extractCallerContext(options);

      const pin = await showApprovalPopup(
        rpId,
        userDisplayName || base64urlEncode(userId).substring(0, 8),
        "create"
      );

      const { publicKey, credentialId } = await nativeDerive(pin, rpId, userId);

      await saveCredential(rpId, userId, userDisplayName, credentialId);

      const authData = await buildAttestedAuthenticatorData(rpId, credentialId, publicKey);
      const clientDataJSON = buildClientDataJSON("webauthn.create", challenge, origin, crossOrigin);
      const attestationObject = buildAttestationObject(authData);
      const spki = buildEd25519Spki(publicKey);

      return JSON.stringify({
        id: base64urlEncode(credentialId),
        rawId: base64urlEncode(credentialId),
        type: "public-key",
        response: {
          attestationObject: base64urlEncode(attestationObject),
          clientDataJSON: base64urlEncode(new TextEncoder().encode(clientDataJSON)),
          authenticatorData: base64urlEncode(authData),
          publicKey: base64urlEncode(spki),
          publicKeyAlgorithm: -8,
          transports: [],
        },
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
      });
    }
  );
}

// ============================================================
// 認証リクエスト処理 (onGetRequest)
// ============================================================

async function resolveCredentialForGet(rpId, allowCredentials) {
  if (allowCredentials.length > 0) {
    for (const cred of allowCredentials) {
      const entry = await findCredentialInRp(rpId, cred.id);
      if (entry) return entry;
    }
    throw new ProxyError("No matching credential found", { silent: true });
  }

  const entries = await findCredentialsByRpId(rpId);
  if (entries.length === 0) {
    throw new ProxyError("No credentials found for this RP", { silent: true });
  }
  if (entries.length === 1) {
    return entries[0];
  }

  const accounts = entries.map((e) => ({
    userId: e.userId,
    userDisplayName: e.userDisplayName,
    credentialId: e.credentialId,
  }));
  const selectedUserId = await showAccountSelectPopup(rpId, accounts);
  return entries.find((e) => e.userId === selectedUserId);
}

async function handleGetRequest(request) {
  await handleProxyRequest(
    request,
    chrome.webAuthenticationProxy.completeGetRequest,
    async () => {
      const options = JSON.parse(request.requestDetailsJson);
      const rpId = options.rpId;
      const challenge = options.challenge;
      const { origin, crossOrigin } = extractCallerContext(options);
      const allowCredentials = options.allowCredentials || [];

      const entry = await resolveCredentialForGet(rpId, allowCredentials);
      const userId = base64urlDecode(entry.userId);

      const pin = await showApprovalPopup(rpId, entry.userDisplayName, "get");

      const authData = await buildAssertionAuthenticatorData(rpId);
      const clientDataJSON = buildClientDataJSON("webauthn.get", challenge, origin, crossOrigin);
      const clientDataJSONBytes = new TextEncoder().encode(clientDataJSON);
      const clientDataHash = new Uint8Array(
        await crypto.subtle.digest("SHA-256", clientDataJSONBytes)
      );

      // 署名対象 = authenticatorData || SHA-256(clientDataJSON)
      const signedData = new Uint8Array(authData.length + clientDataHash.length);
      signedData.set(authData, 0);
      signedData.set(clientDataHash, authData.length);

      const { credentialId, signature } = await nativeSign(pin, rpId, userId, signedData);

      return JSON.stringify({
        id: base64urlEncode(credentialId),
        rawId: base64urlEncode(credentialId),
        type: "public-key",
        response: {
          authenticatorData: base64urlEncode(authData),
          clientDataJSON: base64urlEncode(clientDataJSONBytes),
          signature: base64urlEncode(signature),
          userHandle: base64urlEncode(userId),
        },
        authenticatorAttachment: "platform",
        clientExtensionResults: {},
      });
    }
  );
}

// ============================================================
// メッセージリスナー (ポップアップ ↔ background 通信)
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case "get-approval-data":
      sendResponse(getPopupData(POPUP_APPROVAL));
      break;
    case "get-account-list":
      sendResponse(getPopupData(POPUP_ACCOUNT_SELECT));
      break;
    case "approval-result":
      if (message.result === "approved") {
        resolvePopup(POPUP_APPROVAL, message.pin || "");
      } else {
        rejectPopup(POPUP_APPROVAL, new UserCancelledError("User rejected"));
      }
      break;
    case "account-selected":
      resolvePopup(POPUP_ACCOUNT_SELECT, message.userId);
      break;
  }
  return false;
});

// ============================================================
// WebAuthenticationProxy イベントハンドラ
// ============================================================

chrome.webAuthenticationProxy.onCreateRequest.addListener(async (request) => {
  await handleCreateRequest(request);
});

chrome.webAuthenticationProxy.onGetRequest.addListener(async (request) => {
  await handleGetRequest(request);
});

chrome.webAuthenticationProxy.onIsUvpaaRequest.addListener(({ requestId }) => {
  chrome.webAuthenticationProxy.completeIsUvpaaRequest({
    requestId,
    isUvpaa: true,
  });
});

chrome.webAuthenticationProxy.onRequestCanceled.addListener(({ requestId }) => {
  if (activeRequestId !== requestId) return;
  activeRequestCanceled = true;
  for (const kind of [...popups.keys()]) {
    rejectPopup(kind, new UserCancelledError("Request canceled"));
  }
});

// ============================================================
// 初期化
// ============================================================

chrome.webAuthenticationProxy.attach().catch((e) => {
  console.log("webAuthenticationProxy.attach():", e?.message || "ok");
});
