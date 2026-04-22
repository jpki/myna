"use strict";

// ============================================================
// JPKI FIDO2 Authenticator - Service Worker (background.js)
// ============================================================

const NATIVE_HOST = "com.github.jpki.fido2";

// --- 排他制御 ---
let activeRequestId = null;

// --- ポップアップ通信用の一時データ ---
let pendingApproval = null;
let pendingAccountSelect = null;
let pendingApprovalData = null;
let pendingAccountListData = null;

// ============================================================
// Base64 / Base64URL
// ============================================================

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

// ============================================================
// COSE 公開鍵 (Ed25519)
// ============================================================

function encodeCoseEd25519PublicKey(publicKey) {
  // Map (5 entries → here only 4):
  //   1: 1 (kty: OKP), 3: -8 (alg: EdDSA), -1: 6 (crv: Ed25519), -2: <pubkey>
  const result = [...cborEncodeUint(5, 4)];
  // 1 → 1
  result.push(...cborEncodeUint(0, 1));
  result.push(...cborEncodeUint(0, 1));
  // 3 → -8
  result.push(...cborEncodeUint(0, 3));
  result.push(...cborEncodeNegInt(-8));
  // -1 → 6
  result.push(...cborEncodeNegInt(-1));
  result.push(...cborEncodeUint(0, 6));
  // -2 → publicKey
  result.push(...cborEncodeNegInt(-2));
  result.push(...cborEncodeBytes(publicKey));
  return new Uint8Array(result);
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

async function buildAuthenticatorData(rpId, credentialId, publicKey, isRegistration) {
  const rpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(rpId))
  );

  if (isRegistration) {
    const flags = 0x45; // UP=1, UV=1, AT=1
    const signCount = new Uint8Array([0, 0, 0, 0]);
    const aaguid = new Uint8Array(16);
    const credIdLen = new Uint8Array([(credentialId.length >> 8) & 0xff, credentialId.length & 0xff]);
    const coseKey = encodeCoseEd25519PublicKey(publicKey);

    const totalLen = 32 + 1 + 4 + 16 + 2 + credentialId.length + coseKey.length;
    const authData = new Uint8Array(totalLen);
    let offset = 0;
    authData.set(rpIdHash, offset); offset += 32;
    authData[offset] = flags; offset += 1;
    authData.set(signCount, offset); offset += 4;
    authData.set(aaguid, offset); offset += 16;
    authData.set(credIdLen, offset); offset += 2;
    authData.set(credentialId, offset); offset += credentialId.length;
    authData.set(coseKey, offset);
    return authData;
  } else {
    const flags = 0x05; // UP=1, UV=1, AT=0
    const authData = new Uint8Array(37);
    authData.set(rpIdHash, 0);
    authData[32] = flags;
    return authData;
  }
}

// ============================================================
// clientDataJSON 構築
// ============================================================

function extractCallerContext(options) {
  const override = options.extensions?.remoteDesktopClientOverride;
  if (!override || typeof override.origin !== "string") {
    throw new Error("remoteDesktopClientOverride.origin missing in requestDetailsJson");
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
// attestationObject 構築
// ============================================================

function buildAttestationObject(authData) {
  const encoded = [];
  encoded.push(...cborEncodeUint(5, 3));
  encoded.push(...cborEncodeText("fmt"));
  encoded.push(...cborEncodeText("none"));
  encoded.push(...cborEncodeText("attStmt"));
  encoded.push(...cborEncodeUint(5, 0));
  encoded.push(...cborEncodeText("authData"));
  encoded.push(...cborEncodeBytes(authData));
  return new Uint8Array(encoded);
}

// ============================================================
// Native Messaging
// ============================================================

function sendNative(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendNativeMessage(NATIVE_HOST, message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message || "Native messaging failed"));
        return;
      }
      if (!response) {
        reject(new Error("Native host returned no response"));
        return;
      }
      if (response.result !== "0") {
        reject(new Error(response.message || "Native host error"));
        return;
      }
      resolve(response);
    });
  });
}

async function nativeDerive(pin, rpId, userIdBytes) {
  const res = await sendNative({
    mode: "derive",
    pin,
    rpId,
    userId: bytesToBase64(userIdBytes),
  });
  return {
    publicKey: base64ToBytes(res.publicKey),
    credentialId: base64ToBytes(res.credentialId),
  };
}

async function nativeSign(pin, rpId, userIdBytes, message) {
  const res = await sendNative({
    mode: "sign",
    pin,
    rpId,
    userId: bytesToBase64(userIdBytes),
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
  if (!credentials[rpId]) {
    credentials[rpId] = [];
  }

  const userIdB64 = base64urlEncode(userId);
  const credIdB64 = base64urlEncode(credentialId);

  const displayName =
    userDisplayName && userDisplayName.trim()
      ? userDisplayName
      : userIdB64.substring(0, 8);

  const idx = credentials[rpId].findIndex((c) => c.userId === userIdB64);
  const entry = {
    userId: userIdB64,
    userDisplayName: displayName,
    credentialId: credIdB64,
    createdAt: Math.floor(Date.now() / 1000),
  };

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

async function findCredentialByCredentialId(credentialIdB64) {
  const credentials = await loadCredentials();
  for (const rpId of Object.keys(credentials)) {
    const entry = credentials[rpId].find((c) => c.credentialId === credentialIdB64);
    if (entry) {
      return { rpId, ...entry };
    }
  }
  return null;
}

// ============================================================
// ポップアップ表示
// ============================================================

function showPopup(url, setupFn, { width = 420, height = 420 } = {}) {
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
          chrome.windows.remove(windowId).catch(() => {});
          reject(new Error("Timeout"));
        }, 60000);

        setupFn({ resolve, reject, windowId, timeoutId });

        const onRemoved = (removedWindowId) => {
          if (removedWindowId === windowId) {
            chrome.windows.onRemoved.removeListener(onRemoved);
            clearTimeout(timeoutId);
            reject(new Error("Window closed"));
          }
        };
        chrome.windows.onRemoved.addListener(onRemoved);
      }
    );
  });
}

async function showApprovalPopup(rpId, userDisplayName, operationType) {
  pendingApprovalData = { rpId, userDisplayName, operationType };
  return showPopup("approval/approval.html", (ctx) => {
    pendingApproval = ctx;
  });
}

async function showAccountSelectPopup(rpId, accounts) {
  pendingAccountListData = { rpId, accounts };
  return showPopup("account-select/account-select.html", (ctx) => {
    pendingAccountSelect = ctx;
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
// リクエスト完了ヘルパー
// ============================================================

function resetActiveRequest() {
  activeRequestId = null;
  pendingApproval = null;
  pendingAccountSelect = null;
  pendingApprovalData = null;
  pendingAccountListData = null;
}

// ============================================================
// 登録リクエスト処理 (onCreateRequest)
// ============================================================

async function handleCreateRequest(request) {
  if (activeRequestId !== null) {
    chrome.webAuthenticationProxy.completeCreateRequest({
      requestId: request.requestId,
      error: { name: "InvalidStateError", message: "Authenticator is busy" },
    });
    return;
  }

  activeRequestId = request.requestId;

  try {
    const options = JSON.parse(request.requestDetailsJson);

    const supportsEdDSA = options.pubKeyCredParams.some((p) => p.alg === -8);
    if (!supportsEdDSA) {
      chrome.webAuthenticationProxy.completeCreateRequest({
        requestId: request.requestId,
        error: { name: "NotSupportedError", message: "Only EdDSA (Ed25519) is supported" },
      });
      resetActiveRequest();
      return;
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

    const authData = await buildAuthenticatorData(rpId, credentialId, publicKey, true);
    const clientDataJSON = buildClientDataJSON("webauthn.create", challenge, origin, crossOrigin);
    const attestationObject = buildAttestationObject(authData);
    const spki = buildEd25519Spki(publicKey);

    const responseJson = JSON.stringify({
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

    chrome.webAuthenticationProxy.completeCreateRequest({
      requestId: request.requestId,
      responseJson,
    });
  } catch (e) {
    console.error("handleCreateRequest error:", e);
    if (e.message && e.message !== "User rejected" && e.message !== "Window closed") {
      showErrorPopup(e.message);
    }
    chrome.webAuthenticationProxy.completeCreateRequest({
      requestId: request.requestId,
      error: { name: "NotAllowedError", message: e.message || "User rejected" },
    });
  } finally {
    resetActiveRequest();
  }
}

// ============================================================
// 認証リクエスト処理 (onGetRequest)
// ============================================================

async function handleGetRequest(request) {
  if (activeRequestId !== null) {
    chrome.webAuthenticationProxy.completeGetRequest({
      requestId: request.requestId,
      error: { name: "InvalidStateError", message: "Authenticator is busy" },
    });
    return;
  }

  activeRequestId = request.requestId;

  try {
    const options = JSON.parse(request.requestDetailsJson);
    const rpId = options.rpId;
    const challenge = options.challenge;
    const { origin, crossOrigin } = extractCallerContext(options);
    const allowCredentials = options.allowCredentials || [];

    let userId;
    let userDisplayName;

    if (allowCredentials.length > 0) {
      let found = null;
      for (const cred of allowCredentials) {
        const entry = await findCredentialByCredentialId(cred.id);
        if (entry) {
          found = entry;
          break;
        }
      }

      if (!found) {
        chrome.webAuthenticationProxy.completeGetRequest({
          requestId: request.requestId,
          error: { name: "NotAllowedError", message: "No matching credential found" },
        });
        resetActiveRequest();
        return;
      }

      userId = base64urlDecode(found.userId);
      userDisplayName = found.userDisplayName;
    } else {
      const entries = await findCredentialsByRpId(rpId);

      if (entries.length === 0) {
        chrome.webAuthenticationProxy.completeGetRequest({
          requestId: request.requestId,
          error: { name: "NotAllowedError", message: "No credentials found for this RP" },
        });
        resetActiveRequest();
        return;
      }

      if (entries.length === 1) {
        userId = base64urlDecode(entries[0].userId);
        userDisplayName = entries[0].userDisplayName;
      } else {
        const accounts = entries.map((e) => ({
          userId: e.userId,
          userDisplayName: e.userDisplayName,
          credentialId: e.credentialId,
        }));

        const selectedUserId = await showAccountSelectPopup(rpId, accounts);
        const selectedEntry = entries.find((e) => e.userId === selectedUserId);
        userId = base64urlDecode(selectedUserId);
        userDisplayName = selectedEntry ? selectedEntry.userDisplayName : "";
      }
    }

    const pin = await showApprovalPopup(rpId, userDisplayName, "get");

    // 署名対象 = authenticatorData || SHA-256(clientDataJSON)
    const authData = await buildAuthenticatorData(rpId, null, null, false);
    const clientDataJSON = buildClientDataJSON("webauthn.get", challenge, origin, crossOrigin);
    const clientDataJSONBytes = new TextEncoder().encode(clientDataJSON);
    const clientDataHash = new Uint8Array(
      await crypto.subtle.digest("SHA-256", clientDataJSONBytes)
    );
    const signedData = new Uint8Array(authData.length + clientDataHash.length);
    signedData.set(authData, 0);
    signedData.set(clientDataHash, authData.length);

    const { credentialId, signature } = await nativeSign(pin, rpId, userId, signedData);

    const responseJson = JSON.stringify({
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

    chrome.webAuthenticationProxy.completeGetRequest({
      requestId: request.requestId,
      responseJson,
    });
  } catch (e) {
    console.error("handleGetRequest error:", e);
    if (e.message && e.message !== "User rejected" && e.message !== "Window closed") {
      showErrorPopup(e.message);
    }
    chrome.webAuthenticationProxy.completeGetRequest({
      requestId: request.requestId,
      error: { name: "NotAllowedError", message: e.message || "User rejected" },
    });
  } finally {
    resetActiveRequest();
  }
}

// ============================================================
// メッセージリスナー (ポップアップ ↔ background 通信)
// ============================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case "get-approval-data":
      sendResponse(pendingApprovalData);
      return false;

    case "get-account-list":
      sendResponse(pendingAccountListData);
      return false;

    case "approval-result":
      if (pendingApproval) {
        clearTimeout(pendingApproval.timeoutId);
        const windowId = pendingApproval.windowId;
        if (message.result === "approved") {
          pendingApproval.resolve(message.pin || "");
        } else {
          pendingApproval.reject(new Error("User rejected"));
        }
        pendingApproval = null;
        chrome.windows.remove(windowId).catch(() => {});
      }
      return false;

    case "account-selected":
      if (pendingAccountSelect) {
        clearTimeout(pendingAccountSelect.timeoutId);
        const windowId = pendingAccountSelect.windowId;
        pendingAccountSelect.resolve(message.userId);
        pendingAccountSelect = null;
        chrome.windows.remove(windowId).catch(() => {});
      }
      return false;
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
  if (activeRequestId === requestId) {
    if (pendingApproval) {
      clearTimeout(pendingApproval.timeoutId);
      chrome.windows.remove(pendingApproval.windowId).catch(() => {});
    }
    if (pendingAccountSelect) {
      clearTimeout(pendingAccountSelect.timeoutId);
      chrome.windows.remove(pendingAccountSelect.windowId).catch(() => {});
    }
    resetActiveRequest();
  }
});

// ============================================================
// 初期化
// ============================================================

chrome.webAuthenticationProxy.attach().catch((e) => {
  console.log("webAuthenticationProxy.attach():", e?.message || "ok");
});
