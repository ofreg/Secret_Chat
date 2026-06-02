import nacl from "https://cdn.jsdelivr.net/npm/tweetnacl/+esm";
import naclUtil from "https://cdn.jsdelivr.net/npm/tweetnacl-util/+esm";
import { deleteDB, openDB } from "https://cdn.jsdelivr.net/npm/idb@7/+esm";
import { authFetch } from "./authClient.js?v=20260420i";
import { buildSignedPreKeySignaturePayload } from "./x3dhSignature.js?v=20260601a";

const DEBUG_CRYPTO = false;
const PREKEY_BATCH_SIZE = 10;
const MAX_PREKEY_ID = 2147483647;
const ENCRYPTED_VERSION = 2;
const SIGNED_PREKEY_SIGNATURE_VERSION = 2;
const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;
const USED_PREKEY_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const LOCAL_RATCHET_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const LOCAL_MESSAGE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const VERIFICATION_RETENTION_MS = 180 * 24 * 60 * 60 * 1000;
const CLOUD_BACKUP_VERSION = 1;
const CLOUD_BACKUP_KDF_ITERATIONS = 250000;
const CLOUD_BACKUP_DEBOUNCE_MS = 1200;
const DEFAULT_DEVICE_NAME = "Browser";
let unlockedProtectorKey = null;
const IDB_OPEN_TIMEOUT_MS = 3000;
let dbOpenPromise = null;
let dbConnection = null;
let idbRecoveryAttempted = false;
let cloudBackupSyncTimer = null;
let cloudBackupSyncPromise = null;
let cloudBackupSyncSuppressed = false;

function debugCrypto(...args) {
    if (DEBUG_CRYPTO) {
        console.log(...args);
    }
}

function warnCrypto(...args) {
    if (DEBUG_CRYPTO) {
        console.warn(...args);
    }
}

function createIdbOpenPromise() {
    const openPromise = openDB("e2ee_chat", 4, {
        upgrade(db) {
            debugCrypto("[crypto-debug] idbOpen: upgrade triggered");
            if (!db.objectStoreNames.contains("keys")) {
                db.createObjectStore("keys");
            }
            if (!db.objectStoreNames.contains("ratchets")) {
                db.createObjectStore("ratchets");
            }
            if (!db.objectStoreNames.contains("messages")) {
                db.createObjectStore("messages");
            }
        },
        blocked() {
            warnCrypto("[crypto-debug] idbOpen: blocked by another open tab/version");
        },
        blocking() {
            warnCrypto("[crypto-debug] idbOpen: this tab is blocking a newer version");
        },
        terminated() {
            warnCrypto("[crypto-debug] idbOpen: connection terminated unexpectedly");
        }
    });

    const timeoutPromise = new Promise((_, reject) => {
        window.setTimeout(() => {
            reject(new Error("IndexedDB open timeout"));
        }, IDB_OPEN_TIMEOUT_MS);
    });

    return Promise.race([openPromise, timeoutPromise]);
}

async function idbOpen() {
    if (dbConnection) {
        return dbConnection;
    }

    if (dbOpenPromise) {
        return dbOpenPromise;
    }

    debugCrypto("[crypto-debug] idbOpen: opening IndexedDB");

    try {
        dbOpenPromise = createIdbOpenPromise();
        const db = await dbOpenPromise;
        dbConnection = db;
        debugCrypto("[crypto-debug] idbOpen: success");
        return db;
    } catch (error) {
        console.error("[crypto-debug] idbOpen: failed", error);
        dbOpenPromise = null;

        if (!idbRecoveryAttempted) {
            idbRecoveryAttempted = true;
            warnCrypto("[crypto-debug] idbOpen: attempting one-time IndexedDB recovery");
            try {
                closeIdbConnection();
                await deleteDB("e2ee_chat");
                warnCrypto("[crypto-debug] idbOpen: local IndexedDB deleted, retrying open");
                dbOpenPromise = createIdbOpenPromise();
                const recoveredDb = await dbOpenPromise;
                dbConnection = recoveredDb;
                debugCrypto("[crypto-debug] idbOpen: recovery successful");
                return recoveredDb;
            } catch (recoveryError) {
                console.error("[crypto-debug] idbOpen: recovery failed", recoveryError);
                dbOpenPromise = null;
            }
        }

        throw error;
    }
}

function closeIdbConnection() {
    if (dbConnection?.close) {
        try {
            dbConnection.close();
        } catch {}
    }
    dbConnection = null;
    dbOpenPromise = null;
}

export async function generateIdentityKeys() {
    const keyPair = nacl.box.keyPair();

    return {
        publicKey: naclUtil.encodeBase64(keyPair.publicKey),
        privateKey: naclUtil.encodeBase64(keyPair.secretKey)
    };
}

export async function generateIdentitySigningKeys() {
    const keyPair = nacl.sign.keyPair();

    return {
        publicKey: naclUtil.encodeBase64(keyPair.publicKey),
        privateKey: naclUtil.encodeBase64(keyPair.secretKey)
    };
}

function generatePreKeyPair() {
    const keyPair = nacl.box.keyPair();

    return {
        key_id: buildPreKeyId(),
        public_key: naclUtil.encodeBase64(keyPair.publicKey),
        private_key: naclUtil.encodeBase64(keyPair.secretKey),
        created_at: new Date().toISOString(),
        is_used: false,
        used_at: null
    };
}

function buildPreKeyId() {
    return Math.floor(Math.random() * (MAX_PREKEY_ID - 1)) + 1;
}

export async function saveIdentityKey(keys) {
    const db = await idbOpen();
    await db.put("keys", await encryptIdentityRecord(keys, db), "identity_key");
}

export async function getIdentityPrivateKeyUint8() {
    const db = await idbOpen();
    const data = await readIdentityRecord(db);

    if (!data) return null;

    return naclUtil.decodeBase64(data.privateKey);
}

export async function getIdentityKey() {
    const db = await idbOpen();
    const data = await db.get("keys", "identity_key");

    return data?.publicKey || null;
}

export async function saveRatchetState(chatId, state) {
    const db = await idbOpen();
    await db.put("ratchets", { ...state, _savedAt: Date.now() }, String(chatId));
    scheduleCloudBackupSync();
}

export async function getRatchetState(chatId) {
    const db = await idbOpen();
    const data = await db.get("ratchets", String(chatId));
    if (!data) return null;
    if (typeof data === "object") {
        const { _savedAt, ...state } = data;
        return state;
    }
    return data;
}

export async function deleteRatchetState(chatId) {
    const db = await idbOpen();
    await db.delete("ratchets", String(chatId));
    scheduleCloudBackupSync();
}

export async function saveCachedMessageText(chatId, messageId, text) {
    const db = await idbOpen();
    await db.put("messages", {
        text: String(text ?? ""),
        updatedAt: Date.now()
    }, `msg:${chatId}:${messageId}`);
    scheduleCloudBackupSync();
}

export async function getCachedMessageText(chatId, messageId) {
    const db = await idbOpen();
    const record = await db.get("messages", `msg:${chatId}:${messageId}`);
    if (typeof record === "string") {
        return record;
    }
    return record?.text || null;
}

export async function saveLastSeenMessageId(chatId, messageId) {
    const db = await idbOpen();
    await db.put("messages", { messageId, updatedAt: Date.now() }, `meta:lastSeen:${chatId}`);
    scheduleCloudBackupSync();
}

export async function getLastSeenMessageId(chatId) {
    const db = await idbOpen();
    const record = await db.get("messages", `meta:lastSeen:${chatId}`);
    if (typeof record === "number") {
        return record;
    }
    return record?.messageId || 0;
}

export async function saveVerificationStatus(fingerprintValue, isVerified) {
    const db = await idbOpen();
    await db.put("messages", { isVerified, updatedAt: Date.now() }, `verify:${fingerprintValue}`);
    scheduleCloudBackupSync();
}

export async function getVerificationStatus(fingerprintValue) {
    const db = await idbOpen();
    const record = await db.get("messages", `verify:${fingerprintValue}`);
    return Boolean(record?.isVerified);
}

export async function saveAttachmentHistory(url, payload) {
    if (!url || !payload?.key) {
        return;
    }

    const db = await idbOpen();
    await db.put("messages", {
        key: String(payload.key),
        metadata: payload.metadata || null,
        updatedAt: Date.now()
    }, `attachment:${url}`);
    scheduleCloudBackupSync();
}

export async function getAttachmentHistory(url) {
    if (!url) {
        return null;
    }

    const db = await idbOpen();
    const record = await db.get("messages", `attachment:${url}`);
    if (!record?.key) {
        return null;
    }

    return {
        key: record.key,
        metadata: record.metadata || null
    };
}

export async function getIdentitySigningKey() {
    const db = await idbOpen();
    const data = await readIdentitySigningRecord(db);
    return data?.publicKey || null;
}

export async function getSignedPreKeyPublic() {
    const db = await idbOpen();
    const data = await db.get("keys", "signed_prekey");
    return data?.public_key || data?.publicKey || null;
}

export async function getSignedPreKey() {
    const db = await idbOpen();
    return readSignedPreKeyRecord(db);
}

export async function consumeLocalOneTimePreKey(keyId) {
    const db = await idbOpen();
    const oneTimePreKeys = await readOneTimePreKeysRecord(db);
    const keyIndex = oneTimePreKeys.findIndex((prekey) => prekey.key_id === Number(keyId));
    if (keyIndex === -1) {
        return null;
    }

    if (!oneTimePreKeys[keyIndex].is_used) {
        oneTimePreKeys[keyIndex] = {
            ...oneTimePreKeys[keyIndex],
            is_used: true,
            used_at: new Date().toISOString()
        };
        await db.put("keys", await encryptOneTimePreKeysRecord(oneTimePreKeys, db), "one_time_prekeys");
        scheduleCloudBackupSync();
    }

    return oneTimePreKeys[keyIndex];
}

export async function getX3dhState() {
    const db = await idbOpen();
    return {
        identityKey: await readIdentityRecord(db),
        identitySigning: await readIdentitySigningRecord(db),
        signedPreKey: await readSignedPreKeyRecord(db),
        oneTimePreKeys: await readOneTimePreKeysRecord(db)
    };
}

export async function initKeysIfNeeded() {
    debugCrypto("[crypto-debug] initKeysIfNeeded: start");
    const db = await idbOpen();
    debugCrypto("[crypto-debug] initKeysIfNeeded: db opened");
    const deviceRegistration = await getOrCreateDeviceRegistration(db);
    let identityKey = await readIdentityRecord(db);
    debugCrypto("[crypto-debug] initKeysIfNeeded: identity key loaded", { hasIdentityKey: Boolean(identityKey) });
    let identitySigning = await readIdentitySigningRecord(db);
    debugCrypto("[crypto-debug] initKeysIfNeeded: identity signing loaded", { hasIdentitySigning: Boolean(identitySigning) });
    let signedPreKey = await readSignedPreKeyRecord(db);
    debugCrypto("[crypto-debug] initKeysIfNeeded: signed prekey loaded", { hasSignedPreKey: Boolean(signedPreKey) });
    let oneTimePreKeys = await readOneTimePreKeysRecord(db);
    debugCrypto("[crypto-debug] initKeysIfNeeded: one-time prekeys loaded", { count: oneTimePreKeys.length });

    if (!identityKey) {
        debugCrypto("Generating new identity keys");
        identityKey = await generateIdentityKeys();
        await db.put("keys", await encryptIdentityRecord(identityKey, db), "identity_key");
        debugCrypto("[crypto-debug] initKeysIfNeeded: identity key generated");
    }

    if (!identitySigning) {
        debugCrypto("Generating new identity signing keys");
        identitySigning = await generateIdentitySigningKeys();
        await db.put("keys", await encryptIdentitySigningRecord(identitySigning, db), "identity_signing_key");
        debugCrypto("[crypto-debug] initKeysIfNeeded: identity signing generated");
    }

    if (!signedPreKey || shouldRotateSignedPreKey(signedPreKey)) {
        debugCrypto("Generating signed prekey");
        signedPreKey = createSignedPreKey(identitySigning, identityKey);
        await db.put("keys", await encryptSignedPreKeyRecord(signedPreKey, db), "signed_prekey");
        debugCrypto("[crypto-debug] initKeysIfNeeded: signed prekey generated");
    } else {
        signedPreKey = normalizeSignedPreKey(signedPreKey);
        await db.put("keys", await encryptSignedPreKeyRecord(signedPreKey, db), "signed_prekey");
        debugCrypto("[crypto-debug] initKeysIfNeeded: signed prekey normalized");
    }

    const availablePreKeys = oneTimePreKeys.filter((prekey) => !prekey.is_used);
    if (availablePreKeys.length < PREKEY_BATCH_SIZE) {
        const missingCount = PREKEY_BATCH_SIZE - availablePreKeys.length;
        const replenished = Array.from({ length: missingCount }, () => generatePreKeyPair());
        oneTimePreKeys = [...oneTimePreKeys, ...replenished];
        await db.put("keys", await encryptOneTimePreKeysRecord(oneTimePreKeys, db), "one_time_prekeys");
        debugCrypto("[crypto-debug] initKeysIfNeeded: replenished one-time prekeys", { missingCount });
    }

    const cleanupResult = await cleanupLocalKeyMaterial(db, signedPreKey);
    signedPreKey = cleanupResult.signedPreKey;
    oneTimePreKeys = cleanupResult.oneTimePreKeys;
    await cleanupLocalState(db);
    debugCrypto("[crypto-debug] initKeysIfNeeded: local cleanup done");

    try {
        const x3dhResponse = await authFetch("/users/x3dh-keys", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                device_id: deviceRegistration.deviceId,
                device_name: deviceRegistration.deviceName,
                identity_key: identityKey.publicKey,
                identity_signing_key: identitySigning.publicKey,
                signed_prekey: signedPreKey.public_key,
                signed_prekey_signature: signedPreKey.signature,
                signed_prekey_key_id: signedPreKey.key_id,
                one_time_prekeys: oneTimePreKeys
                    .filter((prekey) => !prekey.is_used)
                    .map((prekey) => ({
                    key_id: prekey.key_id,
                    public_key: prekey.public_key
                    }))
            })
        });

        const x3dhRawResponse = await x3dhResponse.text();
        let x3dhPayload;

        try {
            x3dhPayload = JSON.parse(x3dhRawResponse);
        } catch {
            x3dhPayload = { raw: x3dhRawResponse };
        }

        if (!x3dhResponse.ok || x3dhPayload?.status === "error") {
            console.error("X3DH key sync failed:", x3dhPayload);
        } else {
            if (x3dhPayload?.device_id) {
                await storeDeviceRegistration(db, {
                    deviceId: x3dhPayload.device_id,
                    deviceName: x3dhPayload.device_name || deviceRegistration.deviceName
                });
            }
            debugCrypto("X3DH key sync:", x3dhPayload);
        }
        scheduleCloudBackupSync();
        debugCrypto("[crypto-debug] initKeysIfNeeded: complete");
    } catch (err) {
        console.error("Key upload failed", err);
        console.error("[crypto-debug] initKeysIfNeeded: failed during server sync", err);
    }
}

function createSignedPreKey(identitySigningKeys, identityKeys) {
    const preKey = generatePreKeyPair();
    const payload = buildSignedPreKeySignaturePayload({
        identityDhKeyBase64: identityKeys.publicKey,
        signedPreKeyBase64: preKey.public_key,
        signedPreKeyKeyId: preKey.key_id
    });
    const signature = nacl.sign.detached(
        payload,
        naclUtil.decodeBase64(identitySigningKeys.privateKey)
    );

    return {
        ...preKey,
        signature: naclUtil.encodeBase64(signature),
        created_at: new Date().toISOString(),
        signature_version: SIGNED_PREKEY_SIGNATURE_VERSION
    };
}

function normalizeOneTimePreKeys(prekeys) {
    if (!Array.isArray(prekeys)) {
        return [];
    }

    return prekeys
        .map((prekey) => ({
            key_id: normalizePreKeyId(prekey?.key_id ?? prekey?.keyId ?? null),
            public_key: prekey?.public_key ?? prekey?.publicKey ?? null,
            private_key: prekey?.private_key ?? prekey?.privateKey ?? null,
            private_key_enc: prekey?.private_key_enc ?? prekey?.privateKeyEnc ?? null,
            created_at: prekey?.created_at ?? prekey?.createdAt ?? null,
            is_used: Boolean(prekey?.is_used ?? prekey?.isUsed ?? false),
            used_at: prekey?.used_at ?? prekey?.usedAt ?? null,
            encryptedVersion: prekey?.encryptedVersion ?? prekey?.encrypted_version ?? null
        }))
        .filter((prekey) => prekey.key_id && prekey.public_key && (prekey.private_key || prekey.private_key_enc));
}

function normalizeSignedPreKey(prekey) {
    return {
        ...prekey,
        key_id: normalizePreKeyId(prekey?.key_id ?? prekey?.keyId ?? null),
        public_key: prekey?.public_key ?? prekey?.publicKey ?? null,
        private_key: prekey?.private_key ?? prekey?.privateKey ?? null,
        private_key_enc: prekey?.private_key_enc ?? prekey?.privateKeyEnc ?? null,
        created_at: prekey?.created_at ?? prekey?.createdAt ?? new Date().toISOString(),
        signature_version: prekey?.signature_version ?? prekey?.signatureVersion ?? 1,
        encryptedVersion: prekey?.encryptedVersion ?? prekey?.encrypted_version ?? null
    };
}

function normalizePreKeyId(keyId) {
    const numericId = Number(keyId);
    if (!Number.isFinite(numericId) || numericId <= 0) {
        return buildPreKeyId();
    }

    return (Math.trunc(numericId) % MAX_PREKEY_ID) || buildPreKeyId();
}

function shouldRotateSignedPreKey(prekey) {
    const normalized = normalizeSignedPreKey(prekey);
    if (normalized.signature_version !== SIGNED_PREKEY_SIGNATURE_VERSION) {
        return true;
    }

    const createdAt = Date.parse(normalized.created_at);

    if (!Number.isFinite(createdAt)) {
        return true;
    }

    return Date.now() - createdAt >= SIGNED_PREKEY_ROTATION_MS;
}

export async function fingerprint(base64Key) {
    const data = Uint8Array.from(atob(base64Key), (c) => c.charCodeAt(0));
    const hash = await crypto.subtle.digest("SHA-256", data);

    return Array.from(new Uint8Array(hash))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(":");
}

export async function deriveSafetyNumber(firstBase64Key, secondBase64Key) {
    if (!firstBase64Key || !secondBase64Key) {
        return "";
    }

    const [leftKey, rightKey] = [firstBase64Key, secondBase64Key].sort();
    const label = new TextEncoder().encode("e2ee-chat:safety-number:v1");
    const leftBytes = Uint8Array.from(atob(leftKey), (c) => c.charCodeAt(0));
    const rightBytes = Uint8Array.from(atob(rightKey), (c) => c.charCodeAt(0));

    const merged = new Uint8Array(label.length + leftBytes.length + rightBytes.length);
    merged.set(label, 0);
    merged.set(leftBytes, label.length);
    merged.set(rightBytes, label.length + leftBytes.length);

    const hash = await crypto.subtle.digest("SHA-256", merged);

    return Array.from(new Uint8Array(hash))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join(":");
}

async function cleanupLocalKeyMaterial(db, signedPreKey) {
    const oneTimePreKeys = normalizeOneTimePreKeys((await db.get("keys", "one_time_prekeys")) || []);
    const now = Date.now();
    const signedPreKeyCreatedAt = Date.parse(
        signedPreKey?.created_at ?? signedPreKey?.createdAt ?? new Date().toISOString()
    );

    const filteredPreKeys = oneTimePreKeys.filter((prekey) => {
        if (!prekey.is_used) {
            return true;
        }

        const usedAt = Date.parse(prekey.used_at || "");
        if (!Number.isFinite(usedAt)) {
            return false;
        }

        return now - usedAt <= USED_PREKEY_RETENTION_MS;
    });

    let nextOneTimePreKeys = filteredPreKeys;
    if (filteredPreKeys.length !== oneTimePreKeys.length) {
        await db.put("keys", await encryptOneTimePreKeysRecord(filteredPreKeys, db), "one_time_prekeys");
    }

    let nextSignedPreKey = signedPreKey;

    if (Number.isFinite(signedPreKeyCreatedAt) && now - signedPreKeyCreatedAt > SIGNED_PREKEY_ROTATION_MS * 2) {
        const rotatedSignedPreKey = createSignedPreKey(
            await readIdentitySigningRecord(db),
            await readIdentityRecord(db)
        );
        await db.put("keys", await encryptSignedPreKeyRecord(rotatedSignedPreKey, db), "signed_prekey");
        nextSignedPreKey = rotatedSignedPreKey;
    }

    return {
        signedPreKey: nextSignedPreKey,
        oneTimePreKeys: nextOneTimePreKeys
    };
}

async function cleanupLocalState(db) {
    const now = Date.now();

    await cleanupStoreEntries(db, "ratchets", (key, value) => {
        const savedAt = Number(value?._savedAt || 0);
        return Number.isFinite(savedAt) && now - savedAt > LOCAL_RATCHET_RETENTION_MS;
    });

    await cleanupStoreEntries(db, "messages", (key, value) => {
        const stringKey = String(key);
        const updatedAt = typeof value === "object" && value ? Number(value.updatedAt || 0) : 0;

        if (stringKey.startsWith("verify:")) {
            return Number.isFinite(updatedAt) && updatedAt > 0 && now - updatedAt > VERIFICATION_RETENTION_MS;
        }

        if (stringKey.startsWith("msg:") || stringKey.startsWith("meta:lastSeen:")) {
            return Number.isFinite(updatedAt) && updatedAt > 0 && now - updatedAt > LOCAL_MESSAGE_RETENTION_MS;
        }

        return false;
    });
}

async function cleanupStoreEntries(db, storeName, shouldDelete) {
    const tx = db.transaction(storeName, "readwrite");
    let cursor = await tx.store.openCursor();

    while (cursor) {
        if (shouldDelete(cursor.key, cursor.value)) {
            await cursor.delete();
        }
        cursor = await cursor.continue();
    }

    await tx.done;
}

export async function resetLocalCryptoState() {
    unlockedProtectorKey = null;
    idbRecoveryAttempted = false;
    if (cloudBackupSyncTimer) {
        window.clearTimeout(cloudBackupSyncTimer);
        cloudBackupSyncTimer = null;
    }
    cloudBackupSyncPromise = null;
    closeIdbConnection();
    await deleteDB("e2ee_chat");
}

export { nacl, naclUtil };

export async function ensureLocalAccountBinding(accountData) {
    const binding = buildAccountBinding(accountData);
    if (!binding) {
        return false;
    }

    let db = await idbOpen();
    const existing = await db.get("keys", "account_binding");

    if (existing?.binding && existing.binding !== binding) {
        await resetLocalCryptoState();
        db = await idbOpen();
    }

    await clearStoredPlaintextMessages(db);

    await db.put("keys", {
        binding,
        email: accountData.email || "",
        userId: accountData.id ?? null,
        accountInstanceId: accountData.account_instance_id || "",
        updatedAt: Date.now()
    }, "account_binding");

    return existing?.binding ? existing.binding !== binding : false;
}

export async function getCurrentDeviceRegistration() {
    const db = await idbOpen();
    return getOrCreateDeviceRegistration(db);
}

export async function restoreCloudBackupIfNeeded(accountData) {
    const password = getCloudBackupPassword();
    if (!password) {
        return false;
    }

    const response = await authFetch("/users/key-backup");
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload?.status !== "ok" || !payload?.backup) {
        return false;
    }

    const db = await idbOpen();
    const snapshot = await decryptCloudBackupSnapshot(payload.backup, password);
    if (!snapshot || typeof snapshot !== "object") {
        return false;
    }

    const expectedBinding = buildAccountBinding(accountData);
    const snapshotBinding = snapshot.account_binding?.binding || null;
    if (expectedBinding && snapshotBinding && snapshotBinding !== expectedBinding) {
        console.warn("Cloud backup binding mismatch; skipping restore");
        return false;
    }

    await applyCloudBackupSnapshot(snapshot, db, accountData);
    return true;
}

export function scheduleCloudBackupSync() {
    if (cloudBackupSyncSuppressed || cloudBackupSyncPromise) {
        return;
    }

    const password = getCloudBackupPassword();
    if (!password) {
        return;
    }

    if (cloudBackupSyncTimer) {
        window.clearTimeout(cloudBackupSyncTimer);
    }

    cloudBackupSyncTimer = window.setTimeout(() => {
        cloudBackupSyncTimer = null;
        void syncCloudBackupNow().catch((error) => {
            console.warn("Cloud backup sync failed:", error);
        });
    }, CLOUD_BACKUP_DEBOUNCE_MS);
}

export async function syncCloudBackupNow() {
    if (cloudBackupSyncSuppressed) {
        return false;
    }

    const password = getCloudBackupPassword();
    if (!password) {
        return false;
    }

    if (cloudBackupSyncPromise) {
        return cloudBackupSyncPromise;
    }

    cloudBackupSyncPromise = (async () => {
        const db = await idbOpen();
        const snapshot = await buildCloudBackupSnapshot(db);
        if (!snapshot) {
            return false;
        }

        const encryptedPayload = await encryptCloudBackupSnapshot(snapshot, password);
        const response = await authFetch("/users/key-backup", {
            method: "PUT",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(encryptedPayload)
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || payload?.status !== "ok") {
            throw new Error(payload?.detail || "Cloud key backup update failed");
        }

        return true;
    })().finally(() => {
        cloudBackupSyncPromise = null;
    });

    return cloudBackupSyncPromise;
}

async function clearStoredPlaintextMessages(db) {
    const tx = db.transaction("messages", "readwrite");
    let cursor = await tx.store.openCursor();

    while (cursor) {
        if (String(cursor.key).startsWith("msg:")) {
            await cursor.delete();
        }
        cursor = await cursor.continue();
    }

    await tx.done;
}

async function buildCloudBackupSnapshot(db) {
    const accountBinding = await db.get("keys", "account_binding");
    if (!accountBinding?.binding) {
        return null;
    }

    return {
        backup_version: CLOUD_BACKUP_VERSION,
        exported_at: new Date().toISOString(),
        account_binding: {
            ...accountBinding,
            updatedAt: Date.now()
        },
        messages: await exportMessageMetadata(db)
    };
}

async function exportStoreEntries(db, storeName) {
    const tx = db.transaction(storeName, "readonly");
    const entries = [];
    let cursor = await tx.store.openCursor();

    while (cursor) {
        entries.push({
            key: String(cursor.key),
            value: cursor.value
        });
        cursor = await cursor.continue();
    }

    await tx.done;
    return entries;
}

async function exportMessageMetadata(db) {
    const tx = db.transaction("messages", "readonly");
    const entries = [];
    let cursor = await tx.store.openCursor();

    while (cursor) {
        const key = String(cursor.key);
        if (
            key.startsWith("verify:")
            || key.startsWith("meta:lastSeen:")
            || key.startsWith("msg:")
            || key.startsWith("attachment:")
        ) {
            entries.push({
                key,
                value: cursor.value
            });
        }
        cursor = await cursor.continue();
    }

    await tx.done;
    return entries;
}

async function encryptCloudBackupSnapshot(snapshot, password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveCloudBackupKey(password, salt);
    const plaintextBytes = new TextEncoder().encode(JSON.stringify(snapshot));
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv
        },
        key,
        plaintextBytes
    );

    return {
        version: CLOUD_BACKUP_VERSION,
        salt: encodeBytesToBase64(salt),
        iv: encodeBytesToBase64(iv),
        ciphertext: encodeBytesToBase64(new Uint8Array(ciphertext)),
        backup_version: snapshot.backup_version || CLOUD_BACKUP_VERSION,
        updated_at_client: new Date().toISOString()
    };
}

async function decryptCloudBackupSnapshot(payload, password) {
    const key = await deriveCloudBackupKey(password, decodeBase64ToBytes(payload.salt));
    const plaintextBuffer = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: decodeBase64ToBytes(payload.iv)
        },
        key,
        decodeBase64ToBytes(payload.ciphertext)
    );

    return JSON.parse(new TextDecoder().decode(new Uint8Array(plaintextBuffer)));
}

async function deriveCloudBackupKey(password, saltBytes) {
    const passwordKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: CLOUD_BACKUP_KDF_ITERATIONS,
            hash: "SHA-256"
        },
        passwordKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}

async function applyCloudBackupSnapshot(snapshot, db, accountData) {
    void accountData;
    cloudBackupSyncSuppressed = true;
    try {
        await clearStore(db, "messages");

        const accountBinding = snapshot.account_binding || buildDefaultAccountBindingRecord(accountData);
        if (accountBinding?.binding) {
            await db.put("keys", {
                ...accountBinding,
                updatedAt: Date.now()
            }, "account_binding");
        }

        for (const entry of snapshot.messages || []) {
            await db.put("messages", entry.value, String(entry.key));
        }
    } finally {
        cloudBackupSyncSuppressed = false;
    }
}

async function clearStore(db, storeName) {
    const tx = db.transaction(storeName, "readwrite");
    await tx.store.clear();
    await tx.done;
}

async function readIdentityRecord(db) {
    const record = await db.get("keys", "identity_key");
    if (!record) {
        return null;
    }

    const privateKey = await decryptPrivateValue(record.privateKeyEnc, record.privateKey, db);
    const normalized = {
        publicKey: record.publicKey,
        privateKey
    };
    await db.put("keys", await encryptIdentityRecord(normalized, db), "identity_key");
    return normalized;
}

async function readIdentitySigningRecord(db) {
    const record = await db.get("keys", "identity_signing_key");
    if (!record) {
        return null;
    }

    const privateKey = await decryptPrivateValue(record.privateKeyEnc, record.privateKey, db);
    const normalized = {
        publicKey: record.publicKey,
        privateKey
    };
    await db.put("keys", await encryptIdentitySigningRecord(normalized, db), "identity_signing_key");
    return normalized;
}

async function readSignedPreKeyRecord(db) {
    const record = await db.get("keys", "signed_prekey");
    if (!record) {
        return null;
    }

    const normalizedRecord = normalizeSignedPreKey(record);
    const privateKey = await decryptPrivateValue(
        normalizedRecord.private_key_enc,
        normalizedRecord.private_key,
        db
    );
    const normalized = {
        ...normalizedRecord,
        private_key: privateKey
    };
    await db.put("keys", await encryptSignedPreKeyRecord(normalized, db), "signed_prekey");
    return normalized;
}

async function readOneTimePreKeysRecord(db) {
    const rawPrekeys = normalizeOneTimePreKeys((await db.get("keys", "one_time_prekeys")) || []);
    if (!rawPrekeys.length) {
        return [];
    }

    let needsMigration = false;
    const decrypted = [];

    for (const prekey of rawPrekeys) {
        const privateKey = await decryptPrivateValue(prekey.private_key_enc, prekey.private_key, db);
        if (prekey.private_key || !prekey.private_key_enc || prekey.encryptedVersion !== ENCRYPTED_VERSION) {
            needsMigration = true;
        }
        decrypted.push({
            ...prekey,
            private_key: privateKey,
            private_key_enc: prekey.private_key_enc || null,
            encryptedVersion: ENCRYPTED_VERSION
        });
    }

    if (needsMigration) {
        await db.put("keys", await encryptOneTimePreKeysRecord(decrypted, db), "one_time_prekeys");
    }

    return decrypted;
}

async function encryptIdentityRecord(identityKey, db) {
    return {
        publicKey: identityKey.publicKey,
        privateKeyEnc: await encryptPrivateValue(identityKey.privateKey, db),
        encryptedVersion: ENCRYPTED_VERSION
    };
}

async function encryptIdentitySigningRecord(identitySigning, db) {
    return {
        publicKey: identitySigning.publicKey,
        privateKeyEnc: await encryptPrivateValue(identitySigning.privateKey, db),
        encryptedVersion: ENCRYPTED_VERSION
    };
}

async function encryptSignedPreKeyRecord(prekey, db) {
    const normalized = normalizeSignedPreKey(prekey);
    return {
        key_id: normalized.key_id,
        public_key: normalized.public_key,
        private_key_enc: await encryptPrivateValue(normalized.private_key, db),
        created_at: normalized.created_at,
        is_used: Boolean(normalized.is_used),
        used_at: normalized.used_at ?? null,
        signature: normalized.signature,
        signature_version: normalized.signature_version ?? SIGNED_PREKEY_SIGNATURE_VERSION,
        encryptedVersion: ENCRYPTED_VERSION
    };
}

async function encryptOneTimePreKeysRecord(prekeys, db) {
    const normalizedPrekeys = normalizeOneTimePreKeys(prekeys);
    const encrypted = [];

    for (const prekey of normalizedPrekeys) {
        encrypted.push({
            key_id: prekey.key_id,
            public_key: prekey.public_key,
            private_key_enc: await encryptPrivateValue(prekey.private_key, db),
            created_at: prekey.created_at,
            is_used: Boolean(prekey.is_used),
            used_at: prekey.used_at ?? null,
            encryptedVersion: ENCRYPTED_VERSION
        });
    }

    return encrypted;
}

async function decryptPrivateValue(encryptedValue, plaintextValue, db) {
    if (plaintextValue) {
        return plaintextValue;
    }

    if (!encryptedValue?.ciphertext || !encryptedValue?.iv) {
        return null;
    }

    const protectorKey = await getLocalProtectorKey(db);
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: decodeBase64ToBytes(encryptedValue.iv)
        },
        protectorKey,
        decodeBase64ToBytes(encryptedValue.ciphertext)
    );

    return new TextDecoder().decode(new Uint8Array(decrypted));
}

async function encryptPrivateValue(plaintextValue, db) {
    if (!plaintextValue) {
        return null;
    }

    const protectorKey = await getLocalProtectorKey(db);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv
        },
        protectorKey,
        new TextEncoder().encode(plaintextValue)
    );

    return {
        iv: encodeBytesToBase64(iv),
        ciphertext: encodeBytesToBase64(new Uint8Array(ciphertext))
    };
}

async function getLocalProtectorKey(db) {
    if (unlockedProtectorKey) {
        return unlockedProtectorKey;
    }

    const storedProtector = await db.get("keys", "local_protector");
    if (storedProtector?.key instanceof CryptoKey) {
        unlockedProtectorKey = storedProtector.key;
        return unlockedProtectorKey;
    }

    unlockedProtectorKey = await crypto.subtle.generateKey(
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );

    await db.put(
        "keys",
        {
            version: ENCRYPTED_VERSION,
            key: unlockedProtectorKey
        },
        "local_protector"
    );

    return unlockedProtectorKey;
}

function decodeBase64ToBytes(value) {
    return naclUtil.decodeBase64(String(value || "").replace(/\s+/g, ""));
}

function encodeBytesToBase64(value) {
    return naclUtil.encodeBase64(value);
}

function getCloudBackupPassword() {
    try {
        return window.sessionStorage.getItem("e2ee_backup_password") || "";
    } catch {
        return "";
    }
}

function buildDefaultAccountBindingRecord(accountData) {
    const binding = buildAccountBinding(accountData);
    if (!binding) {
        return null;
    }

    return {
        binding,
        email: accountData?.email || "",
        userId: accountData?.id ?? null,
        accountInstanceId: accountData?.account_instance_id || "",
        updatedAt: Date.now()
    };
}

async function getOrCreateDeviceRegistration(db) {
    const existing = await db.get("keys", "device_registration");
    if (existing?.deviceId) {
        syncDeviceRegistrationToSession(existing);
        return existing;
    }

    const created = {
        deviceId: buildDeviceId(),
        deviceName: buildDeviceName(),
        createdAt: Date.now()
    };
    await storeDeviceRegistration(db, created);
    return created;
}

async function storeDeviceRegistration(db, registration) {
    const normalized = {
        deviceId: String(registration?.deviceId || buildDeviceId()),
        deviceName: String(registration?.deviceName || buildDeviceName()).slice(0, 120),
        createdAt: Number(registration?.createdAt || Date.now())
    };
    await db.put("keys", normalized, "device_registration");
    syncDeviceRegistrationToSession(normalized);
    return normalized;
}

function syncDeviceRegistrationToSession(registration) {
    try {
        window.sessionStorage.setItem("e2ee_device_id", registration.deviceId);
        window.sessionStorage.setItem("e2ee_device_name", registration.deviceName);
    } catch {}
}

function buildDeviceId() {
    if (typeof crypto.randomUUID === "function") {
        return crypto.randomUUID();
    }
    return `browser-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

function buildDeviceName() {
    const userAgent = typeof navigator !== "undefined" ? navigator.userAgent : "";
    if (/firefox/i.test(userAgent)) {
        return "Firefox browser";
    }
    if (/edg/i.test(userAgent)) {
        return "Edge browser";
    }
    if (/chrome/i.test(userAgent)) {
        return "Chrome browser";
    }
    if (/safari/i.test(userAgent) && !/chrome|chromium|edg/i.test(userAgent)) {
        return "Safari browser";
    }
    return DEFAULT_DEVICE_NAME;
}

function buildAccountBinding(accountData) {
    const email = String(accountData?.email || "").trim().toLowerCase();
    const accountInstanceId = String(accountData?.account_instance_id || "").trim();

    if (!email || !accountInstanceId) {
        return null;
    }

    return `${email}:${accountInstanceId}`;
}
