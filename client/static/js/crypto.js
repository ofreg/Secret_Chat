import nacl from "https://cdn.jsdelivr.net/npm/tweetnacl/+esm";
import naclUtil from "https://cdn.jsdelivr.net/npm/tweetnacl-util/+esm";
import { deleteDB, openDB } from "https://cdn.jsdelivr.net/npm/idb@7/+esm";
import { authFetch } from "./authClient.js?v=20260416t";

const PREKEY_BATCH_SIZE = 10;
const MAX_PREKEY_ID = 2147483647;
const ENCRYPTED_VERSION = 2;
const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;
const USED_PREKEY_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const LOCAL_RATCHET_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const LOCAL_MESSAGE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const VERIFICATION_RETENTION_MS = 180 * 24 * 60 * 60 * 1000;
let unlockedProtectorKey = null;
const IDB_OPEN_TIMEOUT_MS = 3000;
let dbOpenPromise = null;
let dbConnection = null;
let idbRecoveryAttempted = false;

function createIdbOpenPromise() {
    const openPromise = openDB("e2ee_chat", 4, {
        upgrade(db) {
            console.log("[crypto-debug] idbOpen: upgrade triggered");
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
            console.warn("[crypto-debug] idbOpen: blocked by another open tab/version");
        },
        blocking() {
            console.warn("[crypto-debug] idbOpen: this tab is blocking a newer version");
        },
        terminated() {
            console.warn("[crypto-debug] idbOpen: connection terminated unexpectedly");
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

    console.log("[crypto-debug] idbOpen: opening IndexedDB");

    try {
        dbOpenPromise = createIdbOpenPromise();
        const db = await dbOpenPromise;
        dbConnection = db;
        console.log("[crypto-debug] idbOpen: success");
        return db;
    } catch (error) {
        console.error("[crypto-debug] idbOpen: failed", error);
        dbOpenPromise = null;

        if (!idbRecoveryAttempted) {
            idbRecoveryAttempted = true;
            console.warn("[crypto-debug] idbOpen: attempting one-time IndexedDB recovery");
            try {
                closeIdbConnection();
                await deleteDB("e2ee_chat");
                console.warn("[crypto-debug] idbOpen: local IndexedDB deleted, retrying open");
                dbOpenPromise = createIdbOpenPromise();
                const recoveredDb = await dbOpenPromise;
                dbConnection = recoveredDb;
                console.log("[crypto-debug] idbOpen: recovery successful");
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

export async function generateSigningKeys() {
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
    await db.put("keys", await encryptIdentityRecord(keys, db), "identity");
}

export async function getPrivateKeyUint8() {
    const db = await idbOpen();
    const data = await readIdentityRecord(db);

    if (!data) return null;

    return naclUtil.decodeBase64(data.privateKey);
}

export async function getPublicKey() {
    const db = await idbOpen();
    const data = await db.get("keys", "identity");

    return data?.publicKey || null;
}

export async function saveRatchetState(chatId, state) {
    const db = await idbOpen();
    await db.put("ratchets", { ...state, _savedAt: Date.now() }, String(chatId));
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
}

export async function saveCachedMessageText(chatId, messageId, text) {
    void chatId;
    void messageId;
    void text;
}

export async function getCachedMessageText(chatId, messageId) {
    void chatId;
    void messageId;
    return null;
}

export async function saveLastSeenMessageId(chatId, messageId) {
    const db = await idbOpen();
    await db.put("messages", { messageId, updatedAt: Date.now() }, `meta:lastSeen:${chatId}`);
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
}

export async function getVerificationStatus(fingerprintValue) {
    const db = await idbOpen();
    const record = await db.get("messages", `verify:${fingerprintValue}`);
    return Boolean(record?.isVerified);
}

export async function getSigningPublicKey() {
    const db = await idbOpen();
    const data = await readSigningRecord(db);
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
    }

    return oneTimePreKeys[keyIndex];
}

export async function getX3dhState() {
    const db = await idbOpen();
    return {
        identity: await readIdentityRecord(db),
        signing: await readSigningRecord(db),
        signedPreKey: await readSignedPreKeyRecord(db),
        oneTimePreKeys: await readOneTimePreKeysRecord(db)
    };
}

export async function initKeysIfNeeded() {
    console.log("[crypto-debug] initKeysIfNeeded: start");
    const db = await idbOpen();
    console.log("[crypto-debug] initKeysIfNeeded: db opened");
    let identity = await readIdentityRecord(db);
    console.log("[crypto-debug] initKeysIfNeeded: identity loaded", { hasIdentity: Boolean(identity) });
    let signing = await readSigningRecord(db);
    console.log("[crypto-debug] initKeysIfNeeded: signing loaded", { hasSigning: Boolean(signing) });
    let signedPreKey = await readSignedPreKeyRecord(db);
    console.log("[crypto-debug] initKeysIfNeeded: signed prekey loaded", { hasSignedPreKey: Boolean(signedPreKey) });
    let oneTimePreKeys = await readOneTimePreKeysRecord(db);
    console.log("[crypto-debug] initKeysIfNeeded: one-time prekeys loaded", { count: oneTimePreKeys.length });

    if (!identity) {
        console.log("Generating new identity encryption keys");
        identity = await generateIdentityKeys();
        await db.put("keys", await encryptIdentityRecord(identity, db), "identity");
        console.log("[crypto-debug] initKeysIfNeeded: identity generated");
    }

    if (!signing) {
        console.log("Generating new identity signing keys");
        signing = await generateSigningKeys();
        await db.put("keys", await encryptSigningRecord(signing, db), "signing");
        console.log("[crypto-debug] initKeysIfNeeded: signing generated");
    }

    if (!signedPreKey || shouldRotateSignedPreKey(signedPreKey)) {
        console.log("Generating signed prekey");
        signedPreKey = createSignedPreKey(signing);
        await db.put("keys", await encryptSignedPreKeyRecord(signedPreKey, db), "signed_prekey");
        console.log("[crypto-debug] initKeysIfNeeded: signed prekey generated");
    } else {
        signedPreKey = normalizeSignedPreKey(signedPreKey);
        await db.put("keys", await encryptSignedPreKeyRecord(signedPreKey, db), "signed_prekey");
        console.log("[crypto-debug] initKeysIfNeeded: signed prekey normalized");
    }

    const availablePreKeys = oneTimePreKeys.filter((prekey) => !prekey.is_used);
    if (availablePreKeys.length < PREKEY_BATCH_SIZE) {
        const missingCount = PREKEY_BATCH_SIZE - availablePreKeys.length;
        const replenished = Array.from({ length: missingCount }, () => generatePreKeyPair());
        oneTimePreKeys = [...oneTimePreKeys, ...replenished];
        await db.put("keys", await encryptOneTimePreKeysRecord(oneTimePreKeys, db), "one_time_prekeys");
        console.log("[crypto-debug] initKeysIfNeeded: replenished one-time prekeys", { missingCount });
    }

    const cleanupResult = await cleanupLocalKeyMaterial(db, signedPreKey);
    signedPreKey = cleanupResult.signedPreKey;
    oneTimePreKeys = cleanupResult.oneTimePreKeys;
    await cleanupLocalState(db);
    console.log("[crypto-debug] initKeysIfNeeded: local cleanup done");

    console.log("Syncing public key with server");

    try {
        const legacyResponse = await authFetch("/users/keys", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                public_key: identity.publicKey
            })
        });

        console.log("Legacy key sync:", await legacyResponse.json());

        const x3dhResponse = await authFetch("/users/x3dh-keys", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                public_key: identity.publicKey,
                identity_key: identity.publicKey,
                signing_key: signing.publicKey,
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
            console.log("X3DH key sync:", x3dhPayload);
        }
        console.log("[crypto-debug] initKeysIfNeeded: complete");
    } catch (err) {
        console.error("Key upload failed", err);
        console.error("[crypto-debug] initKeysIfNeeded: failed during server sync", err);
    }
}

function createSignedPreKey(signingKeys) {
    const preKey = generatePreKeyPair();
    const signature = nacl.sign.detached(
        naclUtil.decodeBase64(preKey.public_key),
        naclUtil.decodeBase64(signingKeys.privateKey)
    );

    return {
        ...preKey,
        signature: naclUtil.encodeBase64(signature),
        created_at: new Date().toISOString()
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
        const rotatedSignedPreKey = createSignedPreKey(await readSigningRecord(db));
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

async function readIdentityRecord(db) {
    const record = await db.get("keys", "identity");
    if (!record) {
        return null;
    }

    const privateKey = await decryptPrivateValue(record.privateKeyEnc, record.privateKey, db);
    const normalized = {
        publicKey: record.publicKey,
        privateKey
    };
    await db.put("keys", await encryptIdentityRecord(normalized, db), "identity");
    return normalized;
}

async function readSigningRecord(db) {
    const record = await db.get("keys", "signing");
    if (!record) {
        return null;
    }

    const privateKey = await decryptPrivateValue(record.privateKeyEnc, record.privateKey, db);
    const normalized = {
        publicKey: record.publicKey,
        privateKey
    };
    await db.put("keys", await encryptSigningRecord(normalized, db), "signing");
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

async function encryptIdentityRecord(identity, db) {
    return {
        publicKey: identity.publicKey,
        privateKeyEnc: await encryptPrivateValue(identity.privateKey, db),
        encryptedVersion: ENCRYPTED_VERSION
    };
}

async function encryptSigningRecord(signing, db) {
    return {
        publicKey: signing.publicKey,
        privateKeyEnc: await encryptPrivateValue(signing.privateKey, db),
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

function buildAccountBinding(accountData) {
    const email = String(accountData?.email || "").trim().toLowerCase();
    const accountInstanceId = String(accountData?.account_instance_id || "").trim();

    if (!email || !accountInstanceId) {
        return null;
    }

    return `${email}:${accountInstanceId}`;
}
