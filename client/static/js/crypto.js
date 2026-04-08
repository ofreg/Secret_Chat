import nacl from "https://cdn.jsdelivr.net/npm/tweetnacl/+esm";
import naclUtil from "https://cdn.jsdelivr.net/npm/tweetnacl-util/+esm";
import { openDB } from "https://cdn.jsdelivr.net/npm/idb@7/+esm";

const PREKEY_BATCH_SIZE = 10;
const MAX_PREKEY_ID = 2147483647;
const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;
const USED_PREKEY_RETENTION_MS = 7 * 24 * 60 * 60 * 1000;
const LOCAL_RATCHET_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const LOCAL_MESSAGE_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const VERIFICATION_RETENTION_MS = 180 * 24 * 60 * 60 * 1000;

async function idbOpen() {
    return openDB("e2ee_chat", 4, {
        upgrade(db) {
            if (!db.objectStoreNames.contains("keys")) {
                db.createObjectStore("keys");
            }
            if (!db.objectStoreNames.contains("ratchets")) {
                db.createObjectStore("ratchets");
            }
            if (!db.objectStoreNames.contains("messages")) {
                db.createObjectStore("messages");
            }
        }
    });
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
    await db.put("keys", keys, "identity");
}

export async function getPrivateKeyUint8() {
    const db = await idbOpen();
    const data = await db.get("keys", "identity");

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
    const db = await idbOpen();
    await db.put("messages", { text, updatedAt: Date.now() }, `msg:${chatId}:${messageId}`);
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
    const data = await db.get("keys", "signing");
    return data?.publicKey || null;
}

export async function getSignedPreKeyPublic() {
    const db = await idbOpen();
    const data = await db.get("keys", "signed_prekey");
    return data?.public_key || data?.publicKey || null;
}

export async function getSignedPreKey() {
    const db = await idbOpen();
    const data = await db.get("keys", "signed_prekey");
    return data ? normalizeSignedPreKey(data) : null;
}

export async function consumeLocalOneTimePreKey(keyId) {
    const db = await idbOpen();
    const oneTimePreKeys = normalizeOneTimePreKeys((await db.get("keys", "one_time_prekeys")) || []);
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
        await db.put("keys", oneTimePreKeys, "one_time_prekeys");
    }

    return oneTimePreKeys[keyIndex];
}

export async function getX3dhState() {
    const db = await idbOpen();
    return {
        identity: await db.get("keys", "identity"),
        signing: await db.get("keys", "signing"),
        signedPreKey: normalizeSignedPreKey(await db.get("keys", "signed_prekey")),
        oneTimePreKeys: normalizeOneTimePreKeys((await db.get("keys", "one_time_prekeys")) || [])
    };
}

export async function initKeysIfNeeded() {
    const db = await idbOpen();
    let identity = await db.get("keys", "identity");
    let signing = await db.get("keys", "signing");
    let signedPreKey = await db.get("keys", "signed_prekey");
    let oneTimePreKeys = normalizeOneTimePreKeys((await db.get("keys", "one_time_prekeys")) || []);

    if (!identity) {
        console.log("Generating new identity encryption keys");
        identity = await generateIdentityKeys();
        await db.put("keys", identity, "identity");
    }

    if (!signing) {
        console.log("Generating new identity signing keys");
        signing = await generateSigningKeys();
        await db.put("keys", signing, "signing");
    }

    if (!signedPreKey || shouldRotateSignedPreKey(signedPreKey)) {
        console.log("Generating signed prekey");
        signedPreKey = createSignedPreKey(signing);
        await db.put("keys", signedPreKey, "signed_prekey");
    } else {
        signedPreKey = normalizeSignedPreKey(signedPreKey);
        await db.put("keys", signedPreKey, "signed_prekey");
    }

    const availablePreKeys = oneTimePreKeys.filter((prekey) => !prekey.is_used);
    if (availablePreKeys.length < PREKEY_BATCH_SIZE) {
        const missingCount = PREKEY_BATCH_SIZE - availablePreKeys.length;
        const replenished = Array.from({ length: missingCount }, () => generatePreKeyPair());
        oneTimePreKeys = [...oneTimePreKeys, ...replenished];
        await db.put("keys", oneTimePreKeys, "one_time_prekeys");
    }

    const cleanupResult = await cleanupLocalKeyMaterial(db, signedPreKey);
    signedPreKey = cleanupResult.signedPreKey;
    oneTimePreKeys = cleanupResult.oneTimePreKeys;
    await cleanupLocalState(db);

    console.log("Syncing public key with server");

    try {
        const legacyResponse = await fetch("/users/keys", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                public_key: identity.publicKey
            })
        });

        console.log("Legacy key sync:", await legacyResponse.json());

        const x3dhResponse = await fetch("/users/x3dh-keys", {
            method: "POST",
            credentials: "include",
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
    } catch (err) {
        console.error("Key upload failed", err);
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
            created_at: prekey?.created_at ?? prekey?.createdAt ?? null,
            is_used: Boolean(prekey?.is_used ?? prekey?.isUsed ?? false),
            used_at: prekey?.used_at ?? prekey?.usedAt ?? null
        }))
        .filter((prekey) => prekey.key_id && prekey.public_key && prekey.private_key);
}

function normalizeSignedPreKey(prekey) {
    return {
        ...prekey,
        key_id: normalizePreKeyId(prekey?.key_id ?? prekey?.keyId ?? null),
        public_key: prekey?.public_key ?? prekey?.publicKey ?? null,
        private_key: prekey?.private_key ?? prekey?.privateKey ?? null,
        created_at: prekey?.created_at ?? prekey?.createdAt ?? new Date().toISOString()
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
        await db.put("keys", filteredPreKeys, "one_time_prekeys");
    }

    let nextSignedPreKey = signedPreKey;

    if (Number.isFinite(signedPreKeyCreatedAt) && now - signedPreKeyCreatedAt > SIGNED_PREKEY_ROTATION_MS * 2) {
        const rotatedSignedPreKey = createSignedPreKey(await db.get("keys", "signing"));
        await db.put("keys", rotatedSignedPreKey, "signed_prekey");
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

export { nacl, naclUtil };
