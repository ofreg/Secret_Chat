import nacl from "https://cdn.jsdelivr.net/npm/tweetnacl/+esm";
import naclUtil from "https://cdn.jsdelivr.net/npm/tweetnacl-util/+esm";
import { openDB } from "https://cdn.jsdelivr.net/npm/idb@7/+esm";

const PREKEY_BATCH_SIZE = 10;
const MAX_PREKEY_ID = 2147483647;
const SIGNED_PREKEY_ROTATION_MS = 7 * 24 * 60 * 60 * 1000;

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
    await db.put("ratchets", state, String(chatId));
}

export async function getRatchetState(chatId) {
    const db = await idbOpen();
    return db.get("ratchets", String(chatId));
}

export async function deleteRatchetState(chatId) {
    const db = await idbOpen();
    await db.delete("ratchets", String(chatId));
}

export async function saveCachedMessageText(chatId, messageId, text) {
    const db = await idbOpen();
    await db.put("messages", text, `msg:${chatId}:${messageId}`);
}

export async function getCachedMessageText(chatId, messageId) {
    const db = await idbOpen();
    return db.get("messages", `msg:${chatId}:${messageId}`);
}

export async function saveLastSeenMessageId(chatId, messageId) {
    const db = await idbOpen();
    await db.put("messages", messageId, `meta:lastSeen:${chatId}`);
}

export async function getLastSeenMessageId(chatId) {
    const db = await idbOpen();
    return (await db.get("messages", `meta:lastSeen:${chatId}`)) || 0;
}

export async function saveVerificationStatus(fingerprintValue, isVerified) {
    const db = await idbOpen();
    await db.put("messages", { isVerified }, `verify:${fingerprintValue}`);
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

export { nacl, naclUtil };
