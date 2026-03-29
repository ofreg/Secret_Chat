import nacl from "https://cdn.jsdelivr.net/npm/tweetnacl/+esm";
import naclUtil from "https://cdn.jsdelivr.net/npm/tweetnacl-util/+esm";
import { openDB } from "https://cdn.jsdelivr.net/npm/idb@7/+esm";
/* ----------- CRYPTO HELPERS ----------- */

// ---------- Open DB ----------
async function idbOpen() {
    return openDB("e2ee_chat", 3, {
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

// ---------- Generate Identity Key ----------
export async function generateIdentityKeys() {
    const keyPair = nacl.box.keyPair();

    return {
        publicKey: naclUtil.encodeBase64(keyPair.publicKey),
        privateKey: naclUtil.encodeBase64(keyPair.secretKey)
    };
}

// ---------- Save keys ----------
export async function saveIdentityKey(keys) {
    const db = await idbOpen();
    await db.put("keys", keys, "identity");
}

// ---------- Load private ----------
export async function getPrivateKeyUint8() {
    const db = await idbOpen();
    const data = await db.get("keys", "identity");

    if (!data) return null;

    return naclUtil.decodeBase64(data.privateKey);
}

// ---------- Load public ----------
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

// ---------- Init ----------
export async function initKeysIfNeeded() {

    const db = await idbOpen();
    let identity = await db.get("keys", "identity");

    if (!identity) {

        console.log("Generating new keys");

        identity = await generateIdentityKeys();

        await db.put("keys", identity, "identity");
    }

    console.log("Syncing public key with server");

    try {

        const res = await fetch("/users/keys", {
            method: "POST",
            credentials: "include",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                public_key: identity.publicKey
            })
        });

        const data = await res.json();

        console.log("Server response:", data);

    } catch (err) {
        console.error("Key upload failed", err);
    }
}

// ---------- Fingerprint ----------
export async function fingerprint(base64Key) {

    const data = Uint8Array.from(atob(base64Key), c => c.charCodeAt(0));

    const hash = await crypto.subtle.digest("SHA-256", data);

    return Array.from(new Uint8Array(hash))
        .map(b => b.toString(16).padStart(2, "0"))
        .join(":");
}

export { nacl, naclUtil };
