import nacl from "https://cdn.jsdelivr.net/npm/tweetnacl/+esm";
import naclUtil from "https://cdn.jsdelivr.net/npm/tweetnacl-util/+esm";
import { openDB } from "https://cdn.jsdelivr.net/npm/idb@7/+esm";
/* ----------- CRYPTO HELPERS ----------- */

// ---------- Open DB ----------
async function idbOpen() {
    return openDB("e2ee_chat", 1, {
        upgrade(db) {
            if (!db.objectStoreNames.contains("keys")) {
                db.createObjectStore("keys");
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
