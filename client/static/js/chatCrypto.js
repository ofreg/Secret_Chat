import {
    nacl,
    naclUtil,
    getAttachmentHistory,
    saveAttachmentHistory
} from "./crypto.js?v=20260602a";
import { decryptRatchetMessage, encryptRatchetMessage } from "./doubleRatchet.js?v=20260420i";

export async function encryptMessage({
    chatId,
    message,
    recipientIdentityKeyBase64,
    recipientPrekeyBundle = null,
    senderIdentityKeyBase64,
    myPrivateKeyUint8
}) {
    return encryptRatchetMessage({
        chatId,
        plaintext: message,
        myPrivateKeyUint8,
        myIdentityKeyBase64: senderIdentityKeyBase64,
        otherIdentityKeyBase64: recipientIdentityKeyBase64,
        recipientPrekeyBundle,
        senderCopyFactory: async (plaintext) => encryptForPublicKey(plaintext, senderIdentityKeyBase64),
        senderStateFactory: async (serializedState) => encryptForPublicKey(serializedState, senderIdentityKeyBase64)
    });
}

export async function encryptMessageForDevices({
    chatId,
    message,
    recipientDeviceBundles,
    senderDeviceBundles = [],
    currentDeviceId,
    senderIdentityKeyBase64,
    myPrivateKeyUint8
}) {
    const normalizedRecipientBundles = Array.isArray(recipientDeviceBundles)
        ? recipientDeviceBundles.filter((bundle) => bundle?.device_id && bundle?.identity_key && bundle?.signed_prekey)
        : [];

    if (!normalizedRecipientBundles.length) {
        throw new Error("Recipient device bundles are missing");
    }

    const devicePayloads = {};
    for (const bundle of normalizedRecipientBundles) {
        const devicePayload = await encryptRatchetMessage({
            chatId: `${chatId}:peer:${bundle.device_id}`,
            plaintext: message,
            myPrivateKeyUint8,
            myIdentityKeyBase64: senderIdentityKeyBase64,
            otherIdentityKeyBase64: bundle.identity_key,
            recipientPrekeyBundle: bundle,
            senderCopyFactory: async (plaintext) => encryptForPublicKey(plaintext, senderIdentityKeyBase64),
            senderStateFactory: async (serializedState) => encryptForPublicKey(serializedState, senderIdentityKeyBase64)
        });
        devicePayloads[bundle.device_id] = JSON.stringify(devicePayload);
    }

    const senderDevicePayloads = {};
    for (const bundle of Array.isArray(senderDeviceBundles) ? senderDeviceBundles : []) {
        if (!bundle?.device_id || !bundle?.identity_key) {
            continue;
        }

        senderDevicePayloads[bundle.device_id] = JSON.stringify({
            version: 3,
            sender_copy: encryptForPublicKey(message, bundle.identity_key),
            sender_state: null
        });
    }

    if (currentDeviceId && !senderDevicePayloads[currentDeviceId]) {
        senderDevicePayloads[currentDeviceId] = JSON.stringify({
            version: 3,
            sender_copy: encryptForPublicKey(message, senderIdentityKeyBase64),
            sender_state: null
        });
    }

    return {
        version: 4,
        device_payloads: devicePayloads,
        sender_device_payloads: senderDevicePayloads
    };
}

export function selectPayloadForCurrentUser(payload, isOwnMessage) {
    if (!payload || typeof payload !== "object") return null;

    if (payload.version === 3 && (payload.ratchet || payload.sender_copy)) {
        return isOwnMessage ? payload.sender_copy : payload.ratchet;
    }

    if (payload.sender && payload.recipient) {
        return isOwnMessage ? payload.sender : payload.recipient;
    }

    if (payload.epk && payload.nonce && payload.message) {
        return payload;
    }

    return null;
}

export async function decryptMessage({
    chatId,
    payload,
    myPrivateKeyUint8,
    myIdentityKeyBase64,
    otherIdentityKeyBase64,
    isOwnMessage,
    allowStateReset = true,
    restoreSenderState = true,
    restoreSenderRootKey = false
}) {
    if (payload?.version === 3) {
        return decryptRatchetMessage({
            chatId,
            payload,
            myPrivateKeyUint8,
            myIdentityKeyBase64,
            otherIdentityKeyBase64,
            isOwnMessage,
            allowStateReset,
            restoreSenderState,
            restoreSenderRootKey,
            senderCopyDecryptor: (senderCopyPayload) => decryptLegacyPayload(senderCopyPayload, myPrivateKeyUint8),
            senderStateDecryptor: (senderStatePayload) => decryptLegacyPayload(senderStatePayload, myPrivateKeyUint8)
        });
    }

    return decryptLegacyPayload(payload, myPrivateKeyUint8);
}

export async function encryptAttachmentData({
    bytes,
    metadata,
    recipientIdentityKeyBase64,
    senderIdentityKeyBase64,
    recipientDeviceBundles = [],
    senderDeviceBundles = [],
    currentDeviceId = null
}) {
    const rawKey = crypto.getRandomValues(new Uint8Array(32));
    const fileIv = crypto.getRandomValues(new Uint8Array(12));
    const metadataIv = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
    const encryptedBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: fileIv },
        cryptoKey,
        bytes
    );
    const metadataBuffer = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: metadataIv },
        cryptoKey,
        naclUtil.decodeUTF8(JSON.stringify(metadata || {}))
    );
    const keyPayload = JSON.stringify({
        key: naclUtil.encodeBase64(rawKey)
    });

    const senderDeviceKeys = {};
    const recipientDeviceKeys = {};
    for (const bundle of Array.isArray(senderDeviceBundles) ? senderDeviceBundles : []) {
        if (!bundle?.device_id || !bundle?.identity_key) {
            continue;
        }
        senderDeviceKeys[bundle.device_id] = encryptForPublicKey(keyPayload, bundle.identity_key);
    }
    for (const bundle of Array.isArray(recipientDeviceBundles) ? recipientDeviceBundles : []) {
        if (!bundle?.device_id || !bundle?.identity_key) {
            continue;
        }
        recipientDeviceKeys[bundle.device_id] = encryptForPublicKey(keyPayload, bundle.identity_key);
    }

    return {
        encryptedBytes: new Uint8Array(encryptedBuffer),
        meta: {
            encrypted: true,
            version: 2,
            algorithm: "AES-GCM",
            file_iv: naclUtil.encodeBase64(fileIv),
            metadata_iv: naclUtil.encodeBase64(metadataIv),
            metadata_ciphertext: naclUtil.encodeBase64(new Uint8Array(metadataBuffer)),
            sender_key: encryptForPublicKey(keyPayload, senderIdentityKeyBase64),
            recipient_key: encryptForPublicKey(keyPayload, recipientIdentityKeyBase64),
            current_device_id: currentDeviceId,
            sender_device_keys: senderDeviceKeys,
            recipient_device_keys: recipientDeviceKeys
        },
        historySecret: {
            key: naclUtil.encodeBase64(rawKey),
            metadata
        }
    };
}

export async function decryptAttachmentData({
    attachment,
    myPrivateKeyUint8,
    isOwnMessage
}) {
    if (!attachment?.url || !attachment?.meta?.encrypted) {
        return attachment?.url || null;
    }

    const { metadata: parsedMetadata, cryptoKey } = await resolveAttachmentHistorySecret({
        attachment,
        myPrivateKeyUint8,
        isOwnMessage
    });
    const fileIv = naclUtil.decodeBase64(attachment.meta.file_iv);

    const response = await fetch(attachment.url, { credentials: "same-origin" });
    if (!response.ok) {
        throw new Error(`Failed to fetch encrypted attachment: ${response.status}`);
    }

    const encryptedBytes = new Uint8Array(await response.arrayBuffer());
    const decryptedBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fileIv },
        cryptoKey,
        encryptedBytes
    );
    const blob = new Blob([decryptedBuffer], {
        type: parsedMetadata.mime_type || "application/octet-stream"
    });

    return {
        ...attachment,
        kind: parsedMetadata.kind || attachment.kind,
        name: parsedMetadata.name || attachment.name,
        mime_type: parsedMetadata.mime_type || attachment.mime_type,
        size: parsedMetadata.size ?? attachment.size,
        url: URL.createObjectURL(blob)
    };
}

export async function cacheAttachmentHistoryFromMessageMeta({
    attachment,
    myPrivateKeyUint8,
    isOwnMessage
}) {
    if (!attachment?.url || !attachment?.meta?.encrypted) {
        return false;
    }

    await resolveAttachmentHistorySecret({
        attachment,
        myPrivateKeyUint8,
        isOwnMessage
    });
    return true;
}

async function resolveAttachmentHistorySecret({
    attachment,
    myPrivateKeyUint8,
    isOwnMessage
}) {
    const currentDeviceId = readCurrentDeviceId();
    const wrappedKeyPayload = isOwnMessage
        ? (attachment.meta.sender_device_keys?.[currentDeviceId] || attachment.meta.sender_key)
        : (attachment.meta.recipient_device_keys?.[currentDeviceId] || attachment.meta.recipient_key);
    const cachedHistory = await getAttachmentHistory(attachment.url);

    if (
        !attachment.meta.file_iv ||
        !attachment.meta.metadata_iv ||
        !attachment.meta.metadata_ciphertext
    ) {
        throw new Error("Missing attachment encryption metadata");
    }

    let parsedKeyPayload = null;
    if (wrappedKeyPayload) {
        const decryptedKeyPayload = decryptLegacyPayload(wrappedKeyPayload, myPrivateKeyUint8);
        parsedKeyPayload = JSON.parse(decryptedKeyPayload);
    } else if (cachedHistory?.key) {
        parsedKeyPayload = { key: cachedHistory.key };
    } else {
        throw new Error("Missing attachment decryption key");
    }

    const rawKey = naclUtil.decodeBase64(parsedKeyPayload.key);
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const parsedMetadata = cachedHistory?.metadata || await decryptAttachmentMetadata({
        attachment,
        cryptoKey
    });

    await saveAttachmentHistory(attachment.url, {
        key: parsedKeyPayload.key,
        metadata: parsedMetadata
    });

    return {
        keyBase64: parsedKeyPayload.key,
        metadata: parsedMetadata,
        cryptoKey
    };
}

async function decryptAttachmentMetadata({ attachment, cryptoKey }) {
    const metadataIv = naclUtil.decodeBase64(attachment.meta.metadata_iv);
    const metadataCiphertext = naclUtil.decodeBase64(attachment.meta.metadata_ciphertext);
    const decryptedMetadataBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: metadataIv },
        cryptoKey,
        metadataCiphertext
    );

    return JSON.parse(naclUtil.encodeUTF8(new Uint8Array(decryptedMetadataBuffer)));
}

function decryptLegacyPayload(payload, myPrivateKeyUint8) {
    if (!payload.epk) throw new Error("Missing epk");

    const epk = naclUtil.decodeBase64(payload.epk);
    const nonce = naclUtil.decodeBase64(payload.nonce);
    const encrypted = naclUtil.decodeBase64(payload.message);
    const shared = nacl.box.before(epk, myPrivateKeyUint8);
    const decrypted = nacl.box.open.after(encrypted, nonce, shared);

    if (!decrypted) throw new Error("Decryption failed");

    return naclUtil.encodeUTF8(decrypted);
}

function encryptForPublicKey(message, publicKeyBase64) {
    const publicKeyUint8 = naclUtil.decodeBase64(publicKeyBase64.replace(/\s+/g, ""));
    const ephemeral = nacl.box.keyPair();
    const shared = nacl.box.before(publicKeyUint8, ephemeral.secretKey);
    const nonce = nacl.randomBytes(24);
    const encrypted = nacl.box.after(naclUtil.decodeUTF8(message), nonce, shared);

    return {
        epk: naclUtil.encodeBase64(ephemeral.publicKey),
        nonce: naclUtil.encodeBase64(nonce),
        message: naclUtil.encodeBase64(encrypted)
    };
}

function readCurrentDeviceId() {
    try {
        return window.sessionStorage.getItem("e2ee_device_id") || "";
    } catch {
        return "";
    }
}
