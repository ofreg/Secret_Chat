import { nacl, naclUtil } from "./crypto.js?v=20260420i";
import { decryptRatchetMessage, encryptRatchetMessage } from "./doubleRatchet.js?v=20260420i";

export async function encryptMessage({
    chatId,
    message,
    recipientPublicBase64,
    recipientPrekeyBundle = null,
    senderPublicBase64,
    myPrivateKeyUint8
}) {
    return encryptRatchetMessage({
        chatId,
        plaintext: message,
        myPrivateKeyUint8,
        myPublicKeyBase64: senderPublicBase64,
        otherPublicKeyBase64: recipientPublicBase64,
        recipientPrekeyBundle,
        senderCopyFactory: async (plaintext) => encryptForPublicKey(plaintext, senderPublicBase64),
        senderStateFactory: async (serializedState) => encryptForPublicKey(serializedState, senderPublicBase64)
    });
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
    myPublicKeyBase64,
    otherPublicKeyBase64,
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
            myPublicKeyBase64,
            otherPublicKeyBase64,
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
    recipientPublicBase64,
    senderPublicBase64
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

    return {
        encryptedBytes: new Uint8Array(encryptedBuffer),
        meta: {
            encrypted: true,
            version: 2,
            algorithm: "AES-GCM",
            file_iv: naclUtil.encodeBase64(fileIv),
            metadata_iv: naclUtil.encodeBase64(metadataIv),
            metadata_ciphertext: naclUtil.encodeBase64(new Uint8Array(metadataBuffer)),
            sender_key: encryptForPublicKey(keyPayload, senderPublicBase64),
            recipient_key: encryptForPublicKey(keyPayload, recipientPublicBase64)
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

    const wrappedKeyPayload = isOwnMessage
        ? attachment.meta.sender_key
        : attachment.meta.recipient_key;

    if (
        !wrappedKeyPayload ||
        !attachment.meta.file_iv ||
        !attachment.meta.metadata_iv ||
        !attachment.meta.metadata_ciphertext
    ) {
        throw new Error("Missing attachment encryption metadata");
    }

    const decryptedKeyPayload = decryptLegacyPayload(wrappedKeyPayload, myPrivateKeyUint8);
    const parsedKeyPayload = JSON.parse(decryptedKeyPayload);
    const rawKey = naclUtil.decodeBase64(parsedKeyPayload.key);
    const fileIv = naclUtil.decodeBase64(attachment.meta.file_iv);
    const metadataIv = naclUtil.decodeBase64(attachment.meta.metadata_iv);
    const metadataCiphertext = naclUtil.decodeBase64(attachment.meta.metadata_ciphertext);

    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
    const decryptedMetadataBuffer = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: metadataIv },
        cryptoKey,
        metadataCiphertext
    );
    const parsedMetadata = JSON.parse(
        naclUtil.encodeUTF8(new Uint8Array(decryptedMetadataBuffer))
    );

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
