import { nacl, naclUtil } from "./crypto.js";
import { decryptRatchetMessage, encryptRatchetMessage } from "./doubleRatchet.js";

export async function encryptMessage({
    chatId,
    message,
    recipientPublicBase64,
    senderPublicBase64,
    myPrivateKeyUint8
}) {
    return encryptRatchetMessage({
        chatId,
        plaintext: message,
        myPrivateKeyUint8,
        myPublicKeyBase64: senderPublicBase64,
        otherPublicKeyBase64: recipientPublicBase64,
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
    allowStateReset = true
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
            senderCopyDecryptor: (senderCopyPayload) => decryptLegacyPayload(senderCopyPayload, myPrivateKeyUint8),
            senderStateDecryptor: (senderStatePayload) => decryptLegacyPayload(senderStatePayload, myPrivateKeyUint8)
        });
    }

    return decryptLegacyPayload(payload, myPrivateKeyUint8);
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
