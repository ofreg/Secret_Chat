import { nacl, naclUtil } from "./crypto.js";

export async function encryptMessage(message, recipientPublicBase64, senderPublicBase64) {
    return {
        version: 2,
        recipient: encryptForPublicKey(message, recipientPublicBase64),
        sender: encryptForPublicKey(message, senderPublicBase64)
    };
}

export function selectPayloadForCurrentUser(payload, isOwnMessage) {
    if (!payload || typeof payload !== "object") return null;

    if (payload.sender && payload.recipient) {
        return isOwnMessage ? payload.sender : payload.recipient;
    }

    if (payload.epk && payload.nonce && payload.message) {
        return payload;
    }

    return null;
}

export async function decryptMessage(payload, myPrivateKeyUint8) {
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
