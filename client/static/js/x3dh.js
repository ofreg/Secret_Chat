import { nacl, naclUtil } from "./crypto.js";

export function verifySignedPreKey({ signingKeyBase64, signedPreKeyBase64, signatureBase64 }) {
    if (!signingKeyBase64 || !signedPreKeyBase64 || !signatureBase64) {
        return false;
    }

    return nacl.sign.detached.verify(
        naclUtil.decodeBase64(signedPreKeyBase64),
        naclUtil.decodeBase64(signatureBase64),
        naclUtil.decodeBase64(signingKeyBase64)
    );
}

export async function deriveInitiatorX3dhSecret({
    myIdentityPrivateKeyBase64,
    myEphemeralPrivateKeyBase64,
    recipientIdentityKeyBase64,
    recipientSignedPreKeyBase64,
    recipientOneTimePreKeyBase64 = null
}) {
    const dh1 = nacl.scalarMult(
        decodeBoxSecret(myIdentityPrivateKeyBase64),
        decodeBoxPublic(recipientSignedPreKeyBase64)
    );
    const dh2 = nacl.scalarMult(
        decodeBoxSecret(myEphemeralPrivateKeyBase64),
        decodeBoxPublic(recipientIdentityKeyBase64)
    );
    const dh3 = nacl.scalarMult(
        decodeBoxSecret(myEphemeralPrivateKeyBase64),
        decodeBoxPublic(recipientSignedPreKeyBase64)
    );

    const parts = [dh1, dh2, dh3];
    if (recipientOneTimePreKeyBase64) {
        parts.push(
            nacl.scalarMult(
                decodeBoxSecret(myEphemeralPrivateKeyBase64),
                decodeBoxPublic(recipientOneTimePreKeyBase64)
            )
        );
    }

    return sha256(concatUint8Arrays(parts));
}

async function sha256(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return naclUtil.encodeBase64(new Uint8Array(digest));
}

function decodeBoxPublic(base64Value) {
    return naclUtil.decodeBase64(base64Value.replace(/\s+/g, ""));
}

function decodeBoxSecret(base64Value) {
    return naclUtil.decodeBase64(base64Value.replace(/\s+/g, ""));
}

function concatUint8Arrays(chunks) {
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }

    return result;
}
