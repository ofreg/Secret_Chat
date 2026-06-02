import { nacl, naclUtil } from "./crypto.js?v=20260420i";
import { concatChunks, hkdf } from "./hkdf.js?v=20260420i";
import { buildSignedPreKeySignaturePayload } from "./x3dhSignature.js?v=20260601a";

export function verifySignedPreKey({
    identitySigningKeyBase64,
    identityKeyBase64,
    signedPreKeyBase64,
    signedPreKeyKeyId,
    signatureBase64
}) {
    if (!identitySigningKeyBase64 || !identityKeyBase64 || !signedPreKeyBase64 || !signatureBase64 || !signedPreKeyKeyId) {
        return false;
    }

    return nacl.sign.detached.verify(
        buildSignedPreKeySignaturePayload({
            identityDhKeyBase64: identityKeyBase64,
            signedPreKeyBase64,
            signedPreKeyKeyId
        }),
        naclUtil.decodeBase64(signatureBase64),
        naclUtil.decodeBase64(identitySigningKeyBase64)
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

    return deriveX3dhRoot(parts);
}

export async function deriveResponderX3dhSecret({
    myIdentityPrivateKeyBase64,
    mySignedPreKeyPrivateKeyBase64,
    myOneTimePreKeyPrivateKeyBase64 = null,
    initiatorIdentityKeyBase64,
    initiatorEphemeralKeyBase64
}) {
    const dh1 = nacl.scalarMult(
        decodeBoxSecret(mySignedPreKeyPrivateKeyBase64),
        decodeBoxPublic(initiatorIdentityKeyBase64)
    );
    const dh2 = nacl.scalarMult(
        decodeBoxSecret(myIdentityPrivateKeyBase64),
        decodeBoxPublic(initiatorEphemeralKeyBase64)
    );
    const dh3 = nacl.scalarMult(
        decodeBoxSecret(mySignedPreKeyPrivateKeyBase64),
        decodeBoxPublic(initiatorEphemeralKeyBase64)
    );

    const parts = [dh1, dh2, dh3];
    if (myOneTimePreKeyPrivateKeyBase64) {
        parts.push(
            nacl.scalarMult(
                decodeBoxSecret(myOneTimePreKeyPrivateKeyBase64),
                decodeBoxPublic(initiatorEphemeralKeyBase64)
            )
        );
    }

    return deriveX3dhRoot(parts);
}

async function deriveX3dhRoot(parts) {
    const ikm = concatChunks(parts);
    const derived = await hkdf(
        naclUtil.decodeUTF8("x3dh-salt"),
        ikm,
        "x3dh:root",
        32
    );
    return naclUtil.encodeBase64(derived);
}

function decodeBoxPublic(base64Value) {
    return naclUtil.decodeBase64(base64Value.replace(/\s+/g, ""));
}

function decodeBoxSecret(base64Value) {
    return naclUtil.decodeBase64(base64Value.replace(/\s+/g, ""));
}
