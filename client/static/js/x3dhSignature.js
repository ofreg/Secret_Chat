const SIGNED_PREKEY_SIGNATURE_LABEL = "e2ee-chat:x3dh:signed-prekey:v2";

export function buildSignedPreKeySignaturePayload({
    identityDhKeyBase64,
    signedPreKeyBase64,
    signedPreKeyKeyId
}) {
    const labelBytes = new TextEncoder().encode(SIGNED_PREKEY_SIGNATURE_LABEL);
    const identityDhBytes = decodeBase64(identityDhKeyBase64);
    const signedPreKeyBytes = decodeBase64(signedPreKeyBase64);
    const keyIdBytes = encodeUint32(signedPreKeyKeyId);
    const separator = Uint8Array.from([0]);
    const payload = new Uint8Array(
        labelBytes.length
        + separator.length
        + identityDhBytes.length
        + separator.length
        + signedPreKeyBytes.length
        + separator.length
        + keyIdBytes.length
    );

    let offset = 0;
    payload.set(labelBytes, offset);
    offset += labelBytes.length;
    payload.set(separator, offset);
    offset += separator.length;
    payload.set(identityDhBytes, offset);
    offset += identityDhBytes.length;
    payload.set(separator, offset);
    offset += separator.length;
    payload.set(signedPreKeyBytes, offset);
    offset += signedPreKeyBytes.length;
    payload.set(separator, offset);
    offset += separator.length;
    payload.set(keyIdBytes, offset);

    return payload;
}

function decodeBase64(value) {
    const normalized = String(value || "").replace(/\s+/g, "");
    return Uint8Array.from(atob(normalized), (char) => char.charCodeAt(0));
}

function encodeUint32(value) {
    const normalized = Number.isFinite(Number(value)) ? Number(value) >>> 0 : 0;
    const bytes = new Uint8Array(4);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, normalized, false);
    return bytes;
}
