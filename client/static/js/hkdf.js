import { naclUtil } from "./crypto.js?v=20260416w";

export async function hkdfExtract(saltBytes, inputKeyMaterialBytes) {
    const normalizedSalt = saltBytes && saltBytes.length
        ? saltBytes
        : new Uint8Array(32);

    return hmacSha256(normalizedSalt, inputKeyMaterialBytes);
}

export async function hkdfExpand(prkBytes, info, length) {
    const infoBytes = typeof info === "string" ? naclUtil.decodeUTF8(info) : info;
    const blocks = [];
    let previous = new Uint8Array(0);

    while (concatChunks(blocks).length < length) {
        const roundInput = concatChunks([previous, infoBytes, Uint8Array.from([blocks.length + 1])]);
        previous = await hmacSha256(prkBytes, roundInput);
        blocks.push(previous);
    }

    return concatChunks(blocks).slice(0, length);
}

export async function hkdf(saltBytes, inputKeyMaterialBytes, info, length) {
    const prk = await hkdfExtract(saltBytes, inputKeyMaterialBytes);
    return hkdfExpand(prk, info, length);
}

export async function deriveLabeledSecrets({ saltBytes, inputKeyMaterialBytes, label, lengthsByName }) {
    const result = {};
    const names = Object.keys(lengthsByName);

    for (const name of names) {
        result[name] = await hkdf(
            saltBytes,
            inputKeyMaterialBytes,
            `${label}:${name}`,
            lengthsByName[name]
        );
    }

    return result;
}

export async function hmacSha256(keyBytes, messageBytes) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );
    const signature = await crypto.subtle.sign("HMAC", cryptoKey, messageBytes);
    return new Uint8Array(signature);
}

export function concatChunks(chunks) {
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }

    return result;
}
