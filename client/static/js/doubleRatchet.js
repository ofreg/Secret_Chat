import { deleteRatchetState, getRatchetState, nacl, naclUtil, saveRatchetState } from "./crypto.js";

const MAX_SKIPPED_KEYS = 64;

export async function encryptRatchetMessage({
    chatId,
    plaintext,
    myPrivateKeyUint8,
    myPublicKeyBase64,
    otherPublicKeyBase64,
    senderCopyFactory,
    senderStateFactory
}) {
    let state = await getOrCreateState(chatId, myPrivateKeyUint8, myPublicKeyBase64, otherPublicKeyBase64);

    if (!state.CKs) {
        state = await initializeSendingChain(state, otherPublicKeyBase64);
    }

    const chainStep = await kdfChain(decodeBase64(state.CKs));
    state.CKs = encodeBase64(chainStep.nextChainKey);

    const header = {
        dh: state.DHs.publicKey,
        pn: state.PN,
        n: state.Ns
    };

    state.Ns += 1;

    const nonce = nacl.randomBytes(24);
    const ciphertext = nacl.secretbox(
        naclUtil.decodeUTF8(plaintext),
        nonce,
        chainStep.messageKey
    );

    await saveRatchetState(chatId, state);

    return {
        version: 3,
        ratchet: {
            header,
            nonce: encodeBase64(nonce),
            ciphertext: encodeBase64(ciphertext)
        },
        sender_copy: await senderCopyFactory(plaintext),
        sender_state: senderStateFactory
            ? await senderStateFactory(JSON.stringify(extractOwnStateSnapshot(state)))
            : null
    };
}

export async function decryptRatchetMessage({
    chatId,
    payload,
    myPrivateKeyUint8,
    myPublicKeyBase64,
    otherPublicKeyBase64,
    isOwnMessage,
    allowStateReset = true,
    senderCopyDecryptor,
    senderStateDecryptor
}) {
    if (isOwnMessage) {
        if (!payload.sender_copy) {
            throw new Error("Missing sender copy");
        }
        const plaintext = senderCopyDecryptor(payload.sender_copy);

        if (payload.sender_state && senderStateDecryptor) {
            const serializedState = senderStateDecryptor(payload.sender_state);
            const restoredSnapshot = JSON.parse(serializedState);
            const currentState = await getOrCreateState(
                chatId,
                myPrivateKeyUint8,
                myPublicKeyBase64,
                otherPublicKeyBase64
            );

            await saveRatchetState(chatId, mergeOwnStateSnapshot(currentState, restoredSnapshot));
        }

        return plaintext;
    }

    const ratchetPayload = payload.ratchet;
    if (!ratchetPayload?.header || !ratchetPayload?.nonce || !ratchetPayload?.ciphertext) {
        throw new Error("Missing ratchet payload");
    }

    try {
        return await decryptWithState({
            chatId,
            ratchetPayload,
            myPrivateKeyUint8,
            myPublicKeyBase64,
            otherPublicKeyBase64
        });
    } catch (error) {
        if (!allowStateReset || !shouldAttemptSessionReset(error, ratchetPayload.header)) {
            throw error;
        }

        await deleteRatchetState(chatId);

        return decryptWithState({
            chatId,
            ratchetPayload,
            myPrivateKeyUint8,
            myPublicKeyBase64,
            otherPublicKeyBase64
        });
    }
}

async function decryptWithState({
    chatId,
    ratchetPayload,
    myPrivateKeyUint8,
    myPublicKeyBase64,
    otherPublicKeyBase64
}) {
    let state = await getOrCreateState(chatId, myPrivateKeyUint8, myPublicKeyBase64, otherPublicKeyBase64);
    const header = ratchetPayload.header;

    const skippedKeyId = buildSkippedKeyId(header.dh, header.n);
    if (state.skippedKeys?.[skippedKeyId]) {
        const messageKey = decodeBase64(state.skippedKeys[skippedKeyId]);
        delete state.skippedKeys[skippedKeyId];
        const plaintext = decryptSecretBox(ratchetPayload, messageKey);
        await saveRatchetState(chatId, state);
        return plaintext;
    }

    if (state.DHr !== header.dh) {
        state = await skipMessageKeys(state, header.pn);
        state = await applyDhRatchet(state, header.dh, myPrivateKeyUint8);
    }

    state = await skipMessageKeys(state, header.n);

    if (!state.CKr) {
        throw new Error("Missing receiving chain");
    }

    const chainStep = await kdfChain(decodeBase64(state.CKr));
    state.CKr = encodeBase64(chainStep.nextChainKey);
    state.Nr += 1;

    const plaintext = decryptSecretBox(ratchetPayload, chainStep.messageKey);
    await saveRatchetState(chatId, state);
    return plaintext;
}

async function getOrCreateState(chatId, myPrivateKeyUint8, myPublicKeyBase64, otherPublicKeyBase64) {
    const existing = await getRatchetState(chatId);
    if (existing) {
        return normalizeState(existing);
    }

    const sharedIdentitySecret = nacl.scalarMult(
        myPrivateKeyUint8,
        decodeBase64(otherPublicKeyBase64)
    );
    const rootKey = await sha256(sharedIdentitySecret);

    const state = normalizeState({
        RK: encodeBase64(rootKey),
        DHs: {
            publicKey: myPublicKeyBase64,
            privateKey: encodeBase64(myPrivateKeyUint8)
        },
        DHr: null,
        remoteIdentityKey: otherPublicKeyBase64,
        CKs: null,
        CKr: null,
        Ns: 0,
        Nr: 0,
        PN: 0,
        useIdentityForSending: true,
        skippedKeys: {}
    });

    await saveRatchetState(chatId, state);
    return state;
}

async function initializeSendingChain(state, otherPublicKeyBase64) {
    const remoteKey = state.DHr || otherPublicKeyBase64;

    if (state.useIdentityForSending) {
        state.DHs = serializeKeyPair(nacl.box.keyPair());
        state.useIdentityForSending = false;
    }

    const rootStep = await kdfRoot(
        decodeBase64(state.RK),
        nacl.scalarMult(decodeBase64(state.DHs.privateKey), decodeBase64(remoteKey))
    );

    state.RK = encodeBase64(rootStep.rootKey);
    state.CKs = encodeBase64(rootStep.chainKey);
    state.PN = state.Ns;
    state.Ns = 0;

    return state;
}

async function applyDhRatchet(state, remoteDhBase64, myPrivateKeyUint8) {
    const receivingPrivateKey = (state.DHr === null && state.Ns === 0 && !state.CKs)
        ? myPrivateKeyUint8
        : decodeBase64(state.DHs.privateKey);

    const recvRootStep = await kdfRoot(
        decodeBase64(state.RK),
        nacl.scalarMult(
            receivingPrivateKey,
            decodeBase64(remoteDhBase64)
        )
    );

    state.RK = encodeBase64(recvRootStep.rootKey);
    state.CKr = encodeBase64(recvRootStep.chainKey);
    state.DHr = remoteDhBase64;
    state.PN = state.Ns;
    state.Ns = 0;
    state.Nr = 0;

    const newSendingKeyPair = nacl.box.keyPair();
    const sendRootStep = await kdfRoot(
        decodeBase64(state.RK),
        nacl.scalarMult(
            newSendingKeyPair.secretKey,
            decodeBase64(state.DHr)
        )
    );

    state.RK = encodeBase64(sendRootStep.rootKey);
    state.CKs = encodeBase64(sendRootStep.chainKey);
    state.DHs = serializeKeyPair(newSendingKeyPair);
    state.useIdentityForSending = false;

    if (!myPrivateKeyUint8) {
        throw new Error("Missing local private key");
    }

    return state;
}

async function skipMessageKeys(state, until) {
    if (!state.CKr) {
        return state;
    }

    while (state.Nr < until) {
        const chainStep = await kdfChain(decodeBase64(state.CKr));
        state.CKr = encodeBase64(chainStep.nextChainKey);
        state.skippedKeys[buildSkippedKeyId(state.DHr, state.Nr)] = encodeBase64(chainStep.messageKey);
        state.Nr += 1;

        const skippedIds = Object.keys(state.skippedKeys);
        if (skippedIds.length > MAX_SKIPPED_KEYS) {
            delete state.skippedKeys[skippedIds[0]];
        }
    }

    return state;
}

function decryptSecretBox(ratchetPayload, messageKey) {
    const nonce = decodeBase64(ratchetPayload.nonce);
    const ciphertext = decodeBase64(ratchetPayload.ciphertext);
    const plaintext = nacl.secretbox.open(ciphertext, nonce, messageKey);

    if (!plaintext) {
        throw new Error("Ratchet decryption failed");
    }

    return naclUtil.encodeUTF8(plaintext);
}

function shouldAttemptSessionReset(error, header) {
    if (!header) return false;
    if (header.n !== 0 || header.pn !== 0) return false;

    const message = error instanceof Error ? error.message : String(error);
    return message.includes("Ratchet decryption failed") || message.includes("Missing receiving chain");
}

async function kdfRoot(rootKeyBytes, dhOutputBytes) {
    const seed = await hmacSha256(rootKeyBytes, dhOutputBytes);
    const rootKey = await hmacSha256(seed, naclUtil.decodeUTF8("root"));
    const chainKey = await hmacSha256(seed, naclUtil.decodeUTF8("chain"));
    return { rootKey, chainKey };
}

async function kdfChain(chainKeyBytes) {
    const nextChainKey = await hmacSha256(chainKeyBytes, naclUtil.decodeUTF8("chain"));
    const messageKey = await hmacSha256(chainKeyBytes, naclUtil.decodeUTF8("message"));
    return { nextChainKey, messageKey };
}

async function hmacSha256(keyBytes, messageBytes) {
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

async function sha256(bytes) {
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return new Uint8Array(digest);
}

function serializeKeyPair(keyPair) {
    return {
        publicKey: encodeBase64(keyPair.publicKey),
        privateKey: encodeBase64(keyPair.secretKey)
    };
}

function buildSkippedKeyId(dh, n) {
    return `${dh}:${n}`;
}

function normalizeState(state) {
    return {
        RK: state.RK,
        DHs: state.DHs,
        DHr: state.DHr || null,
        remoteIdentityKey: state.remoteIdentityKey || null,
        CKs: state.CKs || null,
        CKr: state.CKr || null,
        Ns: state.Ns || 0,
        Nr: state.Nr || 0,
        PN: state.PN || 0,
        useIdentityForSending: state.useIdentityForSending !== false,
        skippedKeys: state.skippedKeys || {}
    };
}

function extractOwnStateSnapshot(state) {
    return {
        RK: state.RK,
        DHs: state.DHs,
        CKs: state.CKs || null,
        Ns: state.Ns || 0,
        PN: state.PN || 0,
        useIdentityForSending: state.useIdentityForSending !== false,
        remoteIdentityKey: state.remoteIdentityKey || null
    };
}

function mergeOwnStateSnapshot(currentState, snapshot) {
    return normalizeState({
        ...currentState,
        RK: snapshot.RK || currentState.RK,
        DHs: snapshot.DHs || currentState.DHs,
        CKs: snapshot.CKs || null,
        Ns: snapshot.Ns || 0,
        PN: snapshot.PN || 0,
        useIdentityForSending: snapshot.useIdentityForSending !== false,
        remoteIdentityKey: snapshot.remoteIdentityKey || currentState.remoteIdentityKey,
        DHr: currentState.DHr,
        CKr: currentState.CKr,
        Nr: currentState.Nr,
        skippedKeys: currentState.skippedKeys || {}
    });
}

function encodeBase64(bytes) {
    return naclUtil.encodeBase64(bytes);
}

function decodeBase64(value) {
    return naclUtil.decodeBase64(value.replace(/\s+/g, ""));
}
