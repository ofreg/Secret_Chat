import {
    consumeLocalOneTimePreKey,
    deleteRatchetState,
    getRatchetState,
    getSignedPreKey,
    nacl,
    naclUtil,
    saveRatchetState
} from "./crypto.js?v=20260419a";
import {
    deriveInitiatorX3dhSecret,
    deriveResponderX3dhSecret,
    verifySignedPreKey
} from "./x3dh.js?v=20260419a";
import { deriveLabeledSecrets, hmacSha256 } from "./hkdf.js?v=20260419a";

const MAX_SKIPPED_KEYS = 64;
const RATCHET_STATE_VERSION = 3;

export async function encryptRatchetMessage({
    chatId,
    plaintext,
    myPrivateKeyUint8,
    myPublicKeyBase64,
    otherPublicKeyBase64,
    recipientPrekeyBundle,
    senderCopyFactory,
    senderStateFactory
}) {
    let state = await getOrCreateState(
        chatId,
        myPrivateKeyUint8,
        myPublicKeyBase64,
        otherPublicKeyBase64,
        recipientPrekeyBundle
    );

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
        chainStep.encryptionKey
    );
    const mac = await buildMessageMac(header, nonce, ciphertext, chainStep.macKey);

    await saveRatchetState(chatId, state);

    let x3dh = null;
    if (state.pendingX3dhHandshake) {
        x3dh = state.pendingX3dhHandshake;
        delete state.pendingX3dhHandshake;
        await saveRatchetState(chatId, state);
    }

    return {
        version: 3,
        x3dh,
        ratchet: {
            header,
            nonce: encodeBase64(nonce),
            ciphertext: encodeBase64(ciphertext),
            mac: encodeBase64(mac)
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
    restoreSenderState = true,
    restoreSenderRootKey = false,
    senderCopyDecryptor,
    senderStateDecryptor
}) {
    if (isOwnMessage) {
        if (!payload.sender_copy) {
            throw new Error("Missing sender copy");
        }
        const plaintext = senderCopyDecryptor(payload.sender_copy);

        if (restoreSenderState && payload.sender_state && senderStateDecryptor) {
            const serializedState = senderStateDecryptor(payload.sender_state);
            const restoredSnapshot = JSON.parse(serializedState);
            const currentState = await getOrCreateState(
                chatId,
                myPrivateKeyUint8,
                myPublicKeyBase64,
                otherPublicKeyBase64
            );

            await saveRatchetState(
                chatId,
                mergeOwnStateSnapshot(currentState, restoredSnapshot, { restoreRootKey: restoreSenderRootKey })
            );
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
            otherPublicKeyBase64,
            x3dhPayload: payload.x3dh || null
        });
    } catch (error) {
        if (!allowStateReset || !shouldAttemptSessionReset(error, ratchetPayload.header, payload.x3dh || null)) {
            throw error;
        }

        await deleteRatchetState(chatId);

        return decryptWithState({
            chatId,
            ratchetPayload,
            myPrivateKeyUint8,
            myPublicKeyBase64,
            otherPublicKeyBase64,
            x3dhPayload: payload.x3dh || null
        });
    }
}

async function decryptWithState({
    chatId,
    ratchetPayload,
    myPrivateKeyUint8,
    myPublicKeyBase64,
    otherPublicKeyBase64,
    x3dhPayload = null
}) {
    let state = await getOrCreateState(
        chatId,
        myPrivateKeyUint8,
        myPublicKeyBase64,
        otherPublicKeyBase64,
        null,
        x3dhPayload
    );
    const header = ratchetPayload.header;

    const skippedKeyId = buildSkippedKeyId(header.dh, header.n);
    if (state.skippedKeys?.[skippedKeyId]) {
        const messageKeyBundle = state.skippedKeys[skippedKeyId];
        delete state.skippedKeys[skippedKeyId];
        const plaintext = await decryptSecretBox(
            ratchetPayload,
            decodeBase64(messageKeyBundle.encryptionKey),
            decodeBase64(messageKeyBundle.macKey)
        );
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

    const plaintext = await decryptSecretBox(
        ratchetPayload,
        chainStep.encryptionKey,
        chainStep.macKey
    );
    await saveRatchetState(chatId, state);
    return plaintext;
}

async function getOrCreateState(
    chatId,
    myPrivateKeyUint8,
    myPublicKeyBase64,
    otherPublicKeyBase64,
    recipientPrekeyBundle = null,
    x3dhPayload = null
) {
    const existing = await getRatchetState(chatId);
    if (existing) {
        const normalizedExisting = normalizeState(existing);
        if (normalizedExisting.stateVersion === RATCHET_STATE_VERSION) {
            return normalizedExisting;
        }

        await deleteRatchetState(chatId);
    }

    const bootstrapState = await createInitialState({
        myPrivateKeyUint8,
        myPublicKeyBase64,
        otherPublicKeyBase64,
        recipientPrekeyBundle,
        x3dhPayload
    });

    const state = normalizeState({
        stateVersion: RATCHET_STATE_VERSION,
        ...bootstrapState
    });

    await saveRatchetState(chatId, state);
    return state;
}

async function initializeSendingChain(state, otherPublicKeyBase64) {
    const remoteKey = state.initialRemotePreKey || state.DHr || otherPublicKeyBase64;

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

async function createInitialState({
    myPrivateKeyUint8,
    myPublicKeyBase64,
    otherPublicKeyBase64,
    recipientPrekeyBundle,
    x3dhPayload
}) {
    if (recipientPrekeyBundle?.signed_prekey) {
        if (
            recipientPrekeyBundle.signing_key &&
            recipientPrekeyBundle.signed_prekey_signature &&
            !verifySignedPreKey({
                signingKeyBase64: recipientPrekeyBundle.signing_key,
                signedPreKeyBase64: recipientPrekeyBundle.signed_prekey,
                signatureBase64: recipientPrekeyBundle.signed_prekey_signature
            })
        ) {
            throw new Error("Signed prekey verification failed");
        }

        const initiatorEphemeral = nacl.box.keyPair();
        const x3dhSecret = await deriveInitiatorX3dhSecret({
            myIdentityPrivateKeyBase64: encodeBase64(myPrivateKeyUint8),
            myEphemeralPrivateKeyBase64: encodeBase64(initiatorEphemeral.secretKey),
            recipientIdentityKeyBase64: recipientPrekeyBundle.identity_key || otherPublicKeyBase64,
            recipientSignedPreKeyBase64: recipientPrekeyBundle.signed_prekey,
            recipientOneTimePreKeyBase64: recipientPrekeyBundle.one_time_prekey?.public_key || null
        });

        return {
            RK: x3dhSecret,
            DHs: {
                publicKey: myPublicKeyBase64,
                privateKey: encodeBase64(myPrivateKeyUint8)
            },
            DHr: null,
            remoteIdentityKey: recipientPrekeyBundle.identity_key || otherPublicKeyBase64,
            CKs: null,
            CKr: null,
            Ns: 0,
            Nr: 0,
            PN: 0,
            useIdentityForSending: true,
            skippedKeys: {},
            initialPrivateKey: null,
            initialRemotePreKey: recipientPrekeyBundle.signed_prekey,
            pendingX3dhHandshake: {
                initiator_identity_key: myPublicKeyBase64,
                initiator_ephemeral_key: encodeBase64(initiatorEphemeral.publicKey),
                signed_prekey_key_id: recipientPrekeyBundle.signed_prekey_key_id,
                one_time_prekey_key_id: recipientPrekeyBundle.one_time_prekey?.key_id || null
            }
        };
    }

    if (x3dhPayload?.initiator_identity_key && x3dhPayload?.initiator_ephemeral_key) {
        const signedPreKey = await getSignedPreKey();
        if (!signedPreKey?.private_key) {
            throw new Error("Missing local signed prekey");
        }

        const oneTimePreKey = x3dhPayload.one_time_prekey_key_id
            ? await consumeLocalOneTimePreKey(x3dhPayload.one_time_prekey_key_id)
            : null;

        const x3dhSecret = await deriveResponderX3dhSecret({
            myIdentityPrivateKeyBase64: encodeBase64(myPrivateKeyUint8),
            mySignedPreKeyPrivateKeyBase64: signedPreKey.private_key,
            myOneTimePreKeyPrivateKeyBase64: oneTimePreKey?.private_key || null,
            initiatorIdentityKeyBase64: x3dhPayload.initiator_identity_key,
            initiatorEphemeralKeyBase64: x3dhPayload.initiator_ephemeral_key
        });

        return {
            RK: x3dhSecret,
            DHs: {
                publicKey: myPublicKeyBase64,
                privateKey: encodeBase64(myPrivateKeyUint8)
            },
            DHr: null,
            remoteIdentityKey: x3dhPayload.initiator_identity_key,
            CKs: null,
            CKr: null,
            Ns: 0,
            Nr: 0,
            PN: 0,
            useIdentityForSending: true,
            skippedKeys: {},
            initialPrivateKey: signedPreKey.private_key,
            initialRemotePreKey: null,
            pendingX3dhHandshake: null
        };
    }

    const sharedIdentitySecret = nacl.scalarMult(
        myPrivateKeyUint8,
        decodeBase64(otherPublicKeyBase64)
    );
    const rootKey = await sha256(sharedIdentitySecret);

    return {
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
        skippedKeys: {},
        initialPrivateKey: null,
        initialRemotePreKey: null,
        pendingX3dhHandshake: null
    };
}

async function applyDhRatchet(state, remoteDhBase64, myPrivateKeyUint8) {
    const receivingPrivateKey = (state.DHr === null && state.Ns === 0 && !state.CKs)
        ? decodeBase64(state.initialPrivateKey || encodeBase64(myPrivateKeyUint8))
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
    state.initialPrivateKey = null;
    state.initialRemotePreKey = null;
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
        state.skippedKeys[buildSkippedKeyId(state.DHr, state.Nr)] = {
            encryptionKey: encodeBase64(chainStep.encryptionKey),
            macKey: encodeBase64(chainStep.macKey)
        };
        state.Nr += 1;

        const skippedIds = Object.keys(state.skippedKeys);
        if (skippedIds.length > MAX_SKIPPED_KEYS) {
            delete state.skippedKeys[skippedIds[0]];
        }
    }

    return state;
}

async function decryptSecretBox(ratchetPayload, encryptionKey, macKey) {
    const nonce = decodeBase64(ratchetPayload.nonce);
    const ciphertext = decodeBase64(ratchetPayload.ciphertext);

    if (ratchetPayload.mac) {
        const expectedMac = await buildMessageMac(
            ratchetPayload.header,
            nonce,
            ciphertext,
            macKey
        );
        const actualMac = decodeBase64(ratchetPayload.mac);

        if (!constantTimeEqual(expectedMac, actualMac)) {
            throw new Error("Message MAC verification failed");
        }
    }

    const plaintext = nacl.secretbox.open(ciphertext, nonce, encryptionKey);

    if (!plaintext) {
        throw new Error("Ratchet decryption failed");
    }

    return naclUtil.encodeUTF8(plaintext);
}

function shouldAttemptSessionReset(error, header, x3dhPayload = null) {
    if (!header) return false;
    if (x3dhPayload) {
        return true;
    }

    if (header.n !== 0 || header.pn !== 0) return false;

    const message = error instanceof Error ? error.message : String(error);
    return message.includes("Ratchet decryption failed")
        || message.includes("Missing receiving chain")
        || message.includes("Message MAC verification failed");
}

async function kdfRoot(rootKeyBytes, dhOutputBytes) {
    const derived = await deriveLabeledSecrets({
        saltBytes: rootKeyBytes,
        inputKeyMaterialBytes: dhOutputBytes,
        label: "double-ratchet-root",
        lengthsByName: {
            rootKey: 32,
            chainKey: 32
        }
    });

    const rootKey = derived.rootKey;
    const chainKey = derived.chainKey;
    return { rootKey, chainKey };
}

async function kdfChain(chainKeyBytes) {
    const derived = await deriveLabeledSecrets({
        saltBytes: chainKeyBytes,
        inputKeyMaterialBytes: chainKeyBytes,
        label: "double-ratchet-chain",
        lengthsByName: {
            nextChainKey: 32,
            encryptionKey: 32,
            macKey: 32
        }
    });

    return {
        nextChainKey: derived.nextChainKey,
        encryptionKey: derived.encryptionKey,
        macKey: derived.macKey
    };
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
        stateVersion: state.stateVersion || 1,
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
        skippedKeys: normalizeSkippedKeys(state.skippedKeys || {}),
        initialPrivateKey: state.initialPrivateKey || null,
        initialRemotePreKey: state.initialRemotePreKey || null,
        pendingX3dhHandshake: state.pendingX3dhHandshake || null
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

function mergeOwnStateSnapshot(currentState, snapshot, { restoreRootKey = false } = {}) {
    return normalizeState({
        ...currentState,
        RK: restoreRootKey ? (snapshot.RK || currentState.RK) : currentState.RK,
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

function normalizeSkippedKeys(skippedKeys) {
    const normalized = {};

    for (const [keyId, value] of Object.entries(skippedKeys)) {
        if (typeof value === "string") {
            normalized[keyId] = {
                encryptionKey: value,
                macKey: value
            };
            continue;
        }

        normalized[keyId] = {
            encryptionKey: value?.encryptionKey || value?.messageKey || null,
            macKey: value?.macKey || value?.encryptionKey || value?.messageKey || null
        };
    }

    return normalized;
}

async function buildMessageMac(header, nonceBytes, ciphertextBytes, macKey) {
    const headerBytes = encodeHeaderForMac(header);
    const macInput = new Uint8Array(headerBytes.length + nonceBytes.length + ciphertextBytes.length);
    macInput.set(headerBytes, 0);
    macInput.set(nonceBytes, headerBytes.length);
    macInput.set(ciphertextBytes, headerBytes.length + nonceBytes.length);
    return hmacSha256(macKey, macInput);
}

function constantTimeEqual(left, right) {
    if (left.length !== right.length) {
        return false;
    }

    let diff = 0;
    for (let i = 0; i < left.length; i += 1) {
        diff |= left[i] ^ right[i];
    }

    return diff === 0;
}

function encodeHeaderForMac(header) {
    const dhBytes = naclUtil.decodeUTF8(String(header?.dh || ""));
    const pnBytes = encodeUint32(header?.pn || 0);
    const nBytes = encodeUint32(header?.n || 0);
    const separator = Uint8Array.from([0]);
    const result = new Uint8Array(dhBytes.length + separator.length + pnBytes.length + nBytes.length);

    let offset = 0;
    result.set(dhBytes, offset);
    offset += dhBytes.length;
    result.set(separator, offset);
    offset += separator.length;
    result.set(pnBytes, offset);
    offset += pnBytes.length;
    result.set(nBytes, offset);

    return result;
}

function encodeUint32(value) {
    const normalized = Number.isFinite(Number(value)) ? Number(value) >>> 0 : 0;
    const bytes = new Uint8Array(4);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, normalized, false);
    return bytes;
}
