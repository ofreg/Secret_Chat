import {
    nacl,
    naclUtil,
    getAttachmentHistory,
    getGroupSenderState,
    getIdentitySigningPrivateKeyUint8,
    saveAttachmentHistory,
    saveGroupSenderState
} from "./crypto.js?v=20260612b";
import { decryptRatchetMessage, encryptRatchetMessage } from "./doubleRatchet.js?v=20260420i";
import { deriveLabeledSecrets } from "./hkdf.js?v=20260420i";

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

export async function encryptGroupMessage({
    chatId,
    message,
    recipientDeviceBundles,
    senderDeviceBundles = [],
    currentDeviceId,
    senderIdentityKeyBase64,
    groupKeyEpoch = 1
}) {
    if (!currentDeviceId) {
        throw new Error("Current device id is missing");
    }

    const { devicePayloads, senderDevicePayloads } = await buildGroupSenderWrappedPayloads({
        chatId,
        plaintext: message,
        recipientDeviceBundles,
        senderDeviceBundles,
        currentDeviceId,
        senderIdentityKeyBase64,
        groupKeyEpoch
    });

    return {
        version: 4,
        device_payloads: devicePayloads,
        sender_device_payloads: senderDevicePayloads
    };
}

export function selectPayloadForCurrentUser(payload, isOwnMessage) {
    if (!payload || typeof payload !== "object") return null;

    if (payload.version === 5 && payload.mode === "group_sender_key") {
        return payload;
    }

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
    myIdentitySigningKeyBase64 = null,
    otherIdentityKeyBase64,
    otherIdentitySigningKeyBase64 = null,
    isOwnMessage,
    allowStateReset = true,
    restoreSenderState = true,
    restoreSenderRootKey = false
}) {
    if (payload?.version === 5 && payload?.mode === "group_sender_key") {
        return decryptGroupSenderMessage({
            chatId,
            payload,
            myPrivateKeyUint8,
            signerIdentitySigningKeyBase64: isOwnMessage
                ? myIdentitySigningKeyBase64
                : otherIdentitySigningKeyBase64
        });
    }

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
    currentDeviceId = null,
    chatId = null,
    isGroupChat = false,
    groupKeyEpoch = 1
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

    let senderDeviceKeys = {};
    let recipientDeviceKeys = {};
    let senderDeviceId = currentDeviceId;

    if (isGroupChat && chatId && currentDeviceId) {
        const wrappedPayloads = await buildGroupSenderWrappedPayloads({
            chatId,
            plaintext: keyPayload,
            recipientDeviceBundles,
            senderDeviceBundles,
            currentDeviceId,
            senderIdentityKeyBase64,
            groupKeyEpoch
        });
        senderDeviceKeys = wrappedPayloads.senderDevicePayloads;
        recipientDeviceKeys = wrappedPayloads.devicePayloads;
        senderDeviceId = wrappedPayloads.senderDeviceId;
    } else {
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
    }

    return {
        encryptedBytes: new Uint8Array(encryptedBuffer),
        meta: {
            encrypted: true,
            version: isGroupChat ? 3 : 2,
            algorithm: "AES-GCM",
            chat_id: chatId ? String(chatId) : null,
            file_iv: naclUtil.encodeBase64(fileIv),
            metadata_iv: naclUtil.encodeBase64(metadataIv),
            metadata_ciphertext: naclUtil.encodeBase64(new Uint8Array(metadataBuffer)),
            sender_key: encryptForPublicKey(keyPayload, senderIdentityKeyBase64),
            recipient_key: encryptForPublicKey(keyPayload, recipientIdentityKeyBase64),
            current_device_id: currentDeviceId,
            sender_device_id: senderDeviceId,
            key_wrap_mode: isGroupChat ? "group_sender_key" : "legacy_public_key",
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
    isOwnMessage,
    myIdentitySigningKeyBase64 = null,
    resolveOwnSigningKeyByDeviceId = null,
    resolveSenderSigningKeyByDeviceId = null
}) {
    if (!attachment?.url || !attachment?.meta?.encrypted) {
        return attachment?.url || null;
    }

    const { metadata: parsedMetadata, cryptoKey } = await resolveAttachmentHistorySecret({
        attachment,
        myPrivateKeyUint8,
        isOwnMessage,
        myIdentitySigningKeyBase64,
        resolveOwnSigningKeyByDeviceId,
        resolveSenderSigningKeyByDeviceId
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
    isOwnMessage,
    myIdentitySigningKeyBase64 = null,
    resolveOwnSigningKeyByDeviceId = null,
    resolveSenderSigningKeyByDeviceId = null
}) {
    if (!attachment?.url || !attachment?.meta?.encrypted) {
        return false;
    }

    await resolveAttachmentHistorySecret({
        attachment,
        myPrivateKeyUint8,
        isOwnMessage,
        myIdentitySigningKeyBase64,
        resolveOwnSigningKeyByDeviceId,
        resolveSenderSigningKeyByDeviceId
    });
    return true;
}

async function resolveAttachmentHistorySecret({
    attachment,
    myPrivateKeyUint8,
    isOwnMessage,
    myIdentitySigningKeyBase64 = null,
    resolveOwnSigningKeyByDeviceId = null,
    resolveSenderSigningKeyByDeviceId = null
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
        const decryptedKeyPayload = isGroupSenderWrappedPayload(wrappedKeyPayload)
            ? await decryptGroupSenderMessage({
                chatId: attachment.meta.chat_id || attachment.chat_id || "",
                payload: wrappedKeyPayload,
                myPrivateKeyUint8,
                signerIdentitySigningKeyBase64: resolveAttachmentSignerKey({
                    attachment,
                    isOwnMessage,
                    myIdentitySigningKeyBase64,
                    resolveOwnSigningKeyByDeviceId,
                    resolveSenderSigningKeyByDeviceId
                })
            })
            : decryptLegacyPayload(wrappedKeyPayload, myPrivateKeyUint8);
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

async function buildGroupSenderWrappedPayloads({
    chatId,
    plaintext,
    recipientDeviceBundles,
    senderDeviceBundles = [],
    currentDeviceId,
    senderIdentityKeyBase64,
    groupKeyEpoch = 1
}) {
    const signingPrivateKeyUint8 = await getIdentitySigningPrivateKeyUint8();
    if (!signingPrivateKeyUint8) {
        throw new Error("Identity signing private key is missing");
    }

    const senderState = await getOrCreateGroupSenderState(chatId, currentDeviceId, groupKeyEpoch);
    const messageSeedBytes = decodeBase64(senderState.chainKey);
    const material = await deriveGroupSenderMessageMaterial({
        senderKeyId: senderState.senderKeyId,
        counter: senderState.counter,
        messageSeedBytes
    });

    const encryptedMessage = await encryptGroupSenderCiphertext({
        plaintext,
        chatId,
        groupKeyEpoch,
        senderDeviceId: currentDeviceId,
        senderKeyId: senderState.senderKeyId,
        counter: senderState.counter,
        messageKeyBytes: material.messageKey
    });

    const distribution = {
        version: 1,
        chat_id: String(chatId),
        group_key_epoch: Number(groupKeyEpoch || 1),
        sender_device_id: String(currentDeviceId),
        sender_key_id: senderState.senderKeyId,
        counter: senderState.counter,
        message_seed: encodeBase64(messageSeedBytes)
    };
    const distributionSignature = encodeBase64(
        nacl.sign.detached(
            buildGroupSenderSignaturePayload(distribution),
            signingPrivateKeyUint8
        )
    );

    const devicePayloads = {};
    for (const bundle of uniqueDeviceBundles(recipientDeviceBundles)) {
        if (!bundle?.device_id || !bundle?.identity_key) {
            continue;
        }
        devicePayloads[bundle.device_id] = buildGroupSenderPayload({
            distribution,
            distributionSignature,
            ciphertextBase64: encryptedMessage.ciphertextBase64,
            ivBase64: encryptedMessage.ivBase64,
            recipientIdentityKeyBase64: bundle.identity_key
        });
    }

    const senderDevicePayloads = {};
    for (const bundle of uniqueDeviceBundles(senderDeviceBundles)) {
        if (!bundle?.device_id || !bundle?.identity_key) {
            continue;
        }
        senderDevicePayloads[bundle.device_id] = buildGroupSenderPayload({
            distribution,
            distributionSignature,
            ciphertextBase64: encryptedMessage.ciphertextBase64,
            ivBase64: encryptedMessage.ivBase64,
            recipientIdentityKeyBase64: bundle.identity_key
        });
    }

    if (!senderDevicePayloads[currentDeviceId]) {
        senderDevicePayloads[currentDeviceId] = buildGroupSenderPayload({
            distribution,
            distributionSignature,
            ciphertextBase64: encryptedMessage.ciphertextBase64,
            ivBase64: encryptedMessage.ivBase64,
            recipientIdentityKeyBase64: senderIdentityKeyBase64
        });
    }

    await saveGroupSenderState(chatId, currentDeviceId, {
        senderKeyId: senderState.senderKeyId,
        counter: senderState.counter + 1,
        chainKey: encodeBase64(material.nextChainKey),
        createdAt: senderState.createdAt,
        updatedAt: new Date().toISOString()
    }, groupKeyEpoch);

    return {
        senderDeviceId: currentDeviceId,
        devicePayloads,
        senderDevicePayloads
    };
}

async function getOrCreateGroupSenderState(chatId, currentDeviceId, groupKeyEpoch = 1) {
    const existing = await getGroupSenderState(chatId, currentDeviceId, groupKeyEpoch);
    if (existing?.chainKey && Number.isFinite(Number(existing.senderKeyId))) {
        return existing;
    }

    const created = {
        senderKeyId: buildGroupSenderKeyId(),
        counter: 0,
        chainKey: encodeBase64(crypto.getRandomValues(new Uint8Array(32))),
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
    };
    await saveGroupSenderState(chatId, currentDeviceId, created, groupKeyEpoch);
    return created;
}

async function deriveGroupSenderMessageMaterial({
    senderKeyId,
    counter,
    messageSeedBytes
}) {
    const label = `group-sender-key:${Number(senderKeyId)}:${Number(counter)}`;
    return deriveLabeledSecrets({
        saltBytes: encodeUint32(senderKeyId),
        inputKeyMaterialBytes: messageSeedBytes,
        label,
        lengthsByName: {
            nextChainKey: 32,
            messageKey: 32
        }
    });
}

async function encryptGroupSenderCiphertext({
    plaintext,
    chatId,
    groupKeyEpoch = 1,
    senderDeviceId,
    senderKeyId,
    counter,
    messageKeyBytes
}) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        messageKeyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );
    const ciphertext = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv,
            additionalData: buildGroupSenderAad({
                chatId,
                groupKeyEpoch,
                senderDeviceId,
                senderKeyId,
                counter
            })
        },
        cryptoKey,
        naclUtil.decodeUTF8(plaintext)
    );

    return {
        ivBase64: encodeBase64(iv),
        ciphertextBase64: encodeBase64(new Uint8Array(ciphertext))
    };
}

async function decryptGroupSenderMessage({
    chatId,
    payload,
    myPrivateKeyUint8,
    signerIdentitySigningKeyBase64
}) {
    const distributionPayload = JSON.parse(decryptLegacyPayload(payload.distribution, myPrivateKeyUint8));
    validateGroupSenderDistribution(chatId, payload, distributionPayload, signerIdentitySigningKeyBase64);

    const material = await deriveGroupSenderMessageMaterial({
        senderKeyId: distributionPayload.sender_key_id,
        counter: distributionPayload.counter,
        messageSeedBytes: decodeBase64(distributionPayload.message_seed)
    });
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        material.messageKey,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: decodeBase64(payload.iv),
            additionalData: buildGroupSenderAad({
                chatId,
                groupKeyEpoch: distributionPayload.group_key_epoch || 1,
                senderDeviceId: distributionPayload.sender_device_id,
                senderKeyId: distributionPayload.sender_key_id,
                counter: distributionPayload.counter
            })
        },
        cryptoKey,
        decodeBase64(payload.ciphertext)
    );

    return naclUtil.encodeUTF8(new Uint8Array(decrypted));
}

function validateGroupSenderDistribution(chatId, payload, distributionPayload, signerIdentitySigningKeyBase64) {
    if (!distributionPayload?.message_seed || !distributionPayload?.sender_device_id) {
        throw new Error("Invalid group sender distribution payload");
    }

    if (String(distributionPayload.chat_id) !== String(chatId)) {
        throw new Error("Group sender distribution chat mismatch");
    }
    if (Number(distributionPayload.group_key_epoch || 1) <= 0) {
        throw new Error("Invalid group sender epoch");
    }

    if (!payload?.distribution_signature || !signerIdentitySigningKeyBase64) {
        throw new Error("Missing group sender signature");
    }

    const isValidSignature = nacl.sign.detached.verify(
        buildGroupSenderSignaturePayload(distributionPayload),
        decodeBase64(payload.distribution_signature),
        decodeBase64(signerIdentitySigningKeyBase64)
    );
    if (!isValidSignature) {
        throw new Error("Group sender signature verification failed");
    }
}

function isGroupSenderWrappedPayload(payload) {
    return Boolean(payload?.version === 5 && payload?.mode === "group_sender_key");
}

function resolveAttachmentSignerKey({
    attachment,
    isOwnMessage,
    myIdentitySigningKeyBase64,
    resolveOwnSigningKeyByDeviceId,
    resolveSenderSigningKeyByDeviceId
}) {
    const senderDeviceId = String(attachment?.meta?.sender_device_id || "");
    if (isOwnMessage) {
        return resolveOwnSigningKeyByDeviceId?.(senderDeviceId) || myIdentitySigningKeyBase64 || null;
    }
    return resolveSenderSigningKeyByDeviceId?.(senderDeviceId) || null;
}

function buildGroupSenderPayload({
    distribution,
    distributionSignature,
    ciphertextBase64,
    ivBase64,
    recipientIdentityKeyBase64
}) {
    return {
        version: 5,
        mode: "group_sender_key",
        sender_device_id: distribution.sender_device_id,
        sender_key_id: distribution.sender_key_id,
        counter: distribution.counter,
        distribution: encryptForPublicKey(
            JSON.stringify(distribution),
            recipientIdentityKeyBase64
        ),
        distribution_signature: distributionSignature,
        algorithm: "AES-GCM",
        iv: ivBase64,
        ciphertext: ciphertextBase64
    };
}

function buildGroupSenderSignaturePayload(distributionPayload) {
    const label = naclUtil.decodeUTF8("e2ee-chat:group-sender-key:v1");
    const separator = Uint8Array.from([0]);
    const chatIdBytes = naclUtil.decodeUTF8(String(distributionPayload.chat_id || ""));
    const epochBytes = encodeUint32(distributionPayload.group_key_epoch || 1);
    const senderDeviceBytes = naclUtil.decodeUTF8(String(distributionPayload.sender_device_id || ""));
    const senderKeyIdBytes = encodeUint32(distributionPayload.sender_key_id || 0);
    const counterBytes = encodeUint32(distributionPayload.counter || 0);
    const messageSeedBytes = decodeBase64(distributionPayload.message_seed || "");
    return concatBytes([
        label,
        separator,
        chatIdBytes,
        separator,
        epochBytes,
        separator,
        senderDeviceBytes,
        separator,
        senderKeyIdBytes,
        separator,
        counterBytes,
        separator,
        messageSeedBytes
    ]);
}

function buildGroupSenderAad({
    chatId,
    groupKeyEpoch = 1,
    senderDeviceId,
    senderKeyId,
    counter
}) {
    return concatBytes([
        naclUtil.decodeUTF8("e2ee-chat:group-sender-key:aad:v1"),
        Uint8Array.from([0]),
        naclUtil.decodeUTF8(String(chatId)),
        Uint8Array.from([0]),
        encodeUint32(groupKeyEpoch || 1),
        Uint8Array.from([0]),
        naclUtil.decodeUTF8(String(senderDeviceId || "")),
        Uint8Array.from([0]),
        encodeUint32(senderKeyId || 0),
        encodeUint32(counter || 0)
    ]);
}

function uniqueDeviceBundles(deviceBundles) {
    const result = [];
    const seen = new Set();
    for (const bundle of Array.isArray(deviceBundles) ? deviceBundles : []) {
        const deviceId = String(bundle?.device_id || "");
        if (!deviceId || seen.has(deviceId)) {
            continue;
        }
        seen.add(deviceId);
        result.push(bundle);
    }
    return result;
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

function buildGroupSenderKeyId() {
    return Math.floor(Math.random() * 2147483646) + 1;
}

function encodeBase64(bytes) {
    return naclUtil.encodeBase64(bytes);
}

function decodeBase64(value) {
    return naclUtil.decodeBase64(String(value || "").replace(/\s+/g, ""));
}

function encodeUint32(value) {
    const normalized = Number.isFinite(Number(value)) ? Number(value) >>> 0 : 0;
    const bytes = new Uint8Array(4);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, normalized, false);
    return bytes;
}

function concatBytes(chunks) {
    const totalLength = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const chunk of chunks) {
        result.set(chunk, offset);
        offset += chunk.length;
    }

    return result;
}
