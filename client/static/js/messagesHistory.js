import {
    clearMessageDeletedForSelf,
    deleteRatchetState,
    getCachedMessageText,
    isMessageDeletedForSelf,
    getLastSeenMessageId,
    removeCachedMessageText,
    getRatchetState,
    saveCachedMessageText,
    saveLastSeenMessageId
} from "./crypto.js?v=20260612a";
import {
    cacheAttachmentHistoryFromMessageMeta,
    decryptMessage,
    selectPayloadForCurrentUser
} from "./chatCrypto.js?v=20260612b";

export function createHistoryController({
    getMyUsername,
    getCurrentChatId,
    getMyPrivateKey,
    getMyIdentityKey,
    getMyIdentitySigningKey,
    getOwnDeviceBundleById,
    getOtherIdentityKey,
    getOtherIdentitySigningKey,
    getOtherDeviceBundleById,
    resolveAttachment,
    renderChatMessage,
    getSenderLabel,
    logChatState
}) {
    let messageProcessingChain = Promise.resolve();
    let renderedMessageIds = new Set();
    let chatTranscript = [];

    function reset() {
        messageProcessingChain = Promise.resolve();
        renderedMessageIds = new Set();
        chatTranscript = [];
    }

    function rememberTranscriptMessage(data) {
        const messageId = data.message_id || null;

        if (messageId) {
            const existingIndex = chatTranscript.findIndex((item) => item.message_id === messageId);
            if (existingIndex !== -1) {
                chatTranscript[existingIndex] = {
                    ...chatTranscript[existingIndex],
                    ...data
                };
                return;
            }
        }

        chatTranscript.push({ ...data });
        chatTranscript.sort((a, b) => (a.message_id || 0) - (b.message_id || 0));
    }

    function saveResolvedTranscriptText(messageId, text) {
        if (!messageId) {
            return;
        }

        const item = chatTranscript.find((entry) => entry.message_id === messageId);
        if (item) {
            item._resolvedText = text;
        }
    }

    async function buildReplyPayload(replyToMessageId) {
        if (!replyToMessageId) {
            return null;
        }

        const target = chatTranscript.find((item) => item.message_id === replyToMessageId);
        const cachedTargetText = await getCachedMessageText(getCurrentChatId(), replyToMessageId);
        const previewText = (target?._resolvedText || cachedTargetText || "").trim();
        const fallbackPreview = target?.attachment ? "[Attachment]" : "Original message";

        return {
            messageId: replyToMessageId,
            senderLabel: target ? getSenderLabel(target.sender) : "Reply",
            previewText: previewText
                ? previewText.replace(/\s+/g, " ").slice(0, 140)
                : fallbackPreview
        };
    }

    function tryParsePayload(content) {
        try {
            return JSON.parse(content);
        } catch {
            return null;
        }
    }

    function buildIncomingSessionId(chatId, data) {
        const senderDeviceId = data?.sender_device_id || "unknown-device";
        return `${chatId}:from:${senderDeviceId}`;
    }

    function resolveOtherIdentityKeyForMessage(data, isOwnMessage) {
        if (isOwnMessage) {
            return getOtherIdentityKey() || getMyIdentityKey();
        }

        const bundle = getOtherDeviceBundleById?.(data?.sender_device_id || "");
        return bundle?.identity_key || getOtherIdentityKey();
    }

    function resolveOtherIdentitySigningKeyForMessage(data, isOwnMessage) {
        if (isOwnMessage) {
            const ownBundle = getOwnDeviceBundleById?.(data?.sender_device_id || "");
            return ownBundle?.identity_signing_key || getMyIdentitySigningKey?.() || null;
        }

        const bundle = getOtherDeviceBundleById?.(data?.sender_device_id || "");
        return bundle?.identity_signing_key || getOtherIdentitySigningKey?.() || null;
    }

    async function rebuildRatchetStateFromTranscript(chatId, upToMessageId) {
        await deleteRatchetState(chatId);
        let replayStartIndex = 0;
        const replayItems = chatTranscript.filter((item) => item.message_id && item.message_id < upToMessageId);

        for (let index = replayItems.length - 1; index >= 0; index -= 1) {
            const candidate = replayItems[index];
            const candidatePayload = tryParsePayload(candidate.content);
            const isOwnCandidate = candidate.sender === getMyUsername();

            if (!isOwnCandidate || !candidatePayload?.version || !candidatePayload?.sender_state) {
                continue;
            }

            try {
                await decryptMessage({
                    chatId,
                    payload: candidatePayload,
                    myPrivateKeyUint8: getMyPrivateKey(),
                    myIdentityKeyBase64: getMyIdentityKey(),
                    otherIdentityKeyBase64: getOtherIdentityKey(),
                    isOwnMessage: true,
                    allowStateReset: false,
                    restoreSenderState: true,
                    restoreSenderRootKey: true
                });
                replayStartIndex = index + 1;
                break;
            } catch (anchorError) {
                console.warn("Replay anchor failed", candidate.message_id, anchorError);
            }
        }

        for (const item of replayItems.slice(replayStartIndex)) {
            const payload = tryParsePayload(item.content);
            const isOwnMessage = item.sender === getMyUsername();
            if (!payload || payload.version === 5 || !selectPayloadForCurrentUser(payload, isOwnMessage)) {
                continue;
            }

            try {
                await decryptMessage({
                    chatId: buildIncomingSessionId(chatId, item),
                    payload,
                    myPrivateKeyUint8: getMyPrivateKey(),
                    myIdentityKeyBase64: getMyIdentityKey(),
                    otherIdentityKeyBase64: resolveOtherIdentityKeyForMessage(item, isOwnMessage),
                    isOwnMessage,
                    allowStateReset: !isOwnMessage,
                    restoreSenderState: true,
                    restoreSenderRootKey: isOwnMessage
                });
            } catch (replayError) {
                console.warn("Replay step failed", item.message_id, replayError);
            }
        }
    }

    async function decryptWithRecovery({
        data,
        payload,
        chatId,
        isOwnMessage,
        allowStateReset,
        restoreSenderState,
        restoreSenderRootKey
    }) {
        if (!isOwnMessage && payload?.version === 3 && payload?.x3dh) {
            const existingRatchetState = await getRatchetState(buildIncomingSessionId(chatId, data));
            if (existingRatchetState?.DHr === null) {
                logChatState("resetting outbound-only ratchet state before incoming X3DH decrypt", {
                    messageId: data.message_id,
                    hasExistingRatchetState: true,
                    hasRemoteDh: Boolean(existingRatchetState?.DHr),
                    hasIncomingX3dh: true
                }, "warn");
                await deleteRatchetState(buildIncomingSessionId(chatId, data));
            }
        }

        const effectiveChatId = payload?.version === 5 && payload?.mode === "group_sender_key"
            ? chatId
            : (isOwnMessage ? chatId : buildIncomingSessionId(chatId, data));
        try {
            return await decryptMessage({
                chatId: effectiveChatId,
                payload,
                myPrivateKeyUint8: getMyPrivateKey(),
                myIdentityKeyBase64: getMyIdentityKey(),
                myIdentitySigningKeyBase64: getMyIdentitySigningKey?.() || null,
                otherIdentityKeyBase64: resolveOtherIdentityKeyForMessage(data, isOwnMessage),
                otherIdentitySigningKeyBase64: resolveOtherIdentitySigningKeyForMessage(data, isOwnMessage),
                isOwnMessage,
                allowStateReset,
                restoreSenderState,
                restoreSenderRootKey
            });
        } catch (error) {
            if (isOwnMessage || !data.message_id || (payload?.version === 5 && payload?.mode === "group_sender_key")) {
                throw error;
            }

            console.warn("Attempting ratchet recovery for message", data.message_id, error);
            await rebuildRatchetStateFromTranscript(chatId, data.message_id);

            return decryptMessage({
                chatId: effectiveChatId,
                payload,
                myPrivateKeyUint8: getMyPrivateKey(),
                myIdentityKeyBase64: getMyIdentityKey(),
                myIdentitySigningKeyBase64: getMyIdentitySigningKey?.() || null,
                otherIdentityKeyBase64: resolveOtherIdentityKeyForMessage(data, isOwnMessage),
                otherIdentitySigningKeyBase64: resolveOtherIdentitySigningKeyForMessage(data, isOwnMessage),
                isOwnMessage,
                allowStateReset: !isOwnMessage,
                restoreSenderState,
                restoreSenderRootKey: true
            });
        }
    }

    async function processMessage(data) {
        const chat = document.getElementById("chat");
        if (!chat) return;

        const chatId = getCurrentChatId();
        const messageId = data.message_id || null;
        const cachedText = messageId ? await getCachedMessageText(chatId, messageId) : null;
        const lastSeenMessageId = await getLastSeenMessageId(chatId);
        const isOwnMessage = data.sender === getMyUsername();
        const payload = tryParsePayload(data.content);
        const encryptedPayload = selectPayloadForCurrentUser(payload, isOwnMessage);
        const isHistorical = Boolean(data.historical);

        rememberTranscriptMessage(data);

        if (messageId && !data.deleted_for_all && await isMessageDeletedForSelf(chatId, messageId)) {
            renderedMessageIds.add(messageId);
            return;
        }

        if (messageId && data.deleted_for_all) {
            await clearMessageDeletedForSelf(chatId, messageId);
            await removeCachedMessageText(chatId, messageId);
        }

        if (messageId && renderedMessageIds.has(messageId)) {
            return;
        }

        if (data.deleted_for_all) {
            if (messageId) {
                renderedMessageIds.add(messageId);
                await saveLastSeenMessageId(chatId, Math.max(lastSeenMessageId, messageId));
            }
            return;
        }

        if (isHistorical && messageId && messageId <= lastSeenMessageId && cachedText) {
            let resolvedAttachment = null;
            let resolvedText = cachedText;
            if (data.attachment) {
                if (data.attachment.meta?.encrypted) {
                    try {
                        await cacheAttachmentHistoryFromMessageMeta({
                            attachment: data.attachment,
                            myPrivateKeyUint8: getMyPrivateKey(),
                            isOwnMessage,
                            myIdentitySigningKeyBase64: getMyIdentitySigningKey?.() || null,
                            resolveOwnSigningKeyByDeviceId: (deviceId) => getOwnDeviceBundleById?.(deviceId)?.identity_signing_key || null,
                            resolveSenderSigningKeyByDeviceId: (deviceId) => getOtherDeviceBundleById?.(deviceId)?.identity_signing_key || null
                        });
                    } catch (attachmentCacheError) {
                        console.warn("Historical attachment history cache error:", attachmentCacheError);
                    }
                }

                try {
                    resolvedAttachment = await resolveAttachment(data.attachment, isOwnMessage);
                } catch (attachmentError) {
                    console.warn("Historical attachment decrypt error:", attachmentError);
                    resolvedText = resolvedText
                        ? `${resolvedText}\n[Encrypted attachment unavailable]`
                        : "[Encrypted attachment unavailable]";
                }
            }
            saveResolvedTranscriptText(messageId, resolvedText);
            renderChatMessage(chat, getSenderLabel(data.sender), resolvedText, {
                messageId,
                deliveryStatus: data.delivery_status,
                isOwnMessage,
                attachment: resolvedAttachment,
                deletedForAll: Boolean(data.deleted_for_all),
                replyTo: await buildReplyPayload(data.reply_to_message_id)
            });
            renderedMessageIds.add(messageId);
            return;
        }

        try {
            let text;
            let attachment = data.attachment || null;

            if (encryptedPayload && payload) {
                text = await decryptWithRecovery({
                    data,
                    payload,
                    chatId,
                    isOwnMessage,
                    allowStateReset: !isOwnMessage,
                    restoreSenderState: isHistorical,
                    restoreSenderRootKey: isHistorical && isOwnMessage
                });
            } else {
                text = cachedText || data.content;
            }

            if (attachment) {
                if (attachment.meta?.encrypted) {
                    try {
                        await cacheAttachmentHistoryFromMessageMeta({
                            attachment,
                            myPrivateKeyUint8: getMyPrivateKey(),
                            isOwnMessage,
                            myIdentitySigningKeyBase64: getMyIdentitySigningKey?.() || null,
                            resolveOwnSigningKeyByDeviceId: (deviceId) => getOwnDeviceBundleById?.(deviceId)?.identity_signing_key || null,
                            resolveSenderSigningKeyByDeviceId: (deviceId) => getOtherDeviceBundleById?.(deviceId)?.identity_signing_key || null
                        });
                    } catch (attachmentCacheError) {
                        console.warn("Attachment history cache error:", attachmentCacheError);
                    }
                }

                try {
                    attachment = await resolveAttachment(attachment, isOwnMessage);
                } catch (attachmentError) {
                    console.warn("Attachment decrypt error:", attachmentError);
                    attachment = null;
                    text = text
                        ? `${text}\n[Encrypted attachment unavailable]`
                        : "[Encrypted attachment unavailable]";
                }
            }

            if (messageId) {
                await saveCachedMessageText(chatId, messageId, text);
                await saveLastSeenMessageId(chatId, Math.max(lastSeenMessageId, messageId));
                renderedMessageIds.add(messageId);
                saveResolvedTranscriptText(messageId, text);
            }

            renderChatMessage(chat, getSenderLabel(data.sender), text, {
                messageId,
                deliveryStatus: data.delivery_status,
                isOwnMessage,
                attachment,
                deletedForAll: Boolean(data.deleted_for_all),
                replyTo: await buildReplyPayload(data.reply_to_message_id)
            });
        } catch (err) {
            console.warn("Decrypt error:", err);
            const fallbackText = encryptedPayload
                ? "[Encrypted message could not be decrypted on this device]"
                : (cachedText || data.content);

            if (messageId) {
                renderedMessageIds.add(messageId);
                saveResolvedTranscriptText(messageId, fallbackText);
            }

            renderChatMessage(chat, getSenderLabel(data.sender), fallbackText, {
                messageId,
                deliveryStatus: data.delivery_status,
                isOwnMessage,
                attachment: data.attachment || null,
                deletedForAll: Boolean(data.deleted_for_all),
                replyTo: await buildReplyPayload(data.reply_to_message_id)
            });
        }
    }

    function queueMessageProcessing(data) {
        messageProcessingChain = messageProcessingChain
            .then(() => processMessage(data))
            .catch((err) => {
                console.warn("Message queue error:", err);
            });
    }

    return {
        reset,
        queueMessageProcessing
    };
}
