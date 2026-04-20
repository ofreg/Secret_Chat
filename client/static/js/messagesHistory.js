import {
    deleteRatchetState,
    getCachedMessageText,
    getLastSeenMessageId,
    getRatchetState,
    saveCachedMessageText,
    saveLastSeenMessageId
} from "./crypto.js?v=20260420c";
import { decryptMessage, selectPayloadForCurrentUser } from "./chatCrypto.js?v=20260420c";

export function createHistoryController({
    getMyUsername,
    getCurrentChatId,
    getMyPrivateKey,
    getMyPublicKey,
    getOtherPublicKey,
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

    function tryParsePayload(content) {
        try {
            return JSON.parse(content);
        } catch {
            return null;
        }
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
                    myPublicKeyBase64: getMyPublicKey(),
                    otherPublicKeyBase64: getOtherPublicKey(),
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
            if (!payload || !selectPayloadForCurrentUser(payload, isOwnMessage)) {
                continue;
            }

            try {
                await decryptMessage({
                    chatId,
                    payload,
                    myPrivateKeyUint8: getMyPrivateKey(),
                    myPublicKeyBase64: getMyPublicKey(),
                    otherPublicKeyBase64: getOtherPublicKey(),
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
            const existingRatchetState = await getRatchetState(chatId);
            if (existingRatchetState?.DHr === null) {
                logChatState("resetting outbound-only ratchet state before incoming X3DH decrypt", {
                    messageId: data.message_id,
                    hasExistingRatchetState: true,
                    hasRemoteDh: Boolean(existingRatchetState?.DHr),
                    hasIncomingX3dh: true
                }, "warn");
                await deleteRatchetState(chatId);
            }
        }

        try {
            return await decryptMessage({
                chatId,
                payload,
                myPrivateKeyUint8: getMyPrivateKey(),
                myPublicKeyBase64: getMyPublicKey(),
                otherPublicKeyBase64: getOtherPublicKey(),
                isOwnMessage,
                allowStateReset,
                restoreSenderState,
                restoreSenderRootKey
            });
        } catch (error) {
            if (isOwnMessage || !data.message_id) {
                throw error;
            }

            console.warn("Attempting ratchet recovery for message", data.message_id, error);
            await rebuildRatchetStateFromTranscript(chatId, data.message_id);

            return decryptMessage({
                chatId,
                payload,
                myPrivateKeyUint8: getMyPrivateKey(),
                myPublicKeyBase64: getMyPublicKey(),
                otherPublicKeyBase64: getOtherPublicKey(),
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

        if (messageId && renderedMessageIds.has(messageId)) {
            return;
        }

        if (isHistorical && messageId && messageId <= lastSeenMessageId && cachedText) {
            renderChatMessage(chat, getSenderLabel(data.sender), cachedText);
            renderedMessageIds.add(messageId);
            return;
        }

        try {
            let text;

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

            if (messageId) {
                await saveCachedMessageText(chatId, messageId, text);
                await saveLastSeenMessageId(chatId, Math.max(lastSeenMessageId, messageId));
                renderedMessageIds.add(messageId);
            }

            renderChatMessage(chat, getSenderLabel(data.sender), text);
        } catch (err) {
            console.warn("Decrypt error:", err);
            const fallbackText = encryptedPayload
                ? "[Encrypted message could not be decrypted on this device]"
                : (cachedText || data.content);

            if (messageId) {
                renderedMessageIds.add(messageId);
            }

            renderChatMessage(chat, getSenderLabel(data.sender), fallbackText);
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
