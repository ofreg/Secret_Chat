import {
    getCachedMessageText,
    deleteRatchetState,
    getLastSeenMessageId,
    getPrivateKeyUint8,
    getPublicKey,
    fingerprint,
    initKeysIfNeeded,
    saveCachedMessageText,
    saveLastSeenMessageId
} from "./crypto.js";
import { decryptMessage, encryptMessage, selectPayloadForCurrentUser } from "./chatCrypto.js";
import { initUserSearch } from "./userSearch.js";

let keysReady = false;
let pendingMessages = [];
let myPrivateKeyCache = null;
let myPublicKeyCache = null;
let myUsername = null;
let currentChatId = null;
let messageProcessingChain = Promise.resolve();
let renderedMessageIds = new Set();
let historySyncInProgress = false;
let deferredLiveMessages = [];
let chatTranscript = [];

window.addEventListener("load", async function () {
    await initKeysIfNeeded();
    myPrivateKeyCache = await getPrivateKeyUint8();
    myPublicKeyCache = await getPublicKey();

    const meRes = await fetch("/users/me");
    const meData = await meRes.json();
    if (meData.status === "ok") {
        myUsername = meData.username || "";
    }

    const params = new URLSearchParams(window.location.search);
    const chatId = params.get("chat_id");
    currentChatId = chatId;

    if (chatId) {
        await initializeChat(chatId);
    }

    window.sendMessage = async function () {
        const input = document.getElementById("messageInput");
        if (!input || !window.chatSocket || !window.otherPublicKey || !myPublicKeyCache || !keysReady) {
            return;
        }

        try {
            const messageText = input.value.trim();
            if (!messageText) return;

            const payload = await encryptMessage({
                chatId: getCurrentChatId(),
                message: messageText,
                recipientPublicBase64: window.otherPublicKey,
                senderPublicBase64: myPublicKeyCache,
                myPrivateKeyUint8: myPrivateKeyCache
            });

            window.chatSocket.send(JSON.stringify(payload));
            input.value = "";
        } catch (err) {
            console.error("Encryption error:", err);
        }
    };

    initUserSearch({
        onChatStarted: async (chatData) => {
            currentChatId = String(chatData.chat_id);
            await applyChatKeys(chatData.public_key, chatData.identity_key, chatData.prekey_bundle);
            openChatSocket(chatData.chat_id);
            await loadChats();
            window.location.search = "?chat_id=" + chatData.chat_id;
        }
    });
});

async function initializeChat(chatId) {
    currentChatId = String(chatId);
    const res = await fetch(`/messages/get_keys?chat_id=${chatId}`);
    const data = await res.json();

    if (data.status !== "ok" || !data.public_key) {
        return;
    }

    await applyChatKeys(data.public_key, data.identity_key, data.prekey_bundle);
    openChatSocket(chatId);
}

async function applyChatKeys(publicKey, identityKey, prekeyBundle = null) {
    window.otherPublicKey = publicKey;
    window.otherIdentityKey = identityKey;
    window.otherPrekeyBundle = prekeyBundle;
    keysReady = true;

    const fp = await fingerprint(window.otherPublicKey);
    const el = document.getElementById("fingerprint");
    if (el) el.innerText = fp;
}

async function openChatSocket(chatId) {
    currentChatId = String(chatId);
    keysReady = false;
    pendingMessages = [];
    messageProcessingChain = Promise.resolve();
    renderedMessageIds = new Set();
    historySyncInProgress = true;
    deferredLiveMessages = [];
    chatTranscript = [];

    const chat = document.getElementById("chat");
    if (chat) {
        chat.innerHTML = "";
    }

    if (window.chatSocket) {
        try {
            window.chatSocket.close();
        } catch {}
    }

    const chatSocket = new WebSocket(`ws://${window.location.host}/ws/${chatId}`);

    chatSocket.onopen = function () {
        console.log("Chat ready:", chatId);
        keysReady = true;

        pendingMessages.forEach(queueMessageProcessing);
        pendingMessages = [];
    };

    chatSocket.onmessage = async function (event) {
        const data = JSON.parse(event.data);

        if (data.type === "status") {
            setUserStatus(data.is_online);
            return;
        }

        if (data.type === "history_complete") {
            historySyncInProgress = false;

            const queuedLiveMessages = [...deferredLiveMessages];
            deferredLiveMessages = [];
            queuedLiveMessages.forEach(queueMessageProcessing);
            return;
        }

        if (data.type === "message") {
            if (!keysReady) {
                pendingMessages.push(data);
                return;
            }

            if (historySyncInProgress && !data.historical) {
                deferredLiveMessages.push(data);
                return;
            }

            queueMessageProcessing(data);
        }
    };

    window.chatSocket = chatSocket;
}

async function processMessage(data) {
    const chat = document.getElementById("chat");
    if (!chat) return;

    const chatId = getCurrentChatId();
    const messageId = data.message_id || null;
    const cachedText = messageId ? await getCachedMessageText(chatId, messageId) : null;
    const lastSeenMessageId = await getLastSeenMessageId(chatId);
    const isOwnMessage = data.sender === myUsername;
    const payload = tryParsePayload(data.content);
    const encryptedPayload = selectPayloadForCurrentUser(payload, isOwnMessage);
    const isHistorical = Boolean(data.historical);

    rememberTranscriptMessage(data);

    if (messageId && renderedMessageIds.has(messageId)) {
        return;
    }

    if (isHistorical && messageId && messageId <= lastSeenMessageId && cachedText) {
        renderMessage(chat, getSenderLabel(data.sender), cachedText);
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
                allowStateReset: !isHistorical
            });
        } else {
            text = cachedText || data.content;
        }

        if (messageId) {
            await saveCachedMessageText(chatId, messageId, text);
            await saveLastSeenMessageId(chatId, Math.max(lastSeenMessageId, messageId));
            renderedMessageIds.add(messageId);
        }

        renderMessage(chat, getSenderLabel(data.sender), text);
    } catch (err) {
        console.warn("Decrypt error:", err);
        const fallbackText = cachedText || data.content;

        if (messageId) {
            renderedMessageIds.add(messageId);
        }

        renderMessage(chat, getSenderLabel(data.sender), fallbackText);
    }
}

function renderMessage(chat, senderLabel, text) {
    const div = document.createElement("div");
    div.innerHTML = `<b>${senderLabel}:</b> ${text}`;
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
}

function getSenderLabel(senderName) {
    return senderName === myUsername ? "You" : senderName;
}

const userSocket = new WebSocket(`ws://${window.location.host}/ws/user`);
const messageSound = new Audio("/static/sounds/new_message.mp3");

userSocket.onmessage = async function (event) {
    const data = JSON.parse(event.data);

    if (data.type === "new_chat") {
        await loadChats();
    }

    if (data.type === "new_message") {
        const updatedChatId = data.chat_id;
        if (!window.location.search.includes("chat_id=" + updatedChatId)) {
            markChatAsUpdated(updatedChatId);
            messageSound.play();
        }
    }
};

userSocket.onclose = function (event) {
    console.log("User WS closed", event);
};

async function loadChats() {
    const response = await fetch("/messages");
    const html = await response.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, "text/html");

    const newChatList = doc.querySelector("#chatList");
    const currentChatList = document.querySelector("#chatList");

    if (newChatList && currentChatList) {
        currentChatList.innerHTML = newChatList.innerHTML;
    }

    const noChatsText = document.getElementById("noChatsText");
    if (currentChatList.children.length > 0) {
        if (noChatsText) noChatsText.style.display = "none";
    } else {
        if (noChatsText) noChatsText.style.display = "block";
    }
}

function markChatAsUpdated(chatId) {
    const link = document.querySelector(`a[href="/messages?chat_id=${chatId}"]`);
    if (link) link.style.fontWeight = "bold";
}

function setUserStatus(isOnline) {
    const statusDot = document.getElementById("userStatus");
    if (!statusDot) return;

    if (isOnline) {
        statusDot.classList.remove("offline");
        statusDot.classList.add("online");
    } else {
        statusDot.classList.remove("online");
        statusDot.classList.add("offline");
    }
}

function getCurrentChatId() {
    return currentChatId;
}

function queueMessageProcessing(data) {
    messageProcessingChain = messageProcessingChain
        .then(() => processMessage(data))
        .catch((err) => {
            console.warn("Message queue error:", err);
        });
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

async function decryptWithRecovery({ data, payload, chatId, isOwnMessage, allowStateReset }) {
    try {
        return await decryptMessage({
            chatId,
            payload,
            myPrivateKeyUint8: myPrivateKeyCache,
            myPublicKeyBase64: myPublicKeyCache,
            otherPublicKeyBase64: window.otherPublicKey,
            isOwnMessage,
            allowStateReset
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
            myPrivateKeyUint8: myPrivateKeyCache,
            myPublicKeyBase64: myPublicKeyCache,
            otherPublicKeyBase64: window.otherPublicKey,
            isOwnMessage,
            allowStateReset: false
        });
    }
}

async function rebuildRatchetStateFromTranscript(chatId, upToMessageId) {
    await deleteRatchetState(chatId);

    for (const item of chatTranscript) {
        if (!item.message_id || item.message_id >= upToMessageId) {
            continue;
        }

        const payload = tryParsePayload(item.content);
        const isOwnMessage = item.sender === myUsername;
        if (!payload || !selectPayloadForCurrentUser(payload, isOwnMessage)) {
            continue;
        }

        try {
            await decryptMessage({
                chatId,
                payload,
                myPrivateKeyUint8: myPrivateKeyCache,
                myPublicKeyBase64: myPublicKeyCache,
                otherPublicKeyBase64: window.otherPublicKey,
                isOwnMessage,
                allowStateReset: false
            });
        } catch (replayError) {
            console.warn("Replay step failed", item.message_id, replayError);
        }
    }
}

function tryParsePayload(content) {
    try {
        return JSON.parse(content);
    } catch {
        return null;
    }
}
