import { getPrivateKeyUint8, getPublicKey, fingerprint, initKeysIfNeeded } from "./crypto.js";
import { decryptMessage, encryptMessage, selectPayloadForCurrentUser } from "./chatCrypto.js";
import { initUserSearch } from "./userSearch.js";

let keysReady = false;
let pendingMessages = [];
let myPrivateKeyCache = null;
let myPublicKeyCache = null;
let myUsername = null;

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

    if (chatId) {
        await initializeChat(chatId);
    }

    window.sendMessage = async function () {
        const input = document.getElementById("messageInput");
        if (!input || !window.chatSocket || !window.otherPublicKey || !myPublicKeyCache || !keysReady) return;

        try {
            const messageText = input.value.trim();
            if (!messageText) return;

            const payload = await encryptMessage(
                messageText,
                window.otherPublicKey,
                myPublicKeyCache
            );

            window.chatSocket.send(JSON.stringify(payload));
            input.value = "";
        } catch (err) {
            console.error("Encryption error:", err);
        }
    };

    initUserSearch({
        onChatStarted: async (chatData) => {
            await applyChatKeys(chatData.public_key, chatData.identity_key);
            openChatSocket(chatData.chat_id);
            await loadChats();
            window.location.search = "?chat_id=" + chatData.chat_id;
        }
    });
});

async function initializeChat(chatId) {
    const res = await fetch(`/messages/get_keys?chat_id=${chatId}`);
    const data = await res.json();

    if (data.status !== "ok" || !data.public_key) {
        return;
    }

    await applyChatKeys(data.public_key, data.identity_key);
    openChatSocket(chatId);
}

async function applyChatKeys(publicKey, identityKey) {
    window.otherPublicKey = publicKey;
    window.otherIdentityKey = identityKey;
    keysReady = true;

    const fp = await fingerprint(window.otherPublicKey);
    const el = document.getElementById("fingerprint");
    if (el) el.innerText = fp;
}

async function openChatSocket(chatId) {
    keysReady = false;
    pendingMessages = [];

    const chat = document.getElementById("chat");
    if (chat) {
        chat.innerHTML = "";
    }

    if (window.chatSocket) {
        try { window.chatSocket.close(); } catch {}
    }

    const chatSocket = new WebSocket(`ws://${window.location.host}/ws/${chatId}`);

    chatSocket.onopen = function () {
        console.log("Chat ready:", chatId);
        keysReady = true;

        pendingMessages.forEach(processMessage);
        pendingMessages = [];
    };

    chatSocket.onmessage = async function (event) {
        const data = JSON.parse(event.data);

        if (data.type === "status") {
            setUserStatus(data.is_online);
            return;
        }

        if (data.type === "message") {
            if (!keysReady) {
                pendingMessages.push(data);
                return;
            }

            processMessage(data);
        }
    };

    window.chatSocket = chatSocket;
}

async function processMessage(data) {
    const chat = document.getElementById("chat");
    if (!chat) return;

    try {
        let text;

        try {
            const payload = JSON.parse(data.content);
            const encryptedPayload = selectPayloadForCurrentUser(payload, data.sender === myUsername);

            if (encryptedPayload) {
                text = await decryptMessage(encryptedPayload, myPrivateKeyCache);
            } else {
                text = data.content;
            }
        } catch {
            text = data.content;
        }

        renderMessage(chat, getSenderLabel(data.sender), text);
    } catch (err) {
        console.warn("Decrypt error:", err);
        const fallbackText = data.sender === myUsername
            ? "[Не вдалося розшифрувати власне повідомлення]"
            : data.content;

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
