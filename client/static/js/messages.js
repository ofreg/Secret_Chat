import { getPrivateKeyUint8, getPublicKey, fingerprint, initKeysIfNeeded, nacl, naclUtil } from "./crypto.js";

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
        const res = await fetch(`/messages/get_keys?chat_id=${chatId}`);
        const data = await res.json();

        if (data.status === "ok" && data.public_key) {
            window.otherPublicKey = data.public_key;
            window.otherIdentityKey = data.identity_key;

            keysReady = true;

            const fp = await fingerprint(window.otherPublicKey);
            const el = document.getElementById("fingerprint");
            if (el) el.innerText = fp;

            openChatSocket(chatId);
        }
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

    const searchInput = document.getElementById("searchInput");
    const searchResults = document.getElementById("searchResults");

    if (searchInput) {
        searchInput.addEventListener("input", async function () {
            const query = searchInput.value;
            if (query.length < 2) {
                searchResults.innerHTML = "";
                return;
            }

            const response = await fetch(`/messages/search?query=${query}`);
            const users = await response.json();

            searchResults.innerHTML = "";
            if (users.length === 0) {
                searchResults.innerHTML = "<p>Нічого не знайдено</p>";
                return;
            }

            users.forEach(user => {
                const div = document.createElement("div");
                div.innerHTML = `
                    ${user.username}
                    <button onclick="startChat('${user.username}')">Написати</button>
                `;
                searchResults.appendChild(div);
            });
        });
    }

    window.startChat = async function (username) {
        const formData = new FormData();
        formData.append("username", username);

        const response = await fetch("/messages/start", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (data.status === "ok") {
            window.otherPublicKey = data.public_key;
            window.otherIdentityKey = data.identity_key;

            if (window.otherIdentityKey) {
                const fp = await fingerprint(window.otherPublicKey);
                const el = document.getElementById("fingerprint");
                if (el) el.innerText = fp;
            }

            openChatSocket(data.chat_id);
            await loadChats();
            window.location.search = "?chat_id=" + data.chat_id;
        } else {
            alert(data.message);
        }
    };
});

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

    chatSocket.onmessage = async function(event) {
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

        const senderLabel = data.sender === myUsername ? "You" : data.sender;
        const div = document.createElement("div");
        div.innerHTML = `<b>${senderLabel}:</b> ${text}`;
        chat.appendChild(div);
        chat.scrollTop = chat.scrollHeight;

    } catch (err) {
        console.warn("Decrypt error:", err);
        const senderLabel = data.sender === myUsername ? "You" : data.sender;
        const div = document.createElement("div");
        div.innerHTML = `<b>${senderLabel}:</b> ${data.sender === myUsername ? "[Не вдалося розшифрувати власне повідомлення]" : data.content}`;
        chat.appendChild(div);
        chat.scrollTop = chat.scrollHeight;
    }
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

userSocket.onclose = function (event) { console.log("User WS closed", event); };

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

async function encryptMessage(message, recipientPublicBase64, senderPublicBase64) {
    return {
        version: 2,
        recipient: encryptForPublicKey(message, recipientPublicBase64),
        sender: encryptForPublicKey(message, senderPublicBase64)
    };
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

function selectPayloadForCurrentUser(payload, isOwnMessage) {
    if (!payload || typeof payload !== "object") return null;

    if (payload.sender && payload.recipient) {
        return isOwnMessage ? payload.sender : payload.recipient;
    }

    if (payload.epk && payload.nonce && payload.message) {
        return payload;
    }

    return null;
}

async function decryptMessage(payload, myPrivateKeyUint8) {
    if (!payload.epk) throw new Error("Missing epk");
    const epk = naclUtil.decodeBase64(payload.epk);
    const nonce = naclUtil.decodeBase64(payload.nonce);
    const encrypted = naclUtil.decodeBase64(payload.message);
    const shared = nacl.box.before(epk, myPrivateKeyUint8);
    const decrypted = nacl.box.open.after(encrypted, nonce, shared);
    if (!decrypted) throw new Error("Decryption failed");
    return naclUtil.encodeUTF8(decrypted);
}
