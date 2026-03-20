import { getPrivateKeyUint8, fingerprint, initKeysIfNeeded, nacl, naclUtil } from "./crypto.js";

let keysReady = false;
let pendingMessages = [];
let myPrivateKeyCache = null;
let myUsername = null; // для визначення своїх повідомлень

window.addEventListener("load", async function () {
    // 🔹 Ініціалізація ключів
    await initKeysIfNeeded();
    myPrivateKeyCache = await getPrivateKeyUint8();

    // 🔹 Отримуємо username з серверу
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

            // Fingerprint для UI
            const fp = await fingerprint(window.otherPublicKey);
            const el = document.getElementById("fingerprint");
            if (el) el.innerText = fp;

            // WS після отримання ключів
            openChatSocket(chatId);
        }
    }

    window.sendMessage = async function () {
        const input = document.getElementById("messageInput");
        if (!input || !input.value || !window.chatSocket || !window.otherPublicKey || !keysReady) return;

        try {
            const messageText = input.value;

            // 🔹 Відразу показуємо своє повідомлення
            const chat = document.getElementById("chat");
            const div = document.createElement("div");
            div.innerHTML = `<b>You:</b> ${messageText}`;
            chat.appendChild(div);
            chat.scrollTop = chat.scrollHeight;

            // 🔹 Шифруємо та відправляємо
            const payload = await encryptMessage(messageText, window.otherPublicKey);
            window.chatSocket.send(JSON.stringify(payload));

            input.value = "";
        } catch (err) {
            console.error("Encryption error:", err);
        }
    };

    /* ----------- SEARCH USERS ----------- */
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
        // 🔹 Пропускаємо свої повідомлення
        if (data.sender === myUsername) return;

        let text;
        try {
            const payload = JSON.parse(data.content);
            if (payload && payload.epk && payload.nonce && payload.message) {
                text = await decryptMessage(payload, myPrivateKeyCache);
            } else {
                text = data.content;
            }
        } catch {
            text = data.content;
        }

        const div = document.createElement("div");
        div.innerHTML = `<b>${data.sender}:</b> ${text}`;
        chat.appendChild(div);
        chat.scrollTop = chat.scrollHeight;

    } catch (err) {
        console.warn("Decrypt error:", err);
        const div = document.createElement("div");
        div.innerHTML = `<b>${data.sender}:</b> ${data.content}`;
        chat.appendChild(div);
        chat.scrollTop = chat.scrollHeight;
    }
}

/* ----------- USER SOCKET ----------- */

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

/* ----------- HELPERS ----------- */
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

/* ----------- EPHEMERAL FORWARD SECRECY ----------- */
async function encryptMessage(message, otherPublicBase64) {
    const otherPubUint8 = naclUtil.decodeBase64(otherPublicBase64.replace(/\s+/g, ''));
    const ephemeral = nacl.box.keyPair();
    const shared = nacl.box.before(otherPubUint8, ephemeral.secretKey);
    const nonce = nacl.randomBytes(24);
    const encrypted = nacl.box.after(naclUtil.decodeUTF8(message), nonce, shared);

    return {
        epk: naclUtil.encodeBase64(ephemeral.publicKey),
        nonce: naclUtil.encodeBase64(nonce),
        message: naclUtil.encodeBase64(encrypted)
    };
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