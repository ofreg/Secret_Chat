import { getPrivateKeyUint8, fingerprint, initKeysIfNeeded, nacl, naclUtil } from "./crypto.js";

window.addEventListener("load", async function () {
    // 🔹 Якщо на /messages з chat_id
    const params = new URLSearchParams(window.location.search);
    const chatId = params.get("chat_id");

    await initKeysIfNeeded(); // 🔹 переконаємось, що ключ є

    if (chatId) {
        const res = await fetch(`/messages/get_keys?chat_id=${chatId}`);
        const data = await res.json();

        if (data.status === "ok" && data.public_key) {
            window.otherPublicKey = data.public_key;
            window.otherIdentityKey = data.identity_key;

            // 🔹 Fingerprint для UI
            const fp = await fingerprint(window.otherIdentityKey);
            const el = document.getElementById("fingerprint");
            if (el) el.innerText = fp;

            // 🔹 WS відкриваємо після отримання ключів
            openChatSocket(chatId);
        }
    }

    window.sendMessage = function () {
        const input = document.getElementById("messageInput");
        if (!input || !input.value || !window.chatSocket || !window.sharedSecret) return;

        const nonce = nacl.randomBytes(24);
        const encrypted = nacl.box.after(
            naclUtil.decodeUTF8(input.value),
            nonce,
            window.sharedSecret
        );

        const payload = {
            nonce: naclUtil.encodeBase64(nonce),
            message: naclUtil.encodeBase64(encrypted)
        };

        window.chatSocket.send(JSON.stringify(payload));
        input.value = "";
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
                    ${user.email}
                    <button onclick="startChat('${user.email}')">Написати</button>
                `;
                searchResults.appendChild(div);
            });
        });
    }

    window.startChat = async function (email) {
        const formData = new FormData();
        formData.append("email", email);

        const response = await fetch("/messages/start", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (data.status === "ok") {
            window.otherPublicKey = data.public_key;
            window.otherIdentityKey = data.identity_key;

            if (window.otherIdentityKey) {
                const fp = await fingerprint(window.otherIdentityKey);
                const el = document.getElementById("fingerprint");
                if (el) el.innerText = fp;
            }

            openChatSocket(data.chat_id); // 🔥 WS після ключів
            await loadChats();
            window.location.search = "?chat_id=" + data.chat_id;
        } else {
            alert(data.message);
        }
    };

});

// 🔥 Відкладене відкриття WebSocket
async function openChatSocket(chatId) {
    const chatSocket = new WebSocket(`ws://${window.location.host}/ws/${chatId}`);

    chatSocket.onopen = async function () {
        const myPrivateUint8 = await getPrivateKeyUint8();
        if (!myPrivateUint8) {
            console.error("Не вдалося отримати приватний ключ");
            return;
        }

        if (!window.otherPublicKey) {
            console.error("Немає public key співрозмовника!");
            return;
        }

        try {
            const cleanKey = window.otherPublicKey.replace(/\s+/g, '');
            const otherKeyUint8 = naclUtil.decodeBase64(cleanKey);
            window.sharedSecret = nacl.box.before(otherKeyUint8, myPrivateUint8);
            console.log("Shared secret успішно створено");
        } catch (err) {
            console.error("Невірне кодування public key:", window.otherPublicKey, err);
            return;
        }
    };

    chatSocket.onmessage = async function(event) {
        const data = JSON.parse(event.data);

        if (data.type === "status") {
            setUserStatus(data.is_online);
            return;
        }

        if (data.type === "message") {
            const chat = document.getElementById("chat");
            if (!chat) return;

            try {
                const payload = JSON.parse(data.content);
                const nonce = naclUtil.decodeBase64(payload.nonce);
                const encrypted = naclUtil.decodeBase64(payload.message);
                const decrypted = nacl.box.open.after(encrypted, nonce, window.sharedSecret);
                if (!decrypted) return;
                const text = naclUtil.encodeUTF8(decrypted);

                chat.innerHTML += `<div><b>${data.sender}:</b> ${text}</div>`;
                chat.scrollTop = chat.scrollHeight;
            } catch {
                chat.innerHTML += `<div><b>${data.sender}:</b> ${data.content}</div>`;
                chat.scrollTop = chat.scrollHeight;
            }
        }
    };

    window.chatSocket = chatSocket; // зберігаємо для sendMessage
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

    userSocket.onclose = function (event) {
        console.log("User WS closed", event);
    };

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
        if (link) {
            link.style.fontWeight = "bold";
        }
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
    const otherPubUint8 = naclUtil.decodeBase64(otherPublicBase64);
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
    const epk = naclUtil.decodeBase64(payload.epk);
    const nonce = naclUtil.decodeBase64(payload.nonce);
    const encrypted = naclUtil.decodeBase64(payload.message);
    const shared = nacl.box.before(epk, myPrivateKeyUint8);
    const decrypted = nacl.box.open.after(encrypted, nonce, shared);
    if (!decrypted) throw new Error("Decryption failed");
    return naclUtil.encodeUTF8(decrypted);
}