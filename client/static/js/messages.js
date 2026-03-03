window.addEventListener("load", function () {

    /* ----------- CHAT SOCKET ----------- */

    const params = new URLSearchParams(window.location.search);
    const chatId = params.get("chat_id");

    let chatSocket = null;

    if (chatId) {
        chatSocket = new WebSocket(`ws://${window.location.host}/ws/${chatId}`);

        chatSocket.onmessage = function(event) {

    const data = JSON.parse(event.data);

    if (data.type === "status") {
        setUserStatus(data.is_online);
        return;
    }

    if (data.type === "message") {
        const chat = document.getElementById("chat");
        if (chat) {
            chat.innerHTML += `<div><b>${data.sender}:</b> ${data.content}</div>`;
            chat.scrollTop = chat.scrollHeight;
        }
        return;
    }
};
    }
    
    window.sendMessage = function () {
        const input = document.getElementById("messageInput");
        if (!input || !input.value || !chatSocket) return;

        chatSocket.send(input.value);
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
            await loadChats(); // підвантажуємо список чатів
            window.location.search = "?chat_id=" + data.chat_id;
        } else {
            alert(data.message);
        }
    };

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

});

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