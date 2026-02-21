let socket;

function connect() {
    const chatId = document.getElementById("chatId").value;
    socket = new WebSocket(`ws://${window.location.host}/ws/${chatId}`);

    socket.onmessage = function(event) {
        const chat = document.getElementById("chat");
        chat.innerHTML += `<div>${event.data}</div>`;
    };
}

function sendMessage() {
    const input = document.getElementById("messageInput");
    socket.send(input.value);
    input.value = "";
}

const searchInput = document.getElementById("searchInput");
const searchResults = document.getElementById("searchResults");

searchInput.addEventListener("input", async function() {
    const query = searchInput.value;

    if (query.length < 2) {
        searchResults.innerHTML = "";
        return;
    }

    const response = await fetch(`/messages/search?query=${query}`);
    const users = await response.json();

    searchResults.innerHTML = "";

    users.forEach(user => {
        const div = document.createElement("div");
        div.innerHTML = `
            ${user.email}
            <button onclick="startChat('${user.email}')">Написати</button>
        `;
        searchResults.appendChild(div);
    });
});

async function startChat(email) {
    const formData = new FormData();
    formData.append("email", email);

    await fetch("/messages/start", {
        method: "POST",
        body: formData
    });

    location.reload();
}