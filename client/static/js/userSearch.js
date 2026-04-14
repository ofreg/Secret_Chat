import { authFetch } from "./authClient.js?v=20260414a";

export function initUserSearch({ onChatStarted }) {
    const searchInput = document.getElementById("searchInput");
    const searchResults = document.getElementById("searchResults");

    if (searchInput) {
        searchInput.addEventListener("input", async function () {
            const query = searchInput.value;
            if (query.length < 2) {
                searchResults.innerHTML = "";
                return;
            }

            const response = await authFetch(`/messages/search?query=${encodeURIComponent(query)}`);
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

        const response = await authFetch("/messages/start", {
            method: "POST",
            body: formData
        });

        const data = await response.json();

        if (data.status === "ok") {
            await onChatStarted(data);
        } else {
            alert(data.message);
        }
    };
}
