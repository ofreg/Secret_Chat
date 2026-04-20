import { authFetch } from "./authClient.js?v=20260420i";

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
                const empty = document.createElement("p");
                empty.textContent = "Нічого не знайдено";
                searchResults.appendChild(empty);
                return;
            }

            users.forEach((user) => {
                searchResults.appendChild(buildSearchResultItem(user));
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

function buildSearchResultItem(user) {
    const container = document.createElement("div");
    container.className = "search-result-item";

    const userInfo = document.createElement("div");
    userInfo.className = "search-result-info";
    userInfo.appendChild(createAvatarElement(user, "search-result-avatar"));

    const name = document.createElement("div");
    name.className = "search-result-name";
    name.textContent = user.username;
    userInfo.appendChild(name);

    const button = document.createElement("button");
    button.type = "button";
    button.className = "secondary-btn";
    button.textContent = "Написати";
    button.addEventListener("click", () => {
        window.startChat(user.username);
    });

    container.appendChild(userInfo);
    container.appendChild(button);
    return container;
}

function createAvatarElement(user, className) {
    if (user.avatar_url) {
        const image = document.createElement("img");
        image.src = user.avatar_url;
        image.alt = user.username;
        image.className = `${className} user-avatar-image`;
        return image;
    }

    const fallback = document.createElement("div");
    fallback.className = `${className} user-avatar-fallback`;
    fallback.textContent = user.avatar_initial || "?";
    if (user.avatar_class) {
        fallback.classList.add(user.avatar_class);
    }
    return fallback;
}
