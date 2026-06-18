import { authFetch } from "./authClient.js?v=20260420i";

export function initUserSearch({ onChatStarted }) {
    const searchInput = document.getElementById("searchInput");
    const searchResults = document.getElementById("searchResults");
    const groupMembers = document.getElementById("groupMembers");
    const groupTitleInput = document.getElementById("groupTitleInput");
    const createGroupBtn = document.getElementById("createGroupBtn");
    const selectedUsers = new Map();

    function renderSelectedUsers() {
        if (!groupMembers) {
            return;
        }

        groupMembers.innerHTML = "";
        [...selectedUsers.values()].forEach((user) => {
            const chip = document.createElement("div");
            chip.className = "group-member-chip";
            chip.appendChild(document.createTextNode(user.username));

            const removeBtn = document.createElement("button");
            removeBtn.type = "button";
            removeBtn.textContent = "x";
            removeBtn.addEventListener("click", () => {
                selectedUsers.delete(user.username);
                renderSelectedUsers();
            });

            chip.appendChild(removeBtn);
            groupMembers.appendChild(chip);
        });
    }

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
                empty.textContent = "Nothing found";
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

    window.addUserToGroup = function (user) {
        selectedUsers.set(user.username, user);
        renderSelectedUsers();
    };

    if (createGroupBtn) {
        createGroupBtn.addEventListener("click", async () => {
            const title = groupTitleInput?.value?.trim() || "";
            if (!title) {
                alert("Specify a group title.");
                return;
            }
            if (selectedUsers.size < 2) {
                alert("Add at least two users to create a group.");
                return;
            }

            const formData = new FormData();
            formData.append("title", title);
            formData.append("usernames", JSON.stringify([...selectedUsers.keys()]));

            const response = await authFetch("/messages/start-group", {
                method: "POST",
                body: formData
            });
            const data = await response.json();

            if (data.status === "ok") {
                selectedUsers.clear();
                renderSelectedUsers();
                if (groupTitleInput) {
                    groupTitleInput.value = "";
                }
                await onChatStarted(data);
                return;
            }

            alert(data.message || "Could not create group.");
        });
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

        const writeButton = document.createElement("button");
        writeButton.type = "button";
        writeButton.className = "secondary-btn";
        writeButton.textContent = "Write";
        writeButton.addEventListener("click", () => {
            window.startChat(user.username);
        });

        const addButton = document.createElement("button");
        addButton.type = "button";
        addButton.className = "secondary-btn";
        addButton.textContent = "Add to group";
        addButton.addEventListener("click", () => {
            window.addUserToGroup(user);
        });

        const actions = document.createElement("div");
        actions.className = "search-result-actions";
        actions.appendChild(writeButton);
        actions.appendChild(addButton);

        container.appendChild(userInfo);
        container.appendChild(actions);
        return container;
    }
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
