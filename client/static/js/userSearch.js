import { authFetch } from "./authClient.js?v=20260420i";

export function initUserSearch({ onChatStarted }) {
    const searchInput = document.getElementById("searchInput");
    const searchResults = document.getElementById("searchResults");
    const modal = document.getElementById("groupStartModal");
    const modalClose = document.getElementById("groupStartModalClose");
    const modalTitleInput = document.getElementById("groupStartTitleInput");
    const modalSelected = document.getElementById("groupStartSelected");
    const modalSearchInput = document.getElementById("groupStartSearchInput");
    const modalSearchResults = document.getElementById("groupStartSearchResults");
    const modalCreateBtn = document.getElementById("groupStartCreateBtn");
    const selectedUsers = new Map();

    function createChip(user, onRemove) {
        const chip = document.createElement("div");
        chip.className = "group-member-chip";
        chip.appendChild(document.createTextNode(user.username));

        const removeBtn = document.createElement("button");
        removeBtn.type = "button";
        removeBtn.textContent = "×";
        removeBtn.addEventListener("click", onRemove);
        chip.appendChild(removeBtn);
        return chip;
    }

    function renderSearchResults(users) {
        if (!searchResults) {
            return;
        }

        searchResults.innerHTML = "";
        if (!Array.isArray(users) || users.length === 0) {
            const empty = document.createElement("p");
            empty.textContent = "Користувача не знайдено";
            searchResults.appendChild(empty);
            return;
        }

        users.forEach((user) => {
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
            writeButton.className = "secondary-btn search-result-action-btn";
            writeButton.textContent = "Написати";
            writeButton.addEventListener("click", () => {
                window.startChat(user.username);
            });

            const actions = document.createElement("div");
            actions.className = "search-result-actions";
            actions.appendChild(writeButton);

            container.appendChild(userInfo);
            container.appendChild(actions);
            searchResults.appendChild(container);
        });
    }

    async function runSidebarSearch(query) {
        if (!searchResults) {
            return;
        }

        if (query.length < 2) {
            searchResults.innerHTML = "";
            return;
        }

        const response = await authFetch(`/messages/search?query=${encodeURIComponent(query)}`);
        const users = await response.json();
        renderSearchResults(users);
    }

    function renderSelectedUsers() {
        if (!modalSelected) {
            return;
        }

        modalSelected.innerHTML = "";
        [...selectedUsers.values()].forEach((user) => {
            modalSelected.appendChild(createChip(user, () => {
                selectedUsers.delete(user.username);
                renderSelectedUsers();
                void runModalSearch(modalSearchInput?.value?.trim() || "");
            }));
        });
    }

    async function runModalSearch(query) {
        if (!modalSearchResults) {
            return;
        }

        modalSearchResults.innerHTML = "";
        if (query.length < 2) {
            return;
        }

        const response = await authFetch(`/messages/search?query=${encodeURIComponent(query)}`);
        const users = await response.json();
        const filteredUsers = Array.isArray(users)
            ? users.filter((user) => !selectedUsers.has(user.username))
            : [];

        if (filteredUsers.length === 0) {
            const empty = document.createElement("p");
            empty.textContent = "Користувача не знайдено";
            modalSearchResults.appendChild(empty);
            return;
        }

        filteredUsers.forEach((user) => {
            const container = document.createElement("div");
            container.className = "search-result-item";

            const userInfo = document.createElement("div");
            userInfo.className = "search-result-info";
            userInfo.appendChild(createAvatarElement(user, "search-result-avatar"));

            const name = document.createElement("div");
            name.className = "search-result-name";
            name.textContent = user.username;
            userInfo.appendChild(name);

            const addButton = document.createElement("button");
            addButton.type = "button";
            addButton.className = "secondary-btn search-result-action-btn";
            addButton.textContent = "Додати";
            addButton.addEventListener("click", () => {
                selectedUsers.set(user.username, user);
                renderSelectedUsers();
                void runModalSearch(modalSearchInput?.value?.trim() || "");
            });

            const actions = document.createElement("div");
            actions.className = "search-result-actions";
            actions.appendChild(addButton);

            container.appendChild(userInfo);
            container.appendChild(actions);
            modalSearchResults.appendChild(container);
        });
    }

    function closeGroupStartModal() {
        if (modal) {
            modal.hidden = true;
        }
        selectedUsers.clear();
        if (modalTitleInput) {
            modalTitleInput.value = "";
        }
        if (modalSearchInput) {
            modalSearchInput.value = "";
        }
        if (modalSearchResults) {
            modalSearchResults.innerHTML = "";
        }
        renderSelectedUsers();
    }

    async function createGroupFromModal() {
        const title = modalTitleInput?.value?.trim() || "";
        if (!title) {
            window.alert("Вкажіть назву групи.");
            return;
        }
        if (selectedUsers.size < 1) {
            window.alert("Додайте щонайменше одного користувача до групи.");
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
            closeGroupStartModal();
            await onChatStarted(data);
            return;
        }

        window.alert(data.message || "Не вдалося створити групу.");
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
            window.alert(data.message);
        }
    };

    window.openDirectGroupBuilder = function (initialUser = null) {
        if (!modal) {
            return;
        }

        selectedUsers.clear();
        if (initialUser?.username) {
            selectedUsers.set(initialUser.username, initialUser);
        }
        renderSelectedUsers();
        if (modalTitleInput) {
            modalTitleInput.value = "";
        }
        if (modalSearchInput) {
            modalSearchInput.value = "";
        }
        if (modalSearchResults) {
            modalSearchResults.innerHTML = "";
        }
        modal.hidden = false;
        modalTitleInput?.focus();
    };

    if (searchInput) {
        searchInput.addEventListener("input", async () => {
            await runSidebarSearch(searchInput.value.trim());
        });
    }

    if (modalSearchInput) {
        modalSearchInput.addEventListener("input", async () => {
            await runModalSearch(modalSearchInput.value.trim());
        });
    }

    if (modalCreateBtn) {
        modalCreateBtn.addEventListener("click", () => {
            void createGroupFromModal();
        });
    }

    if (modalTitleInput) {
        modalTitleInput.addEventListener("keydown", (event) => {
            if (event.key === "Enter") {
                event.preventDefault();
                void createGroupFromModal();
            }
        });
    }

    if (modalClose) {
        modalClose.addEventListener("click", closeGroupStartModal);
    }

    if (modal) {
        modal.addEventListener("click", (event) => {
            if (event.target === modal) {
                closeGroupStartModal();
            }
        });
    }

    window.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && modal && !modal.hidden) {
            closeGroupStartModal();
        }
    });
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
