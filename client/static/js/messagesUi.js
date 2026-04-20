export function bindChatHeaderControls() {
    const toggle = document.getElementById("chatInfoToggle");
    const close = document.getElementById("chatInfoClose");
    const panel = document.getElementById("chatInfoPanel");

    if (!toggle || !close || !panel) {
        return;
    }

    toggle.onclick = function () {
        panel.hidden = !panel.hidden;
    };

    close.onclick = function () {
        panel.hidden = true;
    };
}

export function renderMessage(chat, senderLabel, text) {
    const div = document.createElement("div");
    const sender = document.createElement("b");
    sender.textContent = `${senderLabel}:`;
    div.appendChild(sender);
    div.appendChild(document.createTextNode(` ${text}`));
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
}

export function getSenderLabel(senderName, myUsername) {
    return senderName === myUsername ? "You" : senderName;
}

export function setUserStatus(isOnline) {
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

export function updateChatHeaderAvatar(avatarData) {
    const avatarRoot = document.getElementById("chatUserAvatar");
    if (!avatarRoot) return;

    avatarRoot.innerHTML = "";

    if (avatarData?.avatar_url) {
        const image = document.createElement("img");
        image.src = avatarData.avatar_url;
        image.alt = "Avatar";
        image.className = "chat-user-avatar-image";
        avatarRoot.appendChild(image);
        return;
    }

    const fallback = document.createElement("div");
    fallback.className = "chat-user-avatar-fallback";
    fallback.textContent = avatarData?.avatar_initial || "?";
    if (avatarData?.avatar_class) {
        fallback.classList.add(avatarData.avatar_class);
    }
    avatarRoot.appendChild(fallback);
}

export function markChatAsUpdated(chatId) {
    const link = document.querySelector(`a[href="/messages?chat_id=${chatId}"]`);
    if (link) link.style.fontWeight = "bold";
}
