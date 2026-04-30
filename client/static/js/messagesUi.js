const renderedMessages = new Map();
const pendingMessageStatuses = new Map();

function getStatusRank(status) {
    if (status === "read") return 3;
    if (status === "delivered") return 2;
    return 1;
}

function resolveStatus(previousStatus, nextStatus) {
    if (!previousStatus) return nextStatus || "sent";
    if (!nextStatus) return previousStatus;
    return getStatusRank(nextStatus) >= getStatusRank(previousStatus) ? nextStatus : previousStatus;
}

function getStatusGlyph(status) {
    if (status === "read") return "\u2713\u2713";
    if (status === "delivered") return "\u2713\u2713";
    return "\u2713";
}

function getStatusLabel(status) {
    if (status === "read") return "Read";
    if (status === "delivered") return "Delivered";
    return "Sent";
}

function getStatusClass(status) {
    if (status === "read") return "message-status is-read";
    if (status === "delivered") return "message-status is-delivered";
    return "message-status is-sent";
}

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

export function resetRenderedMessages() {
    renderedMessages.clear();
    pendingMessageStatuses.clear();
}

export function renderMessage(chat, senderLabel, text, options = {}) {
    const { messageId = null, deliveryStatus = null, isOwnMessage = false } = options;

    if (messageId && renderedMessages.has(messageId)) {
        return renderedMessages.get(messageId);
    }

    const div = document.createElement("div");
    div.className = "chat-message";
    if (messageId) {
        div.dataset.messageId = String(messageId);
    }

    const sender = document.createElement("b");
    sender.textContent = `${senderLabel}:`;
    div.appendChild(sender);

    const body = document.createElement("span");
    body.className = "chat-message-text";
    body.textContent = ` ${text}`;
    div.appendChild(body);

    if (isOwnMessage && messageId) {
        const effectiveStatus = resolveStatus(
            deliveryStatus,
            pendingMessageStatuses.get(messageId)
        );
        const status = document.createElement("span");
        status.className = getStatusClass(effectiveStatus);
        status.dataset.messageStatusFor = String(messageId);
        status.dataset.deliveryStatus = effectiveStatus;
        status.setAttribute("aria-label", getStatusLabel(effectiveStatus));
        status.title = getStatusLabel(effectiveStatus);
        status.textContent = "";
        div.appendChild(document.createTextNode(" "));
        div.appendChild(status);
        pendingMessageStatuses.delete(messageId);
    }

    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
    if (messageId) {
        renderedMessages.set(messageId, div);
    }
    return div;
}

export function updateMessageStatus(messageId, status) {
    const row = renderedMessages.get(messageId) || document.querySelector(`[data-message-id="${messageId}"]`);
    if (!row) {
        pendingMessageStatuses.set(
            messageId,
            resolveStatus(pendingMessageStatuses.get(messageId), status)
        );
        return;
    }

    let statusNode = row.querySelector(`[data-message-status-for="${messageId}"]`);
    const nextStatus = resolveStatus(
        statusNode?.dataset.deliveryStatus || pendingMessageStatuses.get(messageId) || null,
        status
    );

    if (!statusNode) {
        statusNode = document.createElement("span");
        statusNode.dataset.messageStatusFor = String(messageId);
        row.appendChild(document.createTextNode(" "));
        row.appendChild(statusNode);
    }

    statusNode.dataset.deliveryStatus = nextStatus;
    statusNode.className = getStatusClass(nextStatus);
    statusNode.setAttribute("aria-label", getStatusLabel(nextStatus));
    statusNode.title = getStatusLabel(nextStatus);
    statusNode.textContent = "";
    pendingMessageStatuses.delete(messageId);
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
