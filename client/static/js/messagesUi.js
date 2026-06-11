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

function getViewerElements() {
    return {
        modal: document.getElementById("mediaViewer"),
        image: document.getElementById("mediaViewerImage"),
        video: document.getElementById("mediaViewerVideo"),
        title: document.getElementById("mediaViewerTitle")
    };
}

function closeMediaViewer() {
    const { modal, image, video } = getViewerElements();
    if (!modal || !image || !video) {
        return;
    }

    modal.hidden = true;
    image.hidden = true;
    image.removeAttribute("src");
    video.hidden = true;
    video.pause();
    video.removeAttribute("src");
    video.load();
}

function openMediaViewer(attachment) {
    const { modal, image, video, title } = getViewerElements();
    if (!modal || !image || !video) {
        return;
    }

    if (title) {
        title.textContent = attachment?.name || "";
    }

    image.hidden = true;
    image.removeAttribute("src");
    video.hidden = true;
    video.pause();
    video.removeAttribute("src");

    if (attachment.kind === "image") {
        image.src = attachment.url;
        image.alt = attachment.name || "Image attachment";
        image.hidden = false;
    } else if (attachment.kind === "video") {
        video.src = attachment.url;
        video.hidden = false;
        void video.play().catch(() => {});
    } else {
        return;
    }

    modal.hidden = false;
}

function buildAttachmentNode(attachment) {
    if (!attachment?.url || !attachment?.kind) {
        return null;
    }

    const wrapper = document.createElement("div");
    wrapper.className = `message-attachment attachment-${attachment.kind}`;

    if (attachment.kind === "image") {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "message-attachment-button";
        button.onclick = () => openMediaViewer(attachment);

        const image = document.createElement("img");
        image.src = attachment.url;
        image.alt = attachment.name || "Image attachment";
        image.className = "message-attachment-image";
        button.appendChild(image);
        wrapper.appendChild(button);
        return wrapper;
    }

    if (attachment.kind === "video") {
        const button = document.createElement("button");
        button.type = "button";
        button.className = "message-attachment-button is-video";
        button.onclick = () => openMediaViewer(attachment);

        const video = document.createElement("video");
        video.src = attachment.url;
        video.className = "message-attachment-video";
        video.preload = "metadata";
        video.muted = true;
        video.playsInline = true;
        button.appendChild(video);

        const badge = document.createElement("span");
        badge.className = "message-attachment-play";
        badge.textContent = "Play";
        button.appendChild(badge);
        wrapper.appendChild(button);
        return wrapper;
    }

    if (attachment.kind === "audio") {
        const title = document.createElement("div");
        title.className = "message-attachment-audio-title";
        title.textContent = attachment.name || "Audio";
        wrapper.appendChild(title);

        const audio = document.createElement("audio");
        audio.src = attachment.url;
        audio.controls = true;
        audio.preload = "metadata";
        audio.className = "message-attachment-audio";
        wrapper.appendChild(audio);
        return wrapper;
    }

    return null;
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

export function bindMediaViewerControls() {
    const modal = document.getElementById("mediaViewer");
    const closeBtn = document.getElementById("mediaViewerClose");

    if (!modal || !closeBtn) {
        return;
    }

    closeBtn.onclick = () => closeMediaViewer();
    modal.onclick = (event) => {
        if (event.target === modal) {
            closeMediaViewer();
        }
    };

    window.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !modal.hidden) {
            closeMediaViewer();
        }
    });
}

export function resetRenderedMessages() {
    renderedMessages.clear();
    pendingMessageStatuses.clear();
}

export function renderMessage(chat, senderLabel, text, options = {}) {
    const {
        messageId = null,
        deliveryStatus = null,
        isOwnMessage = false,
        attachment = null,
        deletedForAll = false
    } = options;

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

    const hasText = Boolean(text && String(text).trim());
    const attachmentNode = buildAttachmentNode(attachment);
    if (attachmentNode) {
        div.appendChild(document.createTextNode(" "));
        div.appendChild(attachmentNode);
    }

    if (hasText) {
        const body = document.createElement("span");
        body.className = attachmentNode ? "chat-message-text has-attachment" : "chat-message-text";
        body.textContent = ` ${text}`;
        div.appendChild(body);
    }

    if (messageId && !deletedForAll) {
        const actions = document.createElement("span");
        actions.className = "message-actions";

        const deleteSelfButton = document.createElement("button");
        deleteSelfButton.type = "button";
        deleteSelfButton.className = "message-action-btn";
        deleteSelfButton.dataset.deleteMessageSelf = String(messageId);
        deleteSelfButton.textContent = "Delete for me";
        actions.appendChild(deleteSelfButton);

        if (isOwnMessage) {
            const deleteAllButton = document.createElement("button");
            deleteAllButton.type = "button";
            deleteAllButton.className = "message-action-btn danger";
            deleteAllButton.dataset.deleteMessageAll = String(messageId);
            deleteAllButton.textContent = "Delete for all";
            actions.appendChild(deleteAllButton);
        }

        div.appendChild(document.createTextNode(" "));
        div.appendChild(actions);
    }

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

export function removeRenderedMessage(messageId) {
    const row = renderedMessages.get(messageId) || document.querySelector(`[data-message-id="${messageId}"]`);
    if (!row) {
        return;
    }

    row.remove();
    renderedMessages.delete(messageId);
    pendingMessageStatuses.delete(messageId);
}

export function markMessageDeletedForAll(messageId) {
    const row = renderedMessages.get(messageId) || document.querySelector(`[data-message-id="${messageId}"]`);
    if (!row) {
        return;
    }

    const attachment = row.querySelector(".message-attachment");
    if (attachment) {
        attachment.remove();
    }

    const body = row.querySelector(".chat-message-text");
    if (body) {
        body.textContent = " [Message deleted]";
        body.classList.remove("has-attachment");
    } else {
        const fallbackBody = document.createElement("span");
        fallbackBody.className = "chat-message-text";
        fallbackBody.textContent = " [Message deleted]";
        row.appendChild(fallbackBody);
    }

    row.querySelectorAll(".message-actions").forEach((node) => node.remove());
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

export function updateAttachmentComposerState(file) {
    const chip = document.getElementById("attachmentChip");
    const label = document.getElementById("attachmentChipLabel");
    if (!chip || !label) {
        return;
    }

    if (!file) {
        chip.hidden = true;
        label.textContent = "";
        return;
    }

    chip.hidden = false;
    label.textContent = file.name;
}

export function setAttachmentFeedback(message = "", tone = "") {
    const feedback = document.getElementById("attachmentFeedback");
    const popup = document.getElementById("attachmentAlert");
    const popupBody = document.getElementById("attachmentAlertBody");

    if (!feedback && !popup) {
        return;
    }

    if (feedback) {
        feedback.textContent = message;
        feedback.className = "attachment-feedback";
        if (tone === "error") {
            feedback.classList.add("is-error");
        } else if (tone === "success") {
            feedback.classList.add("is-success");
        }
    }

    if (!popup || !popupBody) {
        return;
    }

    if (!message) {
        popup.hidden = true;
        popupBody.textContent = "";
        popup.className = "attachment-alert";
        return;
    }

    popup.hidden = false;
    popupBody.textContent = message;
    popup.className = "attachment-alert";
    if (tone === "error") {
        popup.classList.add("is-error");
    } else if (tone === "success") {
        popup.classList.add("is-success");
    }
}

export function bindAttachmentAlertControls() {
    const popup = document.getElementById("attachmentAlert");
    const closeBtn = document.getElementById("attachmentAlertClose");

    if (!popup || !closeBtn) {
        return;
    }

    closeBtn.onclick = () => {
        popup.hidden = true;
    };
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
