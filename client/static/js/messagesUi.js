const renderedMessages = new Map();
const pendingMessageStatuses = new Map();

function formatMessageTime(value) {
    if (!value) {
        return "";
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return "";
    }

    return parsed.toLocaleTimeString("uk-UA", {
        hour: "2-digit",
        minute: "2-digit"
    });
}

function formatMessageDateLabel(value) {
    if (!value) {
        return "";
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return "";
    }

    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const target = new Date(parsed.getFullYear(), parsed.getMonth(), parsed.getDate());
    const diffDays = Math.round((today.getTime() - target.getTime()) / 86400000);
    const timePart = formatMessageTime(value);

    if (diffDays === 0) {
        return timePart;
    }

    if (diffDays === 1) {
        return `Вчора ${timePart}`;
    }

    return parsed.toLocaleString("uk-UA", {
        day: "2-digit",
        month: "2-digit",
        hour: "2-digit",
        minute: "2-digit"
    });
}

function formatExactMessageDate(value) {
    if (!value) {
        return "";
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return "";
    }

    return parsed.toLocaleString("uk-UA", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit"
    });
}

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

function buildReplyNode(replyTo) {
    if (!replyTo?.messageId) {
        return null;
    }

    const wrapper = document.createElement("div");
    wrapper.className = "message-reply";

    const sender = document.createElement("div");
    sender.className = "message-reply-sender";
    sender.textContent = replyTo.senderLabel || "Reply";
    wrapper.appendChild(sender);

    const preview = document.createElement("div");
    preview.className = "message-reply-preview";
    preview.textContent = replyTo.previewText || "Original message";
    wrapper.appendChild(preview);

    return wrapper;
}

export function bindChatHeaderControls() {
    const toggle = document.getElementById("chatInfoToggle");
    const close = document.getElementById("chatInfoClose");
    const panel = document.getElementById("chatInfoPanel");
    const detailsToggle = document.getElementById("chatDetailsToggle");
    const detailsCard = document.getElementById("chatDetailsCard");
    const panelTitle = document.querySelector("#chatInfoPanel .chat-info-title");

    if (!toggle || !close || !panel) {
        return;
    }

    if (panelTitle) {
        panelTitle.textContent = "Дії чату";
    }

    toggle.onclick = function () {
        panel.hidden = !panel.hidden;
        if (panel.hidden && detailsCard) {
            detailsCard.hidden = true;
        }
    };

    close.onclick = function () {
        panel.hidden = true;
        if (detailsCard) {
            detailsCard.hidden = true;
        }
    };

    if (detailsToggle && detailsCard) {
        detailsToggle.onclick = function () {
            detailsCard.hidden = !detailsCard.hidden;
        };
    }
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
        deletedForAll = false,
        replyTo = null,
        createdAt = null,
        readAt = null
    } = options;

    if (messageId && renderedMessages.has(messageId)) {
        return renderedMessages.get(messageId);
    }

    const div = document.createElement("div");
    div.className = "chat-message";
    if (messageId) {
        div.dataset.messageId = String(messageId);
    }
    div.dataset.ownMessage = isOwnMessage ? "1" : "0";
    div.dataset.senderLabel = senderLabel;
    div.dataset.messagePreview = (text && String(text).trim())
        ? String(text).trim().replace(/\s+/g, " ").slice(0, 140)
        : (attachment ? "[Attachment]" : "");
    div.dataset.createdAt = createdAt || new Date().toISOString();
    div.dataset.readAt = readAt || "";

    const sender = document.createElement("b");
    sender.textContent = `${senderLabel}:`;
    div.appendChild(sender);

    const replyNode = buildReplyNode(replyTo);
    if (replyNode) {
        div.appendChild(document.createTextNode(" "));
        div.appendChild(replyNode);
    }

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

    const meta = document.createElement("span");
    meta.className = "message-meta";
    meta.title = formatExactMessageDate(div.dataset.createdAt) || "";

    const timeNode = document.createElement("span");
    timeNode.className = "message-time";
    timeNode.textContent = formatMessageDateLabel(div.dataset.createdAt);
    meta.appendChild(timeNode);

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
        meta.appendChild(status);

        const readNode = document.createElement("span");
        readNode.className = "message-read-time";
        readNode.dataset.readTime = "1";
        readNode.title = div.dataset.readAt ? formatExactMessageDate(div.dataset.readAt) : "";
        if (div.dataset.readAt && effectiveStatus === "read") {
            readNode.textContent = `Прочитано ${formatMessageTime(div.dataset.readAt)}`;
        } else {
            readNode.textContent = "";
        }
        meta.appendChild(readNode);
        pendingMessageStatuses.delete(messageId);
    }

    div.appendChild(document.createTextNode(" "));
    div.appendChild(meta);

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
}

export function updateMessageStatus(messageId, status, readAt = null) {
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
    if (readAt) {
        row.dataset.readAt = readAt;
    } else if (nextStatus === "read" && !row.dataset.readAt) {
        row.dataset.readAt = new Date().toISOString();
    }

    const readNode = row.querySelector("[data-read-time='1']");
    if (readNode) {
        readNode.title = row.dataset.readAt ? formatExactMessageDate(row.dataset.readAt) : "";
        readNode.textContent = nextStatus === "read" && row.dataset.readAt
            ? `Прочитано ${formatMessageTime(row.dataset.readAt)}`
            : "";
    }
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
