import {
    clearLocalChatState,
    clearGroupSenderStatesForChat,
    clearMessageDeletedForSelf,
    ensureLocalAccountBinding,
    deleteRatchetState,
    deriveSafetyNumber,
    getIdentityKey,
    getIdentityPrivateKeyUint8,
    getIdentitySigningKey,
    markMessageDeletedForSelf,
    saveAttachmentHistory,
    getRatchetState,
    getVerificationStatus,
    initKeysIfNeeded,
    restoreCloudBackupIfNeeded,
    resetLocalCryptoState,
    saveVerificationStatus
} from "./crypto.js?v=20260623b";
// Bump module query strings when group E2EE runtime changes so browsers do not reuse stale modules.
import { authFetch, ensureSession } from "./authClient.js?v=20260601b";
import {
    decryptAttachmentData,
    encryptAttachmentData,
    encryptGroupMessage,
    encryptMessage,
    encryptMessageForDevices
} from "./chatCrypto.js?v=20260623a";
import {
    bindMediaViewerControls,
    bindAttachmentAlertControls,
    bindChatHeaderControls,
    getSenderLabel,
    markChatAsUpdated,
    removeRenderedMessage,
    renderMessage,
    resetRenderedMessages,
    setAttachmentFeedback,
    setUserStatus,
    updateAttachmentComposerState,
    updateMessageStatus,
    updateChatHeaderAvatar
} from "./messagesUi.js?v=20260623a";
import {
    createChatSocket,
    createUserSocket,
    reloadChatList
} from "./messagesSockets.js?v=20260612b";
import { createHistoryController } from "./messagesHistory.js?v=20260623a";
import {
    applyChatKeysFlow,
    initializeChatFlow,
    refreshChatKeysFlow,
    refreshSafetyNumberFlow,
    sendCurrentMessage
} from "./messagesChatFlow.js?v=20260623a";
import { updateVerificationUiFlow } from "./messagesVerification.js?v=20260420i";

const DEBUG_CHAT = false;
let keysReady = false;
let pendingMessages = [];
let myIdentityPrivateKeyCache = null;
let myIdentityKeyCache = null;
let myIdentitySigningKeyCache = null;
let myDeviceBundlesCache = [];
let myCurrentDeviceId = null;
let myUsername = null;
let currentChatId = null;
let currentChatIsGroup = false;
let currentGroupCreatorId = null;
let currentGroupKeyEpoch = 1;
let currentDirectChatPeer = null;
let historySyncInProgress = false;
let deferredLiveMessages = [];
let currentFingerprint = null;
let cryptoBootstrapPromise = null;
let chatSocketOpened = false;
let chatKeysRetryTimer = null;
let activeMessageContext = null;
let activeReplyTarget = null;
const decryptedAttachmentCache = new Map();
const historyController = createHistoryController({
    getMyUsername: () => myUsername,
    getCurrentChatId: () => currentChatId,
    getMyPrivateKey: () => myIdentityPrivateKeyCache,
    getMyIdentityKey: () => myIdentityKeyCache,
    getMyIdentitySigningKey: () => myIdentitySigningKeyCache,
    getOwnDeviceBundleById: (deviceId) => {
        const bundles = Array.isArray(myDeviceBundlesCache) ? myDeviceBundlesCache : [];
        return bundles.find((bundle) => bundle?.device_id === deviceId) || null;
    },
    getOtherIdentityKey: () => window.otherIdentityKey,
    getOtherIdentitySigningKey: () => window.otherIdentitySigningKey,
    getOtherDeviceBundleById: (deviceId) => {
        const bundles = Array.isArray(window.otherDeviceBundles) ? window.otherDeviceBundles : [];
        return bundles.find((bundle) => bundle?.device_id === deviceId) || null;
    },
    resolveAttachment: async (attachment, isOwnMessage) => {
        if (!attachment?.meta?.encrypted) {
            return attachment;
        }

        const cacheKey = `${attachment.url}|${isOwnMessage ? "own" : "peer"}`;
        if (decryptedAttachmentCache.has(cacheKey)) {
            return decryptedAttachmentCache.get(cacheKey);
        }

        const decryptedAttachment = await decryptAttachmentData({
            attachment,
            myPrivateKeyUint8: myIdentityPrivateKeyCache,
            isOwnMessage,
            myIdentitySigningKeyBase64: myIdentitySigningKeyCache,
            resolveOwnSigningKeyByDeviceId: (deviceId) => {
                const bundle = myDeviceBundlesCache.find((entry) => entry?.device_id === deviceId);
                return bundle?.identity_signing_key || null;
            },
            resolveSenderSigningKeyByDeviceId: (deviceId) => {
                const bundle = (window.otherDeviceBundles || []).find((entry) => entry?.device_id === deviceId);
                return bundle?.identity_signing_key || null;
            }
        });
        decryptedAttachmentCache.set(cacheKey, decryptedAttachment);
        return decryptedAttachment;
    },
    renderChatMessage: renderMessage,
    getSenderLabel: (senderName) => getSenderLabel(senderName, myUsername),
    logChatState
});

function buildReadinessSnapshot() {
    return {
        currentChatId,
        chatSocketOpened,
        hasChatSocket: Boolean(window.chatSocket),
        hasMyPrivateKey: Boolean(myIdentityPrivateKeyCache),
        hasMyPublicKey: Boolean(myIdentityKeyCache),
        hasMyIdentityKey: Boolean(myIdentityKeyCache),
        hasMyIdentitySigningKey: Boolean(myIdentitySigningKeyCache),
        hasOtherPublicKey: Boolean(window.otherIdentityKey),
        hasOtherIdentitySigningKey: Boolean(window.otherIdentitySigningKey),
        hasOtherPrekeyBundle: Boolean(window.otherPrekeyBundle),
        keysReady,
        historySyncInProgress,
        pendingMessages: pendingMessages.length,
        deferredLiveMessages: deferredLiveMessages.length
    };
}

function logChatState(label, extra = null, level = "info") {
    if (!DEBUG_CHAT) {
        return;
    }

    const payload = {
        ...buildReadinessSnapshot(),
        ...(extra || {})
    };
    const logger = console[level] || console.log;
    logger(`[chat-debug] ${label}`, payload);
}

function sortQueuedMessages(messages) {
    return [...messages].sort((left, right) => {
        const leftId = Number(left?.message_id || 0);
        const rightId = Number(right?.message_id || 0);
        return leftId - rightId;
    });
}

function clearDecryptedAttachmentCache() {
    for (const cachedAttachment of decryptedAttachmentCache.values()) {
        try {
            if (cachedAttachment?.url?.startsWith("blob:")) {
                URL.revokeObjectURL(cachedAttachment.url);
            }
        } catch {}
    }
    decryptedAttachmentCache.clear();
}

function bindGroupControls() {
    const saveBtn = document.getElementById("groupSaveMetaBtn");
    const addBtn = document.getElementById("groupAddUserBtn");
    if (saveBtn) {
        saveBtn.addEventListener("click", () => {
            void saveGroupMetadata();
        });
    }
    if (addBtn) {
        addBtn.addEventListener("click", () => {
            void addUserToCurrentGroup();
        });
    }
}

function setGroupSettingsFeedback(message = "", tone = "") {
    const feedback = document.getElementById("groupSettingsFeedback");
    if (!feedback) {
        return;
    }
    feedback.textContent = message;
    feedback.className = "group-settings-feedback";
    if (tone === "error") {
        feedback.classList.add("is-error");
    } else if (tone === "success") {
        feedback.classList.add("is-success");
    }
}

function renderGroupSettings(payload = null) {
    const root = document.getElementById("groupSettings");
    const titleInput = document.getElementById("groupTitleEditInput");
    const membersList = document.getElementById("groupMembersList");
    const saveBtn = document.getElementById("groupSaveMetaBtn");
    const addInput = document.getElementById("groupAddUserInput");
    const addBtn = document.getElementById("groupAddUserBtn");
    if (!root || !titleInput || !membersList) {
        return;
    }

    const isGroup = Boolean(payload?.is_group);
    root.hidden = !isGroup;
    if (!isGroup) {
        membersList.innerHTML = "";
        currentGroupCreatorId = null;
        return;
    }

    currentGroupCreatorId = payload?.creator_id || null;
    const isCreator = currentGroupCreatorId === meId();
    titleInput.value = payload?.username || "";
    titleInput.disabled = !isCreator;
    if (saveBtn) {
        saveBtn.hidden = !isCreator;
    }
    if (addInput) {
        addInput.hidden = !isCreator;
        addInput.disabled = !isCreator;
    }
    if (addBtn) {
        addBtn.hidden = !isCreator;
    }
    membersList.innerHTML = "";

    const members = Array.isArray(payload?.members) ? payload.members : [];
    members.forEach((member) => {
        const row = document.createElement("div");
        row.className = "group-member-row";

        const main = document.createElement("div");
        main.className = "group-member-main";

        const avatar = document.createElement(member.avatar_url ? "img" : "div");
        if (member.avatar_url) {
            avatar.src = member.avatar_url;
            avatar.alt = member.username;
            avatar.className = "search-result-avatar user-avatar-image";
        } else {
            avatar.className = `search-result-avatar user-avatar-fallback ${member.avatar_class || ""}`.trim();
            avatar.textContent = member.avatar_initial || "?";
        }
        main.appendChild(avatar);

        const meta = document.createElement("div");
        meta.className = "group-member-meta";

        const name = document.createElement("div");
        name.className = "group-member-name";
        name.textContent = member.username;
        meta.appendChild(name);

        const role = document.createElement("div");
        role.className = "group-member-role";
        if (member.user_id === currentGroupCreatorId) {
            role.textContent = "Creator";
        } else if (member.username === myUsername) {
            role.textContent = "You";
        } else {
            role.textContent = "Member";
        }
        meta.appendChild(role);

        main.appendChild(meta);
        row.appendChild(main);

        const actions = document.createElement("div");
        actions.className = "group-member-actions";
        const canRemove = currentGroupCreatorId === Number(meId()) && member.user_id !== currentGroupCreatorId;
        const canLeave = member.username === myUsername;
        if (canRemove || canLeave) {
            const btn = document.createElement("button");
            btn.type = "button";
            btn.className = "safety-btn secondary";
            btn.textContent = canLeave ? "Leave" : "Remove";
            btn.addEventListener("click", () => {
                void removeGroupMember(member.user_id, canLeave);
            });
            actions.appendChild(btn);
        }
        row.appendChild(actions);
        membersList.appendChild(row);
    });
}

function applyChatMetaPayload(payload) {
    if (!payload) {
        return;
    }
    currentChatIsGroup = Boolean(payload.is_group);
    currentGroupCreatorId = payload.creator_id || null;
    currentGroupKeyEpoch = Number(payload.group_key_epoch || 1);
    currentDirectChatPeer = currentChatIsGroup ? null : {
        username: payload.username,
        avatar_url: payload.avatar_url || null,
        avatar_initial: payload.avatar_initial || "?",
        avatar_class: payload.avatar_class || ""
    };
    const chatUserNameEl = document.getElementById("chatUserName");
    const directChatActions = document.getElementById("directChatActions");
    const startGroupBtn = document.getElementById("startGroupFromDirectBtn");
    if (chatUserNameEl && payload.username) {
        chatUserNameEl.textContent = payload.username;
    }
    if (directChatActions) {
        directChatActions.hidden = currentChatIsGroup || !currentDirectChatPeer?.username;
    }
    if (startGroupBtn) {
        startGroupBtn.onclick = () => {
            if (currentDirectChatPeer?.username) {
                window.openDirectGroupBuilder?.(currentDirectChatPeer);
            }
        };
    }
    updateChatHeaderAvatar(payload);
    renderGroupSettings(payload);
}

function meId() {
    return Number(window.currentUserId || 0);
}

async function refreshCurrentChatDetails() {
    if (!currentChatId) {
        return;
    }
    const response = await authFetch(`/chats/${currentChatId}/details`);
    const payload = await response.json();
    if (response.ok && payload?.status === "ok") {
        applyChatMetaPayload(payload);
    }
}

async function saveGroupMetadata() {
    if (!currentChatId || !currentChatIsGroup) {
        return;
    }
    const titleInput = document.getElementById("groupTitleEditInput");
    const avatarInput = document.getElementById("groupAvatarInput");
    const formData = new FormData();
    formData.append("title", titleInput?.value?.trim() || "");
    const avatarFile = avatarInput?.files?.[0];
    if (avatarFile) {
        formData.append("avatar", avatarFile);
    }

    const response = await authFetch(`/chats/${currentChatId}/metadata`, {
        method: "POST",
        body: formData
    });
    const payload = await response.json();
    if (!response.ok || payload?.status !== "ok") {
        setGroupSettingsFeedback(payload?.detail || payload?.message || "Could not update group.", "error");
        return;
    }
    if (avatarInput) {
        avatarInput.value = "";
    }
    applyChatMetaPayload(payload);
    await loadChats();
    setGroupSettingsFeedback("Group updated.", "success");
}

async function addUserToCurrentGroup() {
    if (!currentChatId || !currentChatIsGroup) {
        return;
    }
    const input = document.getElementById("groupAddUserInput");
    const username = input?.value?.trim() || "";
    if (!username) {
        setGroupSettingsFeedback("Enter a username to add.", "error");
        return;
    }

    const formData = new FormData();
    formData.append("username", username);
    const response = await authFetch(`/chats/${currentChatId}/participants`, {
        method: "POST",
        body: formData
    });
    const payload = await response.json();
    if (!response.ok || payload?.status !== "ok") {
        setGroupSettingsFeedback(payload?.detail || payload?.message || "Could not add user.", "error");
        return;
    }

    if (Array.isArray(window.otherDeviceBundles) && payload?.added_user?.device_bundles) {
        window.otherDeviceBundles = [...window.otherDeviceBundles, ...payload.added_user.device_bundles];
    }
    if (input) {
        input.value = "";
    }
    await clearGroupSenderStatesForChat(currentChatId);
    applyChatMetaPayload(payload);
    await loadChats();
    setGroupSettingsFeedback("User added to group.", "success");
}

async function removeGroupMember(userId, isLeaving) {
    if (!currentChatId || !currentChatIsGroup) {
        return;
    }
    const confirmed = window.confirm(isLeaving ? "Leave this group?" : "Remove this user from the group?");
    if (!confirmed) {
        return;
    }

    const response = await authFetch(`/chats/${currentChatId}/participants/${userId}`, {
        method: "DELETE"
    });
    const payload = await response.json();
    if (!response.ok || payload?.status !== "ok") {
        setGroupSettingsFeedback(payload?.detail || payload?.message || "Could not remove user.", "error");
        return;
    }

    if (isLeaving) {
        window.location.href = "/messages";
        return;
    }

    await clearGroupSenderStatesForChat(currentChatId);
    await refreshCurrentChatDetails();
    await loadChats();
    setGroupSettingsFeedback("User removed from group.", "success");
}

window.sendMessage = async function () {
    await sendCurrentMessage({
        awaitCryptoBootstrap: async () => {
            if (cryptoBootstrapPromise) {
                await cryptoBootstrapPromise;
            }
        },
        getCurrentChatId,
        getInput: () => document.getElementById("messageInput"),
        getAttachmentInput: () => document.getElementById("messageAttachmentInput"),
        getChatSocket: () => window.chatSocket,
        getMyIdentityKey: () => myIdentityKeyCache,
        getMyPrivateKey: () => myIdentityPrivateKeyCache,
        getCurrentDeviceId: () => myCurrentDeviceId,
        getOwnDeviceBundles: () => myDeviceBundlesCache,
        getOtherIdentityKey: () => window.otherIdentityKey,
        getOtherPrekeyBundle: () => window.otherPrekeyBundle,
        getOtherDeviceBundles: () => window.otherDeviceBundles || [],
        getCurrentChatIsGroup: () => currentChatIsGroup,
        getCurrentGroupKeyEpoch: () => currentGroupKeyEpoch,
        refreshChatKeys,
        isKeysReady: () => keysReady,
        logChatState,
        getRatchetState,
        deleteRatchetState,
        encryptMessage,
        encryptMessageForDevices,
        encryptGroupMessage,
        encryptAttachmentData,
        saveAttachmentHistory,
        authFetch,
        onAttachmentSent: () => updateAttachmentComposerState(null),
        setAttachmentFeedback,
        getReplyTargetId: () => window.getActiveReplyTargetId?.() || null,
        clearReplyTarget: () => window.clearActiveReplyTarget?.()
    });
};

window.addEventListener("load", async function () {
    logChatState("messages page load started");

    const messageInput = document.getElementById("messageInput");
    if (messageInput) {
        messageInput.addEventListener("keydown", (event) => {
            if (event.key === "Enter" && !event.shiftKey) {
                event.preventDefault();
                void window.sendMessage();
            }
        });
    }

    const sessionOk = await ensureSession();
    if (!sessionOk) {
        window.location.href = "/login";
        return;
    }

    const meRes = await authFetch("/users/me");
    const meData = await meRes.json();
    if (meData.status === "ok") {
        myUsername = meData.username || "";
        const bindingChanged = await ensureLocalAccountBinding(meData);
        myCurrentDeviceId = meData.current_device_id || readCurrentDeviceId();
        await restoreCloudBackupIfNeeded(meData);
        logChatState("account binding ensured on messages page", { bindingChanged });
    }

    bindChatHeaderControls();
    bindMediaViewerControls();
    bindAttachmentAlertControls();
    bindGroupControls();
    connectUserSocket();

    const attachmentInput = document.getElementById("messageAttachmentInput");
    const attachmentButton = document.getElementById("messageAttachmentButton");
    const attachmentClear = document.getElementById("attachmentChipClear");

    if (attachmentButton && attachmentInput) {
        attachmentButton.addEventListener("click", () => {
            attachmentInput.click();
        });
        attachmentInput.addEventListener("change", () => {
            updateAttachmentComposerState(attachmentInput.files?.[0] || null);
            setAttachmentFeedback("");
        });
    }

    if (attachmentClear && attachmentInput) {
        attachmentClear.addEventListener("click", () => {
            attachmentInput.value = "";
            updateAttachmentComposerState(null);
            setAttachmentFeedback("");
        });
    }

    bindDeletionControls();

    cryptoBootstrapPromise = (async () => {
        logChatState("crypto bootstrap started");
        await initKeysIfNeeded();
        myIdentityPrivateKeyCache = await getIdentityPrivateKeyUint8();
        myIdentityKeyCache = await getIdentityKey();
        myIdentitySigningKeyCache = await getIdentitySigningKey();
        myCurrentDeviceId = readCurrentDeviceId();
        await loadOwnDeviceBundles();
        updateChatReadiness();
        logChatState("crypto bootstrap finished");

        if (currentChatId && !window.otherIdentityKey) {
            scheduleChatKeyRefresh(currentChatId);
        }

        if (window.otherIdentityKey || window.otherIdentitySigningKey) {
            await refreshSafetyNumber();
        }
    })().catch((error) => {
        console.error("Crypto bootstrap failed:", error, buildReadinessSnapshot());
        throw error;
    });

    const params = new URLSearchParams(window.location.search);
    const chatId = params.get("chat_id");
    currentChatId = chatId;

    if (chatId) {
        await cryptoBootstrapPromise;
        await initializeChat(chatId);
    }
});

async function initializeChat(chatId) {
    await initializeChatFlow({
        chatId,
        setCurrentChatId: (value) => {
            currentChatId = value;
        },
        authFetch,
        logChatState,
        applyChatKeys,
        openChatSocket,
        scheduleChatKeyRefresh
    });
}

async function loadOwnDeviceBundles() {
    const response = await authFetch("/users/me/device-bundles");
    const payload = await response.json();
    if (response.ok && payload?.status === "ok" && Array.isArray(payload.devices)) {
        myDeviceBundlesCache = payload.devices;
        return true;
    }

    myDeviceBundlesCache = [];
    return false;
}

async function applyChatKeys(identityKey, identitySigningKey, prekeyBundle = null, username = "", avatarData = null, deviceBundles = []) {
    await applyChatKeysFlow({
        identityKey,
        identitySigningKey,
        prekeyBundle,
        deviceBundles,
        username,
        avatarData,
        setChatKind: (isGroup) => {
            currentChatIsGroup = Boolean(isGroup);
        },
        setOtherKeys: ({ identityKey: nextIdentityKey, identitySigningKey: nextIdentitySigningKey, prekeyBundle: nextPrekeyBundle, deviceBundles: nextDeviceBundles }) => {
            window.otherIdentityKey = nextIdentityKey;
            window.otherIdentitySigningKey = nextIdentitySigningKey;
            window.otherPrekeyBundle = nextPrekeyBundle;
            window.otherDeviceBundles = nextDeviceBundles;
        },
        logChatState,
        setChatUserName: (nextUsername) => {
            const chatUserNameEl = document.getElementById("chatUserName");
            if (chatUserNameEl && nextUsername) {
                chatUserNameEl.textContent = nextUsername;
            }
        },
        updateChatHeaderAvatar,
        refreshSafetyNumber,
        updateChatReadiness
    });
    applyChatMetaPayload(avatarData);
}

async function refreshChatKeys(chatId) {
    return refreshChatKeysFlow({
        chatId,
        authFetch,
        logChatState,
        applyChatKeys
    });
}

function clearChatKeyRefreshTimer() {
    if (!chatKeysRetryTimer) {
        return;
    }

    window.clearTimeout(chatKeysRetryTimer);
    chatKeysRetryTimer = null;
}

function scheduleChatKeyRefresh(chatId, attempt = 0) {
    clearChatKeyRefreshTimer();

    if (!chatId || window.otherIdentityKey || attempt >= 20) {
        if (attempt >= 20) {
            logChatState("chat key refresh stopped after max attempts", { attempt }, "warn");
        }
        return;
    }

    chatKeysRetryTimer = window.setTimeout(async () => {
        if (!myIdentityPrivateKeyCache || !myIdentityKeyCache) {
            logChatState("chat key refresh postponed: local keys are not ready", { attempt: attempt + 1 }, "warn");
            scheduleChatKeyRefresh(chatId, attempt + 1);
            return;
        }

        try {
            logChatState("chat key refresh attempt", { attempt: attempt + 1 });
            const refreshed = await refreshChatKeys(chatId);
            if (!refreshed) {
                scheduleChatKeyRefresh(chatId, attempt + 1);
            }
        } catch (error) {
            console.warn("Chat key refresh failed:", error);
            scheduleChatKeyRefresh(chatId, attempt + 1);
        }
    }, 1500);
}

async function refreshSafetyNumber() {
    if (currentChatIsGroup) {
        const fingerprintEl = document.getElementById("fingerprint");
        const statusEl = document.getElementById("verificationStatus");
        if (fingerprintEl) {
            fingerprintEl.textContent = "Group chat";
        }
        if (statusEl) {
            statusEl.textContent = "Group";
            statusEl.classList.remove("verified", "unverified");
        }
        return;
    }

    await refreshSafetyNumberFlow({
        otherIdentitySigningKey: window.otherIdentitySigningKey,
        myIdentitySigningKey: myIdentitySigningKeyCache,
        deriveSafetyNumber,
        setCurrentFingerprint: (fp) => {
            currentFingerprint = fp;
        },
        updateVerificationUi,
        logChatState
    });
}

async function openChatSocket(chatId) {
    currentChatId = String(chatId);
    keysReady = false;
    chatSocketOpened = false;
    clearChatKeyRefreshTimer();
    pendingMessages = [];
    historySyncInProgress = true;
    deferredLiveMessages = [];
    historyController.reset();
    resetRenderedMessages();
    clearDecryptedAttachmentCache();
    if (typeof window.clearActiveReplyTarget === "function") {
        window.clearActiveReplyTarget();
    }

    await clearLocalChatState(chatId);
    logChatState("cleared local chat state before websocket history sync", { chatId });

    const chat = document.getElementById("chat");
    if (chat) {
        chat.innerHTML = "";
    }

    if (window.chatSocket) {
        try {
            window.chatSocket.close();
        } catch {}
    }

    const chatSocket = createChatSocket({
        chatId,
        debug: DEBUG_CHAT,
        onOpen: () => {
            chatSocketOpened = true;
            updateChatReadiness();
            logChatState("chat websocket opened");
        },
        onStatus: (data) => {
            setUserStatus(data.is_online);
        },
        onHistoryComplete: () => {
            historySyncInProgress = false;
            updateChatReadiness();

            const queuedLiveMessages = sortQueuedMessages(deferredLiveMessages);
            deferredLiveMessages = [];
            queuedLiveMessages.forEach(historyController.queueMessageProcessing);
        },
        onChatDeleted: async (data) => {
            await handleChatDeletedEvent(data);
        },
        onChatUpdated: async (data) => {
            if (data?.type === "chat_participants_updated" && data?.chat_id) {
                await clearGroupSenderStatesForChat(data.chat_id);
            }
            applyChatMetaPayload(data);
            await loadChats();
        },
        onMessage: (data) => {
            if (data.type === "message_status") {
                updateMessageStatus(data.message_id, data.delivery_status, data.read_at || null);
                return;
            }

            if (data.type === "message_deleted") {
                handleMessageDeletedEvent(data);
                return;
            }

            if (!keysReady) {
                if (!data.historical) {
                    logChatState("live message queued while keys are not ready", {
                        messageId: data.message_id || null,
                        historical: false
                    }, "warn");
                }
                pendingMessages.push(data);
                return;
            }

            if (historySyncInProgress && !data.historical) {
                deferredLiveMessages.push(data);
                return;
            }

            historyController.queueMessageProcessing(data);
        }
    });

    window.chatSocket = chatSocket;
}

function updateChatReadiness() {
    const cryptoReady = Boolean(
        chatSocketOpened &&
        myIdentityPrivateKeyCache &&
        myIdentityKeyCache &&
        !historySyncInProgress
    );
    keysReady = cryptoReady;
    logChatState("chat readiness updated");

    if (!keysReady || pendingMessages.length === 0) {
        return;
    }

    const queuedMessages = sortQueuedMessages(pendingMessages);
    pendingMessages = [];
    queuedMessages.forEach(historyController.queueMessageProcessing);
}

let userSocket = null;
const messageSound = new Audio("/static/sounds/new_message.mp3");

function connectUserSocket() {
    userSocket = createUserSocket({
        debug: DEBUG_CHAT,
        onNewChat: async () => {
            await loadChats();
        },
        onNewMessage: async (data) => {
            const updatedChatId = data.chat_id;
            if (!window.location.search.includes("chat_id=" + updatedChatId)) {
                markChatAsUpdated(updatedChatId);
                void messageSound.play();
            }
        },
        onMessageStatus: async (data) => {
            updateMessageStatus(data.message_id, data.delivery_status);
        },
        onChatDeleted: async (data) => {
            await handleChatDeletedEvent(data);
        },
        onChatUpdated: async (data) => {
            await loadChats();
            if (String(data.chat_id) === String(currentChatId)) {
                if (data?.type === "chat_participants_updated") {
                    await clearGroupSenderStatesForChat(currentChatId);
                }
                applyChatMetaPayload(data);
            }
        }
    });
}

function bindDeletionControls() {
    const chat = document.getElementById("chat");
    const contextMenu = document.getElementById("messageContextMenu");
    const replyBtn = document.getElementById("messageContextReply");
    const deleteForMeBtn = document.getElementById("messageContextDeleteForMe");
    const deleteForAllBtn = document.getElementById("messageContextDeleteForAll");
    const replyBanner = document.getElementById("replyComposer");
    const replySender = document.getElementById("replyComposerSender");
    const replyPreview = document.getElementById("replyComposerPreview");
    const replyCloseBtn = document.getElementById("replyComposerClose");

    const clearReplyTarget = () => {
        activeReplyTarget = null;
        if (replyBanner) {
            replyBanner.hidden = true;
        }
        if (replySender) {
            replySender.textContent = "";
        }
        if (replyPreview) {
            replyPreview.textContent = "";
        }
    };

    const setReplyTarget = (row) => {
        const messageId = Number(row?.dataset?.messageId || "0");
        if (messageId <= 0) {
            clearReplyTarget();
            return;
        }

        activeReplyTarget = {
            messageId,
            senderLabel: row.dataset.senderLabel || "Reply",
            previewText: row.dataset.messagePreview || "Original message"
        };

        if (replySender) {
            replySender.textContent = activeReplyTarget.senderLabel;
        }
        if (replyPreview) {
            replyPreview.textContent = activeReplyTarget.previewText;
        }
        if (replyBanner) {
            replyBanner.hidden = false;
        }
    };

    const closeMessageContextMenu = () => {
        activeMessageContext = null;
        if (!contextMenu) {
            return;
        }
        contextMenu.hidden = true;
        contextMenu.style.left = "";
        contextMenu.style.top = "";
    };

    const openMessageContextMenu = (event, row) => {
        if (!contextMenu) {
            return;
        }

        const messageId = Number(row?.dataset?.messageId || "0");
        if (messageId <= 0) {
            return;
        }

        const isOwnMessage = row.dataset.ownMessage === "1";
        activeMessageContext = {
            messageId,
            isOwnMessage,
            row
        };

        if (deleteForAllBtn) {
            deleteForAllBtn.hidden = !isOwnMessage;
        }

        contextMenu.hidden = false;

        const menuWidth = 220;
        const menuHeight = isOwnMessage ? 160 : 112;
        const maxLeft = Math.max(12, window.innerWidth - menuWidth - 12);
        const maxTop = Math.max(12, window.innerHeight - menuHeight - 12);
        const left = Math.min(event.clientX, maxLeft);
        const top = Math.min(event.clientY, maxTop);

        contextMenu.style.left = `${left}px`;
        contextMenu.style.top = `${top}px`;
    };

    if (chat) {
        chat.addEventListener("contextmenu", (event) => {
            const row = event.target.closest(".chat-message[data-message-id]");
            if (!row) {
                closeMessageContextMenu();
                return;
            }

            event.preventDefault();
            openMessageContextMenu(event, row);
        });
    }

    if (deleteForMeBtn) {
        deleteForMeBtn.addEventListener("click", async () => {
            const messageId = activeMessageContext?.messageId || 0;
            closeMessageContextMenu();
            if (messageId > 0) {
                await deleteMessageForSelf(messageId);
            }
        });
    }

    if (replyBtn) {
        replyBtn.addEventListener("click", () => {
            const row = activeMessageContext?.row || null;
            closeMessageContextMenu();
            if (!row) {
                return;
            }
            setReplyTarget(row);
            document.getElementById("messageInput")?.focus();
        });
    }

    if (deleteForAllBtn) {
        deleteForAllBtn.addEventListener("click", async () => {
            const messageId = activeMessageContext?.messageId || 0;
            const isOwnMessage = Boolean(activeMessageContext?.isOwnMessage);
            closeMessageContextMenu();
            if (messageId > 0 && isOwnMessage) {
                await deleteMessageForAll(messageId);
            }
        });
    }

    document.addEventListener("click", (event) => {
        if (!contextMenu || contextMenu.hidden) {
            return;
        }
        if (event.target.closest("#messageContextMenu")) {
            return;
        }
        closeMessageContextMenu();
    });

    document.addEventListener("scroll", () => {
        closeMessageContextMenu();
    }, true);

    window.addEventListener("resize", () => {
        closeMessageContextMenu();
    });

    window.addEventListener("keydown", (event) => {
        if (event.key === "Escape") {
            closeMessageContextMenu();
        }
    });

    if (replyCloseBtn) {
        replyCloseBtn.addEventListener("click", () => {
            clearReplyTarget();
        });
    }

    window.getActiveReplyTargetId = () => activeReplyTarget?.messageId || null;
    window.clearActiveReplyTarget = clearReplyTarget;

    const deleteChatForMeBtn = document.getElementById("deleteChatForMeBtn");
    if (deleteChatForMeBtn) {
        deleteChatForMeBtn.onclick = async () => {
            await deleteCurrentChat(false);
        };
    }

    const deleteChatForAllBtn = document.getElementById("deleteChatForAllBtn");
    if (deleteChatForAllBtn) {
        deleteChatForAllBtn.onclick = async () => {
            await deleteCurrentChat(true);
        };
    }
}

async function deleteMessageForSelf(messageId) {
    const confirmed = window.confirm("Delete this message only for your account on all your devices?");
    if (!confirmed) {
        return;
    }

    const response = await authFetch(`/messages/${messageId}/delete-self`, {
        method: "POST"
    });
    const payload = await response.json();
    if (!response.ok || payload?.status !== "ok") {
        alert(payload?.detail || payload?.message || "Failed to delete the message for you.");
        return;
    }

    await markMessageDeletedForSelf(currentChatId, messageId);
    removeRenderedMessage(messageId);
}

async function deleteMessageForAll(messageId) {
    const confirmed = window.confirm("Delete this message for everyone on all devices?");
    if (!confirmed) {
        return;
    }

    const response = await authFetch(`/messages/${messageId}/delete-all`, {
        method: "POST"
    });
    const payload = await response.json();
    if (!response.ok || payload?.status !== "ok") {
        alert(payload?.detail || payload?.message || "Failed to delete the message for everyone.");
        return;
    }

    await clearMessageDeletedForSelf(currentChatId, messageId);
    removeRenderedMessage(messageId);
}

async function deleteCurrentChat(deleteForAll) {
    if (!currentChatId) {
        return;
    }

    const confirmed = window.confirm(
        deleteForAll
            ? "Delete this chat for everyone on all devices?"
            : "Delete this chat only for your account on all your devices?"
    );
    if (!confirmed) {
        return;
    }

    const endpoint = deleteForAll
        ? `/chats/${currentChatId}/delete-all`
        : `/chats/${currentChatId}/delete-self`;
    const response = await authFetch(endpoint, {
        method: "POST"
    });
    const payload = await response.json();
    if (!response.ok || payload?.status !== "ok") {
        alert(payload?.detail || payload?.message || "Failed to delete the chat.");
        return;
    }

    await handleChatDeletedEvent({
        type: "chat_deleted",
        chat_id: Number(currentChatId),
        delete_for_all: deleteForAll
    });
}

function handleMessageDeletedEvent(data) {
    if (!data?.message_id) {
        return;
    }

    if (data.delete_for_all) {
        void clearMessageDeletedForSelf(currentChatId, data.message_id);
        removeRenderedMessage(data.message_id);
        return;
    }

    void markMessageDeletedForSelf(currentChatId, data.message_id);
    removeRenderedMessage(data.message_id);
}

async function handleChatDeletedEvent(data) {
    if (!data?.chat_id) {
        return;
    }

    await clearLocalChatState(data.chat_id);

    await loadChats();

    if (String(data.chat_id) === String(currentChatId)) {
        window.location.href = "/messages";
    }
}

async function loadChats() {
    const sessionOk = await ensureSession();
    if (!sessionOk) {
        return;
    }

    await reloadChatList(authFetch);
    if (currentChatId) {
        await refreshCurrentChatDetails();
    }
}

function getCurrentChatId() {
    return currentChatId;
}

function readCurrentDeviceId() {
    try {
        return window.sessionStorage.getItem("e2ee_device_id") || null;
    } catch {
        return null;
    }
}

async function updateVerificationUi(fp, verificationKey, myIdentitySigningKey) {
    return updateVerificationUiFlow({
        fingerprint: fp,
        verificationKey,
        myIdentitySigningKey,
        getVerificationStatus,
        saveVerificationStatus,
        resetLocalCryptoState
    });

    const statusEl = document.getElementById("verificationStatus");
    const verifyBtn = document.getElementById("verifyFingerprintBtn");
    const resetBtn = document.getElementById("resetFingerprintBtn");
    const copyBtn = document.getElementById("copyFingerprintBtn");
    const qrCanvas = document.getElementById("fingerprintQr");

    if (!statusEl || !verifyBtn || !resetBtn || !copyBtn || !qrCanvas) {
        return;
    }

    const isVerified = await getVerificationStatus(fp);
    statusEl.textContent = isVerified ? "Verified" : "Not verified";
    statusEl.classList.toggle("verified", isVerified);
    statusEl.classList.toggle("unverified", !isVerified);

    verifyBtn.onclick = async function () {
        await saveVerificationStatus(fp, true);
        await updateVerificationUi(fp, verificationKey, myIdentityKey);
    };

    resetBtn.onclick = async function () {
        await saveVerificationStatus(fp, false);
        await updateVerificationUi(fp, verificationKey, myIdentityKey);
    };

    copyBtn.onclick = async function () {
        try {
            await navigator.clipboard.writeText(fp);
            alert("Fingerprint copied");
        } catch {
            alert(fp);
        }
    };

    const resetDbBtn = document.getElementById("resetIndexedDbBtn");
    if (!resetDbBtn) {
        return;
    }
    resetDbBtn.onclick = async function () {
        const confirmed = window.confirm("Скинути весь локальний crypto-state та IndexedDB для цього чату?");
        if (!confirmed) return;

        await resetLocalCryptoState();
        window.location.reload();
    };

    const qrPayload = JSON.stringify({
        type: "chat-safety-number",
        safety_number: fp,
        my_identity_key: myIdentityKey,
        identity_key: verificationKey
    });

    await QRCode.toCanvas(qrCanvas, qrPayload, {
        width: 128,
        margin: 1,
        color: {
            dark: "#0f172a",
            light: "#f8fafc"
        }
    });
}
