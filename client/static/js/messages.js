import {
    ensureLocalAccountBinding,
    deleteRatchetState,
    deriveSafetyNumber,
    getIdentityKey,
    getIdentityPrivateKeyUint8,
    getIdentitySigningKey,
    saveAttachmentHistory,
    getRatchetState,
    getVerificationStatus,
    initKeysIfNeeded,
    restoreCloudBackupIfNeeded,
    resetLocalCryptoState,
    saveVerificationStatus
} from "./crypto.js?v=20260602a";
import { authFetch, ensureSession } from "./authClient.js?v=20260601b";
import {
    decryptAttachmentData,
    encryptAttachmentData,
    encryptMessage,
    encryptMessageForDevices
} from "./chatCrypto.js?v=20260602b";
import {
    bindMediaViewerControls,
    bindAttachmentAlertControls,
    bindChatHeaderControls,
    getSenderLabel,
    markChatAsUpdated,
    renderMessage,
    resetRenderedMessages,
    setAttachmentFeedback,
    setUserStatus,
    updateAttachmentComposerState,
    updateMessageStatus,
    updateChatHeaderAvatar
} from "./messagesUi.js?v=20260430c";
import {
    createChatSocket,
    createUserSocket,
    reloadChatList
} from "./messagesSockets.js?v=20260601b";
import { createHistoryController } from "./messagesHistory.js?v=20260602b";
import {
    applyChatKeysFlow,
    initializeChatFlow,
    refreshChatKeysFlow,
    refreshSafetyNumberFlow,
    sendCurrentMessage
} from "./messagesChatFlow.js?v=20260601a";
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
let historySyncInProgress = false;
let deferredLiveMessages = [];
let currentFingerprint = null;
let cryptoBootstrapPromise = null;
let chatSocketOpened = false;
let chatKeysRetryTimer = null;
const decryptedAttachmentCache = new Map();
const historyController = createHistoryController({
    getMyUsername: () => myUsername,
    getCurrentChatId: () => currentChatId,
    getMyPrivateKey: () => myIdentityPrivateKeyCache,
    getMyIdentityKey: () => myIdentityKeyCache,
    getOtherIdentityKey: () => window.otherIdentityKey,
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
            isOwnMessage
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
        refreshChatKeys,
        isKeysReady: () => keysReady,
        logChatState,
        getRatchetState,
        deleteRatchetState,
        encryptMessage,
        encryptMessageForDevices,
        encryptAttachmentData,
        saveAttachmentHistory,
        authFetch,
        onAttachmentSent: () => updateAttachmentComposerState(null),
        setAttachmentFeedback
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

    await deleteRatchetState(chatId);
    logChatState("cleared local ratchet state before websocket history sync", { chatId });

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
        onMessage: (data) => {
            if (data.type === "message_status") {
                updateMessageStatus(data.message_id, data.delivery_status);
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
        }
    });
}

async function loadChats() {
    const sessionOk = await ensureSession();
    if (!sessionOk) {
        return;
    }

    await reloadChatList(authFetch);
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
