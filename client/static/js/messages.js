import {
    deleteRatchetState,
    deriveSafetyNumber,
    getPrivateKeyUint8,
    getPublicKey,
    getRatchetState,
    getVerificationStatus,
    initKeysIfNeeded,
    resetLocalCryptoState,
    saveVerificationStatus
} from "./crypto.js?v=20260420i";
import { authFetch, ensureSession } from "./authClient.js?v=20260420i";
import { encryptMessage } from "./chatCrypto.js?v=20260420i";
import {
    bindChatHeaderControls,
    getSenderLabel,
    markChatAsUpdated,
    renderMessage,
    resetRenderedMessages,
    setUserStatus,
    updateMessageStatus,
    updateChatHeaderAvatar
} from "./messagesUi.js?v=20260430a";
import {
    createChatSocket,
    createUserSocket,
    reloadChatList
} from "./messagesSockets.js?v=20260420i";
import { createHistoryController } from "./messagesHistory.js?v=20260420i";
import {
    applyChatKeysFlow,
    initializeChatFlow,
    refreshChatKeysFlow,
    refreshSafetyNumberFlow,
    sendCurrentMessage
} from "./messagesChatFlow.js?v=20260420i";
import { updateVerificationUiFlow } from "./messagesVerification.js?v=20260420i";

const DEBUG_CHAT = false;
let keysReady = false;
let pendingMessages = [];
let myPrivateKeyCache = null;
let myPublicKeyCache = null;
let myUsername = null;
let currentChatId = null;
let historySyncInProgress = false;
let deferredLiveMessages = [];
let currentFingerprint = null;
let cryptoBootstrapPromise = null;
let chatSocketOpened = false;
let chatKeysRetryTimer = null;
const historyController = createHistoryController({
    getMyUsername: () => myUsername,
    getCurrentChatId: () => currentChatId,
    getMyPrivateKey: () => myPrivateKeyCache,
    getMyPublicKey: () => myPublicKeyCache,
    getOtherPublicKey: () => window.otherPublicKey,
    renderChatMessage: renderMessage,
    getSenderLabel: (senderName) => getSenderLabel(senderName, myUsername),
    logChatState
});

function buildReadinessSnapshot() {
    return {
        currentChatId,
        chatSocketOpened,
        hasChatSocket: Boolean(window.chatSocket),
        hasMyPrivateKey: Boolean(myPrivateKeyCache),
        hasMyPublicKey: Boolean(myPublicKeyCache),
        hasOtherPublicKey: Boolean(window.otherPublicKey),
        hasOtherIdentityKey: Boolean(window.otherIdentityKey),
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

window.sendMessage = async function () {
    await sendCurrentMessage({
        awaitCryptoBootstrap: async () => {
            if (cryptoBootstrapPromise) {
                await cryptoBootstrapPromise;
            }
        },
        getCurrentChatId,
        getInput: () => document.getElementById("messageInput"),
        getChatSocket: () => window.chatSocket,
        getMyPublicKey: () => myPublicKeyCache,
        getMyPrivateKey: () => myPrivateKeyCache,
        getOtherPublicKey: () => window.otherPublicKey,
        getOtherPrekeyBundle: () => window.otherPrekeyBundle,
        refreshChatKeys,
        isKeysReady: () => keysReady,
        logChatState,
        getRatchetState,
        deleteRatchetState,
        encryptMessage
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
        logChatState("account binding skipped on messages page");
    }

    bindChatHeaderControls();
    connectUserSocket();

    cryptoBootstrapPromise = (async () => {
        logChatState("crypto bootstrap started");
        await initKeysIfNeeded();
        myPrivateKeyCache = await getPrivateKeyUint8();
        myPublicKeyCache = await getPublicKey();
        updateChatReadiness();
        logChatState("crypto bootstrap finished");

        if (currentChatId && !window.otherPublicKey) {
            scheduleChatKeyRefresh(currentChatId);
        }

        if (window.otherPublicKey || window.otherIdentityKey) {
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

async function applyChatKeys(publicKey, identityKey, prekeyBundle = null, username = "", avatarData = null) {
    await applyChatKeysFlow({
        publicKey,
        identityKey,
        prekeyBundle,
        username,
        avatarData,
        setOtherKeys: ({ publicKey: nextPublicKey, identityKey: nextIdentityKey, prekeyBundle: nextPrekeyBundle }) => {
            window.otherPublicKey = nextPublicKey;
            window.otherIdentityKey = nextIdentityKey;
            window.otherPrekeyBundle = nextPrekeyBundle;
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

    if (!chatId || window.otherPublicKey || attempt >= 20) {
        if (attempt >= 20) {
            logChatState("chat key refresh stopped after max attempts", { attempt }, "warn");
        }
        return;
    }

    chatKeysRetryTimer = window.setTimeout(async () => {
        if (!myPrivateKeyCache || !myPublicKeyCache) {
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
        otherIdentityKey: window.otherIdentityKey,
        otherPublicKey: window.otherPublicKey,
        myIdentityKey: myPublicKeyCache,
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
        myPrivateKeyCache &&
        myPublicKeyCache &&
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

async function updateVerificationUi(fp, verificationKey, myIdentityKey) {
    return updateVerificationUiFlow({
        fingerprint: fp,
        verificationKey,
        myIdentityKey,
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
