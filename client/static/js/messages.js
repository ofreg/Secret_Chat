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
} from "./crypto.js?v=20260419a";
import { authFetch, ensureSession } from "./authClient.js?v=20260416w";
import { encryptMessage } from "./chatCrypto.js?v=20260419a";
import {
    bindChatHeaderControls,
    getSenderLabel,
    markChatAsUpdated,
    renderMessage,
    setUserStatus,
    updateChatHeaderAvatar
} from "./messagesUi.js?v=20260419a";
import {
    createChatSocket,
    createUserSocket,
    reloadChatList
} from "./messagesSockets.js?v=20260420b";
import { createHistoryController } from "./messagesHistory.js?v=20260420c";
import QRCode from "https://cdn.jsdelivr.net/npm/qrcode@1.5.4/+esm";

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

window.sendMessage = async function () {
    if (cryptoBootstrapPromise) {
        await cryptoBootstrapPromise;
    }

    const chatId = getCurrentChatId();
    const input = document.getElementById("messageInput");
    if (!input || !window.chatSocket || !myPublicKeyCache) {
        logChatState("send blocked: base prerequisites missing", {
            hasInput: Boolean(input)
        }, "warn");
        return;
    }

    if (!window.otherPublicKey) {
        const refreshed = await refreshChatKeys(chatId);
        if (!refreshed) {
            logChatState("send blocked: recipient keys are not available yet", null, "warn");
            return;
        }
    }

    const activeRatchetState = await getRatchetState(chatId);
    if (
        activeRatchetState &&
        activeRatchetState.DHr === null &&
        Number(activeRatchetState.Ns || 0) === 0 &&
        window.otherPrekeyBundle?.signed_prekey
    ) {
        logChatState("resetting stale unused initiator ratchet state before first send", {
            hasExistingRatchetState: true,
            hasRemoteDh: Boolean(activeRatchetState?.DHr),
            sentCount: Number(activeRatchetState?.Ns || 0),
            hasSignedPrekey: Boolean(window.otherPrekeyBundle?.signed_prekey)
        }, "warn");
        await deleteRatchetState(chatId);
    }

    const currentRatchetState = await getRatchetState(chatId);
    const hasBootstrapBundle = Boolean(window.otherPublicKey && window.otherPrekeyBundle?.signed_prekey);
    if (!currentRatchetState && !hasBootstrapBundle) {
        await refreshChatKeys(chatId);
        if (!(window.otherPublicKey && window.otherPrekeyBundle?.signed_prekey)) {
            logChatState("send blocked: missing X3DH bootstrap bundle for first message", {
                hasSignedPrekey: Boolean(window.otherPrekeyBundle?.signed_prekey),
                hasOneTimePrekey: Boolean(window.otherPrekeyBundle?.one_time_prekey?.public_key)
            }, "warn");
            return;
        }
    }

    if (!keysReady) {
        logChatState("send blocked: chat crypto is not ready yet", null, "warn");
        return;
    }

    try {
        const messageText = input.value.trim();
        if (!messageText) return;

        const payload = await encryptMessage({
            chatId,
            message: messageText,
            recipientPublicBase64: window.otherPublicKey,
            recipientPrekeyBundle: window.otherPrekeyBundle,
            senderPublicBase64: myPublicKeyCache,
            myPrivateKeyUint8: myPrivateKeyCache
        });

        window.chatSocket.send(JSON.stringify(payload));
        input.value = "";
    } catch (err) {
        console.error("Encryption error:", err);
    }
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
    currentChatId = String(chatId);
    const res = await authFetch(`/messages/get_keys?chat_id=${chatId}`);
    const data = await res.json();
    logChatState("initial chat keys response", {
        responseStatus: data.status,
        responseHasPublicKey: Boolean(data.public_key),
        responseHasIdentityKey: Boolean(data.identity_key),
        responseHasPrekeyBundle: Boolean(data.prekey_bundle)
    });

    if (data.status !== "ok") {
        return;
    }

    await applyChatKeys(data.public_key, data.identity_key, data.prekey_bundle, data.username, data);
    openChatSocket(chatId);
    scheduleChatKeyRefresh(chatId);
}

async function applyChatKeys(publicKey, identityKey, prekeyBundle = null, username = "", avatarData = null) {
    window.otherPublicKey = publicKey || null;
    window.otherIdentityKey = identityKey || null;
    window.otherPrekeyBundle = prekeyBundle || null;
    logChatState("applied chat keys", {
        username,
        appliedHasPublicKey: Boolean(window.otherPublicKey),
        appliedHasIdentityKey: Boolean(window.otherIdentityKey),
        appliedHasPrekeyBundle: Boolean(window.otherPrekeyBundle)
    });

    const chatUserNameEl = document.getElementById("chatUserName");
    if (chatUserNameEl && username) {
        chatUserNameEl.textContent = username;
    }

    updateChatHeaderAvatar(avatarData);
    await refreshSafetyNumber();
    updateChatReadiness();
}

async function refreshChatKeys(chatId) {
    if (!chatId) {
        logChatState("refreshChatKeys skipped: missing chatId", null, "warn");
        return false;
    }

    const res = await authFetch(`/messages/get_keys?chat_id=${chatId}`);
    const data = await res.json();
    logChatState("refresh chat keys response", {
        responseStatus: data.status,
        responseHasPublicKey: Boolean(data.public_key),
        responseHasIdentityKey: Boolean(data.identity_key),
        responseHasPrekeyBundle: Boolean(data.prekey_bundle)
    });
    if (data.status !== "ok" || !data.public_key) {
        return false;
    }

    await applyChatKeys(data.public_key, data.identity_key, data.prekey_bundle, data.username, data);
    return true;
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
    const verificationKey = window.otherIdentityKey || window.otherPublicKey;
    const myIdentityKey = myPublicKeyCache;
    if (!verificationKey || !myIdentityKey) {
        logChatState("safety number skipped: missing key material", {
            hasVerificationKey: Boolean(verificationKey),
            hasMyIdentityKey: Boolean(myIdentityKey)
        }, "warn");
        return;
    }

    const fp = await deriveSafetyNumber(myIdentityKey, verificationKey);
    currentFingerprint = fp;
    const el = document.getElementById("fingerprint");
    if (el) el.innerText = fp;
    await updateVerificationUi(fp, verificationKey, myIdentityKey);
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

            const queuedLiveMessages = [...deferredLiveMessages];
            deferredLiveMessages = [];
            queuedLiveMessages.forEach(historyController.queueMessageProcessing);
        },
        onMessage: (data) => {
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

    const queuedMessages = [...pendingMessages];
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
    await reloadChatList(authFetch);
}

function getCurrentChatId() {
    return currentChatId;
}

async function updateVerificationUi(fp, verificationKey, myIdentityKey) {
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
