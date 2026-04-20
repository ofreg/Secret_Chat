export async function sendCurrentMessage({
    awaitCryptoBootstrap,
    getCurrentChatId,
    getInput,
    getChatSocket,
    getMyPublicKey,
    getMyPrivateKey,
    getOtherPublicKey,
    getOtherPrekeyBundle,
    refreshChatKeys,
    isKeysReady,
    logChatState,
    getRatchetState,
    deleteRatchetState,
    encryptMessage
}) {
    await awaitCryptoBootstrap?.();

    const chatId = getCurrentChatId();
    const input = getInput();
    const chatSocket = getChatSocket();
    const myPublicKey = getMyPublicKey();
    const myPrivateKey = getMyPrivateKey();
    const otherPublicKey = getOtherPublicKey();
    const otherPrekeyBundle = getOtherPrekeyBundle();

    if (!input || !chatSocket || !myPublicKey) {
        logChatState("send blocked: base prerequisites missing", {
            hasInput: Boolean(input)
        }, "warn");
        return;
    }

    if (!otherPublicKey) {
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
        getOtherPrekeyBundle()?.signed_prekey
    ) {
        logChatState("resetting stale unused initiator ratchet state before first send", {
            hasExistingRatchetState: true,
            hasRemoteDh: Boolean(activeRatchetState?.DHr),
            sentCount: Number(activeRatchetState?.Ns || 0),
            hasSignedPrekey: Boolean(getOtherPrekeyBundle()?.signed_prekey)
        }, "warn");
        await deleteRatchetState(chatId);
    }

    const currentRatchetState = await getRatchetState(chatId);
    const hasBootstrapBundle = Boolean(getOtherPublicKey() && getOtherPrekeyBundle()?.signed_prekey);
    if (!currentRatchetState && !hasBootstrapBundle) {
        await refreshChatKeys(chatId);
        if (!(getOtherPublicKey() && getOtherPrekeyBundle()?.signed_prekey)) {
            logChatState("send blocked: missing X3DH bootstrap bundle for first message", {
                hasSignedPrekey: Boolean(getOtherPrekeyBundle()?.signed_prekey),
                hasOneTimePrekey: Boolean(getOtherPrekeyBundle()?.one_time_prekey?.public_key)
            }, "warn");
            return;
        }
    }

    if (!isKeysReady()) {
        logChatState("send blocked: chat crypto is not ready yet", null, "warn");
        return;
    }

    try {
        const messageText = input.value.trim();
        if (!messageText) return;

        const payload = await encryptMessage({
            chatId,
            message: messageText,
            recipientPublicBase64: getOtherPublicKey(),
            recipientPrekeyBundle: getOtherPrekeyBundle(),
            senderPublicBase64: myPublicKey,
            myPrivateKeyUint8: myPrivateKey
        });

        chatSocket.send(JSON.stringify(payload));
        input.value = "";
    } catch (err) {
        console.error("Encryption error:", err);
    }
}

export async function initializeChatFlow({
    chatId,
    setCurrentChatId,
    authFetch,
    logChatState,
    applyChatKeys,
    openChatSocket,
    scheduleChatKeyRefresh
}) {
    setCurrentChatId(String(chatId));
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

export async function applyChatKeysFlow({
    publicKey,
    identityKey,
    prekeyBundle = null,
    username = "",
    avatarData = null,
    setOtherKeys,
    logChatState,
    setChatUserName,
    updateChatHeaderAvatar,
    refreshSafetyNumber,
    updateChatReadiness
}) {
    setOtherKeys({
        publicKey: publicKey || null,
        identityKey: identityKey || null,
        prekeyBundle: prekeyBundle || null
    });

    logChatState("applied chat keys", {
        username,
        appliedHasPublicKey: Boolean(publicKey),
        appliedHasIdentityKey: Boolean(identityKey),
        appliedHasPrekeyBundle: Boolean(prekeyBundle)
    });

    setChatUserName?.(username);
    updateChatHeaderAvatar(avatarData);
    await refreshSafetyNumber();
    updateChatReadiness();
}

export async function refreshChatKeysFlow({
    chatId,
    authFetch,
    logChatState,
    applyChatKeys
}) {
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

export async function refreshSafetyNumberFlow({
    otherIdentityKey,
    otherPublicKey,
    myIdentityKey,
    deriveSafetyNumber,
    setCurrentFingerprint,
    updateVerificationUi,
    logChatState
}) {
    const verificationKey = otherIdentityKey || otherPublicKey;
    if (!verificationKey || !myIdentityKey) {
        logChatState("safety number skipped: missing key material", {
            hasVerificationKey: Boolean(verificationKey),
            hasMyIdentityKey: Boolean(myIdentityKey)
        }, "warn");
        return;
    }

    const fp = await deriveSafetyNumber(myIdentityKey, verificationKey);
    setCurrentFingerprint(fp);
    const el = document.getElementById("fingerprint");
    if (el) el.innerText = fp;
    await updateVerificationUi(fp, verificationKey, myIdentityKey);
}
