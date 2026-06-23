const MAX_ATTACHMENT_SIZE_BYTES = 50 * 1024 * 1024;
const ALLOWED_ATTACHMENT_EXTENSIONS = new Set([
    ".jpg", ".jpeg", ".png", ".webp", ".gif",
    ".mp4", ".webm", ".mov",
    ".mp3", ".wav", ".ogg", ".m4a"
]);

function getFileExtension(filename = "") {
    const dotIndex = filename.lastIndexOf(".");
    return dotIndex >= 0 ? filename.slice(dotIndex).toLowerCase() : "";
}

export async function sendCurrentMessage({
    awaitCryptoBootstrap,
    getCurrentChatId,
    getInput,
    getAttachmentInput,
    getChatSocket,
    getMyIdentityKey,
    getMyPrivateKey,
    getCurrentDeviceId,
    getOwnDeviceBundles,
    getOtherIdentityKey,
    getOtherPrekeyBundle,
    getOtherDeviceBundles,
    getCurrentChatIsGroup,
    getCurrentGroupKeyEpoch,
    refreshChatKeys,
    isKeysReady,
    logChatState,
    getRatchetState,
    deleteRatchetState,
    encryptMessage,
    encryptMessageForDevices,
    encryptGroupMessage,
    encryptAttachmentData,
    saveAttachmentHistory,
    authFetch,
    onAttachmentSent,
    setAttachmentFeedback,
    getReplyTargetId,
    clearReplyTarget
}) {
    await awaitCryptoBootstrap?.();

    const chatId = getCurrentChatId();
    const input = getInput();
    const attachmentInput = getAttachmentInput?.();
    const chatSocket = getChatSocket();
    const myIdentityKey = getMyIdentityKey();
    const myIdentityPrivateKey = getMyPrivateKey();
    const currentDeviceId = getCurrentDeviceId?.() || null;
    const ownDeviceBundles = getOwnDeviceBundles?.() || [];
    const otherIdentityKey = getOtherIdentityKey();
    const otherPrekeyBundle = getOtherPrekeyBundle();
    const otherDeviceBundles = getOtherDeviceBundles?.() || [];
    const isGroupChat = Boolean(getCurrentChatIsGroup?.());
    const groupKeyEpoch = Number(getCurrentGroupKeyEpoch?.() || 1);
    const replyToMessageId = getReplyTargetId?.() || null;

    if (!input || !chatSocket || !myIdentityKey) {
        logChatState("send blocked: base prerequisites missing", {
            hasInput: Boolean(input)
        }, "warn");
        return;
    }

    const selectedFile = attachmentInput?.files?.[0] || null;
    const messageText = input.value.trim();

    if (!messageText && !selectedFile) {
        return;
    }

    if (selectedFile) {
        if (!isGroupChat && !otherIdentityKey) {
            const refreshed = await refreshChatKeys(chatId);
            if (!refreshed || !getOtherIdentityKey()) {
                logChatState("media send blocked: recipient keys are not available yet", null, "warn");
                return;
            }
        }

        const extension = getFileExtension(selectedFile.name);
        if (!ALLOWED_ATTACHMENT_EXTENSIONS.has(extension)) {
            setAttachmentFeedback?.("Цей формат файлу не підтримується. Дозволені: JPG, PNG, WEBP, GIF, MP4, WEBM, MOV, MP3, WAV, OGG, M4A.", "error");
            return;
        }

        if (selectedFile.size > MAX_ATTACHMENT_SIZE_BYTES) {
            setAttachmentFeedback?.("Файл завеликий. Максимальний розмір: 50 MB.", "error");
            return;
        }

        try {
            setAttachmentFeedback?.("Encrypting media...", "success");
            const sourceBytes = await selectedFile.arrayBuffer();
            const attachmentKind = selectedFile.type.startsWith("image/")
                ? "image"
                : selectedFile.type.startsWith("video/")
                    ? "video"
                    : "audio";
            const encryptedAttachment = await encryptAttachmentData({
                bytes: sourceBytes,
                metadata: {
                    kind: attachmentKind,
                    name: selectedFile.name,
                    mime_type: selectedFile.type || "application/octet-stream",
                    size: selectedFile.size
                },
                recipientIdentityKeyBase64: getOtherIdentityKey() || myIdentityKey,
                senderIdentityKeyBase64: myIdentityKey,
                recipientDeviceBundles: getOtherDeviceBundles?.() || [],
                senderDeviceBundles: ownDeviceBundles,
                currentDeviceId,
                chatId,
                isGroupChat,
                groupKeyEpoch
            });

            setAttachmentFeedback?.("Uploading media...", "success");
            const formData = new FormData();
            formData.append("chat_id", String(chatId));
            formData.append("encrypted", "true");
            const encryptedFile = new File(
                [encryptedAttachment.encryptedBytes],
                "attachment.bin",
                { type: "application/octet-stream" }
            );
            formData.append("file", encryptedFile);

            const uploadResponse = await authFetch("/messages/upload", {
                method: "POST",
                body: formData
            });
            const uploadPayload = await uploadResponse.json();

            if (!uploadResponse.ok || uploadPayload?.status !== "ok" || !uploadPayload?.attachment) {
                console.error("Attachment upload failed:", uploadPayload);
                setAttachmentFeedback?.(uploadPayload?.detail || "Upload failed", "error");
                return;
            }

            let encryptedCaption = "";
            if (messageText) {
                if (isGroupChat) {
                    encryptedCaption = await encryptGroupMessage({
                        chatId,
                        message: messageText,
                        recipientDeviceBundles: otherDeviceBundles,
                        senderDeviceBundles: ownDeviceBundles,
                        currentDeviceId,
                        senderIdentityKeyBase64: myIdentityKey,
                        groupKeyEpoch
                    });
                } else if (otherDeviceBundles.length) {
                    encryptedCaption = await encryptMessageForDevices({
                        chatId,
                        message: messageText,
                        recipientDeviceBundles: otherDeviceBundles,
                        senderDeviceBundles: ownDeviceBundles,
                        currentDeviceId,
                        senderIdentityKeyBase64: myIdentityKey,
                        myPrivateKeyUint8: myIdentityPrivateKey
                    });
                } else {
                    encryptedCaption = await encryptMessage({
                        chatId,
                        message: messageText,
                        recipientIdentityKeyBase64: getOtherIdentityKey(),
                        recipientPrekeyBundle: getOtherPrekeyBundle(),
                        senderIdentityKeyBase64: myIdentityKey,
                        myPrivateKeyUint8: myIdentityPrivateKey
                    });
                }
            }

            chatSocket.send(JSON.stringify({
                type: "media_message",
                reply_to_message_id: replyToMessageId,
                attachment: {
                    kind: uploadPayload.attachment.kind,
                    url: uploadPayload.attachment.url,
                    name: uploadPayload.attachment.name,
                    mime_type: uploadPayload.attachment.mime_type,
                    size: uploadPayload.attachment.size,
                    meta: encryptedAttachment.meta
                },
                caption: encryptedCaption
            }));
            await saveAttachmentHistory?.(uploadPayload.attachment.url, encryptedAttachment.historySecret);
            input.value = "";
            if (attachmentInput) {
                attachmentInput.value = "";
            }
            onAttachmentSent?.();
            clearReplyTarget?.();
            setAttachmentFeedback?.("");
            return;
        } catch (err) {
            console.error("Attachment send error:", err);
            setAttachmentFeedback?.("Could not upload attachment", "error");
            return;
        }
    }

    if (!isGroupChat && !otherIdentityKey) {
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
    const hasBootstrapBundle = isGroupChat || Boolean(getOtherIdentityKey() && getOtherPrekeyBundle()?.signed_prekey);
    if (!currentRatchetState && !hasBootstrapBundle) {
        await refreshChatKeys(chatId);
        if (!isGroupChat && !(getOtherIdentityKey() && getOtherPrekeyBundle()?.signed_prekey)) {
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
        const payload = isGroupChat
            ? await encryptGroupMessage({
                chatId,
                message: messageText,
                recipientDeviceBundles: otherDeviceBundles,
                senderDeviceBundles: ownDeviceBundles,
                currentDeviceId,
                senderIdentityKeyBase64: myIdentityKey,
                groupKeyEpoch
            })
            : otherDeviceBundles.length
                ? await encryptMessageForDevices({
                chatId,
                message: messageText,
                recipientDeviceBundles: otherDeviceBundles,
                senderDeviceBundles: ownDeviceBundles,
                currentDeviceId,
                senderIdentityKeyBase64: myIdentityKey,
                myPrivateKeyUint8: myIdentityPrivateKey
            })
                : await encryptMessage({
                chatId,
                message: messageText,
                recipientIdentityKeyBase64: getOtherIdentityKey(),
                recipientPrekeyBundle: getOtherPrekeyBundle(),
                senderIdentityKeyBase64: myIdentityKey,
                myPrivateKeyUint8: myIdentityPrivateKey
            });

        if (replyToMessageId && payload && typeof payload === "object") {
            payload.reply_to_message_id = replyToMessageId;
        }

        chatSocket.send(JSON.stringify(payload));
        input.value = "";
        onAttachmentSent?.();
        clearReplyTarget?.();
        setAttachmentFeedback?.("");
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
    const urlParams = new URLSearchParams(window.location.search);
    const forceSessionReset = urlParams.get("session_reset") === "1";
    const res = await authFetch(
        `/messages/get_keys?chat_id=${chatId}${forceSessionReset ? "&force_session_reset=1" : ""}`
    );
    const data = await res.json();
    logChatState("initial chat keys response", {
        responseStatus: data.status,
        responseHasIdentityKey: Boolean(data.identity_key),
        responseHasIdentitySigningKey: Boolean(data.identity_signing_key),
        responseHasPrekeyBundle: Boolean(data.prekey_bundle),
        responseDeviceBundleCount: Array.isArray(data.device_bundles) ? data.device_bundles.length : 0,
        forceSessionReset
    });

    if (data.status !== "ok") {
        return;
    }

    await applyChatKeys(data.identity_key, data.identity_signing_key, data.prekey_bundle, data.username, data, data.device_bundles || []);
    if (forceSessionReset) {
        const cleanParams = new URLSearchParams(window.location.search);
        cleanParams.delete("session_reset");
        const nextQuery = cleanParams.toString();
        const nextUrl = `${window.location.pathname}${nextQuery ? `?${nextQuery}` : ""}`;
        window.history.replaceState({}, "", nextUrl);
    }
    openChatSocket(chatId);
    scheduleChatKeyRefresh(chatId);
}

export async function applyChatKeysFlow({
    identityKey,
    identitySigningKey,
    prekeyBundle = null,
    deviceBundles = [],
    username = "",
    avatarData = null,
    setChatKind,
    setOtherKeys,
    logChatState,
    setChatUserName,
    updateChatHeaderAvatar,
    refreshSafetyNumber,
    updateChatReadiness
}) {
    setOtherKeys({
        identityKey: identityKey || null,
        identitySigningKey: identitySigningKey || null,
        prekeyBundle: prekeyBundle || null,
        deviceBundles: Array.isArray(deviceBundles) ? deviceBundles : []
    });
    setChatKind?.(Boolean(avatarData?.is_group));

    logChatState("applied chat keys", {
        username,
        appliedHasIdentityKey: Boolean(identityKey),
        appliedHasIdentitySigningKey: Boolean(identitySigningKey),
        appliedHasPrekeyBundle: Boolean(prekeyBundle),
        deviceBundleCount: Array.isArray(deviceBundles) ? deviceBundles.length : 0
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
        responseHasIdentityKey: Boolean(data.identity_key),
        responseHasIdentitySigningKey: Boolean(data.identity_signing_key),
        responseHasPrekeyBundle: Boolean(data.prekey_bundle),
        responseDeviceBundleCount: Array.isArray(data.device_bundles) ? data.device_bundles.length : 0,
        isGroup: Boolean(data.is_group)
    });
    if (data.status !== "ok") {
        return false;
    }
    if (!data.is_group && !data.identity_key) {
        return false;
    }

    await applyChatKeys(data.identity_key, data.identity_signing_key, data.prekey_bundle, data.username, data, data.device_bundles || []);
    return true;
}

export async function refreshSafetyNumberFlow({
    otherIdentitySigningKey,
    myIdentitySigningKey,
    deriveSafetyNumber,
    setCurrentFingerprint,
    updateVerificationUi,
    logChatState
}) {
    if (!otherIdentitySigningKey || !myIdentitySigningKey) {
        logChatState("safety number skipped: missing key material", {
            hasVerificationKey: Boolean(otherIdentitySigningKey),
            hasMyIdentityKey: Boolean(myIdentitySigningKey)
        }, "warn");
        return;
    }

    const fp = await deriveSafetyNumber(myIdentitySigningKey, otherIdentitySigningKey);
    setCurrentFingerprint(fp);
    const el = document.getElementById("fingerprint");
    if (el) el.innerText = fp;
    await updateVerificationUi(fp, otherIdentitySigningKey, myIdentitySigningKey);
}
