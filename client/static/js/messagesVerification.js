import QRCode from "https://cdn.jsdelivr.net/npm/qrcode@1.5.4/+esm";

export async function updateVerificationUiFlow({
    fingerprint,
    verificationKey,
    myIdentityKey,
    getVerificationStatus,
    saveVerificationStatus,
    resetLocalCryptoState
}) {
    const statusEl = document.getElementById("verificationStatus");
    const verifyBtn = document.getElementById("verifyFingerprintBtn");
    const resetBtn = document.getElementById("resetFingerprintBtn");
    const copyBtn = document.getElementById("copyFingerprintBtn");
    const qrCanvas = document.getElementById("fingerprintQr");
    const feedbackEl = document.getElementById("verificationFeedback");

    if (!statusEl || !verifyBtn || !resetBtn || !copyBtn || !qrCanvas) {
        return;
    }

    function setFeedback(message, tone = "") {
        if (!feedbackEl) {
            return;
        }

        feedbackEl.textContent = message;
        feedbackEl.classList.remove("is-success", "is-error");
        if (tone) {
            feedbackEl.classList.add(tone);
        }
    }

    const isVerified = await getVerificationStatus(fingerprint);
    statusEl.textContent = isVerified ? "Verified" : "Not verified";
    statusEl.classList.toggle("verified", isVerified);
    statusEl.classList.toggle("unverified", !isVerified);
    setFeedback("");

    verifyBtn.onclick = async function () {
        await saveVerificationStatus(fingerprint, true);
        setFeedback("Fingerprint marked as verified.", "is-success");
        await updateVerificationUiFlow({
            fingerprint,
            verificationKey,
            myIdentityKey,
            getVerificationStatus,
            saveVerificationStatus,
            resetLocalCryptoState
        });
    };

    resetBtn.onclick = async function () {
        await saveVerificationStatus(fingerprint, false);
        setFeedback("Verification status was reset.", "is-success");
        await updateVerificationUiFlow({
            fingerprint,
            verificationKey,
            myIdentityKey,
            getVerificationStatus,
            saveVerificationStatus,
            resetLocalCryptoState
        });
    };

    copyBtn.onclick = async function () {
        try {
            await navigator.clipboard.writeText(fingerprint);
            setFeedback("Fingerprint copied to clipboard.", "is-success");
        } catch {
            setFeedback("Could not copy automatically. Copy the fingerprint manually.", "is-error");
        }
    };

    const resetDbBtn = document.getElementById("resetIndexedDbBtn");
    if (resetDbBtn) {
        resetDbBtn.onclick = async function () {
            const confirmed = window.confirm("РЎРєРёРЅСѓС‚Рё РІРµСЃСЊ Р»РѕРєР°Р»СЊРЅРёР№ crypto-state С‚Р° IndexedDB РґР»СЏ С†СЊРѕРіРѕ С‡Р°С‚Сѓ?");
            if (!confirmed) {
                return;
            }

            await resetLocalCryptoState();
            window.location.reload();
        };
    }

    const qrPayload = JSON.stringify({
        type: "chat-safety-number",
        safety_number: fingerprint,
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
