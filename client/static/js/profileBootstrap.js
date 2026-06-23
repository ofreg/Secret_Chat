import { authFetch, ensureSession } from "./authClient.js?v=20260601b";
import {
    ensureLocalAccountBinding,
    initKeysIfNeeded,
    restoreCloudBackupIfNeeded
} from "./crypto.js?v=20260602a";

function formatDeviceTimestamp(value) {
    if (!value) {
        return "Немає даних";
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
        return value;
    }

    return parsed.toLocaleString("uk-UA", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit"
    });
}

function setDevicesStatus(message, isError = false) {
    const statusEl = document.getElementById("devicesPanelStatus");
    if (!statusEl) {
        return;
    }

    statusEl.textContent = message;
    statusEl.classList.toggle("error-text", isError);
    statusEl.classList.toggle("success-text", !isError);
}

function renderDevicesList(devices, currentDeviceId) {
    const listEl = document.getElementById("devicesPanelList");
    const introEl = document.getElementById("devicesPanelIntro");
    if (!listEl) {
        return;
    }

    if (introEl) {
        introEl.textContent = "Тут відображаються браузери, прив'язані до вашого акаунта.";
    }

    listEl.className = "profile-facts devices-panel-list";

    if (!Array.isArray(devices) || devices.length === 0) {
        listEl.innerHTML = "<p class=\"card-copy\">Ще немає зареєстрованих браузерів.</p>";
        return;
    }

    listEl.innerHTML = devices.map((device) => {
        const isCurrent = device.device_id === currentDeviceId;
        const statusLabel = device.has_complete_bundle ? "E2EE готовий" : "Ключі ще не ініціалізовані";
        const actionButton = isCurrent
            ? "<button type=\"button\" class=\"danger-btn device-card-badge\" disabled>Поточний браузер</button>"
            : `<button type="button" class="danger-btn device-card-badge" data-device-revoke="${device.device_id}">Відкликати</button>`;

        return `
            <div class="device-card" data-device-card="${device.device_id}">
                <div class="device-card-header">
                    <h3 class="device-card-title">${escapeHtml(device.device_name || "Browser device")}${isCurrent ? " (поточний)" : ""}</h3>
                    <div>${actionButton}</div>
                </div>
                <div class="device-card-meta">
                    <div class="device-card-meta-item">
                        <span class="device-card-meta-label">ID</span>
                        <span class="device-card-meta-value">${escapeHtml(device.device_id)}</span>
                    </div>
                    <div class="device-card-meta-item">
                        <span class="device-card-meta-label">Створено</span>
                        <span class="device-card-meta-value">${escapeHtml(formatDeviceTimestamp(device.created_at))}</span>
                    </div>
                    <div class="device-card-meta-item">
                        <span class="device-card-meta-label">Остання активність</span>
                        <span class="device-card-meta-value">${escapeHtml(formatDeviceTimestamp(device.last_seen_at))}</span>
                    </div>
                    <div class="device-card-meta-item">
                        <span class="device-card-meta-label">Готовність E2EE</span>
                        <span class="device-card-meta-value">${escapeHtml(statusLabel)}</span>
                    </div>
                </div>
            </div>
        `;
    }).join("");
}

function bindDeviceActions({ currentDeviceId, reloadDevices }) {
    const buttons = document.querySelectorAll("[data-device-revoke]");
    buttons.forEach((button) => {
        button.addEventListener("click", async () => {
            const deviceId = button.getAttribute("data-device-revoke") || "";
            if (!deviceId || deviceId === currentDeviceId) {
                return;
            }

            const confirmed = window.confirm("Відкликати цей браузер і заборонити йому подальший доступ?");
            if (!confirmed) {
                return;
            }

            button.disabled = true;
            setDevicesStatus("Відкликання пристрою...");
            try {
                const response = await authFetch(`/users/devices/${encodeURIComponent(deviceId)}`, {
                    method: "DELETE"
                });
                const payload = await response.json();
                if (!response.ok || payload?.status !== "ok") {
                    throw new Error(payload?.detail || payload?.message || "Не вдалося відкликати пристрій");
                }

                setDevicesStatus("Пристрій відкликано.");
                await reloadDevices();
            } catch (error) {
                console.warn("Device revoke failed:", error);
                setDevicesStatus("Не вдалося відкликати пристрій.", true);
                button.disabled = false;
            }
        });
    });
}

function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll("\"", "&quot;")
        .replaceAll("'", "&#39;");
}

function bindAvatarCropper() {
    const input = document.getElementById("avatarInput");
    const modal = document.getElementById("avatarCropModal");
    const cancelBtn = document.getElementById("avatarCropCancel");
    const applyBtn = document.getElementById("avatarCropApply");
    const resetBtn = document.getElementById("avatarCropReset");
    const viewport = document.getElementById("avatarCropViewport");
    const image = document.getElementById("avatarCropImage");
    const zoomInput = document.getElementById("avatarCropZoom");
    const previewRoot = document.querySelector(".profile-avatar-preview");
    const previewImage = document.querySelector(".profile-avatar-image");

    if (!input || !modal || !cancelBtn || !applyBtn || !resetBtn || !viewport || !image || !zoomInput) {
        return;
    }

    const state = {
        file: null,
        objectUrl: "",
        imageBitmap: null,
        zoom: 1,
        offsetX: 0,
        offsetY: 0,
        dragStartX: 0,
        dragStartY: 0,
        pointerActive: false
    };

    const VIEWPORT_SIZE = 260;
    const EXPORT_SIZE = 512;

    function revokePreviewUrl() {
        if (state.objectUrl) {
            URL.revokeObjectURL(state.objectUrl);
            state.objectUrl = "";
        }
    }

    function closeModal(resetInput = false) {
        modal.hidden = true;
        viewport.classList.remove("is-dragging");
        state.pointerActive = false;
        if (resetInput) {
            input.value = "";
            revokePreviewUrl();
            state.file = null;
            state.imageBitmap = null;
        }
    }

    function getBaseScale() {
        if (!state.imageBitmap) {
            return 1;
        }
        return Math.max(VIEWPORT_SIZE / state.imageBitmap.width, VIEWPORT_SIZE / state.imageBitmap.height);
    }

    function clampOffsets() {
        if (!state.imageBitmap) {
            return;
        }
        const scaledWidth = state.imageBitmap.width * getBaseScale() * state.zoom;
        const scaledHeight = state.imageBitmap.height * getBaseScale() * state.zoom;
        const maxX = Math.max(0, (scaledWidth - VIEWPORT_SIZE) / 2);
        const maxY = Math.max(0, (scaledHeight - VIEWPORT_SIZE) / 2);
        state.offsetX = Math.min(maxX, Math.max(-maxX, state.offsetX));
        state.offsetY = Math.min(maxY, Math.max(-maxY, state.offsetY));
    }

    function renderCropPreview() {
        if (!state.imageBitmap) {
            return;
        }
        clampOffsets();
        const scaledWidth = state.imageBitmap.width * getBaseScale() * state.zoom;
        const scaledHeight = state.imageBitmap.height * getBaseScale() * state.zoom;
        image.style.width = `${scaledWidth}px`;
        image.style.height = `${scaledHeight}px`;
        image.style.transform = `translate(calc(-50% + ${state.offsetX}px), calc(-50% + ${state.offsetY}px))`;
    }

    function resetCropState() {
        state.zoom = 1;
        state.offsetX = 0;
        state.offsetY = 0;
        zoomInput.value = "1";
        renderCropPreview();
    }

    async function openCropper(file) {
        revokePreviewUrl();
        state.file = file;
        state.objectUrl = URL.createObjectURL(file);
        state.imageBitmap = await createImageBitmap(file);
        image.src = state.objectUrl;
        modal.hidden = false;
        resetCropState();
    }

    async function applyCrop() {
        if (!state.file || !state.imageBitmap) {
            closeModal(true);
            return;
        }

        const canvas = document.createElement("canvas");
        canvas.width = EXPORT_SIZE;
        canvas.height = EXPORT_SIZE;
        const ctx = canvas.getContext("2d");
        if (!ctx) {
            return;
        }

        const baseScale = getBaseScale();
        const scaledWidth = state.imageBitmap.width * baseScale * state.zoom;
        const scaledHeight = state.imageBitmap.height * baseScale * state.zoom;
        const exportScale = EXPORT_SIZE / VIEWPORT_SIZE;
        const drawX = (VIEWPORT_SIZE / 2 - scaledWidth / 2 + state.offsetX) * exportScale;
        const drawY = (VIEWPORT_SIZE / 2 - scaledHeight / 2 + state.offsetY) * exportScale;

        ctx.drawImage(
            state.imageBitmap,
            drawX,
            drawY,
            scaledWidth * exportScale,
            scaledHeight * exportScale
        );

        const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/png", 0.95));
        if (!(blob instanceof Blob)) {
            return;
        }

        const croppedFile = new File(
            [blob],
            `${(state.file.name || "avatar").replace(/\.[^.]+$/, "")}.png`,
            { type: "image/png" }
        );
        const transfer = new DataTransfer();
        transfer.items.add(croppedFile);
        input.files = transfer.files;

        const previewUrl = URL.createObjectURL(blob);
        if (previewImage) {
            previewImage.src = previewUrl;
        } else if (previewRoot) {
            previewRoot.innerHTML = "";
            const img = document.createElement("img");
            img.className = "profile-avatar-image";
            img.src = previewUrl;
            img.alt = "Avatar preview";
            previewRoot.appendChild(img);
        }

        closeModal(false);
    }

    input.addEventListener("change", async () => {
        const file = input.files?.[0];
        if (!file) {
            return;
        }
        try {
            await openCropper(file);
        } catch (error) {
            console.warn("Avatar crop open failed:", error);
            closeModal(true);
        }
    });

    zoomInput.addEventListener("input", () => {
        state.zoom = Number(zoomInput.value || "1");
        renderCropPreview();
    });

    resetBtn.addEventListener("click", () => {
        resetCropState();
    });

    cancelBtn.addEventListener("click", () => {
        closeModal(true);
    });

    applyBtn.addEventListener("click", () => {
        void applyCrop();
    });

    modal.addEventListener("click", (event) => {
        if (event.target === modal) {
            closeModal(true);
        }
    });

    viewport.addEventListener("pointerdown", (event) => {
        if (!state.imageBitmap) {
            return;
        }
        state.pointerActive = true;
        state.dragStartX = event.clientX;
        state.dragStartY = event.clientY;
        viewport.classList.add("is-dragging");
        viewport.setPointerCapture(event.pointerId);
    });

    viewport.addEventListener("pointermove", (event) => {
        if (!state.pointerActive) {
            return;
        }
        const deltaX = event.clientX - state.dragStartX;
        const deltaY = event.clientY - state.dragStartY;
        state.dragStartX = event.clientX;
        state.dragStartY = event.clientY;
        state.offsetX += deltaX;
        state.offsetY += deltaY;
        renderCropPreview();
    });

    viewport.addEventListener("pointerup", () => {
        state.pointerActive = false;
        viewport.classList.remove("is-dragging");
    });

    viewport.addEventListener("pointercancel", () => {
        state.pointerActive = false;
        viewport.classList.remove("is-dragging");
    });
}

async function loadDevicesPanel(currentDeviceId) {
    const response = await authFetch("/users/devices");
    const payload = await response.json();
    if (!response.ok || payload?.status !== "ok") {
        throw new Error(payload?.detail || payload?.message || "Не вдалося завантажити список пристроїв");
    }

    renderDevicesList(payload.devices, currentDeviceId);
    bindDeviceActions({
        currentDeviceId,
        reloadDevices: async () => {
            await loadDevicesPanel(currentDeviceId);
        }
    });
    setDevicesStatus(`Знайдено пристроїв: ${payload.devices.length}`);
}

async function bootstrapProfileCrypto() {
    const sessionOk = await ensureSession();
    if (!sessionOk) {
        return;
    }

    try {
        const meResponse = await authFetch("/users/me");
        const meData = await meResponse.json();
        if (meData?.status !== "ok") {
            return;
        }

        await ensureLocalAccountBinding(meData);
        await restoreCloudBackupIfNeeded(meData);
        await initKeysIfNeeded();
        await loadDevicesPanel(meData.current_device_id || "");
    } catch (error) {
        console.warn("Profile crypto bootstrap failed:", error);
        setDevicesStatus("Не вдалося ініціалізувати криптографію або завантажити пристрої.", true);
    }
}

window.addEventListener("load", () => {
    bindAvatarCropper();
    void bootstrapProfileCrypto();
});
