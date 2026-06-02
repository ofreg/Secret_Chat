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
    if (!listEl) {
        return;
    }

    if (!Array.isArray(devices) || devices.length === 0) {
        listEl.innerHTML = "<p class=\"card-copy\">Ще немає зареєстрованих браузерів.</p>";
        return;
    }

    listEl.innerHTML = devices.map((device) => {
        const isCurrent = device.device_id === currentDeviceId;
        const statusLabel = device.has_complete_bundle ? "E2EE готовий" : "Ключі ще не ініціалізовані";
        const actionButton = isCurrent
            ? "<button type=\"button\" class=\"danger-btn\" disabled>Поточний браузер</button>"
            : `<button type="button" class="danger-btn" data-device-revoke="${device.device_id}">Відкликати</button>`;

        return `
            <div class="fact-row" data-device-card="${device.device_id}" style="align-items:flex-start; gap:16px;">
                <div style="flex:1;">
                    <div class="fact-label">${escapeHtml(device.device_name || "Browser device")}${isCurrent ? " (поточний)" : ""}</div>
                    <div class="fact-value" style="display:block; margin-top:4px;">ID: ${escapeHtml(device.device_id)}</div>
                    <div class="fact-value" style="display:block; margin-top:4px;">Створено: ${escapeHtml(formatDeviceTimestamp(device.created_at))}</div>
                    <div class="fact-value" style="display:block; margin-top:4px;">Остання активність: ${escapeHtml(formatDeviceTimestamp(device.last_seen_at))}</div>
                    <div class="fact-value" style="display:block; margin-top:4px;">Стан: ${escapeHtml(statusLabel)}</div>
                </div>
                <div>${actionButton}</div>
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
    void bootstrapProfileCrypto();
});
