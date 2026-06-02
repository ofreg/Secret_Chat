let refreshInFlight = null;

function readCookie(name) {
    const prefix = `${name}=`;
    return document.cookie
        .split(";")
        .map((part) => part.trim())
        .find((part) => part.startsWith(prefix))
        ?.slice(prefix.length) || "";
}

function wantsJsonResponse() {
    return {
        "X-Requested-With": "fetch",
        "Accept": "application/json"
    };
}

function buildAuthHeaders(init = {}) {
    const headers = {
        ...wantsJsonResponse(),
        ...(init.headers || {})
    };
    const deviceId = readCurrentDeviceId();
    if (deviceId) {
        headers["X-Device-ID"] = deviceId;
    }

    const method = String(init.method || "GET").toUpperCase();
    if (!["GET", "HEAD", "OPTIONS", "TRACE"].includes(method)) {
        const csrfToken = readCookie("csrf_token");
        if (csrfToken) {
            headers["X-CSRF-Token"] = csrfToken;
        }
    }

    return headers;
}

function readCurrentDeviceId() {
    try {
        return window.sessionStorage.getItem("e2ee_device_id") || "";
    } catch {
        return "";
    }
}

export async function refreshAccessToken() {
    if (!refreshInFlight) {
        refreshInFlight = fetch("/refresh", {
            method: "POST",
            credentials: "include",
            headers: buildAuthHeaders({ method: "POST" })
        }).then(async (response) => {
            let payload = null;
            try {
                payload = await response.json();
            } catch {}

            if (!response.ok || payload?.status !== "ok") {
                throw new Error(payload?.message || "Token refresh failed");
            }

            return payload;
        }).finally(() => {
            refreshInFlight = null;
        });
    }

    return refreshInFlight;
}

export async function ensureSession() {
    try {
        await refreshAccessToken();
        return true;
    } catch (error) {
        console.warn("Session refresh failed:", error);
        return false;
    }
}

export async function authFetch(input, init = {}, retry = true) {
    const response = await fetch(input, {
        credentials: "include",
        ...init,
        headers: buildAuthHeaders(init)
    });

    if (response.status !== 401 || !retry) {
        return response;
    }

    const refreshed = await ensureSession();
    if (!refreshed) {
        return response;
    }

    return fetch(input, {
        credentials: "include",
        ...init,
        headers: buildAuthHeaders(init)
    });
}
