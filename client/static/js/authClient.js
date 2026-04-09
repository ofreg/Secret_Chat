let refreshInFlight = null;

function wantsJsonResponse() {
    return {
        "X-Requested-With": "fetch",
        "Accept": "application/json"
    };
}

export async function refreshAccessToken() {
    if (!refreshInFlight) {
        refreshInFlight = fetch("/refresh", {
            method: "POST",
            credentials: "include",
            headers: wantsJsonResponse()
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
        headers: {
            ...wantsJsonResponse(),
            ...(init.headers || {})
        }
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
        headers: {
            ...wantsJsonResponse(),
            ...(init.headers || {})
        }
    });
}
