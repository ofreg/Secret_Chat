import { ensureSession } from "./authClient.js?v=20260430a";
import { initKeysIfNeeded } from "./crypto.js?v=20260430a";

async function bootstrapProfileCrypto() {
    const sessionOk = await ensureSession();
    if (!sessionOk) {
        return;
    }

    try {
        await initKeysIfNeeded();
    } catch (error) {
        console.warn("Profile crypto bootstrap failed:", error);
    }
}

window.addEventListener("load", () => {
    void bootstrapProfileCrypto();
});
