import { initUserSearch } from "./userSearch.js?v=20260623a";

window.addEventListener("load", () => {
    initUserSearch({
        onChatStarted: async (chatData) => {
            const params = new URLSearchParams();
            params.set("chat_id", String(chatData.chat_id));
            if (chatData?.session_reset) {
                params.set("session_reset", "1");
            }
            window.location.search = `?${params.toString()}`;
        }
    });
});
