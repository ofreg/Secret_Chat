import { initUserSearch } from "./userSearch.js?v=20260416t";

window.addEventListener("load", () => {
    initUserSearch({
        onChatStarted: async (chatData) => {
            window.location.search = `?chat_id=${chatData.chat_id}`;
        }
    });
});
