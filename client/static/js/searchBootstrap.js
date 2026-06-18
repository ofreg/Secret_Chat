import { initUserSearch } from "./userSearch.js?v=20260612a";

window.addEventListener("load", () => {
    initUserSearch({
        onChatStarted: async (chatData) => {
            window.location.search = `?chat_id=${chatData.chat_id}`;
        }
    });
});
