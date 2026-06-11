export function getWebSocketProtocol() {
    return window.location.protocol === "https:" ? "wss" : "ws";
}

export function createChatSocket({
    chatId,
    debug = false,
    onOpen,
    onStatus,
    onHistoryComplete,
    onMessage,
    onChatDeleted
}) {
    const chatSocket = new WebSocket(
        `${getWebSocketProtocol()}://${window.location.host}/ws/${chatId}${buildDeviceQuery()}`
    );

    chatSocket.onopen = function () {
        if (debug) {
            console.log("Chat ready:", chatId);
        }
        onOpen?.();
    };

    chatSocket.onmessage = async function (event) {
        const data = JSON.parse(event.data);

        if (data.type === "status") {
            onStatus?.(data);
            return;
        }

        if (data.type === "history_complete") {
            onHistoryComplete?.(data);
            return;
        }

        if (data.type === "chat_deleted") {
            onChatDeleted?.(data);
            return;
        }

        if (data.type === "message" || data.type === "message_status" || data.type === "message_deleted") {
            onMessage?.(data);
        }
    };

    return chatSocket;
}

export function createUserSocket({
    debug = false,
    onNewChat,
    onNewMessage,
    onMessageStatus,
    onChatDeleted
}) {
    const userSocket = new WebSocket(
        `${getWebSocketProtocol()}://${window.location.host}/ws/user${buildDeviceQuery()}`
    );

    userSocket.onmessage = async function (event) {
        const data = JSON.parse(event.data);

        if (data.type === "new_chat") {
            await onNewChat?.(data);
            return;
        }

        if (data.type === "new_message") {
            await onNewMessage?.(data);
            return;
        }

        if (data.type === "message_status") {
            await onMessageStatus?.(data);
            return;
        }

        if (data.type === "chat_deleted") {
            await onChatDeleted?.(data);
        }
    };

    userSocket.onclose = function (event) {
        if (debug) {
            console.log("User WS closed", event);
        }
    };

    return userSocket;
}

function buildDeviceQuery() {
    try {
        const deviceId = window.sessionStorage.getItem("e2ee_device_id") || "";
        return deviceId ? `?device_id=${encodeURIComponent(deviceId)}` : "";
    } catch {
        return "";
    }
}
 
export async function reloadChatList(authFetch) {
    const response = await authFetch("/messages");
    if (!response.ok) {
        return false;
    }

    const html = await response.text();
    const parser = new DOMParser();
    const doc = parser.parseFromString(html, "text/html");

    const newChatList = doc.querySelector("#chatList");
    const currentChatList = document.querySelector("#chatList");

    if (newChatList && currentChatList) {
        currentChatList.innerHTML = newChatList.innerHTML;
    }

    const noChatsText = document.getElementById("noChatsText");
    if (!currentChatList) {
        return true;
    }

    if (currentChatList.children.length > 0) {
        if (noChatsText) noChatsText.style.display = "none";
    } else {
        if (noChatsText) noChatsText.style.display = "block";
    }

    return true;
}
