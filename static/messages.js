function scrollThreadToBottom() {
    const thread = document.querySelector('[data-thread]');
    if (!thread) return;
    thread.scrollTop = thread.scrollHeight;
}

function escapeHtml(value) {
    return value
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function buildMessageRow(message) {
    const row = document.createElement('article');
    row.className = `message-row ${message.is_mine ? 'mine' : 'theirs'}`;
    row.dataset.messageId = message.id;
    row.innerHTML = `
        <div class="message-bubble-wrap">
            <div class="message-bubble">${escapeHtml(message.content)}</div>
            <span class="message-time">${escapeHtml(message.display_time || '')}</span>
        </div>
    `;
    return row;
}

function updateConversationPreview(conversationId, preview, displayTime) {
    const conversationItem = document.querySelector(`[data-conversation-id="${conversationId}"]`);
    const list = document.querySelector('.messages-conversation-list');
    if (!conversationItem || !list) return;

    const previewNode = conversationItem.querySelector('[data-conversation-preview]');
    const timeNode = conversationItem.querySelector('[data-conversation-time]');
    if (previewNode) previewNode.textContent = preview;
    if (timeNode) timeNode.textContent = displayTime;
    list.prepend(conversationItem);
}

document.addEventListener('DOMContentLoaded', () => {
    scrollThreadToBottom();

    const form = document.getElementById('messageForm');
    if (!form) return;

    form.addEventListener('submit', async (event) => {
        event.preventDefault();

        const input = form.querySelector('input[name="content"]');
        const thread = document.querySelector('[data-thread]');
        const emptyState = thread ? thread.querySelector('.messages-thread-empty') : null;
        const submitButton = form.querySelector('button[type="submit"]');
        const content = input.value.trim();

        if (!content) {
            input.focus();
            return;
        }

        submitButton.disabled = true;

        try {
            const response = await fetch(form.dataset.sendUrl, {
                method: 'POST',
                body: new FormData(form)
            });
            const payload = await response.json();

            if (!response.ok) {
                throw new Error(payload.error || '메시지를 전송하지 못했습니다.');
            }

            if (emptyState) {
                emptyState.remove();
            }

            const row = buildMessageRow(payload.message);
            thread.appendChild(row);
            updateConversationPreview(form.dataset.conversationId, payload.preview, payload.display_time);
            input.value = '';
            input.focus();
            scrollThreadToBottom();
        } catch (error) {
            alert(error.message);
        } finally {
            submitButton.disabled = false;
        }
    });
});
