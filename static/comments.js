document.addEventListener('DOMContentLoaded', () => {
    if (window.lucide) {
        lucide.createIcons();
    }

    const pageRoot = document.querySelector('.post-detail-layout');
    if (!pageRoot) {
        return;
    }

    const postId = pageRoot.dataset.postId;
    const commentList = document.getElementById('commentList');
    const commentCountNodes = document.querySelectorAll('[data-comment-count], #commentCount');
    const composerForm = document.getElementById('commentComposerForm');
    const composerInput = document.getElementById('commentComposerInput');
    const commentTemplate = document.getElementById('commentItemTemplate');
    const likeButtons = document.querySelectorAll('[data-like-button]');
    const likeCountNodes = document.querySelectorAll('[data-like-count]');
    const shareButton = document.querySelector('[data-share-button]');
    const followButton = document.querySelector('[data-follow-button]');
    let openMenuPopover = null;

    const setCommentCount = (count) => {
        commentCountNodes.forEach((node) => {
            node.textContent = count;
        });
    };

    const setLikeCount = (count) => {
        likeCountNodes.forEach((node) => {
            node.textContent = count;
        });
    };

    const setLikeState = (liked) => {
        likeButtons.forEach((button) => {
            button.classList.toggle('liked', liked);
        });
    };

    const removeEmptyState = () => {
        const emptyState = document.getElementById('commentEmptyState');
        if (emptyState) {
            emptyState.remove();
        }
    };

    const buildCommentElement = (comment) => {
        const fragment = commentTemplate.content.cloneNode(true);
        const article = fragment.querySelector('.comment-item');
        article.dataset.commentId = comment.id;

        const avatar = fragment.querySelector('.comment-avatar');
        avatar.src = comment.author_avatar;

        fragment.querySelector('.comment-meta strong').textContent = comment.author_name;
        fragment.querySelector('.comment-time').textContent = `${comment.display_time}${comment.is_edited ? ' · 수정됨' : ''}`;
        fragment.querySelector('[data-comment-text]').textContent = comment.content;
        fragment.querySelector('[data-comment-edit-form] textarea').value = comment.content;

        if (!comment.is_owner) {
            fragment.querySelector('.comment-actions')?.remove();
        }

        return fragment;
    };

    const closeAllMenus = () => {
        document.querySelectorAll('.comment-menu-popover').forEach((node) => {
            node.setAttribute('hidden', 'hidden');
        });
        openMenuPopover = null;
    };

    document.addEventListener('click', (event) => {
        if (!event.target.closest('.comment-actions')) {
            closeAllMenus();
        }
    });

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            closeAllMenus();
        }
    });

    likeButtons.forEach((button) => {
        button.addEventListener('click', async () => {
            const response = await fetch(`/post/${postId}/like`, {
                method: 'POST',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            if (response.status === 401) {
                window.location.href = '/login';
                return;
            }

            const data = await response.json();
            if (data.status !== 'success') {
                return;
            }

            setLikeState(data.liked);
            setLikeCount(data.like_count);
        });
    });

    shareButton?.addEventListener('click', async () => {
        try {
            await navigator.clipboard.writeText(window.location.href);
            shareButton.classList.add('copied');
            shareButton.innerHTML = '<i data-lucide="check"></i> 링크 복사됨';
            if (window.lucide) {
                lucide.createIcons();
            }
            window.setTimeout(() => {
                shareButton.classList.remove('copied');
                shareButton.innerHTML = '<i data-lucide="send"></i> 공유';
                if (window.lucide) {
                    lucide.createIcons();
                }
            }, 1800);
        } catch (error) {
            window.alert('링크 복사에 실패했습니다.');
        }
    });

    followButton?.addEventListener('click', async () => {
        const userId = followButton.dataset.userId;
        const response = await fetch(`/follow/${userId}`, { method: 'POST' });
        if (response.status === 401) {
            window.location.href = '/login';
            return;
        }
        const data = await response.json();
        if (data.status !== 'success') {
            return;
        }
        const following = data.action === 'followed';
        followButton.classList.toggle('following', following);
        followButton.textContent = following ? '팔로잉' : '팔로우';
    });

    if (composerForm && composerInput) {
        composerForm.addEventListener('submit', async (event) => {
            event.preventDefault();
            const content = composerInput.value.trim();
            if (!content) {
                return;
            }

            const formData = new FormData();
            formData.append('content', content);

            const response = await fetch(`/post/${postId}/comments`, {
                method: 'POST',
                body: formData
            });

            if (response.status === 401) {
                window.location.href = '/login';
                return;
            }

            const data = await response.json();
            if (data.status !== 'success') {
                window.alert(data.error || '댓글 등록에 실패했습니다.');
                return;
            }

            removeEmptyState();
            commentList.appendChild(buildCommentElement(data.comment));
            composerInput.value = '';
            setCommentCount(data.comment_count);
            if (window.lucide) {
                lucide.createIcons();
            }
        });
    }

    commentList.addEventListener('click', async (event) => {
        const commentItem = event.target.closest('.comment-item');
        if (!commentItem) {
            return;
        }

        if (event.target.closest('[data-comment-menu]')) {
            const popover = commentItem.querySelector('.comment-menu-popover');
            const isSameMenuOpen = openMenuPopover === popover && !popover.hasAttribute('hidden');
            closeAllMenus();
            if (!isSameMenuOpen) {
                popover.removeAttribute('hidden');
                openMenuPopover = popover;
            }
            return;
        }

        if (event.target.closest('[data-edit-comment]')) {
            commentItem.querySelector('[data-comment-edit-form]').removeAttribute('hidden');
            commentItem.querySelector('[data-comment-text]').setAttribute('hidden', 'hidden');
            closeAllMenus();
            return;
        }

        if (event.target.closest('[data-cancel-edit]')) {
            commentItem.querySelector('[data-comment-edit-form]').setAttribute('hidden', 'hidden');
            commentItem.querySelector('[data-comment-text]').removeAttribute('hidden');
            return;
        }

        if (event.target.closest('[data-delete-comment]')) {
            const confirmed = window.confirm('댓글을 삭제하시겠습니까?');
            if (!confirmed) {
                return;
            }

            const response = await fetch(`/comment/${commentItem.dataset.commentId}/delete`, {
                method: 'POST'
            });
            const data = await response.json();
            if (data.status !== 'success') {
                window.alert(data.error || '댓글 삭제에 실패했습니다.');
                return;
            }

            commentItem.remove();
            setCommentCount(data.comment_count);
            closeAllMenus();
            if (!commentList.querySelector('.comment-item')) {
                const empty = document.createElement('div');
                empty.className = 'comment-empty-state';
                empty.id = 'commentEmptyState';
                empty.textContent = '아직 댓글이 없습니다. 가장 먼저 따뜻한 한마디를 남겨보세요.';
                commentList.appendChild(empty);
            }
        }
    });

    commentList.addEventListener('submit', async (event) => {
        const editForm = event.target.closest('[data-comment-edit-form]');
        if (!editForm) {
            return;
        }

        event.preventDefault();
        const commentItem = editForm.closest('.comment-item');
        const textarea = editForm.querySelector('textarea');
        const content = textarea.value.trim();
        if (!content) {
            window.alert('빈 댓글은 저장할 수 없습니다.');
            return;
        }

        const formData = new FormData();
        formData.append('content', content);

        const response = await fetch(`/comment/${commentItem.dataset.commentId}/update`, {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        if (data.status !== 'success') {
            window.alert(data.error || '댓글 수정에 실패했습니다.');
            return;
        }

        commentItem.querySelector('[data-comment-text]').textContent = data.comment.content;
        commentItem.querySelector('[data-comment-text]').removeAttribute('hidden');
        commentItem.querySelector('.comment-time').textContent = `${data.comment.display_time} · 수정됨`;
        editForm.setAttribute('hidden', 'hidden');
        closeAllMenus();
    });
});
