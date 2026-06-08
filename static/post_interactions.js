document.addEventListener('DOMContentLoaded', () => {
    if (window.lucide) {
        lucide.createIcons();
    }

    const body = document.body;
    const isGuestUser = body.dataset.guestUser === '1';
    const modalLayer = document.getElementById('guestAuthModalLayer');
    const authRequiredTargets = document.querySelectorAll('[data-auth-required]');

    const openGuestAuthModal = () => {
        if (!isGuestUser || !modalLayer) {
            return;
        }
        body.classList.add('auth-modal-open');
        modalLayer.setAttribute('aria-hidden', 'false');
    };

    const closeGuestAuthModal = () => {
        if (!modalLayer) {
            return;
        }
        body.classList.remove('auth-modal-open');
        modalLayer.setAttribute('aria-hidden', 'true');
    };

    window.openGuestAuthModal = openGuestAuthModal;

    if (isGuestUser) {
        authRequiredTargets.forEach((element) => {
            element.addEventListener('click', (event) => {
                event.preventDefault();
                event.stopPropagation();
                openGuestAuthModal();
            });
        });

        document.querySelectorAll('[data-close-guest-modal]').forEach((element) => {
            element.addEventListener('click', (event) => {
                event.preventDefault();
                closeGuestAuthModal();
            });
        });

        document.addEventListener('keydown', (event) => {
            if (event.key === 'Escape' && body.classList.contains('auth-modal-open')) {
                closeGuestAuthModal();
            }
        });

        if (body.dataset.openAuthModal === '1') {
            openGuestAuthModal();
        }
    }

    const likeButtons = document.querySelectorAll('[data-like-button]');

    likeButtons.forEach((button) => {
        button.addEventListener('click', async () => {
            const postId = button.dataset.postId;
            if (!postId) {
                return;
            }

            if (isGuestUser) {
                openGuestAuthModal();
                return;
            }

            try {
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

                button.classList.toggle('liked', data.liked);
                const counter = button.querySelector('[data-like-count]');
                if (counter) {
                    counter.textContent = data.like_count;
                }

                if (window.lucide) {
                    lucide.createIcons();
                }
            } catch (error) {
                console.error('Failed to toggle like:', error);
            }
        });
    });
});
