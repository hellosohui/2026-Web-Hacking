document.addEventListener('DOMContentLoaded', () => {
    if (window.lucide) {
        lucide.createIcons();
    }

    const fileInput = document.getElementById('profileImageInput');
    const preview = document.getElementById('profileImagePreview');
    const trigger = document.querySelector('[data-trigger-profile-image]');

    if (!fileInput || !preview) {
        return;
    }

    trigger?.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (event) => {
        const [file] = event.target.files || [];
        if (!file) {
            return;
        }

        const reader = new FileReader();
        reader.onload = ({ target }) => {
            preview.src = target.result;
        };
        reader.readAsDataURL(file);
    });
});
