document.addEventListener('DOMContentLoaded', () => {
    if (window.lucide) {
        lucide.createIcons();
    }

    const fileInput = document.getElementById('petPhotoInput');
    const preview = document.getElementById('petPreview');
    const fileTriggers = document.querySelectorAll('[data-trigger-file]');
    const genderSelector = document.querySelector('[data-gender-selector]');
    const genderInput = document.getElementById('genderInput');
    const tagsContainer = document.getElementById('tagsContainer');
    const personalityInput = document.getElementById('personalityInput');
    const addCustomTagBtn = document.getElementById('addCustomTagBtn');

    const syncPersonalityInput = () => {
        const activeTags = Array.from(tagsContainer.querySelectorAll('.tag-btn.active'))
            .map((button) => button.dataset.tagValue.trim())
            .filter(Boolean);
        personalityInput.value = activeTags.join(',');
    };

    if (fileInput && preview) {
        fileTriggers.forEach((button) => {
            button.addEventListener('click', () => fileInput.click());
        });

        fileInput.addEventListener('change', (event) => {
            const [file] = event.target.files || [];
            if (!file) {
                return;
            }

            const reader = new FileReader();
            reader.onload = ({ target }) => {
                preview.src = target.result;
                preview.classList.add('has-image');
            };
            reader.readAsDataURL(file);
        });
    }

    if (genderSelector && genderInput) {
        genderSelector.addEventListener('click', (event) => {
            const button = event.target.closest('.gender-btn');
            if (!button) {
                return;
            }

            genderSelector.querySelectorAll('.gender-btn').forEach((item) => item.classList.remove('active'));
            button.classList.add('active');
            genderInput.value = button.dataset.genderValue;
        });
    }

    if (tagsContainer && personalityInput) {
        tagsContainer.addEventListener('click', (event) => {
            const button = event.target.closest('.tag-btn');
            if (!button) {
                return;
            }

            button.classList.toggle('active');
            syncPersonalityInput();
        });

        addCustomTagBtn?.addEventListener('click', () => {
            const customTag = window.prompt('추가할 성격 태그를 입력해 주세요.');
            if (!customTag) {
                return;
            }

            const cleanedTag = customTag.trim();
            if (!cleanedTag) {
                return;
            }

            const existingTag = tagsContainer.querySelector(`[data-tag-value="${cleanedTag}"]`);
            if (existingTag) {
                existingTag.classList.add('active');
                syncPersonalityInput();
                return;
            }

            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'tag-btn active custom-tag';
            button.dataset.tagValue = cleanedTag;
            button.textContent = cleanedTag;
            tagsContainer.insertBefore(button, addCustomTagBtn);
            syncPersonalityInput();
        });

        syncPersonalityInput();
    }
});
