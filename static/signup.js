document.addEventListener('DOMContentLoaded', () => {
    const config = window.signupConfig || {};
    const serverVerifiedEmail = (config.verifiedEmail || '').trim().toLowerCase();
    const form = document.getElementById('signup-form');
    const emailInput = document.getElementById('signup-email');
    const codeInput = document.getElementById('verification-code');
    const passwordInput = document.getElementById('signup-password');
    const confirmPasswordInput = document.getElementById('signup-confirm-password');
    const passwordChecklist = document.getElementById('password-checklist');
    const passwordMatchMessage = document.getElementById('password-match-message');
    const sendButton = document.getElementById('send-verification-btn');
    const verifyButton = document.getElementById('verify-code-btn');
    const statusBox = document.getElementById('verification-status');
    const verifiedFlag = document.getElementById('email-verified-flag');
    const sqlFilterPatterns = [
        /\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|UNION)\b/i,
        /(?:'|")?\s*OR\s+(?:'?\d+'?\s*=\s*'?\d+'?|'.*'\s*=\s*'.*'|".*"\s*=\s*".*")/i,
        /--/,
        /;\s*--/i,
        /\/\*|\*\//,
        /@@/,
        /\b(?:char|nchar|varchar|nvarchar)\s*\(/i
    ];

    if (!form || !emailInput || !codeInput || !sendButton || !verifyButton || !statusBox || !verifiedFlag) {
        return;
    }

    const hasSqlPattern = (value) => sqlFilterPatterns.some((pattern) => pattern.test(String(value || '')));

    const setStatus = (message, type) => {
        statusBox.hidden = false;
        statusBox.textContent = message;
        statusBox.className = 'signup-status-message';
        if (type) {
            statusBox.classList.add(type);
        }
    };

    const setVerified = (value) => {
        verifiedFlag.value = value ? 'true' : 'false';
    };

    const resetVerificationState = (showMessage = true) => {
        setVerified(false);
        if (showMessage) {
            setStatus('이메일이 변경되었습니다. 인증번호를 다시 받아 주세요.', 'warning');
        }
    };

    const postJson = async (url, payload) => {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        let data = {};
        try {
            data = await response.json();
        } catch (error) {
            data = { success: false, message: '서버 응답을 처리하지 못했습니다.' };
        }

        if (!response.ok) {
            throw new Error(data.message || '요청 처리 중 오류가 발생했습니다.');
        }
        return data;
    };

    let lastEmailValue = emailInput.value.trim().toLowerCase();

    const passwordRules = {
        length: (value) => value.length >= 8 && value.length <= 29,
        letter: (value) => /[A-Za-z]/.test(value),
        number: (value) => /\d/.test(value),
        special: (value) => /[!@#$%^&*]/.test(value),
        allowed: (value) => /^[A-Za-z\d!@#$%^&*]*$/.test(value)
    };

    const setRuleState = (node, passed, hasValue) => {
        node.classList.remove('is-valid', 'is-invalid', 'is-neutral');
        if (!hasValue) {
            node.classList.add('is-neutral');
            return;
        }
        node.classList.add(passed ? 'is-valid' : 'is-invalid');
    };

    const updatePasswordFeedback = () => {
        if (!passwordInput || !passwordChecklist) {
            return;
        }

        const passwordValue = passwordInput.value;
        const hasPasswordValue = passwordValue.length > 0;
        passwordChecklist.querySelectorAll('[data-rule]').forEach((item) => {
            const ruleName = item.dataset.rule;
            const validator = passwordRules[ruleName];
            if (!validator) {
                return;
            }
            setRuleState(item, validator(passwordValue), hasPasswordValue);
        });

        if (!confirmPasswordInput || !passwordMatchMessage) {
            return;
        }

        const confirmValue = confirmPasswordInput.value;
        passwordMatchMessage.classList.remove('is-valid', 'is-invalid', 'is-neutral');
        if (!confirmValue) {
            passwordMatchMessage.textContent = '비밀번호 확인을 입력하면 일치 여부가 표시됩니다.';
            passwordMatchMessage.classList.add('is-neutral');
            return;
        }

        if (passwordValue === confirmValue) {
            passwordMatchMessage.textContent = '비밀번호가 일치합니다.';
            passwordMatchMessage.classList.add('is-valid');
            return;
        }

        passwordMatchMessage.textContent = '비밀번호가 일치하지 않습니다.';
        passwordMatchMessage.classList.add('is-invalid');
    };

    emailInput.addEventListener('input', () => {
        const currentEmail = emailInput.value.trim().toLowerCase();
        if (currentEmail !== lastEmailValue) {
            const shouldWarn = verifiedFlag.value === 'true' || codeInput.value.trim() !== '';
            lastEmailValue = currentEmail;
            resetVerificationState(shouldWarn);
        }
    });

    if (passwordInput) {
        passwordInput.addEventListener('input', updatePasswordFeedback);
    }
    if (confirmPasswordInput) {
        confirmPasswordInput.addEventListener('input', updatePasswordFeedback);
    }
    updatePasswordFeedback();

    sendButton.addEventListener('click', async () => {
        const email = emailInput.value.trim();
        if (!email) {
            setStatus('이메일 주소를 먼저 입력해 주세요.', 'error');
            emailInput.focus();
            return;
        }

        sendButton.disabled = true;
        setVerified(false);
        try {
            const data = await postJson(config.sendVerificationUrl, { email });
            setStatus(data.message, 'success');
            codeInput.focus();
        } catch (error) {
            setStatus(error.message, 'error');
        } finally {
            sendButton.disabled = false;
        }
    });

    verifyButton.addEventListener('click', async () => {
        const email = emailInput.value.trim();
        const code = codeInput.value.trim();

        if (!email) {
            setStatus('이메일 주소를 먼저 입력해 주세요.', 'error');
            emailInput.focus();
            return;
        }
        if (!code) {
            setStatus('인증번호를 입력해 주세요.', 'error');
            codeInput.focus();
            return;
        }

        verifyButton.disabled = true;
        try {
            const data = await postJson(config.verifyCodeUrl, { email, code });
            setVerified(true);
            setStatus(data.message, 'success');
        } catch (error) {
            setVerified(false);
            setStatus(error.message, 'error');
        } finally {
            verifyButton.disabled = false;
        }
    });

    form.addEventListener('submit', (event) => {
        const sqlTargets = [
            form.elements.name?.value,
            form.elements.username?.value,
            form.elements.email?.value,
            form.elements.password?.value,
            form.elements.confirm_password?.value
        ];
        if (sqlTargets.some(hasSqlPattern)) {
            event.preventDefault();
            window.alert('비정상적인 입력입니다.');
            return;
        }

        const email = emailInput.value.trim().toLowerCase();
        const isVerified = verifiedFlag.value === 'true' || (serverVerifiedEmail && email === serverVerifiedEmail);
        if (!isVerified) {
            event.preventDefault();
            setStatus('이메일 인증을 완료한 뒤 회원가입해 주세요.', 'error');
        }
    });
});
