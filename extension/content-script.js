// VaultX Content Script - Form Detection, Auto-Fill, and Save Prompt

const API_BASE_URL = 'https://vaultx-password-manager-production.up.railway.app/api';

class VaultXContentScript {
    constructor() {
        this.token = null;
        this.capturedCredentials = null;
        this.currentDomain = this.getCurrentDomain();
        this.init();
    }

    async init() {
        // Get token from storage
        this.token = await this.getToken();

        if (!this.token) {
            console.log('VaultX: Not logged in');
            return;
        }

        // Check if site is excluded
        const isExcluded = await this.checkIfExcluded();
        if (isExcluded) {
            console.log('VaultX: Site is excluded');
            return;
        }

        // Auto-fill existing credentials
        await this.autoFillCredentials();

        // Listen for form submissions
        this.attachFormListeners();
    }

    getCurrentDomain() {
        return window.location.hostname;
    }

    async getToken() {
        return new Promise((resolve) => {
            chrome.storage.local.get(['vaultx_token'], (result) => {
                resolve(result.vaultx_token || null);
            });
        });
    }

    async checkIfExcluded() {
        try {
            const response = await fetch(`${API_BASE_URL}/excluded-sites/check`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({ website_url: window.location.href })
            });

            if (response.ok) {
                const data = await response.json();
                return data.excluded;
            }
        } catch (error) {
            console.error('VaultX: Error checking exclusion:', error);
        }
        return false;
    }

    async autoFillCredentials() {
        try {
            const response = await fetch(`${API_BASE_URL}/credentials/for-site`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({ website_url: window.location.href })
            });

            if (response.ok) {
                const data = await response.json();
                if (data.credentials && data.credentials.length > 0) {
                    this.showAutoFillPrompt(data.credentials);
                }
            }
        } catch (error) {
            console.error('VaultX: Error fetching credentials:', error);
        }
    }

    showAutoFillPrompt(credentials) {
        // If there's only one credential, auto-fill immediately
        if (credentials.length === 1) {
            this.fillForm(credentials[0]);
            return;
        }

        // If multiple credentials, show selection prompt
        const prompt = this.createSelectionPrompt(credentials);
        document.body.appendChild(prompt);
    }

    createSelectionPrompt(credentials) {
        const container = document.createElement('div');
        container.id = 'vaultx-autofill-prompt';
        container.className = 'vaultx-prompt vaultx-autofill';

        const content = document.createElement('div');
        content.className = 'vaultx-prompt-content';

        const title = document.createElement('div');
        title.className = 'vaultx-prompt-title';
        title.textContent = '🔐 VaultX - Select Account';

        const list = document.createElement('div');
        list.className = 'vaultx-credential-list';

        credentials.forEach(cred => {
            const item = document.createElement('div');
            item.className = 'vaultx-credential-item';
            item.textContent = cred.username;
            item.onclick = () => {
                this.fillForm(cred);
                container.remove();
            };
            list.appendChild(item);
        });

        const closeBtn = document.createElement('button');
        closeBtn.className = 'vaultx-close-btn';
        closeBtn.textContent = '×';
        closeBtn.onclick = () => container.remove();

        content.appendChild(title);
        content.appendChild(list);
        content.appendChild(closeBtn);
        container.appendChild(content);

        return container;
    }

    fillForm(credential) {
        const forms = document.querySelectorAll('form');

        for (const form of forms) {
            const usernameField = this.findUsernameField(form);
            const passwordField = this.findPasswordField(form);

            if (usernameField && passwordField) {
                usernameField.value = credential.username;
                passwordField.value = credential.password;

                // Trigger input events for React/Vue forms
                this.triggerInputEvent(usernameField);
                this.triggerInputEvent(passwordField);

                console.log('VaultX: Credentials auto-filled');
                break;
            }
        }
    }

    triggerInputEvent(element) {
        const inputEvent = new Event('input', { bubbles: true });
        const changeEvent = new Event('change', { bubbles: true });
        element.dispatchEvent(inputEvent);
        element.dispatchEvent(changeEvent);
    }

    attachFormListeners() {
        const forms = document.querySelectorAll('form');

        forms.forEach(form => {
            // Avoid duplicate listeners
            if (form.dataset.vaultxListening) return;
            form.dataset.vaultxListening = 'true';

            form.addEventListener('submit', (e) => {
                this.captureFormData(form);
            });
        });

        // Watch for dynamically added forms
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.tagName === 'FORM') {
                        if (!node.dataset.vaultxListening) {
                            node.dataset.vaultxListening = 'true';
                            node.addEventListener('submit', (e) => {
                                this.captureFormData(node);
                            });
                        }
                    } else if (node.querySelectorAll) {
                        const forms = node.querySelectorAll('form');
                        forms.forEach(form => {
                            if (!form.dataset.vaultxListening) {
                                form.dataset.vaultxListening = 'true';
                                form.addEventListener('submit', (e) => {
                                    this.captureFormData(form);
                                });
                            }
                        });
                    }
                });
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    captureFormData(form) {
        const usernameField = this.findUsernameField(form);
        const passwordField = this.findPasswordField(form);

        if (usernameField && passwordField) {
            const username = usernameField.value.trim();
            const password = passwordField.value;

            if (username && password) {
                this.capturedCredentials = {
                    website_url: window.location.href,
                    website_name: document.title || this.currentDomain,
                    username: username,
                    password: password
                };

                // Show save prompt after a short delay to allow form submission
                setTimeout(() => {
                    this.showSavePrompt();
                }, 500);
            }
        }
    }

    findUsernameField(form) {
        // Try common username field identifiers
        const selectors = [
            'input[type="email"]',
            'input[type="text"][name*="user"]',
            'input[type="text"][name*="email"]',
            'input[type="text"][id*="user"]',
            'input[type="text"][id*="email"]',
            'input[autocomplete="username"]',
            'input[autocomplete="email"]',
            'input[name="username"]',
            'input[name="email"]',
            'input[id="username"]',
            'input[id="email"]'
        ];

        for (const selector of selectors) {
            const field = form.querySelector(selector);
            if (field && field.value) return field;
        }

        // Fallback: find first text input before password
        const textInputs = form.querySelectorAll('input[type="text"], input[type="email"]');
        if (textInputs.length > 0) return textInputs[0];

        return null;
    }

    findPasswordField(form) {
        return form.querySelector('input[type="password"]');
    }

    showSavePrompt() {
        // Check if prompt already exists
        if (document.getElementById('vaultx-save-prompt')) return;

        const prompt = document.createElement('div');
        prompt.id = 'vaultx-save-prompt';
        prompt.className = 'vaultx-prompt vaultx-save';

        const content = document.createElement('div');
        content.className = 'vaultx-prompt-content';

        const title = document.createElement('div');
        title.className = 'vaultx-prompt-title';
        title.textContent = '🔐 Save password in VaultX?';

        const message = document.createElement('div');
        message.className = 'vaultx-prompt-message';
        message.textContent = `${this.capturedCredentials.username} on ${this.currentDomain}`;

        const buttons = document.createElement('div');
        buttons.className = 'vaultx-prompt-buttons';

        const saveBtn = document.createElement('button');
        saveBtn.className = 'vaultx-btn vaultx-btn-primary';
        saveBtn.textContent = 'Save';
        saveBtn.onclick = () => this.saveCredentials();

        const neverBtn = document.createElement('button');
        neverBtn.className = 'vaultx-btn vaultx-btn-danger';
        neverBtn.textContent = 'Never for this site';
        neverBtn.onclick = () => this.excludeSite();

        const notNowBtn = document.createElement('button');
        notNowBtn.className = 'vaultx-btn vaultx-btn-secondary';
        notNowBtn.textContent = 'Not now';
        notNowBtn.onclick = () => prompt.remove();

        buttons.appendChild(saveBtn);
        buttons.appendChild(neverBtn);
        buttons.appendChild(notNowBtn);

        content.appendChild(title);
        content.appendChild(message);
        content.appendChild(buttons);
        prompt.appendChild(content);

        document.body.appendChild(prompt);

        // Auto-remove after 30 seconds
        setTimeout(() => {
            if (document.getElementById('vaultx-save-prompt')) {
                prompt.remove();
            }
        }, 30000);
    }

    async saveCredentials() {
        try {
            const response = await fetch(`${API_BASE_URL}/credentials/save`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify(this.capturedCredentials)
            });

            const prompt = document.getElementById('vaultx-save-prompt');

            if (response.ok) {
                this.showSuccessMessage('Password saved successfully!');
                if (prompt) prompt.remove();
            } else {
                const data = await response.json();
                this.showErrorMessage(data.error || 'Failed to save password');
            }
        } catch (error) {
            console.error('VaultX: Error saving credentials:', error);
            this.showErrorMessage('Failed to save password');
        }
    }

    async excludeSite() {
        try {
            const response = await fetch(`${API_BASE_URL}/excluded-sites/add`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.token}`
                },
                body: JSON.stringify({ website_url: window.location.href })
            });

            const prompt = document.getElementById('vaultx-save-prompt');

            if (response.ok) {
                this.showSuccessMessage('Site added to exclusion list');
                if (prompt) prompt.remove();
            } else {
                this.showErrorMessage('Failed to exclude site');
            }
        } catch (error) {
            console.error('VaultX: Error excluding site:', error);
            this.showErrorMessage('Failed to exclude site');
        }
    }

    showSuccessMessage(message) {
        this.showToast(message, 'success');
    }

    showErrorMessage(message) {
        this.showToast(message, 'error');
    }

    showToast(message, type = 'info') {
        const toast = document.createElement('div');
        toast.className = `vaultx-toast vaultx-toast-${type}`;
        toast.textContent = message;

        document.body.appendChild(toast);

        setTimeout(() => toast.classList.add('vaultx-toast-show'), 100);

        setTimeout(() => {
            toast.classList.remove('vaultx-toast-show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    }
}

// Initialize VaultX content script
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
        new VaultXContentScript();
    });
} else {
    new VaultXContentScript();
}
