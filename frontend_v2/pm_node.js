// API Configuration
const API_BASE_URL = window.location.hostname === 'localhost'
    ? 'http://localhost:5000/api'
    : 'vaultx-password-manager-production.up.railway.app/api';

async function makeAPIRequest(endpoint, options = {}) {
    const token = sessionStorage.getItem('token');
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers
    });

    if (response.status === 401) {
        sessionStorage.clear();
        window.location.href = 'index.html';
        throw new Error('Unauthorized');
    }

    return response;
}

class PasswordManager {
    constructor() {
        this.credentials = [];
        this.excludedSites = [];
        this.checkAuthentication();
        this.initEventListeners();
        this.loadCredentials();
    }

    async checkAuthentication() {
        const token = sessionStorage.getItem('token');
        if (!token) {
            window.location.href = 'index.html';
            return;
        }

        try {
            const response = await makeAPIRequest('/auth/verify');
            if (!response.ok) {
                sessionStorage.clear();
                window.location.href = 'index.html';
            }
        } catch (error) {
            sessionStorage.clear();
            window.location.href = 'index.html';
        }
    }

    initEventListeners() {
        // Logout button
        document.getElementById('logoutBtn').addEventListener('click', () => this.logout());

        // Add credential button
        document.getElementById('addCredentialBtn').addEventListener('click', () => this.showAddCredentialModal());

        // Generate password button
        document.getElementById('generatePasswordBtn').addEventListener('click', () => this.generateAndDisplayPassword());

        // Manage excluded sites button
        document.getElementById('manageExcludedBtn').addEventListener('click', () => this.showExcludedSitesModal());

        // Modal close buttons
        document.querySelector('.close').addEventListener('click', () => this.closeAddCredentialModal());
        document.querySelector('.close-excluded').addEventListener('click', () => this.closeExcludedSitesModal());
        document.getElementById('cancelAddBtn').addEventListener('click', () => this.closeAddCredentialModal());

        // Add credential form
        document.getElementById('addCredentialForm').addEventListener('submit', (e) => this.handleAddCredential(e));

        // Close modals on outside click
        window.addEventListener('click', (e) => {
            const addModal = document.getElementById('addCredentialModal');
            const excludedModal = document.getElementById('excludedSitesModal');
            if (e.target === addModal) {
                this.closeAddCredentialModal();
            }
            if (e.target === excludedModal) {
                this.closeExcludedSitesModal();
            }
        });
    }

    logout() {
        sessionStorage.clear();
        window.location.href = 'index.html';
    }

    showAddCredentialModal() {
        document.getElementById('addCredentialModal').style.display = 'block';
    }

    closeAddCredentialModal() {
        document.getElementById('addCredentialModal').style.display = 'none';
        document.getElementById('addCredentialForm').reset();
    }

    async showExcludedSitesModal() {
        document.getElementById('excludedSitesModal').style.display = 'block';
        await this.loadExcludedSites();
    }

    closeExcludedSitesModal() {
        document.getElementById('excludedSitesModal').style.display = 'none';
    }

    async handleAddCredential(e) {
        e.preventDefault();

        let websiteUrl = document.getElementById('modalWebsiteUrl').value.trim();
        const websiteName = document.getElementById('modalWebsiteName').value.trim();
        const username = document.getElementById('modalUsername').value.trim();
        const password = document.getElementById('modalPassword').value;

        // Add https:// if missing
        if (!websiteUrl.startsWith('http://') && !websiteUrl.startsWith('https://')) {
            websiteUrl = 'https://' + websiteUrl;
        }

        try {
            const response = await makeAPIRequest('/credentials/save', {
                method: 'POST',
                body: JSON.stringify({
                    website_url: websiteUrl,
                    website_name: websiteName || new URL(websiteUrl).hostname,
                    username: username,
                    password: password
                })
            });

            const data = await response.json();

            if (response.ok) {
                alert(data.message || 'Credential saved successfully!');
                this.closeAddCredentialModal();
                await this.loadCredentials();
            } else {
                alert(data.error || 'Failed to save credential');
            }
        } catch (error) {
            console.error('Error saving credential:', error);
            alert('Failed to save credential. Please try again.');
        }
    }

    async loadCredentials() {
        try {
            const response = await makeAPIRequest('/credentials/list');
            const data = await response.json();

            if (response.ok) {
                this.credentials = data.credentials;
                this.renderCredentials();
            } else {
                throw new Error(data.error || 'Failed to load credentials');
            }
        } catch (error) {
            console.error('Error loading credentials:', error);
            this.showError('Failed to load credentials');
        }
    }

    renderCredentials() {
        const listContainer = document.getElementById('credentialsList');
        listContainer.innerHTML = '';

        if (this.credentials.length === 0) {
            listContainer.innerHTML = '<div class="no-credentials">No credentials saved yet. Click "Add Credential" to get started.</div>';
            return;
        }

        this.credentials.forEach(cred => {
            const credCard = this.createCredentialCard(cred);
            listContainer.appendChild(credCard);
        });
    }

    createCredentialCard(cred) {
        const card = document.createElement('div');
        card.className = 'credential-card';

        const favicon = this.getFaviconUrl(cred.websiteUrl);

        card.innerHTML = `
            <div class="credential-header">
                <img src="${favicon}" class="website-favicon" alt="favicon" onerror="this.src='data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🌐</text></svg>'">
                <div class="credential-info">
                    <div class="website-name">${this.escapeHtml(cred.websiteName)}</div>
                    <div class="website-url">${this.escapeHtml(this.getDomain(cred.websiteUrl))}</div>
                </div>
            </div>
            <div class="credential-details">
                <div class="detail-row">
                    <span class="detail-label">Username:</span>
                    <span class="detail-value">${this.escapeHtml(cred.username)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Password:</span>
                    <span class="detail-value password-hidden" id="password-${cred.id}">••••••••</span>
                </div>
            </div>
            <div class="credential-actions">
                <button class="btn btn-small" onclick="passwordManager.showPassword(${cred.id})">👁️ Show</button>
                <button class="btn btn-small" onclick="passwordManager.copyPassword(${cred.id})">📋 Copy</button>
                <button class="btn btn-small btn-danger" onclick="passwordManager.deleteCredential(${cred.id})">🗑️ Delete</button>
            </div>
        `;

        return card;
    }

    getFaviconUrl(url) {
        try {
            const domain = new URL(url).hostname;
            return `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;
        } catch {
            return 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><text y=".9em" font-size="90">🌐</text></svg>';
        }
    }

    getDomain(url) {
        try {
            return new URL(url).hostname;
        } catch {
            return url;
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    async showPassword(credId) {
        try {
            const response = await makeAPIRequest(`/credentials/decrypt/${credId}`);
            const data = await response.json();

            if (response.ok) {
                const passwordElement = document.getElementById(`password-${credId}`);
                passwordElement.textContent = data.password;
                passwordElement.classList.remove('password-hidden');

                // Hide again after 30 seconds
                setTimeout(() => {
                    passwordElement.textContent = '••••••••';
                    passwordElement.classList.add('password-hidden');
                }, 30000);
            } else {
                alert(data.error || 'Failed to decrypt password');
            }
        } catch (error) {
            console.error('Error decrypting password:', error);
            alert('Failed to decrypt password');
        }
    }

    async copyPassword(credId) {
        try {
            const response = await makeAPIRequest(`/credentials/decrypt/${credId}`);
            const data = await response.json();

            if (response.ok) {
                await navigator.clipboard.writeText(data.password);
                alert('Password copied to clipboard!');
            } else {
                alert(data.error || 'Failed to copy password');
            }
        } catch (error) {
            console.error('Error copying password:', error);
            alert('Failed to copy password');
        }
    }

    async deleteCredential(credId) {
        if (!confirm('Are you sure you want to delete this credential?')) {
            return;
        }

        try {
            const response = await makeAPIRequest(`/credentials/delete/${credId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                alert('Credential deleted successfully');
                await this.loadCredentials();
            } else {
                const data = await response.json();
                alert(data.error || 'Failed to delete credential');
            }
        } catch (error) {
            console.error('Error deleting credential:', error);
            alert('Failed to delete credential');
        }
    }

    async loadExcludedSites() {
        try {
            const response = await makeAPIRequest('/excluded-sites/list');
            const data = await response.json();

            if (response.ok) {
                this.excludedSites = data.excludedSites;
                this.renderExcludedSites();
            } else {
                throw new Error(data.error || 'Failed to load excluded sites');
            }
        } catch (error) {
            console.error('Error loading excluded sites:', error);
            this.showError('Failed to load excluded sites');
        }
    }

    renderExcludedSites() {
        const listContainer = document.getElementById('excludedSitesList');
        listContainer.innerHTML = '';

        if (this.excludedSites.length === 0) {
            listContainer.innerHTML = '<div class="no-excluded">No excluded sites</div>';
            return;
        }

        this.excludedSites.forEach(site => {
            const siteItem = document.createElement('div');
            siteItem.className = 'excluded-site-item';
            siteItem.innerHTML = `
                <span>${this.escapeHtml(site.domain)}</span>
                <button class="btn btn-small btn-danger" onclick="passwordManager.removeExcludedSite(${site.id})">Remove</button>
            `;
            listContainer.appendChild(siteItem);
        });
    }

    async removeExcludedSite(siteId) {
        try {
            const response = await makeAPIRequest(`/excluded-sites/remove/${siteId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                await this.loadExcludedSites();
            } else {
                const data = await response.json();
                alert(data.error || 'Failed to remove site');
            }
        } catch (error) {
            console.error('Error removing excluded site:', error);
            alert('Failed to remove site');
        }
    }

    async generateAndDisplayPassword() {
        try {
            const response = await makeAPIRequest('/password/generate');
            const data = await response.json();

            if (response.ok) {
                const container = document.getElementById('generatedPasswordContainer');
                const input = document.getElementById('generatedPassword');

                container.style.display = 'block';
                input.value = data.password;
            } else {
                alert('Failed to generate password');
            }
        } catch (error) {
            console.error('Error generating password:', error);
            alert('Failed to generate password');
        }
    }

    copyGeneratedPassword() {
        const input = document.getElementById('generatedPassword');
        input.select();
        navigator.clipboard.writeText(input.value).then(() => {
            alert('Password copied to clipboard!');
        }).catch(() => {
            alert('Failed to copy password');
        });
    }

    showError(message) {
        const listContainer = document.getElementById('credentialsList');
        listContainer.innerHTML = `<div class="error-message">${message}</div>`;
    }
}

const passwordManager = new PasswordManager();
