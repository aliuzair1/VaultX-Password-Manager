// VaultX Background Service Worker

const API_BASE_URL = 'https://your-backend-url.com/api'; // Update with your backend URL

// Listen for messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'login') {
        handleLogin(request.data)
            .then(sendResponse)
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true; // Keep channel open for async response
    }
    
    if (request.action === 'logout') {
        handleLogout()
            .then(sendResponse)
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
    }
    
    if (request.action === 'checkAuth') {
        checkAuth()
            .then(sendResponse)
            .catch(error => sendResponse({ success: false, error: error.message }));
        return true;
    }
});

async function handleLogin(credentials) {
    try {
        const response = await fetch(`${API_BASE_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(credentials)
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Store token in chrome.storage
            await chrome.storage.local.set({
                vaultx_token: data.token,
                vaultx_username: data.username
            });
            
            return { success: true, username: data.username };
        } else {
            return { success: false, error: data.error || 'Login failed' };
        }
    } catch (error) {
        console.error('Login error:', error);
        return { success: false, error: 'Network error' };
    }
}

async function handleLogout() {
    try {
        await chrome.storage.local.remove(['vaultx_token', 'vaultx_username']);
        return { success: true };
    } catch (error) {
        console.error('Logout error:', error);
        return { success: false, error: 'Logout failed' };
    }
}

async function checkAuth() {
    try {
        const result = await chrome.storage.local.get(['vaultx_token', 'vaultx_username']);
        
        if (!result.vaultx_token) {
            return { authenticated: false };
        }
        
        // Verify token with backend
        const response = await fetch(`${API_BASE_URL}/auth/verify`, {
            headers: {
                'Authorization': `Bearer ${result.vaultx_token}`
            }
        });
        
        if (response.ok) {
            return { 
                authenticated: true, 
                username: result.vaultx_username 
            };
        } else {
            // Token invalid, clear storage
            await chrome.storage.local.remove(['vaultx_token', 'vaultx_username']);
            return { authenticated: false };
        }
    } catch (error) {
        console.error('Auth check error:', error);
        return { authenticated: false };
    }
}

// Icon badge to show extension status
chrome.storage.local.get(['vaultx_token'], (result) => {
    if (result.vaultx_token) {
        chrome.action.setBadgeText({ text: '✓' });
        chrome.action.setBadgeBackgroundColor({ color: '#28a745' });
    }
});

// Listen for storage changes
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (namespace === 'local' && changes.vaultx_token) {
        if (changes.vaultx_token.newValue) {
            chrome.action.setBadgeText({ text: '✓' });
            chrome.action.setBadgeBackgroundColor({ color: '#28a745' });
        } else {
            chrome.action.setBadgeText({ text: '' });
        }
    }
});
