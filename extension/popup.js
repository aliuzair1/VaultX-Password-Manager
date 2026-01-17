// VaultX Extension Popup Script

const API_BASE_URL = 'https://your-backend-url.com/api'; // Update with your backend URL
const DASHBOARD_URL = 'https://your-frontend-url.com/pm.html'; // Update with your frontend URL

let currentToken = null;

// Initialize popup
document.addEventListener('DOMContentLoaded', async () => {
    await checkAuthentication();
    setupEventListeners();
});

async function checkAuthentication() {
    const response = await chrome.runtime.sendMessage({ action: 'checkAuth' });
    
    if (response.authenticated) {
        currentToken = await getToken();
        showMainView(response.username);
    } else {
        showLoginView();
    }
}

function showLoginView() {
    document.getElementById('loginView').style.display = 'block';
    document.getElementById('mainView').style.display = 'none';
}

function showMainView(username) {
    document.getElementById('loginView').style.display = 'none';
    document.getElementById('mainView').style.display = 'block';
    document.getElementById('currentUsername').textContent = username;
}

function setupEventListeners() {
    // Login form
    document.getElementById('loginForm').addEventListener('submit', handleLogin);
    
    // Logout button
    document.getElementById('logoutBtn').addEventListener('click', handleLogout);
    
    // Add credential form
    document.getElementById('addCredentialForm').addEventListener('submit', handleAddCredential);
    
    // Open dashboard links
    document.getElementById('openDashboard').addEventListener('click', openDashboard);
    document.getElementById('openDashboardMain').addEventListener('click', openDashboard);
    
    // Generate password
    document.getElementById('generatePasswordBtn').addEventListener('click', handleGeneratePassword);
    
    // Copy generated password
    document.getElementById('copyGeneratedPassword').addEventListener('click', copyGeneratedPassword);
}

async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value;
    const errorDiv = document.getElementById('loginError');
    
    errorDiv.textContent = '';
    
    if (!username || !password) {
        errorDiv.textContent = 'Please fill in all fields';
        return;
    }
    
    const response = await chrome.runtime.sendMessage({
        action: 'login',
        data: { username, password }
    });
    
    if (response.success) {
        currentToken = await getToken();
        showMainView(response.username);
        document.getElementById('loginForm').reset();
    } else {
        errorDiv.textContent = response.error || 'Login failed';
    }
}

async function handleLogout() {
    const response = await chrome.runtime.sendMessage({ action: 'logout' });
    
    if (response.success) {
        currentToken = null;
        showLoginView();
        document.getElementById('loginError').textContent = '';
    }
}

async function handleAddCredential(e) {
    e.preventDefault();
    
    const websiteUrl = document.getElementById('websiteUrl').value.trim();
    const websiteName = document.getElementById('websiteName').value.trim();
    const username = document.getElementById('credUsername').value.trim();
    const password = document.getElementById('credPassword').value;
    const messageDiv = document.getElementById('addCredentialMessage');
    
    messageDiv.textContent = '';
    messageDiv.className = 'message';
    
    if (!websiteUrl || !username || !password) {
        messageDiv.textContent = 'Please fill in required fields';
        messageDiv.classList.add('error');
        return;
    }
    
    // Add https:// if missing
    let fullUrl = websiteUrl;
    if (!websiteUrl.startsWith('http://') && !websiteUrl.startsWith('https://')) {
        fullUrl = 'https://' + websiteUrl;
    }
    
    try {
        const response = await fetch(`${API_BASE_URL}/credentials/save`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${currentToken}`
            },
            body: JSON.stringify({
                website_url: fullUrl,
                website_name: websiteName || new URL(fullUrl).hostname,
                username: username,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            messageDiv.textContent = data.message || 'Credential saved successfully!';
            messageDiv.classList.add('success');
            document.getElementById('addCredentialForm').reset();
            
            // Clear message after 3 seconds
            setTimeout(() => {
                messageDiv.textContent = '';
                messageDiv.className = 'message';
            }, 3000);
        } else {
            messageDiv.textContent = data.error || 'Failed to save credential';
            messageDiv.classList.add('error');
        }
    } catch (error) {
        console.error('Error saving credential:', error);
        messageDiv.textContent = 'Network error. Please try again.';
        messageDiv.classList.add('error');
    }
}

async function handleGeneratePassword() {
    try {
        const response = await fetch(`${API_BASE_URL}/password/generate`, {
            headers: {
                'Authorization': `Bearer ${currentToken}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            document.getElementById('generatedPassword').value = data.password;
            document.getElementById('generatedPasswordSection').style.display = 'block';
        } else {
            alert('Failed to generate password');
        }
    } catch (error) {
        console.error('Error generating password:', error);
        alert('Failed to generate password');
    }
}

function copyGeneratedPassword() {
    const passwordInput = document.getElementById('generatedPassword');
    passwordInput.select();
    document.execCommand('copy');
    
    // Show feedback
    const btn = document.getElementById('copyGeneratedPassword');
    const originalText = btn.textContent;
    btn.textContent = '✓';
    setTimeout(() => {
        btn.textContent = originalText;
    }, 1000);
}

function openDashboard(e) {
    e.preventDefault();
    chrome.tabs.create({ url: DASHBOARD_URL });
}

async function getToken() {
    return new Promise((resolve) => {
        chrome.storage.local.get(['vaultx_token'], (result) => {
            resolve(result.vaultx_token || null);
        });
    });
}
