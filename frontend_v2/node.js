// API Configuration
const API_BASE_URL = window.location.hostname === 'localhost'
    ? 'http://localhost:5000/api'
    : 'https://vrhaoyicgurovmddmtxq.supabase.co/api';

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

    return response;
}

document.querySelector('form').addEventListener('submit', async function (event) {
    event.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    if (!username || !password) {
        alert('Please fill in all fields');
        return;
    }

    try {
        const response = await makeAPIRequest('/auth/login', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (response.ok) {
            sessionStorage.setItem('token', data.token);
            sessionStorage.setItem('authenticated', 'true');
            sessionStorage.setItem('username', data.username);
            window.location.href = 'pm.html';
        } else {
            alert(data.error || 'Incorrect username/password');
            document.getElementById('password').value = '';
        }
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed. Please check your connection and try again.');
    }
});

window.addEventListener('load', async function () {
    const token = sessionStorage.getItem('token');
    if (token) {
        try {
            const response = await makeAPIRequest('/auth/verify');
            if (response.ok) {
                window.location.href = 'pm.html';
            } else {
                sessionStorage.clear();
            }
        } catch (error) {
            sessionStorage.clear();
        }
    }
});
