// src/services/auth.js

// Récupérer l'URL de base depuis l'environnement
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';
const API_URL = `${API_BASE_URL}/api`;

console.log('🔧 API_URL =', API_URL);

// Stocker le token
export const setToken = (token) => {
  localStorage.setItem('token', token);
};

export const getToken = () => {
  return localStorage.getItem('token');
};

export const removeToken = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
};

// Stocker l'utilisateur
export const setUser = (user) => {
  localStorage.setItem('user', JSON.stringify(user));
};

export const getUser = () => {
  const user = localStorage.getItem('user');
  return user ? JSON.parse(user) : null;
};

export const isAuthenticated = () => {
  return !!getToken();
};

// Inscription
export const register = async (username, email, password) => {
  console.log('📝 Tentative inscription à:', `${API_URL}/auth/register`);
  
  const response = await fetch(`${API_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, email, password })
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    throw new Error(data.error || 'Erreur lors de l\'inscription');
  }
  
  setToken(data.token);
  setUser(data.user);
  return data;
};

// Connexion
export const login = async (email, password) => {
  console.log('🔐 Tentative connexion à:', `${API_URL}/auth/login`);
  
  const response = await fetch(`${API_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  
  const data = await response.json();
  
  if (!response.ok) {
    throw new Error(data.error || 'Erreur lors de la connexion');
  }
  
  setToken(data.token);
  setUser(data.user);
  return data;
};

// Déconnexion
export const logout = () => {
  removeToken();
};

// Helper pour les fetch avec token
export const fetchWithAuth = async (url, options = {}) => {
  const token = getToken();
  
  const response = await fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : '',
      ...options.headers
    }
  });
  
  if (response.status === 401) {
    // Token expiré ou invalide
    removeToken();
    window.location.reload();
    throw new Error('Session expirée');
  }
  
  return response;
};
