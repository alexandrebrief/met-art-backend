// src/services/auth.js

// Définir l'URL de base selon l'environnement
const isDevelopment = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';

const API_BASE_URL = isDevelopment 
  ? 'http://localhost:3000' 
  : (import.meta.env.VITE_API_URL || 'https://met-art-backend.onrender.com');

const API_URL = `${API_BASE_URL}/api`;

console.log('🔧 Environnement:', isDevelopment ? 'DEVELOPPEMENT' : 'PRODUCTION');
console.log('🔧 API_BASE_URL =', API_BASE_URL);

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
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Erreur lors de l\'inscription');
  }
  
  const data = await response.json();
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
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Erreur lors de la connexion');
  }
  
  const data = await response.json();
  setToken(data.token);
  setUser(data.user);
  return data;
};

// Déconnexion
export const logout = () => {
  removeToken();
};

// Récupérer l'utilisateur connecté
export const getCurrentUser = async () => {
  const token = getToken();
  if (!token) return null;

  const response = await fetch(`${API_URL}/auth/me`, {
    headers: { 'Authorization': `Bearer ${token}` }
  });
  
  if (!response.ok) {
    removeToken();
    return null;
  }
  
  return response.json();
};

// Helper pour les fetch avec token
export const fetchWithAuth = async (url, options = {}) => {
  const token = getToken();
  
  return fetch(url, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': token ? `Bearer ${token}` : '',
      ...options.headers
    }
  });
};
