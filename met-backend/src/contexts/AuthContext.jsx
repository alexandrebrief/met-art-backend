// src/contexts/AuthContext.jsx
import React, { createContext, useState, useContext, useEffect } from 'react';
import { getUser, setUser as saveUser, removeToken, getToken, login as authLogin, register as authRegister, logout as authLogout, setToken } from '../services/auth';

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // Vérifier si un utilisateur est déjà connecté
    const checkUser = () => {
      const storedUser = getUser();
      const token = getToken();
      
      console.log('Vérification auth:', { storedUser, token }); // Pour debug
      
      if (storedUser && token) {
        setUser(storedUser);
      }
      setLoading(false);
    };
    
    checkUser();
  }, []);

  const login = async (email, password) => {
    try {
      setError(null);
      console.log('Tentative de connexion pour:', email);
      
      const data = await authLogin(email, password);
      console.log('Réponse login:', data);
      
      if (data && data.user && data.token) {
        setUser(data.user);
        return data;
      } else {
        throw new Error('Réponse invalide du serveur');
      }
    } catch (err) {
      console.error('Erreur login dans context:', err);
      setError(err.message);
      throw err;
    }
  };

  const register = async (username, email, password) => {
    try {
      setError(null);
      console.log('Tentative d\'inscription pour:', email);
      
      const data = await authRegister(username, email, password);
      console.log('Réponse register:', data);
      
      if (data && data.user && data.token) {
        setUser(data.user);
        return data;
      } else {
        throw new Error('Réponse invalide du serveur');
      }
    } catch (err) {
      console.error('Erreur register dans context:', err);
      setError(err.message);
      throw err;
    }
  };

  const logout = () => {
    authLogout();
    setUser(null);
  };

  const value = {
    user,
    loading,
    error,
    login,
    register,
    logout,
    isAuthenticated: !!user
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};
