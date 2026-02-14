// src/components/Login.jsx
import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';

const Login = ({ onToggleForm, onLoginSuccess }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState('');
  
  const { login, error, isAuthenticated } = useAuth();

  // Rediriger quand connecté
useEffect(() => {
  if (isAuthenticated) {
    console.log('✅ Utilisateur connecté, redirection immédiate');
    // Appeler le callback de succès
    if (onLoginSuccess) {
      onLoginSuccess();
    }
  }
}, [isAuthenticated, onLoginSuccess]); // Dépendance à isAuthenticated

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setLocalError('');
    
    try {
      console.log('Tentative de connexion...');
      await login(email, password);
      // La redirection se fera via l'useEffect ci-dessus
    } catch (err) {
      console.error('Erreur de connexion:', err);
      setLocalError(err.message || 'Email ou mot de passe incorrect');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>Connexion</h2>
      
      {(localError || error) && (
        <div style={styles.error}>
          {localError || error}
        </div>
      )}
      
      <form onSubmit={handleSubmit} style={styles.form}>
        <div style={styles.inputGroup}>
          <label style={styles.label}>Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={styles.input}
            placeholder="exemple@email.com"
          />
        </div>
        
        <div style={styles.inputGroup}>
          <label style={styles.label}>Mot de passe</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            style={styles.input}
            placeholder="••••••••"
          />
        </div>
        
        <button 
          type="submit" 
          disabled={loading}
          style={styles.button}
        >
          {loading ? 'Connexion...' : 'Se connecter'}
        </button>
      </form>
      
      <p style={styles.switchText}>
        Pas encore de compte ?{' '}
        <button 
          onClick={onToggleForm}
          style={styles.switchButton}
        >
          S'inscrire
        </button>
      </p>
    </div>
  );
};

// Styles (identiques)
const styles = {
  container: {
    maxWidth: '400px',
    margin: '0 auto',
    padding: '2rem',
    backgroundColor: 'white',
    borderRadius: '8px',
    boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
  },
  title: {
    textAlign: 'center',
    marginBottom: '1.5rem',
    color: '#333'
  },
  error: {
    backgroundColor: '#ffebee',
    color: '#c62828',
    padding: '0.75rem',
    borderRadius: '4px',
    marginBottom: '1rem',
    fontSize: '0.9rem'
  },
  form: {
    display: 'flex',
    flexDirection: 'column',
    gap: '1rem'
  },
  inputGroup: {
    display: 'flex',
    flexDirection: 'column',
    gap: '0.25rem'
  },
  label: {
    fontSize: '0.9rem',
    fontWeight: '500',
    color: '#555'
  },
  input: {
    padding: '0.75rem',
    fontSize: '1rem',
    border: '2px solid #ddd',
    borderRadius: '4px',
    outline: 'none'
  },
  button: {
    padding: '0.75rem',
    fontSize: '1rem',
    backgroundColor: '#0066cc',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    marginTop: '1rem'
  },
  switchText: {
    textAlign: 'center',
    marginTop: '1rem',
    color: '#666'
  },
  switchButton: {
    background: 'none',
    border: 'none',
    color: '#0066cc',
    cursor: 'pointer',
    fontSize: '0.9rem',
    textDecoration: 'underline'
  }
};

export default Login;
