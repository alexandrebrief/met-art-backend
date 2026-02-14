// src/components/Register.jsx
import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';

const Register = ({ onToggleForm, onRegisterSuccess }) => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState('');
  
  const { register, error, isAuthenticated } = useAuth();

  // Rediriger quand inscrit et connecté
useEffect(() => {
  if (isAuthenticated) {
    console.log('✅ Inscription réussie, redirection immédiate');
    if (onRegisterSuccess) {
      onRegisterSuccess();
    }
  }
}, [isAuthenticated, onRegisterSuccess]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validation
    if (password !== confirmPassword) {
      setLocalError('Les mots de passe ne correspondent pas');
      return;
    }
    
    if (password.length < 6) {
      setLocalError('Le mot de passe doit contenir au moins 6 caractères');
      return;
    }
    
    setLoading(true);
    setLocalError('');
    
    try {
      console.log('Tentative d\'inscription...');
      await register(username, email, password);
      // La redirection se fera via l'useEffect
    } catch (err) {
      console.error('Erreur inscription:', err);
      setLocalError(err.message || 'Erreur lors de l\'inscription');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>Inscription</h2>
      
      {(localError || error) && (
        <div style={styles.error}>
          {localError || error}
        </div>
      )}
      
      <form onSubmit={handleSubmit} style={styles.form}>
        <div style={styles.inputGroup}>
          <label style={styles.label}>Nom d'utilisateur</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            required
            style={styles.input}
            placeholder="johndoe"
          />
        </div>
        
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
          <small style={styles.hint}>Minimum 6 caractères</small>
        </div>
        
        <div style={styles.inputGroup}>
          <label style={styles.label}>Confirmer le mot de passe</label>
          <input
            type="password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
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
          {loading ? 'Inscription...' : 'S\'inscrire'}
        </button>
      </form>
      
      <p style={styles.switchText}>
        Déjà un compte ?{' '}
        <button 
          onClick={onToggleForm}
          style={styles.switchButton}
        >
          Se connecter
        </button>
      </p>
    </div>
  );
};

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
    outline: 'none',
    ':focus': {
      borderColor: '#0066cc'
    }
  },
  hint: {
    fontSize: '0.8rem',
    color: '#666',
    marginTop: '0.25rem'
  },
  button: {
    padding: '0.75rem',
    fontSize: '1rem',
    backgroundColor: '#0066cc',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    marginTop: '1rem',
    ':hover': {
      backgroundColor: '#0052a3'
    },
    ':disabled': {
      backgroundColor: '#ccc',
      cursor: 'not-allowed'
    }
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
    textDecoration: 'underline',
    ':hover': {
      color: '#0052a3'
    }
  }
};

export default Register;
