import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';

const Login = ({ onToggleForm, onLoginSuccess, onForgotPassword }) => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState('');
  
  const { login, error, isAuthenticated } = useAuth();

  useEffect(() => {
    if (isAuthenticated) {
      if (onLoginSuccess) onLoginSuccess();
    }
  }, [isAuthenticated, onLoginSuccess]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setLocalError('');
    
    try {
      await login(email, password);
    } catch (err) {
      setLocalError(err.message || 'Email ou mot de passe incorrect');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      maxWidth: '400px',
      width: '100%',
      padding: '2.5rem',
      background: 'var(--surface)',
      borderRadius: '20px',
      boxShadow: 'var(--shadow-lg)'
    }}>
      <h2 style={{
        fontFamily: 'var(--font-serif)',
        fontSize: '2rem',
        color: 'var(--primary)',
        marginBottom: '2rem',
        textAlign: 'center'
      }}>
        Connexion
      </h2>
      
      {(localError || error) && (
        <div style={{
          background: '#fee',
          color: '#c0392b',
          padding: '1rem',
          borderRadius: '8px',
          marginBottom: '1.5rem',
          fontSize: '0.9rem',
          textAlign: 'center'
        }}>
          {localError || error}
        </div>
      )}
      
      <form onSubmit={handleSubmit}>
        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{
            display: 'block',
            marginBottom: '0.5rem',
            color: 'var(--text)',
            fontSize: '0.9rem',
            fontWeight: '500'
          }}>
            Email
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            style={{
              width: '100%',
              padding: '0.75rem 1rem',
              border: '1px solid var(--border)',
              borderRadius: '8px',
              fontFamily: 'var(--font-sans)',
              fontSize: '0.95rem',
              outline: 'none',
              transition: 'border-color 0.2s'
            }}
            onFocus={(e) => e.target.style.borderColor = 'var(--accent)'}
            onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
            placeholder="Votre adresse email"
          />
        </div>
        
        <div style={{ marginBottom: '2rem' }}>
          <label style={{
            display: 'block',
            marginBottom: '0.5rem',
            color: 'var(--text)',
            fontSize: '0.9rem',
            fontWeight: '500'
          }}>
            Mot de passe
          </label>
          <div style={{ position: 'relative' }}>
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{
                width: '100%',
                padding: '0.75rem 1rem',
                paddingRight: '40px',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                fontFamily: 'var(--font-sans)',
                fontSize: '0.95rem',
                outline: 'none',
                transition: 'border-color 0.2s'
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--accent)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
              placeholder="Mot de passe"
            />
            <button
              type="button"
              style={{
                position: 'absolute',
                right: '10px',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--text-light)',
                fontSize: '1.1rem',
                padding: '0 5px'
              }}
              onClick={() => setShowPassword(!showPassword)}
            >
              {showPassword ? '👁️' : '🔒'}
            </button>
          </div>
          
          {/* Lien mot de passe oublié */}
          <div style={{ textAlign: 'right', marginTop: '0.5rem' }}>
            <button
              type="button"
              onClick={onForgotPassword}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--accent)',
                fontSize: '0.85rem',
                cursor: 'pointer',
                textDecoration: 'underline'
              }}
            >
              Mot de passe oublié ?
            </button>
          </div>
        </div>
        
        <button 
          type="submit" 
          disabled={loading}
          style={{
            width: '100%',
            padding: '1rem',
            background: 'var(--primary)',
            color: 'white',
            border: 'none',
            borderRadius: '8px',
            fontFamily: 'var(--font-sans)',
            fontSize: '1rem',
            fontWeight: '500',
            cursor: loading ? 'not-allowed' : 'pointer',
            opacity: loading ? 0.6 : 1,
            transition: 'all 0.2s',
            marginBottom: '1.5rem'
          }}
          onMouseEnter={(e) => !loading && (e.target.style.background = 'var(--primary-dark)')}
          onMouseLeave={(e) => !loading && (e.target.style.background = 'var(--primary)')}
        >
          {loading ? 'Connexion...' : 'Se connecter'}
        </button>
      </form>
      
      <p style={{
        textAlign: 'center',
        color: 'var(--text-light)',
        fontSize: '0.9rem'
      }}>
        Pas encore de compte ?{' '}
        <button 
          onClick={onToggleForm}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--accent)',
            fontWeight: '500',
            cursor: 'pointer',
            fontSize: '0.9rem'
          }}
          onMouseEnter={(e) => e.target.style.textDecoration = 'underline'}
          onMouseLeave={(e) => e.target.style.textDecoration = 'none'}
        >
          S'inscrire
        </button>
      </p>
    </div>
  );
};

export default Login;
