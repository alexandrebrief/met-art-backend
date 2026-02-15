import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';

const Register = ({ onToggleForm, onRegisterSuccess }) => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [localError, setLocalError] = useState('');
  
  const { register, error, isAuthenticated } = useAuth();

  useEffect(() => {
    if (isAuthenticated) {
      if (onRegisterSuccess) onRegisterSuccess();
    }
  }, [isAuthenticated, onRegisterSuccess]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    
    // Validations
    if (password !== confirmPassword) {
      setLocalError('Les mots de passe ne correspondent pas');
      return;
    }
    
    if (password.length < 8) {
      setLocalError('Le mot de passe doit contenir au moins 8 caractères');
      return;
    }
    
    setLoading(true);
    setLocalError('');
    
    try {
      await register(username, email, password);
    } catch (err) {
      setLocalError(err.message || 'Erreur lors de l\'inscription');
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
        Inscription
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
            Nom d'utilisateur
          </label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
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
            placeholder="Votre nom d'utilisateur"
          />
        </div>
        
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
        
        <div style={{ marginBottom: '1.5rem' }}>
          <label style={{
            display: 'block',
            marginBottom: '0.5rem',
            color: 'var(--text)',
            fontSize: '0.9rem',
            fontWeight: '500'
          }}>
            Mot de passe
          </label>
          <div className="password-input-container" style={{ position: 'relative' }}>
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
              minLength={8}
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
          <small style={{
            display: 'block',
            marginTop: '0.25rem',
            color: 'var(--text-light)',
            fontSize: '0.8rem'
          }}>
            Minimum 8 caractères
          </small>
        </div>
        
        <div style={{ marginBottom: '2rem' }}>
          <label style={{
            display: 'block',
            marginBottom: '0.5rem',
            color: 'var(--text)',
            fontSize: '0.9rem',
            fontWeight: '500'
          }}>
            Confirmer le mot de passe
          </label>
          <div className="password-input-container" style={{ position: 'relative' }}>
            <input
              type={showConfirmPassword ? "text" : "password"}
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
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
              placeholder="Confirmer le mot de passe"
              minLength={8}
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
              onClick={() => setShowConfirmPassword(!showConfirmPassword)}
            >
              {showConfirmPassword ? '👁️' : '🔒'}
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
          {loading ? 'Inscription...' : 'S\'inscrire'}
        </button>
      </form>
      
      <p style={{
        textAlign: 'center',
        color: 'var(--text-light)',
        fontSize: '0.9rem'
      }}>
        Déjà un compte ?{' '}
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
          Se connecter
        </button>
      </p>
    </div>
  );
};

export default Register;
