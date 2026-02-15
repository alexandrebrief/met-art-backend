import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';

const ResetPassword = ({ onSuccess }) => {
  const [searchParams] = useSearchParams();
  const token = searchParams.get('token');

  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [tokenValid, setTokenValid] = useState(true);

  useEffect(() => {
    if (!token) {
      setTokenValid(false);
      setError('Lien de réinitialisation invalide');
    }
  }, [token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (newPassword !== confirmPassword) {
      setError('Les mots de passe ne correspondent pas');
      return;
    }

    if (newPassword.length < 8) {
      setError('Le mot de passe doit contenir au moins 8 caractères');
      return;
    }

    setLoading(true);

    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/reset-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token, newPassword })
      });

      const data = await res.json();

      if (res.ok) {
        setSuccess(true);
        setTimeout(() => {
          if (onSuccess) onSuccess();
        }, 2000);
      } else {
        setError(data.error || 'Erreur lors de la réinitialisation');
        if (data.error?.includes('expiré') || data.error?.includes('invalide')) {
          setTokenValid(false);
        }
      }
    } catch (err) {
      setError('Erreur de connexion au serveur');
    } finally {
      setLoading(false);
    }
  };

  if (!tokenValid) {
    return (
      <div style={{
        maxWidth: '400px',
        width: '100%',
        padding: '2.5rem',
        background: 'var(--surface)',
        borderRadius: '20px',
        boxShadow: 'var(--shadow-lg)',
        textAlign: 'center'
      }}>
        <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>❌</div>
        <h2 style={{
          fontFamily: 'var(--font-serif)',
          fontSize: '1.8rem',
          color: 'var(--primary)',
          marginBottom: '1rem'
        }}>
          Lien invalide
        </h2>
        <p style={{ color: 'var(--text-light)', marginBottom: '2rem' }}>
          Ce lien de réinitialisation a expiré ou n'est pas valide.
        </p>
        <a
          href="/forgot-password"
          style={{
            display: 'inline-block',
            padding: '0.75rem 2rem',
            background: 'var(--accent)',
            color: 'white',
            textDecoration: 'none',
            borderRadius: '8px'
          }}
        >
          Demander un nouveau lien
        </a>
      </div>
    );
  }

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
        marginBottom: '1rem',
        textAlign: 'center'
      }}>
        Nouveau mot de passe
      </h2>
      
      {success ? (
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>✅</div>
          <h3 style={{ color: 'var(--primary)', marginBottom: '1rem' }}>
            Mot de passe modifié !
          </h3>
          <p style={{ color: 'var(--text-light)', marginBottom: '2rem' }}>
            Vous pouvez maintenant vous connecter avec votre nouveau mot de passe.
          </p>
        </div>
      ) : (
        <>
          {error && (
            <div style={{
              background: '#fee',
              color: '#c0392b',
              padding: '0.75rem',
              borderRadius: '4px',
              marginBottom: '1rem'
            }}>
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '1rem' }}>
              <label style={{
                display: 'block',
                marginBottom: '0.5rem',
                color: 'var(--text)',
                fontSize: '0.9rem',
                fontWeight: '500'
              }}>
                Nouveau mot de passe
              </label>
              <div className="password-input-container">
                <input
                  type={showNew ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  className="password-input"
                  placeholder="••••••••"
                  minLength={8}
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowNew(!showNew)}
                >
                  {showNew ? '👁️' : '👁️‍🗨️'}
                </button>
              </div>
              <small style={{ color: 'var(--text-light)' }}>Minimum 8 caractères</small>
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
              <div className="password-input-container">
                <input
                  type={showConfirm ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  className="password-input"
                  placeholder="••••••••"
                  minLength={8}
                />
                <button
                  type="button"
                  className="password-toggle"
                  onClick={() => setShowConfirm(!showConfirm)}
                >
                  {showConfirm ? '👁️' : '👁️‍🗨️'}
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
                transition: 'all 0.2s'
              }}
            >
              {loading ? 'Chargement...' : 'Réinitialiser'}
            </button>
          </form>
        </>
      )}
    </div>
  );
};

export default ResetPassword;
