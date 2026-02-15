import React, { useState } from 'react';

const ForgotPassword = ({ onBackToLogin, onClose }) => {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);
  const [message, setMessage] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/auth/forgot-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email })
      });

      const data = await res.json();

      if (res.ok) {
        setSuccess(true);
        setMessage(data.message || 'Un nouveau mot de passe vous a été envoyé par email');
        setEmail('');
      } else {
        setError(data.error || 'Une erreur est survenue');
      }
    } catch (err) {
      setError('Erreur de connexion au serveur');
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
        marginBottom: '1rem',
        textAlign: 'center'
      }}>
        Mot de passe oublié
      </h2>
      
      {!success ? (
        <>
          <p style={{ textAlign: 'center', color: 'var(--text-light)', marginBottom: '2rem' }}>
            Entrez votre email pour recevoir un nouveau mot de passe
          </p>

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
            <div style={{ marginBottom: '2rem' }}>
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
                placeholder="votre@email.com"
              />
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
                marginBottom: '1rem'
              }}
            >
              {loading ? 'Envoi...' : 'Envoyer un nouveau mot de passe'}
            </button>
          </form>
        </>
      ) : (
        <div style={{ textAlign: 'center' }}>
          <div style={{
            fontSize: '3rem',
            marginBottom: '1rem'
          }}>
            ✉️
          </div>
          <h3 style={{ color: 'var(--primary)', marginBottom: '1rem' }}>
            Email envoyé !
          </h3>
          <p style={{ color: 'var(--text-light)', marginBottom: '2rem' }}>
            {message}
          </p>
          <p style={{ color: 'var(--text-light)', fontSize: '0.9rem', marginBottom: '1.5rem' }}>
            Vérifiez votre boîte de réception (et vos spams) pour trouver votre nouveau mot de passe.
          </p>
          <button
            onClick={onBackToLogin}
            style={{
              padding: '0.75rem 2rem',
              background: 'var(--accent)',
              color: 'white',
              border: 'none',
              borderRadius: '8px',
              cursor: 'pointer',
              fontSize: '1rem'
            }}
          >
            Retour à la connexion
          </button>
        </div>
      )}
    </div>
  );
};

export default ForgotPassword;
