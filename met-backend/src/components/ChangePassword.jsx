import React, { useState } from 'react';
import { fetchWithAuth } from '../services/auth';

const ChangePassword = ({ onClose }) => {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showCurrent, setShowCurrent] = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [showConfirm, setShowConfirm] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (newPassword !== confirmPassword) {
      setError('Les nouveaux mots de passe ne correspondent pas');
      return;
    }

    if (newPassword.length < 8) {
      setError('Le nouveau mot de passe doit contenir au moins 8 caractères');
      return;
    }

    setLoading(true);

    try {
      const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/auth/change-password`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ currentPassword, newPassword })
      });

      const data = await res.json();

      if (res.ok) {
        setSuccess(true);
        setTimeout(() => {
          onClose();
        }, 2000);
      } else {
        setError(data.error || 'Erreur lors du changement');
      }
    } catch (err) {
      setError('Erreur de connexion');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()} style={{ 
        maxWidth: '450px',
        padding: '2rem'
      }}>
        <button className="modal-close" onClick={onClose}>✕</button>
        
        <h2 style={{ 
          fontFamily: 'var(--font-serif)', 
          fontSize: '1.8rem',
          color: 'white',
          marginBottom: '2rem',
          textAlign: 'center',
          paddingTop: '0.5rem'
        }}>
          Changer le mot de passe
        </h2>
        
        {error && (
          <div style={{
            background: 'rgba(255,0,0,0.1)',
            border: '1px solid #ff6b6b',
            color: '#ff6b6b',
            padding: '0.75rem',
            borderRadius: '8px',
            marginBottom: '1.5rem',
            textAlign: 'center'
          }}>
            {error}
          </div>
        )}
        
        {success && (
          <div style={{
            background: 'rgba(76,175,80,0.1)',
            border: '1px solid #4caf50',
            color: '#4caf50',
            padding: '1rem',
            borderRadius: '8px',
            marginBottom: '1.5rem',
            textAlign: 'center'
          }}>
            ✓ Mot de passe modifié avec succès !
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {/* Mot de passe actuel */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ 
              display: 'block', 
              marginBottom: '0.5rem', 
              color: 'var(--text-light)',
              fontSize: '0.9rem',
              fontWeight: '500'
            }}>
              Mot de passe actuel
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type={showCurrent ? 'text' : 'password'}
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem',
                  paddingRight: '40px',
                  background: 'rgba(255,255,255,0.1)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  color: 'white',
                  fontSize: '0.95rem',
                  outline: 'none',
                  transition: 'border-color 0.2s'
                }}
                onFocus={(e) => e.target.style.borderColor = 'var(--accent)'}
                onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
                placeholder="Mot de passe actuel"  // ← PLUS DE PETITS POINTS
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
                onClick={() => setShowCurrent(!showCurrent)}
              >
                {showCurrent ? '👁️' : '🔒'}
              </button>
            </div>
          </div>

          {/* Nouveau mot de passe */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ 
              display: 'block', 
              marginBottom: '0.5rem', 
              color: 'var(--text-light)',
              fontSize: '0.9rem',
              fontWeight: '500'
            }}>
              Nouveau mot de passe
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type={showNew ? 'text' : 'password'}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem',
                  paddingRight: '40px',
                  background: 'rgba(255,255,255,0.1)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  color: 'white',
                  fontSize: '0.95rem',
                  outline: 'none',
                  transition: 'border-color 0.2s'
                }}
                onFocus={(e) => e.target.style.borderColor = 'var(--accent)'}
                onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
                placeholder="Nouveau mot de passe"  // ← PLUS DE PETITS POINTS
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
                onClick={() => setShowNew(!showNew)}
              >
                {showNew ? '👁️' : '🔒'}
              </button>
            </div>
            <small style={{ 
              display: 'block', 
              marginTop: '0.25rem',
              color: 'var(--text-light)',
              fontSize: '0.75rem'
            }}>
              Minimum 8 caractères
            </small>
          </div>

          {/* Confirmation */}
          <div style={{ marginBottom: '2rem' }}>
            <label style={{ 
              display: 'block', 
              marginBottom: '0.5rem', 
              color: 'var(--text-light)',
              fontSize: '0.9rem',
              fontWeight: '500'
            }}>
              Confirmer le nouveau mot de passe
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type={showConfirm ? 'text' : 'password'}
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem',
                  paddingRight: '40px',
                  background: 'rgba(255,255,255,0.1)',
                  border: '1px solid var(--border)',
                  borderRadius: '8px',
                  color: 'white',
                  fontSize: '0.95rem',
                  outline: 'none',
                  transition: 'border-color 0.2s'
                }}
                onFocus={(e) => e.target.style.borderColor = 'var(--accent)'}
                onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
                placeholder="Confirmer le mot de passe"  // ← PLUS DE PETITS POINTS
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
                onClick={() => setShowConfirm(!showConfirm)}
              >
                {showConfirm ? '👁️' : '🔒'}
              </button>
            </div>
          </div>

          {/* Boutons */}
          <div style={{ display: 'flex', gap: '1rem', marginTop: '1rem' }}>
            <button
              type="submit"
              disabled={loading || success}
              style={{
                flex: 1,
                padding: '0.75rem',
                background: 'var(--accent)',
                color: 'var(--primary)',
                border: 'none',
                borderRadius: '8px',
                fontWeight: '600',
                fontSize: '0.95rem',
                cursor: loading || success ? 'not-allowed' : 'pointer',
                opacity: loading || success ? 0.6 : 1,
                transition: 'all 0.2s'
              }}
              onMouseEnter={(e) => !loading && !success && (e.target.style.background = 'var(--accent-light)')}
              onMouseLeave={(e) => !loading && !success && (e.target.style.background = 'var(--accent)')}
            >
              {loading ? 'Changement...' : 'Changer'}
            </button>

            <button
              type="button"
              onClick={onClose}
              style={{
                flex: 1,
                padding: '0.75rem',
                background: 'transparent',
                color: 'var(--text-light)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                cursor: 'pointer',
                fontSize: '0.95rem',
                transition: 'all 0.2s'
              }}
              onMouseEnter={(e) => {
                e.target.style.background = 'rgba(255,255,255,0.1)';
                e.target.style.color = 'white';
              }}
              onMouseLeave={(e) => {
                e.target.style.background = 'transparent';
                e.target.style.color = 'var(--text-light)';
              }}
            >
              Annuler
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ChangePassword;
