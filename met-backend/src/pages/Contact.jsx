import React, { useState } from 'react';
import { Link } from 'react-router-dom';

const Contact = () => {
  const [form, setForm] = useState({ name: '', email: '', message: '' });
  const [status, setStatus] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setStatus('Envoi...');
    
    try {
      const res = await fetch('https://formspree.io/f/xjgewabb', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(form)
      });
      
      if (res.ok) {
        setStatus('Message envoyé !');
        setForm({ name: '', email: '', message: '' });
      } else {
        setStatus('Erreur lors de l\'envoi');
      }
    } catch (err) {
      setStatus('Erreur de connexion');
    }
  };

  return (
    <div className="app-container">
      <div style={{ 
        maxWidth: '600px', 
        margin: '2rem auto', 
        padding: '2rem', 
        background: 'rgba(255,255,255,0.05)', 
        borderRadius: '12px',
        border: '1px solid var(--border)'
      }}>
        <h1 style={{ 
          fontFamily: 'var(--font-serif)', 
          color: 'white', 
          marginBottom: '2rem', 
          textAlign: 'center',
          fontSize: '2rem'
        }}>
          Contact
        </h1>
        
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ 
              display: 'block', 
              color: 'var(--text-light)', 
              marginBottom: '0.5rem',
              fontSize: '0.9rem'
            }}>
              Nom
            </label>
            <input
              type="text"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
              style={{
                width: '100%',
                padding: '0.75rem',
                background: 'rgba(255,255,255,0.1)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                color: 'white',
                fontSize: '0.95rem',
                outline: 'none'
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--accent)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
            />
          </div>
          
          <div style={{ marginBottom: '1.5rem' }}>
            <label style={{ 
              display: 'block', 
              color: 'var(--text-light)', 
              marginBottom: '0.5rem',
              fontSize: '0.9rem'
            }}>
              Email
            </label>
            <input
              type="email"
              value={form.email}
              onChange={(e) => setForm({ ...form, email: e.target.value })}
              required
              style={{
                width: '100%',
                padding: '0.75rem',
                background: 'rgba(255,255,255,0.1)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                color: 'white',
                fontSize: '0.95rem',
                outline: 'none'
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--accent)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
            />
          </div>
          
          <div style={{ marginBottom: '2rem' }}>
            <label style={{ 
              display: 'block', 
              color: 'var(--text-light)', 
              marginBottom: '0.5rem',
              fontSize: '0.9rem'
            }}>
              Message
            </label>
            <textarea
              value={form.message}
              onChange={(e) => setForm({ ...form, message: e.target.value })}
              required
              rows="5"
              style={{
                width: '100%',
                padding: '0.75rem',
                background: 'rgba(255,255,255,0.1)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                color: 'white',
                fontSize: '0.95rem',
                outline: 'none',
                resize: 'vertical'
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--accent)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
            />
          </div>
          
          <button 
            type="submit"
            style={{
              width: '100%',
              padding: '1rem',
              background: 'var(--accent)',
              color: 'var(--primary)',
              border: 'none',
              borderRadius: '8px',
              fontWeight: '600',
              cursor: 'pointer',
              fontSize: '1rem',
              marginBottom: '1rem',
              transition: 'background 0.2s'
            }}
            onMouseEnter={(e) => e.target.style.background = 'var(--accent-light)'}
            onMouseLeave={(e) => e.target.style.background = 'var(--accent)'}
          >
            Envoyer
          </button>
          
          {status && (
            <p style={{ 
              textAlign: 'center', 
              color: status.includes('Erreur') ? '#ff6b6b' : '#4caf50',
              marginTop: '1rem' 
            }}>
              {status}
            </p>
          )}
        </form>
        
        <Link 
          to="/" 
          style={{ 
            color: 'var(--accent)', 
            textDecoration: 'none', 
            display: 'block', 
            textAlign: 'center', 
            marginTop: '1rem',
            fontSize: '0.9rem'
          }}
        >
          ← Retour à l'accueil
        </Link>
      </div>
    </div>
  );
};

export default Contact;
