import React from 'react';
import { Link } from 'react-router-dom';

const MentionsLegales = () => {
  return (
    <div className="app-container">
      <div style={{ 
        maxWidth: '800px', 
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
          fontSize: '2rem'
        }}>
          Mentions légales
        </h1>
        
        <div style={{ color: 'white', lineHeight: '1.8' }}>
          <h3 style={{ color: 'var(--accent)', marginBottom: '1rem' }}>Éditeur du site</h3>
          <p style={{ marginBottom: '1.5rem' }}>
            MET Art Explorer est un projet personnel développé par Alexandre Brief.
          </p>
          
          <h3 style={{ color: 'var(--accent)', margin: '1.5rem 0 1rem' }}>Hébergement</h3>
          <p style={{ marginBottom: '1.5rem' }}>
            Ce site est hébergé par Vercel (frontend) et Render (backend).
          </p>
          
          <h3 style={{ color: 'var(--accent)', margin: '1.5rem 0 1rem' }}>Propriété intellectuelle</h3>
          <p style={{ marginBottom: '1.5rem' }}>
            Les images des œuvres d'art proviennent de l'API publique du Metropolitan Museum of Art.
          </p>
          
          <h3 style={{ color: 'var(--accent)', margin: '1.5rem 0 1rem' }}>Contact</h3>
          <p style={{ marginBottom: '1.5rem' }}>
            Pour toute question : alexandre.brief2.0@gmail.com
          </p>
        </div>
        
        <Link 
          to="/" 
          style={{ 
            color: 'var(--accent)', 
            textDecoration: 'none', 
            display: 'inline-block', 
            marginTop: '2rem',
            padding: '0.5rem 1.5rem',
            border: '1px solid var(--accent)',
            borderRadius: '30px',
            transition: 'all 0.2s'
          }}
          onMouseEnter={(e) => {
            e.target.style.background = 'var(--accent)';
            e.target.style.color = 'var(--primary)';
          }}
          onMouseLeave={(e) => {
            e.target.style.background = 'transparent';
            e.target.style.color = 'var(--accent)';
          }}
        >
          ← Retour à l'accueil
        </Link>
      </div>
    </div>
  );
};

export default MentionsLegales;
