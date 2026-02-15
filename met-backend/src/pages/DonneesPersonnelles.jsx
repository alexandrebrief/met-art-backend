import React from 'react';
import { Link } from 'react-router-dom';

const DonneesPersonnelles = () => {
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
          Données personnelles
        </h1>
        
        <div style={{ color: 'white', lineHeight: '1.8' }}>
          <h3 style={{ color: 'var(--accent)', marginBottom: '1rem' }}>Collecte des données</h3>
          <p style={{ marginBottom: '1rem' }}>
            Nous collectons uniquement les données nécessaires au fonctionnement du site :
          </p>
          <ul style={{ marginLeft: '2rem', marginBottom: '1.5rem' }}>
            <li>Nom d'utilisateur (pour identifier votre compte)</li>
            <li>Adresse email (pour la communication et la réinitialisation du mot de passe)</li>
            <li>Mot de passe (haché et stocké de manière sécurisée)</li>
            <li>Favoris et notes (pour votre expérience personnelle)</li>
          </ul>
          
          <h3 style={{ color: 'var(--accent)', margin: '1.5rem 0 1rem' }}>Utilisation des données</h3>
          <p style={{ marginBottom: '1.5rem' }}>
            Vos données sont utilisées exclusivement pour le fonctionnement de l'application. 
            Aucune donnée n'est revendue à des tiers.
          </p>
          
          <h3 style={{ color: 'var(--accent)', margin: '1.5rem 0 1rem' }}>Droit de suppression</h3>
          <p style={{ marginBottom: '1.5rem' }}>
            Vous pouvez supprimer votre compte à tout moment depuis le menu de votre profil. 
            Toutes vos données seront alors effacées.
          </p>
          
          <h3 style={{ color: 'var(--accent)', margin: '1.5rem 0 1rem' }}>Cookies</h3>
          <p style={{ marginBottom: '1.5rem' }}>
            Nous utilisons uniquement des cookies techniques pour maintenir votre session de connexion.
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

export default DonneesPersonnelles;
