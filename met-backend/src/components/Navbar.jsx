// src/components/Navbar.jsx
import React, { useState } from 'react';
import { useAuth } from '../contexts/AuthContext';

const Navbar = ({ 
  onShowFavorites, 
  onShowAll, 
  onShowRated, 
  onShowAuth, 
  showFavorites, 
  showRated, 
  favoritesCount, 
  ratedCount 
}) => {
  const { user, logout } = useAuth();
  const [showMenu, setShowMenu] = useState(false);

  const handleLogout = () => {
    logout();
    setShowMenu(false);
    onShowAll();
  };

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleDateString('fr-FR', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric'
    });
  };

  return (
    <div style={styles.navbar}>
      <div style={styles.left}>
        <h2 style={styles.logo} onClick={onShowAll}>🎨 MET Art</h2>
        <button 
          onClick={onShowAll}
          style={{
            ...styles.navButton,
            backgroundColor: !showFavorites && !showRated ? '#0066cc' : '#f0f0f0',
            color: !showFavorites && !showRated ? 'white' : '#333'
          }}
        >
          📚 Toutes les œuvres
        </button>
        <button 
          onClick={onShowFavorites}
          style={{
            ...styles.navButton,
            backgroundColor: showFavorites ? '#0066cc' : '#f0f0f0',
            color: showFavorites ? 'white' : '#333'
          }}
        >
          ⭐ Mes favoris {favoritesCount > 0 && `(${favoritesCount})`}
        </button>
        <button 
          onClick={onShowRated}
          style={{
            ...styles.navButton,
            backgroundColor: showRated ? '#0066cc' : '#f0f0f0',
            color: showRated ? 'white' : '#333'
          }}
        >
          📊 Mes œuvres notées {ratedCount > 0 && `(${ratedCount})`}
        </button>
      </div>
      
      <div style={styles.right}>
        {user ? (
          <div style={styles.userContainer}>
            <button 
              onClick={() => setShowMenu(!showMenu)}
              style={styles.userButton}
            >
              <span style={styles.userIcon}>👤</span>
              <span style={styles.username}>{user.username}</span>
              <span style={styles.arrow}>{showMenu ? '▲' : '▼'}</span>
            </button>
            
            {showMenu && (
              <div style={styles.dropdown}>
                <div style={styles.userInfo}>
                  <p><strong>{user.username}</strong></p>
                  <p style={styles.userEmail}>{user.email}</p>
                  <p style={styles.userDate}>
                    Membre depuis le {formatDate(user.created_at)}
                  </p>
                </div>
                <div style={styles.dropdownDivider}></div>
                <button 
                  onClick={handleLogout}
                  style={styles.logoutButton}
                >
                  🚪 Déconnexion
                </button>
              </div>
            )}
          </div>
        ) : (
          <button 
            onClick={onShowAuth}
            style={styles.loginButton}
          >
            🔐 Se connecter / S'inscrire
          </button>
        )}
      </div>
    </div>
  );
};

const styles = {
  navbar: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '1rem 2rem',
    backgroundColor: 'white',
    boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
    marginBottom: '2rem',
    position: 'relative',
    flexWrap: 'wrap',
    gap: '1rem'
  },
  left: {
    display: 'flex',
    alignItems: 'center',
    gap: '1rem',
    flexWrap: 'wrap'
  },
  logo: {
    margin: 0,
    fontSize: '1.5rem',
    color: '#333',
    cursor: 'pointer',
    ':hover': {
      color: '#0066cc'
    }
  },
  navButton: {
    padding: '0.5rem 1rem',
    fontSize: '0.9rem',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    transition: 'all 0.2s',
    whiteSpace: 'nowrap'
  },
  right: {
    position: 'relative'
  },
  userContainer: {
    position: 'relative'
  },
  userButton: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    padding: '0.5rem 1rem',
    backgroundColor: '#f0f0f0',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '0.9rem',
    transition: 'all 0.2s',
    ':hover': {
      backgroundColor: '#e0e0e0'
    }
  },
  userIcon: {
    fontSize: '1.1rem'
  },
  username: {
    maxWidth: '150px',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap'
  },
  arrow: {
    fontSize: '0.8rem',
    marginLeft: '0.25rem'
  },
  dropdown: {
    position: 'absolute',
    top: '100%',
    right: 0,
    marginTop: '0.5rem',
    backgroundColor: 'white',
    borderRadius: '8px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
    minWidth: '250px',
    zIndex: 1000
  },
  userInfo: {
    padding: '1rem'
  },
  userEmail: {
    color: '#666',
    fontSize: '0.85rem',
    margin: '0.25rem 0'
  },
  userDate: {
    color: '#999',
    fontSize: '0.8rem',
    margin: '0.5rem 0 0 0'
  },
  dropdownDivider: {
    height: '1px',
    backgroundColor: '#eee',
    margin: '0.5rem 0'
  },
  logoutButton: {
    width: '100%',
    padding: '0.75rem 1rem',
    backgroundColor: 'transparent',
    border: 'none',
    textAlign: 'left',
    cursor: 'pointer',
    color: '#d32f2f',
    fontSize: '0.9rem',
    borderRadius: '0 0 8px 8px',
    ':hover': {
      backgroundColor: '#ffebee'
    }
  },
  loginButton: {
    padding: '0.5rem 1rem',
    backgroundColor: '#0066cc',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer',
    fontSize: '0.9rem',
    transition: 'all 0.2s',
    ':hover': {
      backgroundColor: '#0052a3'
    }
  }
};

export default Navbar;
