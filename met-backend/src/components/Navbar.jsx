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
  ratedCount,
  query,
  setQuery,
  onSearch,
  isAuthenticated,
  user,
  onShowDeleteConfirm,
  onChangePassword  // ← Nouvelle prop
}) => {
  const [showMenu, setShowMenu] = useState(false);

  const formatDate = (date) => {
    if (!date) return '';
    return new Date(date).toLocaleDateString('fr-FR', {
      day: 'numeric', 
      month: 'long', 
      year: 'numeric'
    });
  };

  const getInitials = (name) => name?.charAt(0).toUpperCase() || '?';

  const handleKeyPress = (e) => e.key === 'Enter' && onSearch();

  return (
    <nav className="navbar">
      <div className="navbar-left">
        <div className="logo" onClick={onShowAll}>MET·Art</div>
        <div className="nav-links">
          <button 
            onClick={onShowAll} 
            className={`nav-button ${!showFavorites && !showRated ? 'active' : ''}`}
          >
            Accueil
          </button>
          <button 
            onClick={onShowFavorites} 
            className={`nav-button ${showFavorites ? 'active' : ''}`}
          >
            Favoris {favoritesCount > 0 && `(${favoritesCount})`}
          </button>
          <button 
            onClick={onShowRated} 
            className={`nav-button ${showRated ? 'active' : ''}`}
          >
            Mes œuvres {ratedCount > 0 && `(${ratedCount})`}
          </button>
        </div>
      </div>

      <div className="search-container">
        <div className="search-input-group">
          <input
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyPress={handleKeyPress}
            placeholder="Rechercher une œuvre, un artiste..."
            className="search-input"
          />
          <button onClick={onSearch} className="search-button">Rechercher</button>
        </div>
      </div>

      <div className="user-menu">
        {isAuthenticated && user ? (
          <>
            <button className="user-button" onClick={() => setShowMenu(!showMenu)}>
              <span className="user-avatar">{getInitials(user.username)}</span>
              <span className="user-name">{user.username}</span>
            </button>
            
            {showMenu && (
              <div className="dropdown-menu">
                {/* En-tête avec infos utilisateur */}
                <div className="dropdown-header">
                  <p style={{ 
                    fontSize: '1rem', 
                    fontWeight: '600', 
                    marginBottom: '0.25rem',
                    color: 'white'
                  }}>
                    {user.username}
                  </p>
                  <p style={{ 
                    fontSize: '0.8rem', 
                    color: 'var(--text-light)', 
                    marginBottom: '0.25rem' 
                  }}>
                    {user.email}
                  </p>
                  {user.created_at && (
                    <p style={{ 
                      fontSize: '0.7rem', 
                      color: 'var(--text-light)', 
                      opacity: 0.7,
                      marginTop: '0.25rem' 
                    }}>
                      Membre depuis le {formatDate(user.created_at)}
                    </p>
                  )}
                </div>

                {/* Bouton Changer le mot de passe */}
                <button 
                  className="dropdown-item"
                  onClick={() => {
                    setShowMenu(false);
                    if (onChangePassword) onChangePassword();
                  }}
                  style={{
                    width: '100%',
                    padding: '0.75rem 1rem',
                    border: 'none',
                    background: 'none',
                    textAlign: 'left',
                    color: 'white',
                    fontSize: '0.9rem',
                    cursor: 'pointer',
                    transition: 'background 0.2s',
                    borderBottom: '1px solid var(--border)'
                  }}
                  onMouseEnter={(e) => e.target.style.background = 'rgba(255,255,255,0.1)'}
                  onMouseLeave={(e) => e.target.style.background = 'none'}
                >
                  🔑 Changer le mot de passe
                </button>

                {/* Bouton Supprimer le compte */}
                <button 
                  className="dropdown-item"
                  onClick={() => {
                    setShowMenu(false);
                    onShowDeleteConfirm();
                  }}
                  style={{
                    width: '100%',
                    padding: '0.75rem 1rem',
                    border: 'none',
                    background: 'none',
                    textAlign: 'left',
                    color: '#ff6b6b',
                    fontSize: '0.9rem',
                    cursor: 'pointer',
                    transition: 'background 0.2s'
                  }}
                  onMouseEnter={(e) => e.target.style.background = 'rgba(255,107,107,0.1)'}
                  onMouseLeave={(e) => e.target.style.background = 'none'}
                >
                  🗑️ Supprimer le compte
                </button>

                {/* Bouton Déconnexion */}
                <button 
                  className="dropdown-item logout"
                  onClick={() => {
                    localStorage.removeItem('token');
                    localStorage.removeItem('user');
                    window.location.reload();
                  }}
                  style={{
                    width: '100%',
                    padding: '0.75rem 1rem',
                    border: 'none',
                    background: 'none',
                    textAlign: 'left',
                    color: 'var(--text-light)',
                    fontSize: '0.9rem',
                    cursor: 'pointer',
                    transition: 'background 0.2s',
                    borderTop: '1px solid var(--border)'
                  }}
                  onMouseEnter={(e) => e.target.style.background = 'rgba(255,255,255,0.1)'}
                  onMouseLeave={(e) => e.target.style.background = 'none'}
                >
                  🚪 Déconnexion
                </button>
              </div>
            )}
          </>
        ) : (
          <button className="user-button" onClick={onShowAuth}>
            <span className="user-avatar">👤</span>
            <span className="user-name">Se connecter</span>
          </button>
        )}
      </div>
    </nav>
  );
};

export default Navbar;
