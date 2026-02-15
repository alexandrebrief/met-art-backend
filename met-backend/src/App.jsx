import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Login from './components/Login';
import Register from './components/Register';
import Navbar from './components/Navbar';
import Rating from './components/Rating';
import { fetchWithAuth } from './services/auth';
import './App.css';
import SliderRating from './components/SliderRating';
import ChangePassword from './components/ChangePassword';

function AppContent() {

  const [query, setQuery] = useState('');
  const [artworks, setArtworks] = useState([]);
  const [selectedArtwork, setSelectedArtwork] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showFavorites, setShowFavorites] = useState(false);
  const [showRated, setShowRated] = useState(false);
  const [favorites, setFavorites] = useState([]);
  const [ratedArtworks, setRatedArtworks] = useState([]);
  const [showAuth, setShowAuth] = useState(false);
  const [authMode, setAuthMode] = useState('login');
  const [ratings, setRatings] = useState({});
  const [stats, setStats] = useState({ metTotal: 0 });
  const [departments, setDepartments] = useState([]);
  const [selectedDepartment, setSelectedDepartment] = useState(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);

  console.log('🔍 authMode =', authMode);
  console.log('🔍 showAuth =', showAuth);
  
  // États pour la pagination de recherche
  const [searchPage, setSearchPage] = useState(1);
  const [searchPagination, setSearchPagination] = useState({
    currentPage: 1,
    totalPages: 1,
    totalResults: 0,
    hasNext: false,
    hasPrev: false
  });

  const [showChangePassword, setShowChangePassword] = useState(false); 
  const { user, isAuthenticated, logout } = useAuth();

  useEffect(() => {
    fetchStats();
    fetchDepartments();
    fetchArtworks();
  }, []);

  useEffect(() => {
    if (showFavorites && isAuthenticated) fetchFavorites();
  }, [showFavorites, isAuthenticated]);

  useEffect(() => {
    if (showRated && isAuthenticated) fetchRatedArtworks();
  }, [showRated, isAuthenticated]);

  const fetchStats = async () => {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/stats`);
      const data = await res.json();
      setStats(data);
    } catch (err) {
      console.error('Erreur stats:', err);
    }
  };

  const fetchDepartments = async () => {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/departments`);
      const data = await res.json();
      setDepartments(data);
    } catch (err) {
      console.error('Erreur départements:', err);
    }
  };

  const fetchArtworks = async () => {
    setLoading(true);
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/artworks`);
      const data = await res.json();
      setArtworks(data.artworks || []);
    } catch (err) {
      console.error('Erreur chargement:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchFavorites = async () => {
    setLoading(true);
    try {
      const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/favorites`);
      const data = await res.json();
      setFavorites(data.artworks || []);
    } catch (err) {
      console.error('Erreur favoris:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchRatedArtworks = async () => {
    setLoading(true);
    try {
      const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/user/rated-artworks`);
      const data = await res.json();
      setRatedArtworks(data.artworks || []);
      
      const ratingsMap = {};
      (data.artworks || []).forEach(art => {
        ratingsMap[art.id] = {
          overall_rating: art.overall_rating,
          technique_rating: art.technique_rating,
          originality_rating: art.originality_rating,
          emotion_rating: art.emotion_rating
        };
      });
      setRatings(prev => ({ ...prev, ...ratingsMap }));
    } catch (err) {
      console.error('Erreur chargement notées:', err);
    } finally {
      setLoading(false);
    }
  };

const fetchDepartmentArtworks = async (department) => {
  setLoading(true);
  setSelectedDepartment(department);
  setShowFavorites(false);
  setShowRated(false);
  try {
    const res = await fetch(
      `${import.meta.env.VITE_API_URL}/api/artworks/by-department/${encodeURIComponent(department)}`
    );
    const data = await res.json();
    setArtworks(data.artworks || []);
  } catch (err) {
    console.error('Erreur chargement département:', err);
  } finally {
    setLoading(false);
  }
};

  const handleSearch = async (page = 1) => {
    if (!query.trim()) return;
    setLoading(page === 1);
    setSelectedDepartment(null);
    setShowFavorites(false);
    setShowRated(false);
    try {
      const res = await fetch(
        `${import.meta.env.VITE_API_URL}/api/search?q=${encodeURIComponent(query)}&page=${page}`
      );
      const data = await res.json();
    // 👇 AJOUTE LE CONSOLE.LOG ICI
    console.log('📦 Réponse backend:', {
      artworksCount: data.artworks?.length,
      pagination: data.pagination
    });      

      if (page === 1) {
        setArtworks(data.artworks || []);
      } else {
        setArtworks(prev => [...prev, ...(data.artworks || [])]);
      }
      
      setSearchPagination(data.pagination || {
        currentPage: 1,
        totalPages: 1,
        totalResults: 0,
        hasNext: false,
        hasPrev: false
      });
      setSearchPage(page);
      
    } catch (err) {
      console.error('Erreur recherche:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRatingChange = async (artworkId, criteria, value) => {
    const current = ratings[artworkId] || {
      overall_rating: 0,
      technique_rating: 0,
      originality_rating: 0,
      emotion_rating: 0
    };
    const updated = { ...current, [criteria]: value };
    setRatings(prev => ({ ...prev, [artworkId]: updated }));
    
    if (isAuthenticated) {
      try {
        await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/ratings/${artworkId}`, {
          method: 'POST',
          body: JSON.stringify({
            overall: updated.overall_rating,
            technique: updated.technique_rating,
            originality: updated.originality_rating,
            emotion: updated.emotion_rating
          })
        });
        if (showRated) fetchRatedArtworks();
      } catch (err) {
        console.error('Erreur sauvegarde note:', err);
      }
    }
  };

  const toggleFavorite = async (artwork, e) => {
    e.stopPropagation();
    if (!isAuthenticated) {
      setShowAuth(true);
      return;
    }
    try {
      const isFav = favorites.some(f => f.id === artwork.id);
      if (isFav) {
        await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/favorites/${artwork.id}`, { method: 'DELETE' });
        setFavorites(prev => prev.filter(f => f.id !== artwork.id));
      } else {
        await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/favorites/${artwork.id}`, { method: 'POST' });
        setFavorites(prev => [...prev, artwork]);
      }
    } catch (err) {
      console.error('Erreur favori:', err);
    }
  };

  const handleDeleteAccount = async () => {
    try {
      await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/auth/delete-account`, { method: 'DELETE' });
      logout();
      window.location.reload();
    } catch (err) {
      console.error('Erreur suppression compte:', err);
    }
  };

  const displayedArtworks = showFavorites ? favorites : showRated ? ratedArtworks : artworks;

  if (showAuth && !isAuthenticated) {
    return (
      <div className="auth-container">
        {authMode === 'login' ? (
<Login 
  onToggleForm={() => {
    console.log('🟠 onToggleForm appelé dans App.jsx');
    setAuthMode('register');
    console.log('🔵 authMode après set:', 'register');
  }}
  onLoginSuccess={() => setShowAuth(false)}
  onForgotPassword={() => setShowForgotPassword(true)}
/>
        ) : (
          <Register 
            onToggleForm={() => setAuthMode('login')}
            onRegisterSuccess={() => setShowAuth(false)}
          />
        )}
      </div>
    );
  }

  return (
    <div className="app-container">
      <Navbar 
        onShowFavorites={() => {
          setShowFavorites(true);
          setShowRated(false);
          setSelectedDepartment(null);
          if (isAuthenticated) fetchFavorites();
        }}
        onShowAll={() => {
          setShowFavorites(false);
          setShowRated(false);
          setSelectedDepartment(null);
          setQuery('');
          fetchArtworks();
        }}
        onShowRated={() => {
          setShowRated(true);
          setShowFavorites(false);
          setSelectedDepartment(null);
          if (isAuthenticated) fetchRatedArtworks();
        }}
        onShowAuth={() => setShowAuth(true)}
        showFavorites={showFavorites}
        showRated={showRated}
        favoritesCount={favorites.length}
        ratedCount={ratedArtworks.length}
        query={query}
        setQuery={setQuery}
        onSearch={() => handleSearch(1)}
        isAuthenticated={isAuthenticated}
        user={user}
        onShowDeleteConfirm={() => setShowDeleteConfirm(true)}
  onChangePassword={() => setShowChangePassword(true)}
      />

      {/* Statistiques */}
      <div className="stats-bar">
        <div className="stat-item">
          <div className="stat-value">{stats.metTotal?.toLocaleString() || 0}</div>
          <div className="stat-label">Œuvres au MET</div>
        </div>
      </div>

      {/* Départements */}
      {!showFavorites && !showRated && !selectedDepartment && !query && (
        <div className="departments-section">
          <h2 className="departments-title">Explorez par département</h2>
          <div className="departments-grid">
            {departments.map(dept => (
              <div
                key={dept}
                className="department-card"
                onClick={() => fetchDepartmentArtworks(dept)}
              >
                <div className="department-name">{dept}</div>
              </div>
            ))}
          </div>
        </div>
      )}

{/* Titre et indicateur de recherche */}
{(showFavorites || showRated || selectedDepartment || (query && !loading)) && (
  <div className="view-header">
    <h2>
      {showFavorites ? 'Mes favoris' : 
       showRated ? 'Mes œuvres' : 
       selectedDepartment ? selectedDepartment :
       query ? `Résultats pour "${query}"` : ''}
    </h2>
    
    {/* Indicateur de recherche */}
    {query && !showFavorites && !showRated && !selectedDepartment && !loading && (
      <div className="search-stats">
        <span className="search-total">{searchPagination.totalResults} œuvres trouvées</span>
        <span className="search-loaded">({artworks.length} affichées)</span>
      </div>
    )}
  </div>
)}

      {/* Grille */}
      {loading ? (
        <div style={{ textAlign: 'center', padding: '2rem' }}>
          <div className="spinner"></div>
          <p style={{ color: 'var(--text-light)', marginTop: '1rem' }}>
            Recherche en cours...
          </p>
        </div>
      ) : (
        <>
          {displayedArtworks.length === 0 ? (
            <div className="empty-state">
              <div className="empty-state-icon">🔍</div>
              <h3 className="empty-state-title">Aucun résultat</h3>
              <p className="empty-state-text">
                {showFavorites ? 'Ajoutez des œuvres à vos favoris' :
                 showRated ? 'Notez des œuvres pour les voir apparaître' :
                 'Essayez une autre recherche'}
              </p>
            </div>
          ) : (
            <>
              <div className="artworks-grid">
                {displayedArtworks.map(art => {
                  const isFavorite = favorites.some(f => f.id === art.id);
                  const artRating = ratings[art.id] || {};
                  return (
                    <div
                      key={art.id}
                      className="artwork-card"
                      onClick={() => setSelectedArtwork(art)}
                    >
                      <div className="artwork-image-container">
                        {art.image ? (
                          <img src={art.image} alt={art.title} className="artwork-image" />
                        ) : (
                          <div className="no-image"></div>
                        )}
                        <button
                          onClick={(e) => toggleFavorite(art, e)}
                          className={`favorite-button ${isFavorite ? 'active' : ''}`}
                        >
                          {isFavorite ? '★' : '☆'}
                        </button>
                      </div>
                      <div className="artwork-content">
                        <h3 className="artwork-title">{art.title}</h3>
                        <p className="artwork-artist">{art.artist}</p>
                        <div className="artwork-meta">
                          <span>{art.date || 'Date inconnue'}</span>
                          {artRating.overall_rating > 0 && (
                            <span>★ {artRating.overall_rating.toFixed(1)}</span>
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Bouton Voir plus pour la recherche */}
              {query && !showFavorites && !showRated && !selectedDepartment && 
               searchPagination.hasNext && (
                <div className="load-more-container">
                  <button
                    onClick={() => handleSearch(searchPage + 1)}
                    className="load-more-button"
                  >
                    Voir plus ({searchPagination.totalResults - (searchPage * 50)} restantes)
                  </button>
                </div>
              )}
            </>
          )}
        </>
      )}






{selectedArtwork && (
  <div className="modal-overlay" onClick={() => setSelectedArtwork(null)}>
    <div className="modal" onClick={e => e.stopPropagation()}>
      <button className="modal-close" onClick={() => setSelectedArtwork(null)}>✕</button>
      
      <div style={{ 
        display: 'flex', 
        flexDirection: 'row',
        height: '85vh',
        maxHeight: '900px'
      }}>
        {/* Partie image - 70% */}
        <div style={{ 
          flex: 7,
          background: 'rgba(0,0,0,0.3)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: 0
        }}>
          {selectedArtwork.image ? (
            <img 
              src={selectedArtwork.image} 
              alt={selectedArtwork.title} 
              style={{
                width: '100%',
                height: '100%',
                objectFit: 'contain',
                backgroundColor: 'rgba(0,0,0,0.3)'
              }}
            />
          ) : (
            <div style={{ color: 'white' }}>Pas d'image disponible</div>
          )}
        </div>

        {/* Partie infos - 30% PLUS LARGE qu'avant (30% au lieu de 25%) */}
        <div style={{ 
          flex: 3,
          padding: '1rem 1.2rem 1rem 1rem',  // Marges ajustées
          overflowY: 'auto',
          background: 'var(--primary-light)',
          fontFamily: 'var(--font-sans)'
        }}>
          {/* Titre */}
          <h2 style={{ 
            fontSize: '1.4rem',
            fontWeight: '600',
            margin: '0 0 0.3rem 0',
            fontFamily: 'var(--font-serif)',
            color: 'white',
            lineHeight: '1.3',
            letterSpacing: '-0.01em'
          }}>
            {selectedArtwork.title}
          </h2>
          
          {/* Artiste */}
          <p style={{ 
            fontSize: '1rem',
            fontWeight: '500',
            color: 'var(--accent)',
            marginBottom: '0.5rem',
            fontFamily: 'var(--font-sans)'
          }}>
            {selectedArtwork.artist}
          </p>
          
          {/* Bio */}
          {selectedArtwork.artistDisplayBio && (
            <p style={{ 
              fontSize: '0.8rem',
              fontWeight: '300',
              color: 'var(--text-light)',
              marginBottom: '1rem',
              lineHeight: '1.5',
              fontStyle: 'italic'
            }}>
              {selectedArtwork.artistDisplayBio}
            </p>
          )}

          {/* Détails avec barres dorées - plus compact */}
          <div style={{ marginBottom: '1rem' }}>
            {selectedArtwork.date && (
              <div style={{ marginBottom: '0.6rem' }}>
                <div style={{ borderLeft: '3px solid var(--accent)', paddingLeft: '0.5rem' }}>
                  <span style={{ 
                    fontSize: '0.6rem', 
                    fontWeight: '600',
                    color: 'var(--text-light)', 
                    display: 'block', 
                    marginBottom: '0.1rem',
                    letterSpacing: '0.5px',
                    textTransform: 'uppercase'
                  }}>
                    DATE
                  </span>
                  <span style={{ 
                    fontSize: '0.8rem',
                    fontWeight: '400',
                    color: 'white',
                    lineHeight: '1.3'
                  }}>
                    {selectedArtwork.date}
                  </span>
                </div>
              </div>
            )}
            
            {selectedArtwork.medium && (
              <div style={{ marginBottom: '0.6rem' }}>
                <div style={{ borderLeft: '3px solid var(--accent)', paddingLeft: '0.5rem' }}>
                  <span style={{ 
                    fontSize: '0.6rem', 
                    fontWeight: '600',
                    color: 'var(--text-light)', 
                    display: 'block', 
                    marginBottom: '0.1rem',
                    letterSpacing: '0.5px',
                    textTransform: 'uppercase'
                  }}>
                    MEDIUM
                  </span>
                  <span style={{ 
                    fontSize: '0.8rem',
                    fontWeight: '400',
                    color: 'white',
                    lineHeight: '1.3'
                  }}>
                    {selectedArtwork.medium}
                  </span>
                </div>
              </div>
            )}
            
            {selectedArtwork.dimensions && (
              <div style={{ marginBottom: '0.6rem' }}>
                <div style={{ borderLeft: '3px solid var(--accent)', paddingLeft: '0.5rem' }}>
                  <span style={{ 
                    fontSize: '0.6rem', 
                    fontWeight: '600',
                    color: 'var(--text-light)', 
                    display: 'block', 
                    marginBottom: '0.1rem',
                    letterSpacing: '0.5px',
                    textTransform: 'uppercase'
                  }}>
                    DIMENSIONS
                  </span>
                  <span style={{ 
                    fontSize: '0.8rem',
                    fontWeight: '400',
                    color: 'white',
                    lineHeight: '1.3'
                  }}>
                    {selectedArtwork.dimensions}
                  </span>
                </div>
              </div>
            )}
            
            {selectedArtwork.department && (
              <div style={{ marginBottom: '0.6rem' }}>
                <div style={{ borderLeft: '3px solid var(--accent)', paddingLeft: '0.5rem' }}>
                  <span style={{ 
                    fontSize: '0.6rem', 
                    fontWeight: '600',
                    color: 'var(--text-light)', 
                    display: 'block', 
                    marginBottom: '0.1rem',
                    letterSpacing: '0.5px',
                    textTransform: 'uppercase'
                  }}>
                    DÉPARTEMENT
                  </span>
                  <span style={{ 
                    fontSize: '0.8rem',
                    fontWeight: '400',
                    color: 'white',
                    lineHeight: '1.3'
                  }}>
                    {selectedArtwork.department}
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Lien MET - plus compact */}
          {selectedArtwork.objectURL && (
            <a
              href={selectedArtwork.objectURL}
              target="_blank"
              rel="noopener noreferrer"
              style={{
                display: 'block',
                marginBottom: '0.8rem',
                padding: '0.4rem',
                background: 'rgba(255,255,255,0.05)',
                color: 'white',
                textDecoration: 'none',
                borderRadius: '4px',
                fontSize: '0.75rem',
                fontWeight: '400',
                textAlign: 'center',
                border: '1px solid rgba(255,255,255,0.1)'
              }}
            >
              Voir sur le site du MET
            </a>
          )}

          {/* Séparateur - plus fin */}
          <div style={{ 
            borderTop: '1px solid rgba(196, 154, 108, 0.3)',
            margin: '0.8rem 0 0.8rem 0',
            width: '40px'
          }}></div>

          {/* Section notation */}
          {isAuthenticated && (
            <div>
              <h3 style={{ 
                fontSize: '0.85rem',
                fontWeight: '600',
                marginBottom: '0.8rem',
                color: 'white',
                letterSpacing: '1px',
                textTransform: 'uppercase'
              }}>
                Votre avis
              </h3>
              
              {/* Note globale */}
              <div style={{ 
                display: 'flex', 
                alignItems: 'center', 
                gap: '0.5rem', 
                marginBottom: '0.6rem'
              }}>
                <span style={{ 
                  width: '65px', 
                  fontSize: '0.75rem',      
                  fontWeight: '500',        
                  color: 'var(--text-light)' 
                }}>
                  Globale
                </span>
                <Rating
                  value={ratings[selectedArtwork.id]?.overall_rating || 0}
                  onChange={v => handleRatingChange(selectedArtwork.id, 'overall_rating', v)}
                  size="small"
                />
              </div>
              
              {/* Technique */}
              <SliderRating
                label="Technique"
                value={ratings[selectedArtwork.id]?.technique_rating || 0}
                onChange={v => handleRatingChange(selectedArtwork.id, 'technique_rating', v)}
              />
              
              {/* Originalité */}
              <SliderRating
                label="Originalité"
                value={ratings[selectedArtwork.id]?.originality_rating || 0}
                onChange={v => handleRatingChange(selectedArtwork.id, 'originality_rating', v)}
              />
              
              {/* Émotion */}
              <SliderRating
                label="Émotion"
                value={ratings[selectedArtwork.id]?.emotion_rating || 0}
                onChange={v => handleRatingChange(selectedArtwork.id, 'emotion_rating', v)}
              />
            </div>
          )}

          {/* Message non connecté - plus compact */}
          {!isAuthenticated && (
            <div style={{ 
              marginTop: '0.8rem',
              padding: '0.6rem',
              background: 'rgba(0,0,0,0.2)',
              borderRadius: '6px',
              textAlign: 'center',
              border: '1px dashed rgba(196, 154, 108, 0.3)'
            }}>
              <p style={{ 
                fontSize: '0.75rem',
                fontWeight: '300',
                marginBottom: '0.5rem',
                color: 'var(--text-light)'
              }}>
                Connectez-vous pour noter
              </p>
              <button
                onClick={() => {
                  setSelectedArtwork(null);
                  setShowAuth(true);
                }}
                style={{
                  padding: '0.25rem 1rem',
                  background: 'var(--accent)',
                  color: 'var(--primary)',
                  border: 'none',
                  borderRadius: '20px',
                  cursor: 'pointer',
                  fontSize: '0.75rem',
                  fontWeight: '500'
                }}
              >
                Se connecter
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  </div>
)}





{/* Confirmation suppression compte */}
{showDeleteConfirm && (
  <div className="modal-overlay" onClick={() => setShowDeleteConfirm(false)}>
    <div className="modal" onClick={e => e.stopPropagation()} style={{ 
      maxWidth: '400px',
      padding: '2rem'  // ← AJOUT DE MARGES INTERNES
    }}>
      <button className="modal-close" onClick={() => setShowDeleteConfirm(false)}>✕</button>
      
      <h2 style={{ 
        fontFamily: 'var(--font-serif)', 
        fontSize: '1.6rem',
        color: 'white',
        marginBottom: '1.5rem',  // ← ESPACE SOUS LE TITRE
        textAlign: 'center',
        paddingTop: '0.5rem'
      }}>
        Supprimer le compte
      </h2>
      
      <p style={{ 
        color: 'var(--text-light)',
        marginBottom: '2rem',  // ← ESPACE SOUS LE MESSAGE
        textAlign: 'center',
        lineHeight: '1.6',
        fontSize: '0.95rem'
      }}>
        Êtes-vous sûr de vouloir supprimer votre compte ?<br />
        <span style={{ color: '#ff6b6b', fontWeight: '500' }}>
          Cette action est irréversible.
        </span>
      </p>
      
      <div style={{ 
        display: 'flex', 
        gap: '1rem', 
        justifyContent: 'center'
      }}>
        <button 
          onClick={handleDeleteAccount} 
          style={{
            flex: 1,
            padding: '0.75rem',
            background: '#dc3545',
            color: 'white',
            border: 'none',
            borderRadius: '8px',
            fontWeight: '500',
            fontSize: '0.95rem',
            cursor: 'pointer',
            transition: 'all 0.2s'
          }}
          onMouseEnter={(e) => e.target.style.background = '#c82333'}
          onMouseLeave={(e) => e.target.style.background = '#dc3545'}
        >
          Supprimer
        </button>
        
        <button 
          onClick={() => setShowDeleteConfirm(false)} 
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
    </div>
  </div>
)}
      
      
            {/* Modal de changement de mot de passe */}
      {showChangePassword && (
        <ChangePassword onClose={() => setShowChangePassword(false)} />
      )}

      

      {/* Footer */}
      <footer className="footer">
        <div className="footer-links">
          <a href="/mentions-legales" className="footer-link">Mentions légales</a>
          <a href="/donnees-personnelles" className="footer-link">Données personnelles</a>
          <a href="/contact" className="footer-link">Contact</a>
        </div>
        <div className="copyright">
          © 2025 MET Art Explorer
        </div>
      </footer>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
