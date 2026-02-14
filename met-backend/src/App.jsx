import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Login from './components/Login';
import Register from './components/Register';
import Navbar from './components/Navbar';
import Rating from './components/Rating';
import { fetchWithAuth } from './services/auth';

function AppContent() {
  const [query, setQuery] = useState('');
  const [artworks, setArtworks] = useState([]);
  const [selectedArtwork, setSelectedArtwork] = useState(null);
  const [loading, setLoading] = useState(false);
  const [searchMode, setSearchMode] = useState('met');
  const [metFilter, setMetFilter] = useState('all');
  const [showFavorites, setShowFavorites] = useState(false);
  const [showRated, setShowRated] = useState(false);
  const [favorites, setFavorites] = useState([]);
  const [ratedArtworks, setRatedArtworks] = useState([]);
  const [showAuth, setShowAuth] = useState(false);
  const [authMode, setAuthMode] = useState('login');
  const [ratings, setRatings] = useState({});
  const [showRatingPanel, setShowRatingPanel] = useState(false);
  
  const { user, isAuthenticated } = useAuth();

  // États pour la pagination
  const [pagination, setPagination] = useState({
    page: 1,
    limit: 20,
    total: 0,
    pages: 0,
    hasNext: false,
    hasPrev: false
  });
  
  const [loadingMore, setLoadingMore] = useState(false);

  // Rediriger vers l'auth si non connecté et essaie d'accéder aux fonctionnalités protégées
  useEffect(() => {
    if (!isAuthenticated && (showFavorites || showRated)) {
      setShowAuth(true);
    }
  }, [isAuthenticated, showFavorites, showRated]);

  // Charge toutes les œuvres au démarrage
  useEffect(() => {
    if (isAuthenticated) {
      fetchArtworks(1);
    }
  }, [isAuthenticated]);

  // Charge les favoris quand on change de vue
  useEffect(() => {
    if (showFavorites && isAuthenticated) {
      fetchFavorites(1);
    }
  }, [showFavorites, isAuthenticated]);

  // Charge les œuvres notées quand on change de vue
  useEffect(() => {
    if (showRated && isAuthenticated) {
      fetchRatedArtworks(1);
    }
  }, [showRated, isAuthenticated]);

  const fetchArtworks = async (page = 1) => {
    setLoading(page === 1);
    setLoadingMore(page > 1);
    try {
      const res = await fetch(`${import.meta.env.VITE_API_URL}/api/artworks?page=${page}&limit=${pagination.limit}`);
      const data = await res.json();
      
      if (page === 1) {
        setArtworks(data.artworks || []);
      } else {
        setArtworks(prev => [...prev, ...(data.artworks || [])]);
      }
      
      setPagination(data.pagination || {
        page: 1,
        total: 0,
        pages: 0,
        hasNext: false,
        hasPrev: false
      });
    } catch (err) {
      console.error('Erreur chargement:', err);
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  const fetchFavorites = async (page = 1) => {
    setLoading(page === 1);
    setLoadingMore(page > 1);
    try {
      const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/favorites?page=${page}&limit=${pagination.limit}`);
      const data = await res.json();
      
      if (page === 1) {
        setFavorites(data.artworks || []);
      } else {
        setFavorites(prev => [...prev, ...(data.artworks || [])]);
      }
      
      setPagination(data.pagination || {
        page: 1,
        total: 0,
        pages: 0,
        hasNext: false,
        hasPrev: false
      });
    } catch (err) {
      console.error('Erreur chargement favoris:', err);
      setFavorites([]);
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  const fetchRatedArtworks = async (page = 1) => {
    setLoading(page === 1);
    setLoadingMore(page > 1);
    try {
      const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/user/rated-artworks?page=${page}&limit=${pagination.limit}`);
      const data = await res.json();
      
      if (page === 1) {
        setRatedArtworks(data.artworks || []);
      } else {
        setRatedArtworks(prev => [...prev, ...(data.artworks || [])]);
      }
      
      setPagination(data.pagination || {
        page: 1,
        total: 0,
        pages: 0,
        hasNext: false,
        hasPrev: false
      });

      // Charger les notes dans le state ratings
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
      console.error('Erreur chargement œuvres notées:', err);
      setRatedArtworks([]);
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  const loadRating = async (artworkId) => {
    if (!isAuthenticated) return;
    try {
      const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/ratings/${artworkId}`);
      const data = await res.json();
      setRatings(prev => ({
        ...prev,
        [artworkId]: data
      }));
    } catch (err) {
      console.error('Erreur chargement note:', err);
    }
  };

// Dans App.jsx - Remplacer la fonction saveRating par celle-ci
const saveRating = async (artworkId, ratingData) => {
  if (!isAuthenticated) {
    setShowAuth(true);
    return;
  }
  
  try {
    console.log('Sauvegarde de la note:', { artworkId, ratingData });
    
    const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/ratings/${artworkId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        overall: ratingData.overall_rating || 0,
        technique: ratingData.technique_rating || 0,
        originality: ratingData.originality_rating || 0,
        emotion: ratingData.emotion_rating || 0
      })
    });
    
    if (res.ok) {
      console.log('Note sauvegardée avec succès');
      
      // Mettre à jour le state local
      setRatings(prev => ({
        ...prev,
        [artworkId]: ratingData
      }));
      
      // Rafraîchir les œuvres notées si on est sur cette vue
      if (showRated) {
        fetchRatedArtworks(1);
      }
      
      // Afficher un message de succès (optionnel)
      alert('Note enregistrée !');
    } else {
      const error = await res.json();
      console.error('Erreur sauvegarde:', error);
      alert('Erreur lors de la sauvegarde');
    }
  } catch (err) {
    console.error('Erreur sauvegarde note:', err);
    alert('Erreur de connexion');
  }
};

  const toggleFavorite = async (artwork, event) => {
    event.stopPropagation();
    
    if (!isAuthenticated) {
      setShowAuth(true);
      return;
    }
    
    try {
      const isFav = favorites.some(f => f.id === artwork.id);
      
      if (isFav) {
        const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/favorites/${artwork.id}`, {
          method: 'DELETE'
        });
        
        if (res.ok) {
          setFavorites(prev => prev.filter(a => a.id !== artwork.id));
        }
      } else {
        const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/favorites/${artwork.id}`, {
          method: 'POST'
        });
        
        if (res.ok) {
          setFavorites(prev => [...prev, artwork]);
        }
      }
    } catch (err) {
      console.error('Erreur toggle favorite:', err);
    }
  };

  const handleLocalSearch = async (page = 1) => {
    if (!query.trim() && page === 1) {
      fetchArtworks(1);
      return;
    }
    
    setLoading(page === 1);
    setLoadingMore(page > 1);
    try {
      const res = await fetch(
        `${import.meta.env.VITE_API_URL}/api/artworks/search/local?q=${encodeURIComponent(query)}&page=${page}&limit=${pagination.limit}`
      );
      const data = await res.json();
      
      if (page === 1) {
        setArtworks(data.artworks || []);
      } else {
        setArtworks(prev => [...prev, ...(data.artworks || [])]);
      }
      
      setPagination(data.pagination || {
        page: 1,
        total: 0,
        pages: 0,
        hasNext: false,
        hasPrev: false
      });
    } catch (err) {
      console.error("Erreur recherche locale:", err);
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  const handleMetSearch = async (page = 1) => {
    if (!query.trim()) return;
    
    setLoading(page === 1);
    setLoadingMore(page > 1);
    try {
      const url = `${import.meta.env.VITE_API_URL}/api/artworks/search/met/filtered?q=${encodeURIComponent(query)}&filterBy=${metFilter}&page=${page}&limit=${pagination.limit}`;
      
      const res = await fetch(url);
      const data = await res.json();
      
      if (page === 1) {
        setArtworks(data.artworks || []);
      } else {
        setArtworks(prev => [...prev, ...(data.artworks || [])]);
      }
      
      setPagination(data.pagination || {
        page: 1,
        total: 0,
        pages: 0,
        hasNext: false,
        hasPrev: false
      });
    } catch (err) {
      console.error("Erreur recherche MET:", err);
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  const handleSearch = (page = 1) => {
    if (showFavorites || showRated) return;
    
    if (searchMode === "met") {
      handleMetSearch(page);
    } else {
      handleLocalSearch(page);
    }
  };

  const loadMore = () => {
    if (!pagination.hasNext || loadingMore) return;
    
    const nextPage = pagination.page + 1;
    
    if (showFavorites) {
      fetchFavorites(nextPage);
    } else if (showRated) {
      fetchRatedArtworks(nextPage);
    } else {
      handleSearch(nextPage);
    }
  };

const openModal = async (artwork) => {
  setSelectedArtwork(artwork);
  setShowRatingPanel(false);
  
  if (isAuthenticated) {
    try {
      console.log('Chargement de la note pour:', artwork.id);
      const res = await fetchWithAuth(`${import.meta.env.VITE_API_URL}/api/ratings/${artwork.id}`);
      
      if (res.ok) {
        const data = await res.json();
        console.log('Note chargée:', data);
        
        // Mettre à jour les notes dans le state
        setRatings(prev => ({
          ...prev,
          [artwork.id]: {
            overall_rating: data.overall_rating || 0,
            technique_rating: data.technique_rating || 0,
            originality_rating: data.originality_rating || 0,
            emotion_rating: data.emotion_rating || 0
          }
        }));
      }
    } catch (err) {
      console.error('Erreur chargement note:', err);
    }
  }
};

  const closeModal = () => {
    setSelectedArtwork(null);
    setShowRatingPanel(false);
  };

  // Détermine quelle liste afficher
  const getDisplayedArtworks = () => {
    if (showFavorites) return favorites;
    if (showRated) return ratedArtworks;
    return artworks;
  };

  const displayedArtworks = getDisplayedArtworks();

  const getPlaceholder = () => {
    if (searchMode === "local") {
      return "Rechercher dans ma collection (titre, artiste, ID...)";
    } else {
      switch(metFilter) {
        case "title":
          return "Rechercher dans le titre (ex: Sunflowers, Water Lilies...)";
        case "artist":
          return "Rechercher par artiste (ex: Monet, Van Gogh, Rembrandt...)";
        default:
          return "Rechercher dans tout le MET (titre, artiste, description...)";
      }
    }
  };

  // Gestion de l'authentification
  if (showAuth && !isAuthenticated) {
    return (
      <div style={styles.authContainer}>
        {authMode === 'login' ? (
          <Login 
            onToggleForm={() => setAuthMode('register')} 
            onLoginSuccess={() => {
              console.log('Login success, masquage auth');
              setShowAuth(false);
              fetchArtworks(1);
            }}
          />
        ) : (
          <Register 
            onToggleForm={() => setAuthMode('login')}
            onRegisterSuccess={() => {
              console.log('Register success, masquage auth');
              setShowAuth(false);
              fetchArtworks(1);
            }}
          />
        )}
      </div>
    );
  }

  return (
    <div style={styles.container}>
      <Navbar 
        onShowFavorites={() => {
          setShowFavorites(true);
          setShowRated(false);
          fetchFavorites(1);
        }}
        onShowAll={() => {
          setShowFavorites(false);
          setShowRated(false);
          fetchArtworks(1);
          setQuery('');
        }}
        onShowRated={() => {
          setShowRated(true);
          setShowFavorites(false);
          fetchRatedArtworks(1);
        }}
        onShowAuth={() => {
          setShowAuth(true);
          setAuthMode('login');
        }}
        showFavorites={showFavorites}
        showRated={showRated}
        favoritesCount={favorites.length}
        ratedCount={ratedArtworks.length}
      />

      {/* Barre de recherche (cachée dans les vues Favoris et Mes œuvres) */}
      {!showFavorites && !showRated && (
        <div style={styles.searchContainer}>
          <div style={styles.radioGroup}>
            <label style={styles.radioLabel}>
              <input
                type="radio"
                value="met"
                checked={searchMode === "met"}
                onChange={(e) => setSearchMode(e.target.value)}
              />
              🌐 Tout le MET
            </label>
            <label style={styles.radioLabel}>
              <input
                type="radio"
                value="local"
                checked={searchMode === "local"}
                onChange={(e) => setSearchMode(e.target.value)}
              />
              📍 Base locale
            </label>
          </div>

          {searchMode === "met" && (
            <div style={styles.filterGroup}>
              <span style={styles.filterLabel}>Filtrer par :</span>
              <label style={styles.filterOption}>
                <input
                  type="radio"
                  name="metFilter"
                  value="all"
                  checked={metFilter === "all"}
                  onChange={(e) => setMetFilter(e.target.value)}
                />
                🌐 Tout
              </label>
              <label style={styles.filterOption}>
                <input
                  type="radio"
                  name="metFilter"
                  value="title"
                  checked={metFilter === "title"}
                  onChange={(e) => setMetFilter(e.target.value)}
                />
                📝 Titre
              </label>
              <label style={styles.filterOption}>
                <input
                  type="radio"
                  name="metFilter"
                  value="artist"
                  checked={metFilter === "artist"}
                  onChange={(e) => setMetFilter(e.target.value)}
                />
                🖌️ Artiste
              </label>
            </div>
          )}
          
          <div style={styles.inputGroup}>
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSearch(1)}
              placeholder={getPlaceholder()}
              style={styles.input}
            />
            <button 
              onClick={() => handleSearch(1)} 
              style={styles.button}
              disabled={loading}
            >
              {loading ? "Chargement..." : "Rechercher"}
            </button>
          </div>

          {pagination.total > 0 && (
            <div style={styles.paginationInfo}>
              {pagination.total} résultat(s) • Page {pagination.page}/{pagination.pages}
            </div>
          )}
        </div>
      )}

      {/* Titre de la vue actuelle */}
      <div style={styles.viewHeader}>
        <h2>
          {showFavorites ? '⭐ Mes favoris' : 
           showRated ? '📊 Mes œuvres notées' : 
           '🖼️ Toutes les œuvres'}
          {displayedArtworks.length > 0 && ` (${displayedArtworks.length})`}
        </h2>
      </div>

      {/* Résultats */}
      <div style={styles.resultsContainer}>
        {loading && displayedArtworks.length === 0 ? (
          <p style={styles.loading}>Chargement...</p>
        ) : (
          <>
<div style={styles.grid}>
  {displayedArtworks.map((art) => {
    const isFavorite = favorites.some(f => f.id === art.id);
    const artworkRating = ratings[art.id] || {};
    
    return (
      <div
        key={art.id}
        style={styles.card}
        onClick={() => openModal(art)}
      >
        <div style={styles.cardImageContainer}>
          {art.image ? (
            <img
              src={art.image}
              alt={art.title}
              style={styles.cardImage}
            />
          ) : (
            <div style={styles.noImage}>
              Pas d'image
            </div>
          )}
          
          <button
            onClick={(e) => toggleFavorite(art, e)}
            style={{
              ...styles.favoriteButton,
              backgroundColor: isFavorite ? '#ffd700' : 'white',
              color: isFavorite ? '#000' : '#666'
            }}
          >
            {isFavorite ? '★' : '☆'}
          </button>
        </div>

        <div style={styles.cardContent}>
          <h3 style={styles.cardTitle}>{art.title}</h3>
          <p style={styles.cardArtist}>{art.artist}</p>
          <p style={styles.cardDate}>{art.date || "Date inconnue"}</p>
          
          {/* Indicateur de note visible sur TOUTES les vues si l'œuvre est notée */}
          {artworkRating.overall_rating > 0 && (
            <div style={styles.cardRating}>
              <Rating 
                value={artworkRating.overall_rating} 
                interactive={false} 
                size="small"
              />
              <span style={styles.ratingBadge}>
                {artworkRating.overall_rating.toFixed(1)}
              </span>
            </div>
          )}
        </div>
      </div>
    );
  })}
</div>

            {pagination.hasNext && !loading && (
              <div style={styles.loadMoreContainer}>
                <button
                  onClick={loadMore}
                  style={styles.loadMoreButton}
                  disabled={loadingMore}
                >
                  {loadingMore ? "Chargement..." : "⬇️ Voir plus d'œuvres"}
                </button>
              </div>
            )}

            {displayedArtworks.length === 0 && !loading && (
              <p style={styles.noResults}>
                {showFavorites 
                  ? "⭐ Aucun favori pour l'instant. Cliquez sur l'étoile d'une œuvre pour l'ajouter !" 
                  : showRated
                  ? "📊 Aucune œuvre notée pour l'instant. Notez des œuvres pour les voir apparaître ici !"
                  : "🔍 Aucune œuvre trouvée"}
              </p>
            )}
          </>
        )}
      </div>

      {/* Modal détaillé avec notation */}
      {selectedArtwork && (
        <div style={styles.modalOverlay} onClick={closeModal}>
          <div style={styles.modal} onClick={(e) => e.stopPropagation()}>
            <button style={styles.closeButton} onClick={closeModal}>✕</button>
            
            <h2 style={styles.modalTitle}>{selectedArtwork.title}</h2>
            
            {selectedArtwork.image && (
              <img
                src={selectedArtwork.image}
                alt={selectedArtwork.title}
                style={styles.modalImage}
              />
            )}
            
            <div style={styles.modalDetails}>
              <p><strong>Artiste :</strong> {selectedArtwork.artist}</p>
              {selectedArtwork.artistDisplayBio && (
                <p><strong>Bio :</strong> {selectedArtwork.artistDisplayBio}</p>
              )}
              {selectedArtwork.artistNationality && (
                <p><strong>Nationalité :</strong> {selectedArtwork.artistNationality}</p>
              )}
              
              <p><strong>Date :</strong> {selectedArtwork.date || "Non renseigné"}</p>
              <p><strong>Medium :</strong> {selectedArtwork.medium || "Non renseigné"}</p>
              <p><strong>Dimensions :</strong> {selectedArtwork.dimensions || "Non renseigné"}</p>
              
              {selectedArtwork.department && (
                <p><strong>Département :</strong> {selectedArtwork.department}</p>
              )}
              
              {selectedArtwork.culture && (
                <p><strong>Culture :</strong> {selectedArtwork.culture}</p>
              )}
              
              {selectedArtwork.creditLine && (
                <p><strong>Provenance :</strong> {selectedArtwork.creditLine}</p>
              )}
              
              {/* Section notation */}
              {isAuthenticated && (
                <div style={styles.ratingSection}>
                  <h3>Ma note</h3>
                  
                  {!showRatingPanel ? (
                    <div style={styles.ratingSummary}>
                      <Rating 
                        value={ratings[selectedArtwork.id]?.overall_rating || 0} 
                        onChange={() => setShowRatingPanel(true)}
                        interactive={false}
                      />
                      <button 
                        onClick={() => setShowRatingPanel(true)}
                        style={styles.rateButton}
                      >
                        {ratings[selectedArtwork.id]?.overall_rating ? 'Modifier' : 'Noter'}
                      </button>
                    </div>
                  ) : (
                    <div style={styles.ratingPanel}>
                      <div style={styles.ratingRow}>
                        <label>Note globale</label>
                        <Rating 
                          value={ratings[selectedArtwork.id]?.overall_rating || 0}
                          onChange={(value) => setRatings(prev => ({
                            ...prev,
                            [selectedArtwork.id]: {
                              ...prev[selectedArtwork.id],
                              overall_rating: value
                            }
                          }))}
                        />
                      </div>
                      
                      <div style={styles.ratingRow}>
                        <label>Technique</label>
                        <Rating 
                          value={ratings[selectedArtwork.id]?.technique_rating || 0}
                          onChange={(value) => setRatings(prev => ({
                            ...prev,
                            [selectedArtwork.id]: {
                              ...prev[selectedArtwork.id],
                              technique_rating: value
                            }
                          }))}
                        />
                      </div>
                      
                      <div style={styles.ratingRow}>
                        <label>Originalité</label>
                        <Rating 
                          value={ratings[selectedArtwork.id]?.originality_rating || 0}
                          onChange={(value) => setRatings(prev => ({
                            ...prev,
                            [selectedArtwork.id]: {
                              ...prev[selectedArtwork.id],
                              originality_rating: value
                            }
                          }))}
                        />
                      </div>
                      
                      <div style={styles.ratingRow}>
                        <label>Émotion</label>
                        <Rating 
                          value={ratings[selectedArtwork.id]?.emotion_rating || 0}
                          onChange={(value) => setRatings(prev => ({
                            ...prev,
                            [selectedArtwork.id]: {
                              ...prev[selectedArtwork.id],
                              emotion_rating: value
                            }
                          }))}
                        />
                      </div>
                      
                      <div style={styles.ratingActions}>
                        <button 
                          onClick={() => {
                            saveRating(selectedArtwork.id, ratings[selectedArtwork.id]);
                            setShowRatingPanel(false);
                          }}
                          style={styles.saveButton}
                        >
                          Enregistrer
                        </button>
                        <button 
                          onClick={() => setShowRatingPanel(false)}
                          style={styles.cancelButton}
                        >
                          Annuler
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              )}
              
              {selectedArtwork.objectURL && (
                <p style={styles.link}>
                  <a href={selectedArtwork.objectURL} target="_blank" rel="noopener noreferrer">
                    🔗 Voir sur le site du MET
                  </a>
                </p>
              )}
            </div>
          </div>
        </div>
      )}
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

// Styles
const styles = {
  authContainer: {
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    backgroundColor: '#f5f5f5'
  },
  container: {
    maxWidth: '1200px',
    margin: '0 auto',
    padding: '2rem',
    fontFamily: 'Arial, sans-serif'
  },
  searchContainer: {
    marginBottom: '2rem',
    padding: '1rem',
    backgroundColor: '#f5f5f5',
    borderRadius: '8px'
  },
  radioGroup: {
    marginBottom: '1rem',
    display: 'flex',
    gap: '2rem'
  },
  radioLabel: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.5rem',
    cursor: 'pointer'
  },
  filterGroup: {
    marginBottom: '1rem',
    padding: '0.5rem',
    backgroundColor: '#e8f4fd',
    borderRadius: '4px',
    display: 'flex',
    gap: '1rem',
    alignItems: 'center',
    flexWrap: 'wrap'
  },
  filterLabel: {
    fontWeight: 'bold',
    color: '#0066cc'
  },
  filterOption: {
    display: 'flex',
    alignItems: 'center',
    gap: '0.3rem',
    cursor: 'pointer'
  },
  inputGroup: {
    display: 'flex',
    gap: '0.5rem'
  },
  input: {
    flex: 1,
    padding: '0.75rem',
    fontSize: '1rem',
    border: '2px solid #ddd',
    borderRadius: '4px',
    outline: 'none'
  },
  button: {
    padding: '0.75rem 1.5rem',
    fontSize: '1rem',
    backgroundColor: '#0066cc',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer'
  },
  paginationInfo: {
    marginTop: '0.5rem',
    textAlign: 'center',
    color: '#666',
    fontSize: '0.9rem'
  },
  viewHeader: {
    marginBottom: '1rem'
  },
  resultsContainer: {
    marginTop: '1rem'
  },
  loading: {
    textAlign: 'center',
    padding: '2rem'
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fill, minmax(250px, 1fr))',
    gap: '1.5rem',
    marginTop: '1rem'
  },
  card: {
    border: '1px solid #ddd',
    borderRadius: '8px',
    overflow: 'hidden',
    cursor: 'pointer',
    position: 'relative',
    transition: 'transform 0.2s'
  },
  cardImageContainer: {
    position: 'relative',
    height: '200px',
    backgroundColor: '#f0f0f0'
  },
  cardImage: {
    width: '100%',
    height: '100%',
    objectFit: 'cover'
  },
  noImage: {
    width: '100%',
    height: '100%',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    color: '#999'
  },
  favoriteButton: {
    position: 'absolute',
    top: '10px',
    right: '10px',
    width: '36px',
    height: '36px',
    borderRadius: '50%',
    border: 'none',
    fontSize: '20px',
    cursor: 'pointer',
    boxShadow: '0 2px 5px rgba(0,0,0,0.2)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: 0
  },
  cardContent: {
    padding: '1rem'
  },
  cardTitle: {
    margin: '0 0 0.5rem 0',
    fontSize: '1rem',
    fontWeight: 'bold'
  },
  cardArtist: {
    margin: '0.25rem 0',
    fontSize: '0.9rem',
    color: '#444'
  },
  cardDate: {
    margin: '0.25rem 0',
    fontSize: '0.8rem',
    color: '#666'
  },
cardRating: {
  marginTop: '0.75rem',
  display: 'flex',
  alignItems: 'center',
  gap: '0.5rem',
  padding: '0.25rem 0',
  borderTop: '1px solid #f0f0f0'
},
ratingBadge: {
  fontSize: '0.8rem',
  color: '#666',
  backgroundColor: '#f0f0f0',
  padding: '0.2rem 0.5rem',
  borderRadius: '12px',
  fontWeight: 'bold',
  minWidth: '35px',
  textAlign: 'center'
},
  loadMoreContainer: {
    textAlign: 'center',
    marginTop: '2rem'
  },
  loadMoreButton: {
    padding: '0.75rem 2rem',
    fontSize: '1rem',
    backgroundColor: '#0066cc',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer'
  },
  noResults: {
    textAlign: 'center',
    padding: '2rem',
    color: '#666',
    backgroundColor: '#f9f9f9',
    borderRadius: '8px'
  },
  modalOverlay: {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    bottom: 0,
    backgroundColor: 'rgba(0,0,0,0.7)',
    display: 'flex',
    justifyContent: 'center',
    alignItems: 'center',
    zIndex: 1000
  },
  modal: {
    backgroundColor: 'white',
    padding: '2rem',
    borderRadius: '12px',
    maxWidth: '600px',
    maxHeight: '90vh',
    overflowY: 'auto',
    position: 'relative'
  },
  closeButton: {
    position: 'absolute',
    top: '1rem',
    right: '1rem',
    background: 'none',
    border: 'none',
    fontSize: '1.5rem',
    cursor: 'pointer',
    width: '36px',
    height: '36px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    borderRadius: '50%'
  },
  modalTitle: {
    margin: '0 0 1.5rem 0',
    paddingRight: '2rem'
  },
  modalImage: {
    maxWidth: '100%',
    marginBottom: '1.5rem',
    borderRadius: '8px'
  },
  modalDetails: {
    lineHeight: '1.6'
  },
  ratingSection: {
    marginTop: '2rem',
    paddingTop: '1rem',
    borderTop: '1px solid #eee'
  },
  ratingSummary: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    marginTop: '0.5rem'
  },
  rateButton: {
    padding: '0.5rem 1rem',
    backgroundColor: '#0066cc',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer'
  },
  ratingPanel: {
    marginTop: '1rem',
    padding: '1rem',
    backgroundColor: '#f9f9f9',
    borderRadius: '8px'
  },
  ratingRow: {
    marginBottom: '1rem',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between'
  },
  ratingActions: {
    display: 'flex',
    gap: '0.5rem',
    justifyContent: 'flex-end',
    marginTop: '1rem'
  },
  saveButton: {
    padding: '0.5rem 1rem',
    backgroundColor: '#4caf50',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer'
  },
  cancelButton: {
    padding: '0.5rem 1rem',
    backgroundColor: '#f44336',
    color: 'white',
    border: 'none',
    borderRadius: '4px',
    cursor: 'pointer'
  },
  link: {
    marginTop: '1rem',
    textAlign: 'center'
  }
};

export default App;
