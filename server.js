// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

// db.js gère automatiquement SQLite (dev) ou PostgreSQL (prod)
const db = require('./db.js');
const { authenticateToken, JWT_SECRET } = require('./middleware/auth.js');

const app = express();

// Configuration CORS
app.use(cors({
  origin: [
    'https://met-art-frontend.vercel.app',
    'http://localhost:5173'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Middleware pour logger les requêtes
app.use((req, res, next) => {
  console.log(`[${new Date().toLocaleTimeString()}] ${req.method} ${req.url}`);
  next();
});

// ==================== ROUTES D'AUTHENTIFICATION ====================

// POST /api/auth/register - Inscription
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Tous les champs sont requis' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 6 caractères' });
    }

    // Vérifier si l'utilisateur existe déjà
    let existingUser;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
      existingUser = result.rows[0];
    } else {
      existingUser = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(email, username);
    }

    if (existingUser) {
      return res.status(400).json({ error: 'Email ou nom d\'utilisateur déjà utilisé' });
    }

    // Hacher le mot de passe
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Insérer l'utilisateur
    let newUser;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query(
        'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email, created_at',
        [username, email, passwordHash]
      );
      newUser = result.rows[0];
    } else {
      const stmt = db.prepare('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)');
      const result = stmt.run(username, email, passwordHash);
      newUser = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(result.lastInsertRowid);
    }

    // Créer le token JWT
    const token = jwt.sign(
      { id: newUser.id, username: newUser.username, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'Utilisateur créé avec succès',
      token,
      user: newUser
    });

  } catch (err) {
    console.error('Erreur inscription:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/auth/login - Connexion
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email et mot de passe requis' });
    }

    // Chercher l'utilisateur
    let userRecord;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
      userRecord = result.rows[0];
    } else {
      userRecord = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    }

    if (!userRecord) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    // Vérifier le mot de passe
    const validPassword = await bcrypt.compare(password, userRecord.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
    }

    // Récupérer l'utilisateur sans le mot de passe
    let user;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT id, username, email, created_at FROM users WHERE id = $1', [userRecord.id]);
      user = result.rows[0];
    } else {
      user = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(userRecord.id);
    }

    // Créer le token
    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Connexion réussie',
      token,
      user
    });

  } catch (err) {
    console.error('Erreur connexion:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/auth/me - Récupérer l'utilisateur connecté
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    let user;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT id, username, email, created_at FROM users WHERE id = $1', [req.user.id]);
      user = result.rows[0];
    } else {
      user = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(req.user.id);
    }

    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }
    res.json(user);
  } catch (err) {
    console.error('Erreur récupération utilisateur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== ROUTES ARTWORKS ====================

// GET /api/artworks - Liste toutes les œuvres avec pagination
app.get('/api/artworks', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    let total, artworks;

    if (process.env.NODE_ENV === 'production') {
      // PostgreSQL
      const totalResult = await db.query('SELECT COUNT(*) as count FROM artworks');
      total = parseInt(totalResult.rows[0].count);

      const artworksResult = await db.query(
        'SELECT * FROM artworks ORDER BY created_at DESC LIMIT $1 OFFSET $2',
        [limit, offset]
      );
      artworks = artworksResult.rows;
    } else {
      // SQLite
      total = db.prepare('SELECT COUNT(*) as count FROM artworks').get().count;
      artworks = db.prepare(`
        SELECT * FROM artworks 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
      `).all(limit, offset);
    }

    res.json({
      artworks,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    });
  } catch (err) {
    console.error('Erreur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/artworks/search/local - Recherche locale
app.get('/api/artworks/search/local', async (req, res) => {
  try {
    const { q } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;
    
    if (!q || q.trim() === '') {
      return res.json({ artworks: [], pagination: { total: 0, pages: 0 } });
    }

    const searchTerm = `%${q}%`;
    let totalCount, artworks;

    if (process.env.NODE_ENV === 'production') {
      // PostgreSQL
      const totalResult = await db.query(
        'SELECT COUNT(*) as count FROM artworks WHERE title ILIKE $1 OR artist ILIKE $1 OR CAST("metID" AS TEXT) ILIKE $1',
        [searchTerm]
      );
      totalCount = parseInt(totalResult.rows[0].count);

      const artworksResult = await db.query(
        `SELECT * FROM artworks 
         WHERE title ILIKE $1 OR artist ILIKE $1 OR CAST("metID" AS TEXT) ILIKE $1
         ORDER BY 
           CASE 
             WHEN title ILIKE $1 THEN 1
             WHEN artist ILIKE $1 THEN 2
             ELSE 3
           END
         LIMIT $2 OFFSET $3`,
        [searchTerm, limit, offset]
      );
      artworks = artworksResult.rows;
    } else {
      // SQLite
      totalCount = db.prepare(`
        SELECT COUNT(*) as count FROM artworks 
        WHERE title LIKE ? OR artist LIKE ? OR CAST(metID AS TEXT) LIKE ?
      `).get(searchTerm, searchTerm, searchTerm).count;

      artworks = db.prepare(`
        SELECT * FROM artworks 
        WHERE title LIKE ? 
           OR artist LIKE ? 
           OR CAST(metID AS TEXT) LIKE ?
        ORDER BY 
          CASE 
            WHEN title LIKE ? THEN 1
            WHEN artist LIKE ? THEN 2
            ELSE 3
          END
        LIMIT ? OFFSET ?
      `).all(searchTerm, searchTerm, searchTerm, searchTerm, searchTerm, limit, offset);
    }
    
    res.json({
      artworks,
      pagination: {
        page,
        limit,
        total: totalCount,
        pages: Math.ceil(totalCount / limit),
        hasNext: page < Math.ceil(totalCount / limit),
        hasPrev: page > 1,
        query: q
      }
    });
  } catch (err) {
    console.error('Erreur recherche locale:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/artworks/search/met/filtered - Recherche MET (publique)
app.get('/api/artworks/search/met/filtered', async (req, res) => {
  try {
    const { q, filterBy = 'all' } = req.query;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    
    if (!q || q.trim() === '') {
      return res.json({ artworks: [], total: 0 });
    }

    console.log(`🔍 Recherche MET filtrée: "${q}" (filtre: ${filterBy})`);

    // Recherche large sur l'API MET
    const searchUrl = `https://collectionapi.metmuseum.org/public/collection/v1/search?q=${encodeURIComponent(q)}&hasImages=true`;
    const searchResponse = await fetch(searchUrl);
    const searchData = await searchResponse.json();

    if (!searchData.objectIDs || searchData.objectIDs.length === 0) {
      return res.json({ artworks: [], pagination: { total: 0, pages: 0 } });
    }

    // Limiter à 50 résultats
    const objectIDsToFetch = searchData.objectIDs.slice(0, 50);
    
    // Récupérer les détails
    const allArtworks = [];
    
    for (const objectID of objectIDsToFetch) {
      try {
        let artwork;
        
        if (process.env.NODE_ENV === 'production') {
          const result = await db.query('SELECT * FROM artworks WHERE "metID" = $1', [objectID]);
          artwork = result.rows[0];
        } else {
          artwork = db.prepare('SELECT * FROM artworks WHERE metID = ?').get(objectID);
        }
        
        if (!artwork) {
          const detailResponse = await fetch(`https://collectionapi.metmuseum.org/public/collection/v1/objects/${objectID}`);
          const data = await detailResponse.json();
          
          if (data.primaryImageSmall) {
            if (process.env.NODE_ENV === 'production') {
              // PostgreSQL insert
              await db.query(
                `INSERT INTO artworks (
                  "metID", title, artist, "artistDisplayName", "artistDisplayBio",
                  "artistNationality", "artistBeginDate", "artistEndDate",
                  image, "primaryImage", "primaryImageSmall",
                  date, "objectDate", "objectBeginDate", "objectEndDate",
                  medium, dimensions, "objectURL", "creditLine",
                  culture, department, classification, period,
                  dynasty, reign, portfolio, repository, "accessionNumber",
                  "additionalImages"
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)`,
                [
                  data.objectID,
                  data.title || 'Titre inconnu',
                  data.artistDisplayName || 'Artiste inconnu',
                  data.artistDisplayName || null,
                  data.artistDisplayBio || null,
                  data.artistNationality || null,
                  data.artistBeginDate || null,
                  data.artistEndDate || null,
                  data.primaryImageSmall || '',
                  data.primaryImage || null,
                  data.primaryImageSmall || null,
                  data.objectDate || null,
                  data.objectDate || null,
                  data.objectBeginDate || null,
                  data.objectEndDate || null,
                  data.medium || null,
                  data.dimensions || null,
                  data.objectURL || null,
                  data.creditLine || null,
                  data.culture || null,
                  data.department || null,
                  data.classification || null,
                  data.period || null,
                  data.dynasty || null,
                  data.reign || null,
                  data.portfolio || null,
                  data.repository || null,
                  data.accessionNumber || null,
                  JSON.stringify(data.additionalImages || [])
                ]
              );

              const result = await db.query('SELECT * FROM artworks WHERE "metID" = $1', [data.objectID]);
              artwork = result.rows[0];
            } else {
              // SQLite insert (votre code existant)
              const stmt = db.prepare(`
                INSERT INTO artworks (
                  metID, title, artist, artistDisplayName, artistDisplayBio,
                  artistNationality, artistBeginDate, artistEndDate,
                  image, primaryImage, primaryImageSmall,
                  date, objectDate, objectBeginDate, objectEndDate,
                  medium, dimensions, objectURL, creditLine,
                  culture, department, classification, period,
                  dynasty, reign, portfolio, repository, accessionNumber,
                  additionalImages
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `);

              stmt.run(
                data.objectID,
                data.title || 'Titre inconnu',
                data.artistDisplayName || 'Artiste inconnu',
                data.artistDisplayName || null,
                data.artistDisplayBio || null,
                data.artistNationality || null,
                data.artistBeginDate || null,
                data.artistEndDate || null,
                data.primaryImageSmall || '',
                data.primaryImage || null,
                data.primaryImageSmall || null,
                data.objectDate || null,
                data.objectDate || null,
                data.objectBeginDate || null,
                data.objectEndDate || null,
                data.medium || null,
                data.dimensions || null,
                data.objectURL || null,
                data.creditLine || null,
                data.culture || null,
                data.department || null,
                data.classification || null,
                data.period || null,
                data.dynasty || null,
                data.reign || null,
                data.portfolio || null,
                data.repository || null,
                data.accessionNumber || null,
                JSON.stringify(data.additionalImages || [])
              );

              artwork = db.prepare('SELECT * FROM artworks WHERE metID = ?').get(data.objectID);
            }
          }
        }

        if (artwork) {
          allArtworks.push(artwork);
        }
      } catch (err) {
        console.error(`Erreur sur objectID ${objectID}:`, err.message);
      }
    }

    // Filtrer
    let filteredArtworks = allArtworks;
    const searchTermLower = q.toLowerCase();
    
    if (filterBy === 'title') {
      filteredArtworks = allArtworks.filter(art => 
        art.title && art.title.toLowerCase().includes(searchTermLower)
      );
    } else if (filterBy === 'artist') {
      filteredArtworks = allArtworks.filter(art => 
        art.artist && art.artist.toLowerCase().includes(searchTermLower)
      );
    }

    // Paginer
    const total = filteredArtworks.length;
    const start = (page - 1) * limit;
    const end = start + limit;
    const paginatedArtworks = filteredArtworks.slice(start, end);

    res.json({
      artworks: paginatedArtworks,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1,
        query: q,
        filterBy
      }
    });

  } catch (err) {
    console.error('❌ Erreur recherche MET:', err);
    res.status(500).json({ error: 'Erreur serveur', details: err.message });
  }
});

// GET /api/artworks/:id - Récupérer une œuvre par son ID
app.get('/api/artworks/:id', async (req, res) => {
  try {
    let artwork;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM artworks WHERE id = $1', [req.params.id]);
      artwork = result.rows[0];
    } else {
      artwork = db.prepare('SELECT * FROM artworks WHERE id = ?').get(req.params.id);
    }

    if (!artwork) {
      return res.status(404).json({ error: 'Œuvre non trouvée' });
    }
    res.json(artwork);
  } catch (err) {
    console.error('Erreur:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/artworks/fetch - Récupérer depuis l'API MET
app.post('/api/artworks/fetch', async (req, res) => {
  const { objectID } = req.body;
  
  if (!objectID) {
    return res.status(400).json({ error: 'objectID requis' });
  }

  try {
    let artwork;
    
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM artworks WHERE "metID" = $1', [objectID]);
      artwork = result.rows[0];
    } else {
      artwork = db.prepare('SELECT * FROM artworks WHERE metID = ?').get(objectID);
    }

    if (artwork) {
      return res.json(artwork);
    }

    const response = await fetch(`https://collectionapi.metmuseum.org/public/collection/v1/objects/${objectID}`);
    const data = await response.json();

    if (data.message === 'ObjectID not found') {
      return res.status(404).json({ error: 'Œuvre non trouvée sur MET' });
    }

    if (process.env.NODE_ENV === 'production') {
      // PostgreSQL insert
      await db.query(
        `INSERT INTO artworks (
          "metID", title, artist, "artistDisplayName", "artistDisplayBio",
          "artistNationality", "artistBeginDate", "artistEndDate",
          image, "primaryImage", "primaryImageSmall",
          date, "objectDate", "objectBeginDate", "objectEndDate",
          medium, dimensions, "objectURL", "creditLine",
          culture, department, classification, period,
          dynasty, reign, portfolio, repository, "accessionNumber",
          "additionalImages"
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29)`,
        [
          data.objectID,
          data.title || 'Titre inconnu',
          data.artistDisplayName || 'Artiste inconnu',
          data.artistDisplayName || null,
          data.artistDisplayBio || null,
          data.artistNationality || null,
          data.artistBeginDate || null,
          data.artistEndDate || null,
          data.primaryImageSmall || '',
          data.primaryImage || null,
          data.primaryImageSmall || null,
          data.objectDate || null,
          data.objectDate || null,
          data.objectBeginDate || null,
          data.objectEndDate || null,
          data.medium || null,
          data.dimensions || null,
          data.objectURL || null,
          data.creditLine || null,
          data.culture || null,
          data.department || null,
          data.classification || null,
          data.period || null,
          data.dynasty || null,
          data.reign || null,
          data.portfolio || null,
          data.repository || null,
          data.accessionNumber || null,
          JSON.stringify(data.additionalImages || [])
        ]
      );

      const result = await db.query('SELECT * FROM artworks WHERE "metID" = $1', [data.objectID]);
      artwork = result.rows[0];
    } else {
      // SQLite insert (votre code existant)
      const stmt = db.prepare(`
        INSERT INTO artworks (
          metID, title, artist, artistDisplayName, artistDisplayBio,
          artistNationality, artistBeginDate, artistEndDate,
          image, primaryImage, primaryImageSmall,
          date, objectDate, objectBeginDate, objectEndDate,
          medium, dimensions, objectURL, creditLine,
          culture, department, classification, period,
          dynasty, reign, portfolio, repository, accessionNumber,
          additionalImages
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run(
        data.objectID,
        data.title || 'Titre inconnu',
        data.artistDisplayName || 'Artiste inconnu',
        data.artistDisplayName || null,
        data.artistDisplayBio || null,
        data.artistNationality || null,
        data.artistBeginDate || null,
        data.artistEndDate || null,
        data.primaryImageSmall || '',
        data.primaryImage || null,
        data.primaryImageSmall || null,
        data.objectDate || null,
        data.objectDate || null,
        data.objectBeginDate || null,
        data.objectEndDate || null,
        data.medium || null,
        data.dimensions || null,
        data.objectURL || null,
        data.creditLine || null,
        data.culture || null,
        data.department || null,
        data.classification || null,
        data.period || null,
        data.dynasty || null,
        data.reign || null,
        data.portfolio || null,
        data.repository || null,
        data.accessionNumber || null,
        JSON.stringify(data.additionalImages || [])
      );

      artwork = db.prepare('SELECT * FROM artworks WHERE metID = ?').get(data.objectID);
    }

    res.json(artwork);
  } catch (err) {
    console.error('❌ Erreur fetch:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== ROUTES FAVORIS ====================

// GET /api/favorites - Récupérer les favoris de l'utilisateur
app.get('/api/favorites', authenticateToken, async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    const userId = req.user.id;

    let total, favorites;

    if (process.env.NODE_ENV === 'production') {
      const totalResult = await db.query(
        'SELECT COUNT(*) as count FROM user_favorites WHERE user_id = $1',
        [userId]
      );
      total = parseInt(totalResult.rows[0].count);

      const favoritesResult = await db.query(
        `SELECT a.* FROM artworks a
         JOIN user_favorites uf ON a.id = uf.artwork_id
         WHERE uf.user_id = $1
         ORDER BY uf.created_at DESC
         LIMIT $2 OFFSET $3`,
        [userId, limit, offset]
      );
      favorites = favoritesResult.rows;
    } else {
      total = db.prepare('SELECT COUNT(*) as count FROM user_favorites WHERE user_id = ?').get(userId).count;
      favorites = db.prepare(`
        SELECT a.* FROM artworks a
        JOIN user_favorites uf ON a.id = uf.artwork_id
        WHERE uf.user_id = ?
        ORDER BY uf.created_at DESC
        LIMIT ? OFFSET ?
      `).all(userId, limit, offset);
    }

    res.json({
      artworks: favorites,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    });

  } catch (err) {
    console.error('Erreur récupération favoris:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/favorites/:artworkId - Ajouter aux favoris
app.post('/api/favorites/:artworkId', authenticateToken, async (req, res) => {
  try {
    const { artworkId } = req.params;
    const userId = req.user.id;

    // Vérifier si l'œuvre existe
    let artwork;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM artworks WHERE id = $1', [artworkId]);
      artwork = result.rows[0];
    } else {
      artwork = db.prepare('SELECT * FROM artworks WHERE id = ?').get(artworkId);
    }

    if (!artwork) {
      return res.status(404).json({ error: 'Œuvre non trouvée' });
    }

    // Ajouter aux favoris
    if (process.env.NODE_ENV === 'production') {
      await db.query(
        'INSERT INTO user_favorites (user_id, artwork_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [userId, artworkId]
      );
    } else {
      const stmt = db.prepare('INSERT OR IGNORE INTO user_favorites (user_id, artwork_id) VALUES (?, ?)');
      stmt.run(userId, artworkId);
    }

    res.json({ success: true, message: 'Ajouté aux favoris' });

  } catch (err) {
    console.error('Erreur ajout favori:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// DELETE /api/favorites/:artworkId - Retirer des favoris
app.delete('/api/favorites/:artworkId', authenticateToken, async (req, res) => {
  try {
    const { artworkId } = req.params;
    const userId = req.user.id;

    if (process.env.NODE_ENV === 'production') {
      await db.query('DELETE FROM user_favorites WHERE user_id = $1 AND artwork_id = $2', [userId, artworkId]);
    } else {
      const stmt = db.prepare('DELETE FROM user_favorites WHERE user_id = ? AND artwork_id = ?');
      stmt.run(userId, artworkId);
    }

    res.json({ success: true, message: 'Retiré des favoris' });

  } catch (err) {
    console.error('Erreur suppression favori:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== ROUTES NOTATIONS ====================

// GET /api/ratings/:artworkId - Récupérer la note de l'utilisateur
app.get('/api/ratings/:artworkId', authenticateToken, async (req, res) => {
  try {
    const { artworkId } = req.params;
    const userId = req.user.id;

    let rating;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query(
        'SELECT overall_rating, technique_rating, originality_rating, emotion_rating FROM artwork_ratings WHERE user_id = $1 AND artwork_id = $2',
        [userId, artworkId]
      );
      rating = result.rows[0];
    } else {
      rating = db.prepare(`
        SELECT overall_rating, technique_rating, originality_rating, emotion_rating 
        FROM artwork_ratings 
        WHERE user_id = ? AND artwork_id = ?
      `).get(userId, artworkId);
    }

    res.json(rating || {
      overall_rating: 0,
      technique_rating: 0,
      originality_rating: 0,
      emotion_rating: 0
    });

  } catch (err) {
    console.error('Erreur récupération note:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// POST /api/ratings/:artworkId - Ajouter/mettre à jour une note
app.post('/api/ratings/:artworkId', authenticateToken, async (req, res) => {
  try {
    const { artworkId } = req.params;
    const userId = req.user.id;
    const { overall, technique, originality, emotion } = req.body;

    // Vérifier si l'œuvre existe
    let artwork;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM artworks WHERE id = $1', [artworkId]);
      artwork = result.rows[0];
    } else {
      artwork = db.prepare('SELECT * FROM artworks WHERE id = ?').get(artworkId);
    }

    if (!artwork) {
      return res.status(404).json({ error: 'Œuvre non trouvée' });
    }

    if (process.env.NODE_ENV === 'production') {
      // Vérifier si une note existe déjà
      const existing = await db.query(
        'SELECT id FROM artwork_ratings WHERE user_id = $1 AND artwork_id = $2',
        [userId, artworkId]
      );

      if (existing.rows.length > 0) {
        // Mise à jour
        await db.query(
          `UPDATE artwork_ratings 
           SET overall_rating = $1, technique_rating = $2, 
               originality_rating = $3, emotion_rating = $4,
               updated_at = CURRENT_TIMESTAMP
           WHERE user_id = $5 AND artwork_id = $6`,
          [overall, technique, originality, emotion, userId, artworkId]
        );
      } else {
        // Insertion
        await db.query(
          `INSERT INTO artwork_ratings 
           (user_id, artwork_id, overall_rating, technique_rating, originality_rating, emotion_rating)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [userId, artworkId, overall, technique, originality, emotion]
        );
      }
    } else {
      // SQLite
      const existing = db.prepare(`
        SELECT id FROM artwork_ratings 
        WHERE user_id = ? AND artwork_id = ?
      `).get(userId, artworkId);

      if (existing) {
        db.prepare(`
          UPDATE artwork_ratings 
          SET overall_rating = ?, technique_rating = ?, 
              originality_rating = ?, emotion_rating = ?,
              updated_at = CURRENT_TIMESTAMP
          WHERE user_id = ? AND artwork_id = ?
        `).run(overall, technique, originality, emotion, userId, artworkId);
      } else {
        db.prepare(`
          INSERT INTO artwork_ratings 
          (user_id, artwork_id, overall_rating, technique_rating, originality_rating, emotion_rating)
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(userId, artworkId, overall, technique, originality, emotion);
      }
    }

    res.json({ success: true, message: 'Note enregistrée' });

  } catch (err) {
    console.error('Erreur enregistrement note:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// GET /api/user/rated-artworks - Récupérer toutes les œuvres notées
app.get('/api/user/rated-artworks', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const offset = (page - 1) * limit;

    let total, ratedArtworks;

    if (process.env.NODE_ENV === 'production') {
      const totalResult = await db.query(
        'SELECT COUNT(*) as count FROM artwork_ratings WHERE user_id = $1',
        [userId]
      );
      total = parseInt(totalResult.rows[0].count);

      const result = await db.query(
        `SELECT a.*, 
                r.overall_rating, r.technique_rating, 
                r.originality_rating, r.emotion_rating,
                r.updated_at as rated_at
         FROM artworks a
         JOIN artwork_ratings r ON a.id = r.artwork_id
         WHERE r.user_id = $1
         ORDER BY r.overall_rating DESC, r.updated_at DESC
         LIMIT $2 OFFSET $3`,
        [userId, limit, offset]
      );
      ratedArtworks = result.rows;
    } else {
      total = db.prepare('SELECT COUNT(*) as count FROM artwork_ratings WHERE user_id = ?').get(userId).count;
      ratedArtworks = db.prepare(`
        SELECT a.*, 
               r.overall_rating, r.technique_rating, 
               r.originality_rating, r.emotion_rating,
               r.updated_at as rated_at
        FROM artworks a
        JOIN artwork_ratings r ON a.id = r.artwork_id
        WHERE r.user_id = ?
        ORDER BY r.overall_rating DESC, r.updated_at DESC
        LIMIT ? OFFSET ?
      `).all(userId, limit, offset);
    }

    res.json({
      artworks: ratedArtworks,
      pagination: {
        page,
        limit,
        total,
        pages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1
      }
    });

  } catch (err) {
    console.error('Erreur récupération œuvres notées:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== DÉMARRAGE ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Serveur démarré sur http://localhost:${PORT}`);
  console.log(`🌍 Environnement: ${process.env.NODE_ENV || 'development'}`);
  console.log('📡 Routes disponibles:');
  console.log('   🔐 Authentification:');
  console.log('      POST /api/auth/register');
  console.log('      POST /api/auth/login');
  console.log('      GET  /api/auth/me (protégée)');
  console.log('   ⭐ Favoris (protégées):');
  console.log('      GET  /api/favorites');
  console.log('      POST /api/favorites/:artworkId');
  console.log('      DELETE /api/favorites/:artworkId');
  console.log('   📊 Notations (protégées):');
  console.log('      GET  /api/ratings/:artworkId');
  console.log('      POST /api/ratings/:artworkId');
  console.log('      GET  /api/user/rated-artworks');
  console.log('   🖼️  Artworks (publiques):');
  console.log('      GET  /api/artworks');
  console.log('      GET  /api/artworks/search/local');
  console.log('      GET  /api/artworks/search/met/filtered');
  console.log('      GET  /api/artworks/:id');
  console.log('      POST /api/artworks/fetch\n');
});
