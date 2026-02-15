// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./db.js');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

// ✅ CONFIGURATION CORS CORRIGÉE (accepte localhost ET Vercel)
app.use(cors({
  origin: [
    'http://localhost:5173',                // Développement local
    'https://met-art-frontend.vercel.app'    // Production
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

// Middleware d'authentification
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Non autorisé' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token invalide' });
    req.user = user;
    next();
  });
};

// ==================== STATISTIQUES ====================
app.get('/api/stats', async (req, res) => {
  try {
    const metResponse = await fetch('https://collectionapi.metmuseum.org/public/collection/v1/objects');
    const metData = await metResponse.json();
    const metTotal = metData.total || 0;
    res.json({ metTotal });
  } catch (err) {
    console.error('Erreur stats:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// ==================== RECHERCHE HYBRIDE INTELLIGENTE ====================
app.get('/api/search', async (req, res) => {
  try {
    const { q, page = 1 } = req.query;
    const limit = 20;
    const offset = (page - 1) * limit;
    
    if (!q || q.trim() === '') return res.json({ artworks: [], pagination: {} });

    const searchTerm = q.trim().toLowerCase();
    
    // 1. RECHERCHE DANS L'API MET (on récupère BEAUCOUP d'IDs)
    let metTotal = 0;
    let allMetArtworks = [];
    
    try {
      const searchUrl = `https://collectionapi.metmuseum.org/public/collection/v1/search?q=${encodeURIComponent(searchTerm)}&hasImages=true`;
      const searchResponse = await fetch(searchUrl);
      const searchData = await searchResponse.json();
      
      metTotal = searchData.total || 0;
      
      if (searchData.objectIDs && searchData.objectIDs.length > 0) {
        // Prendre PLUS d'IDs pour avoir assez de matches après filtrage
        const idsToFetch = searchData.objectIDs.slice(0, 100); // 100 IDs analysés
        
        const detailPromises = idsToFetch.map(id => 
          fetch(`https://collectionapi.metmuseum.org/public/collection/v1/objects/${id}`)
            .then(res => res.json())
            .catch(() => null)
        );
        
        const details = await Promise.all(detailPromises);
        
        // Filtrer intelligemment
        for (const data of details) {
          if (!data || !data.objectID) continue;
          
          const titleMatch = data.title?.toLowerCase().includes(searchTerm);
          const artistMatch = data.artistDisplayName?.toLowerCase().includes(searchTerm);
          
          // On garde seulement les pertinents
          if (titleMatch || artistMatch) {
            allMetArtworks.push({
              id: data.objectID,
              metID: data.objectID,
              title: data.title || 'Titre inconnu',
              artist: data.artistDisplayName || 'Artiste inconnu',
              image: data.primaryImageSmall,
              date: data.objectDate || null,
              medium: data.medium || null,
              dimensions: data.dimensions || null,
              department: data.department || null,
              objectURL: data.objectURL || null,
              // Score de pertinence pour le tri
              relevanceScore: (titleMatch ? 2 : 0) + (artistMatch ? 1 : 0)
            });
          }
        }
        
        // Trier par pertinence
        allMetArtworks.sort((a, b) => b.relevanceScore - a.relevanceScore);
      }
    } catch (err) {
      console.error('Erreur API MET:', err);
    }

    // 2. PAGINATION des résultats pertinents
    const paginatedArtworks = allMetArtworks.slice(offset, offset + limit);
    
    // 3. Si pas assez de pertinents pour remplir la page, on complète avec d'autres
    if (paginatedArtworks.length < limit && allMetArtworks.length < metTotal) {
      console.log(`⚠️ Pas assez de pertinents, complément avec d'autres...`);
      // Logique pour compléter (optionnel)
    }

    const totalPages = Math.ceil(allMetArtworks.length / limit);
    
    res.json({ 
      artworks: paginatedArtworks,
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalResults: allMetArtworks.length,
        resultsPerPage: limit,
        hasNext: page < totalPages,
        hasPrev: page > 1
      }
    });

  } catch (err) {
    console.error('Erreur recherche:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});


// ==================== AUTH ====================
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Tous les champs sont requis' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: '8 caractères minimum' });
    }

    let existingUser;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
      existingUser = result.rows[0];
    } else {
      existingUser = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?').get(email, username);
    }

    if (existingUser) {
      return res.status(400).json({ error: 'Email ou nom déjà utilisé' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

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

    const token = jwt.sign(
      { id: newUser.id, username: newUser.username, email: newUser.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({ token, user: newUser });
  } catch (err) {
    console.error('Erreur inscription:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });

    let userRecord;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
      userRecord = result.rows[0];
    } else {
      userRecord = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    }

    if (!userRecord) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    const validPassword = await bcrypt.compare(password, userRecord.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

    let user;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT id, username, email, created_at FROM users WHERE id = $1', [userRecord.id]);
      user = result.rows[0];
    } else {
      user = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(userRecord.id);
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, email: user.email },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ token, user });
  } catch (err) {
    console.error('Erreur connexion:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Tous les champs sont requis' });
    }
    if (newPassword.length < 8) {
      return res.status(400).json({ error: '8 caractères minimum' });
    }

    let user;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
      user = result.rows[0];
    } else {
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    }

    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) return res.status(401).json({ error: 'Mot de passe actuel incorrect' });

    const saltRounds = 10;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    if (process.env.NODE_ENV === 'production') {
      await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newPasswordHash, userId]);
    } else {
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newPasswordHash, userId);
    }

    res.json({ success: true, message: 'Mot de passe modifié avec succès' });
  } catch (err) {
    console.error('Erreur changement mot de passe:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/auth/delete-account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;

    if (process.env.NODE_ENV === 'production') {
      await db.query('DELETE FROM user_favorites WHERE user_id = $1', [userId]);
      await db.query('DELETE FROM artwork_ratings WHERE user_id = $1', [userId]);
      await db.query('DELETE FROM users WHERE id = $1', [userId]);
    } else {
      db.prepare('DELETE FROM user_favorites WHERE user_id = ?').run(userId);
      db.prepare('DELETE FROM artwork_ratings WHERE user_id = ?').run(userId);
      db.prepare('DELETE FROM users WHERE id = ?').run(userId);
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Erreur suppression compte:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== FAVORIS ====================
app.get('/api/favorites', authenticateToken, async (req, res) => {
  try {
    let favorites;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query(
        `SELECT a.* FROM artworks a
         JOIN user_favorites uf ON a.id = uf.artwork_id
         WHERE uf.user_id = $1
         ORDER BY uf.created_at DESC`,
        [req.user.id]
      );
      favorites = result.rows;
    } else {
      favorites = db.prepare(
        `SELECT a.* FROM artworks a
         JOIN user_favorites uf ON a.id = uf.artwork_id
         WHERE uf.user_id = ?
         ORDER BY uf.created_at DESC`
      ).all(req.user.id);
    }
    res.json({ artworks: favorites });
  } catch (err) {
    console.error('Erreur favoris:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.post('/api/favorites/:artworkId', authenticateToken, async (req, res) => {
  try {
    const { artworkId } = req.params;
    if (process.env.NODE_ENV === 'production') {
      await db.query(
        'INSERT INTO user_favorites (user_id, artwork_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
        [req.user.id, artworkId]
      );
    } else {
      db.prepare('INSERT OR IGNORE INTO user_favorites (user_id, artwork_id) VALUES (?, ?)')
        .run(req.user.id, artworkId);
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Erreur ajout favori:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.delete('/api/favorites/:artworkId', authenticateToken, async (req, res) => {
  try {
    const { artworkId } = req.params;
    if (process.env.NODE_ENV === 'production') {
      await db.query('DELETE FROM user_favorites WHERE user_id = $1 AND artwork_id = $2', [req.user.id, artworkId]);
    } else {
      db.prepare('DELETE FROM user_favorites WHERE user_id = ? AND artwork_id = ?').run(req.user.id, artworkId);
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Erreur suppression favori:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== NOTATIONS ====================
app.get('/api/ratings/:artworkId', authenticateToken, async (req, res) => {
  try {
    const { artworkId } = req.params;
    let rating;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query(
        'SELECT * FROM artwork_ratings WHERE user_id = $1 AND artwork_id = $2',
        [req.user.id, artworkId]
      );
      rating = result.rows[0];
    } else {
      rating = db.prepare('SELECT * FROM artwork_ratings WHERE user_id = ? AND artwork_id = ?')
        .get(req.user.id, artworkId);
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

app.post('/api/ratings/:artworkId', authenticateToken, async (req, res) => {
  try {
    const { artworkId } = req.params;
    const { overall, technique, originality, emotion } = req.body;

    if (process.env.NODE_ENV === 'production') {
      const existing = await db.query(
        'SELECT id FROM artwork_ratings WHERE user_id = $1 AND artwork_id = $2',
        [req.user.id, artworkId]
      );

      if (existing.rows.length > 0) {
        await db.query(
          `UPDATE artwork_ratings 
           SET overall_rating = $1, technique_rating = $2, 
               originality_rating = $3, emotion_rating = $4,
               updated_at = CURRENT_TIMESTAMP
           WHERE user_id = $5 AND artwork_id = $6`,
          [overall, technique, originality, emotion, req.user.id, artworkId]
        );
      } else {
        await db.query(
          `INSERT INTO artwork_ratings 
           (user_id, artwork_id, overall_rating, technique_rating, originality_rating, emotion_rating)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [req.user.id, artworkId, overall, technique, originality, emotion]
        );
      }
    } else {
      const existing = db.prepare(
        'SELECT id FROM artwork_ratings WHERE user_id = ? AND artwork_id = ?'
      ).get(req.user.id, artworkId);

      if (existing) {
        db.prepare(
          `UPDATE artwork_ratings 
           SET overall_rating = ?, technique_rating = ?, 
               originality_rating = ?, emotion_rating = ?,
               updated_at = CURRENT_TIMESTAMP
           WHERE user_id = ? AND artwork_id = ?`
        ).run(overall, technique, originality, emotion, req.user.id, artworkId);
      } else {
        db.prepare(
          `INSERT INTO artwork_ratings 
           (user_id, artwork_id, overall_rating, technique_rating, originality_rating, emotion_rating)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).run(req.user.id, artworkId, overall, technique, originality, emotion);
      }
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Erreur sauvegarde note:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/user/rated-artworks', authenticateToken, async (req, res) => {
  try {
    let artworks;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query(
        `SELECT a.*, 
                r.overall_rating, r.technique_rating, 
                r.originality_rating, r.emotion_rating
         FROM artworks a
         JOIN artwork_ratings r ON a.id = r.artwork_id
         WHERE r.user_id = $1
         ORDER BY r.overall_rating DESC`,
        [req.user.id]
      );
      artworks = result.rows;
    } else {
      artworks = db.prepare(
        `SELECT a.*, 
                r.overall_rating, r.technique_rating, 
                r.originality_rating, r.emotion_rating
         FROM artworks a
         JOIN artwork_ratings r ON a.id = r.artwork_id
         WHERE r.user_id = ?
         ORDER BY r.overall_rating DESC`
      ).all(req.user.id);
    }
    res.json({ artworks });
  } catch (err) {
    console.error('Erreur récupération œuvres notées:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== DÉPARTEMENTS ====================
app.get('/api/departments', async (req, res) => {
  try {
    let departments;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query(
        'SELECT DISTINCT department FROM artworks WHERE department IS NOT NULL ORDER BY department'
      );
      departments = result.rows.map(r => r.department);
    } else {
      departments = db.prepare(
        'SELECT DISTINCT department FROM artworks WHERE department IS NOT NULL ORDER BY department'
      ).all().map(r => r.department);
    }
    res.json(departments);
  } catch (err) {
    console.error('Erreur départements:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

app.get('/api/artworks/by-department/:department', async (req, res) => {
  try {
    const { department } = req.params;
    let artworks;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query(
        'SELECT * FROM artworks WHERE department = $1 ORDER BY created_at DESC',
        [department]
      );
      artworks = result.rows;
    } else {
      artworks = db.prepare(
        'SELECT * FROM artworks WHERE department = ? ORDER BY created_at DESC'
      ).all(department);
    }
    res.json({ artworks });
  } catch (err) {
    console.error('Erreur récupération œuvres par département:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Serveur démarré sur http://localhost:${PORT}`);
  console.log(`🌍 Environnement: ${process.env.NODE_ENV || 'development'}`);
});
