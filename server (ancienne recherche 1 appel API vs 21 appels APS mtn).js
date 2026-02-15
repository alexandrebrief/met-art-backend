// server.js
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const db = require('./db.js');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET;

app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
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
    // Appel API MET pour le nombre total d'œuvres
    const metResponse = await fetch('https://collectionapi.metmuseum.org/public/collection/v1/objects');
    const metData = await metResponse.json();
    const metTotal = metData.total || 0;

    res.json({ metTotal });
  } catch (err) {
    console.error('Erreur stats:', err);
    res.status(500).json({ error: 'Erreur serveur' });
  }
});

// ==================== RECHERCHE AVEC PAGINATION ====================
app.get('/api/search', async (req, res) => {
  try {
    const { q, page = 1 } = req.query;
    const limit = 50; // 50 résultats par page
    
    if (!q || q.trim() === '') return res.json({ artworks: [], pagination: {} });

    const searchTerm = q.trim();
    
    // 1. Récupérer le total depuis l'API MET
    let metTotal = 0;
    let allIds = [];
    
    try {
      const metResponse = await fetch(
        `https://collectionapi.metmuseum.org/public/collection/v1/search?q=${encodeURIComponent(searchTerm)}`
      );
      
      if (!metResponse.ok) {
        throw new Error(`API MET retourne ${metResponse.status}`);
      }
      
      const metData = await metResponse.json();
      metTotal = metData.total || 0;
      allIds = metData.objectIDs || [];
      
      console.log(`📊 MET: ${metTotal} œuvres trouvées pour "${searchTerm}"`);
      
    } catch (err) {
      console.error('Erreur API MET:', err);
      return res.json({ 
        artworks: [], 
        pagination: {
          currentPage: parseInt(page),
          totalPages: 0,
          totalResults: 0,
          resultsPerPage: limit,
          hasNext: false,
          hasPrev: page > 1
        }
      });
    }

    // 2. Pagination des IDs
    const offset = (page - 1) * limit;
    const idsToFetch = allIds.slice(offset, offset + limit);
    
    console.log(`🔍 Page ${page}: chargement de ${idsToFetch.length} œuvres (IDs ${offset+1} à ${offset+idsToFetch.length})`);
    
    // 3. Récupérer les détails pour les IDs de cette page
    let metArtworks = [];
    
    for (let i = 0; i < idsToFetch.length; i++) {
      const id = idsToFetch[i];
      
      // Petit délai pour ne pas surcharger l'API
      if (i > 0) await new Promise(resolve => setTimeout(resolve, 100));
      
      try {
        // Vérifier d'abord dans la base locale
        let artwork;
        if (process.env.NODE_ENV === 'production') {
          const result = await db.query('SELECT * FROM artworks WHERE "metID" = $1', [id]);
          artwork = result.rows[0];
        } else {
          artwork = db.prepare('SELECT * FROM artworks WHERE metID = ?').get(id);
        }

        if (artwork) {
          metArtworks.push(artwork);
        } else {
          // Récupérer depuis l'API MET
          const detailResponse = await fetch(
            `https://collectionapi.metmuseum.org/public/collection/v1/objects/${id}`
          );
          
          if (!detailResponse.ok) continue;
          
          const data = await detailResponse.json();
          
          // On garde même sans image
          const imageUrl = data.primaryImageSmall || '';
          
          // Insérer dans la base
          if (process.env.NODE_ENV === 'production') {
            await db.query(
              `INSERT INTO artworks (
                "metID", title, artist, "artistDisplayName", image,
                date, medium, dimensions, "objectURL", department
              ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
              [
                data.objectID,
                data.title || 'Titre inconnu',
                data.artistDisplayName || 'Artiste inconnu',
                data.artistDisplayName || null,
                imageUrl,
                data.objectDate || null,
                data.medium || null,
                data.dimensions || null,
                data.objectURL || null,
                data.department || null
              ]
            );
          } else {
            const stmt = db.prepare(
              `INSERT INTO artworks (
                metID, title, artist, artistDisplayName, image,
                date, medium, dimensions, objectURL, department
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
            );
            stmt.run(
              data.objectID,
              data.title || 'Titre inconnu',
              data.artistDisplayName || 'Artiste inconnu',
              data.artistDisplayName || null,
              imageUrl,
              data.objectDate || null,
              data.medium || null,
              data.dimensions || null,
              data.objectURL || null,
              data.department || null
            );
          }

          // Récupérer l'œuvre insérée
          if (process.env.NODE_ENV === 'production') {
            const result = await db.query('SELECT * FROM artworks WHERE "metID" = $1', [id]);
            artwork = result.rows[0];
          } else {
            artwork = db.prepare('SELECT * FROM artworks WHERE metID = ?').get(id);
          }
          metArtworks.push(artwork);
        }
      } catch (err) {
        console.error(`Erreur sur l'ID ${id}:`, err.message);
      }
    }

    console.log(`✅ Page ${page}: ${metArtworks.length} résultats affichés sur ${metTotal} trouvés`);
    
    // Informations de pagination
    const totalPages = Math.ceil(metTotal / limit);
    
    res.json({ 
      artworks: metArtworks, // ← UNIQUEMENT les résultats MET paginés
      pagination: {
        currentPage: parseInt(page),
        totalPages,
        totalResults: metTotal,
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

// ==================== CHANGER LE MOT DE PASSE ====================
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.id;

    // Validation
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Tous les champs sont requis' });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({ error: 'Le mot de passe doit contenir au moins 8 caractères' });
    }

    // Récupérer l'utilisateur
    let user;
    if (process.env.NODE_ENV === 'production') {
      const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
      user = result.rows[0];
    } else {
      user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    }

    if (!user) {
      return res.status(404).json({ error: 'Utilisateur non trouvé' });
    }

    // Vérifier l'ancien mot de passe
    const validPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Mot de passe actuel incorrect' });
    }

    // Hacher le nouveau mot de passe
    const saltRounds = 10;
    const newPasswordHash = await bcrypt.hash(newPassword, saltRounds);

    // Mettre à jour
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





const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`\n🚀 Serveur démarré sur http://localhost:${PORT}`);
});
