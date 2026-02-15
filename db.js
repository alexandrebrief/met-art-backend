// db.js
const Database = require('better-sqlite3');
const { Pool } = require('pg');
require('dotenv').config();

// 🔍 Nettoyer la variable d'environnement
const rawEnv = process.env.NODE_ENV || 'development';
const cleanedEnv = rawEnv.trim().toLowerCase();

console.log('🔍 [db.js] NODE_ENV =', cleanedEnv);
console.log('🔍 [db.js] DATABASE_URL =', process.env.DATABASE_URL ? 'Définie ✓' : 'Non définie ✗');

// Déterminer l'environnement
const isProduction = cleanedEnv === 'production';
console.log('🔍 [db.js] isProduction =', isProduction);

let db;

if (isProduction) {
  console.log('✅ [db.js] Connexion à PostgreSQL...');
  
  // Configuration PostgreSQL pour la production
  const connectionString = process.env.DATABASE_URL;
  
  if (!connectionString) {
    console.error('❌ [db.js] DATABASE_URL non définie !');
    process.exit(1);
  }

  db = new Pool({
    connectionString,
    ssl: {
      rejectUnauthorized: false
    },
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000
  });

  console.log('✅ [db.js] Pool PostgreSQL créé');

  // Tester la connexion
  (async () => {
    try {
      const client = await db.connect();
      console.log('✅ [db.js] Connexion PostgreSQL réussie !');
      client.release();
    } catch (err) {
      console.error('❌ [db.js] Erreur connexion PostgreSQL:', err.message);
    }
  })();

  // Créer les tables si elles n'existent pas
  const initPostgres = async () => {
    try {
      console.log('🔄 [db.js] Création/vérification des tables...');
      
      // Table users
      await db.query(`
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username VARCHAR(255) UNIQUE NOT NULL,
          email VARCHAR(255) UNIQUE NOT NULL,
          password_hash VARCHAR(255) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Table artworks
      await db.query(`
        CREATE TABLE IF NOT EXISTS artworks (
          id SERIAL PRIMARY KEY,
          "metID" INTEGER UNIQUE,
          title TEXT,
          artist TEXT,
          "artistDisplayName" TEXT,
          "artistDisplayBio" TEXT,
          "artistNationality" TEXT,
          "artistBeginDate" TEXT,
          "artistEndDate" TEXT,
          image TEXT,
          "primaryImage" TEXT,
          "primaryImageSmall" TEXT,
          date TEXT,
          "objectDate" TEXT,
          "objectBeginDate" TEXT,
          "objectEndDate" TEXT,
          medium TEXT,
          dimensions TEXT,
          "objectURL" TEXT,
          "creditLine" TEXT,
          culture TEXT,
          department TEXT,
          classification TEXT,
          period TEXT,
          dynasty TEXT,
          reign TEXT,
          portfolio TEXT,
          repository TEXT,
          "accessionNumber" TEXT,
          "additionalImages" TEXT,
          favorite INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
      `);

      // Table user_favorites
      await db.query(`
        CREATE TABLE IF NOT EXISTS user_favorites (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          artwork_id INTEGER NOT NULL REFERENCES artworks(id) ON DELETE CASCADE,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id, artwork_id)
        )
      `);

      // Table artwork_ratings
      await db.query(`
        CREATE TABLE IF NOT EXISTS artwork_ratings (
          id SERIAL PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          artwork_id INTEGER NOT NULL REFERENCES artworks(id) ON DELETE CASCADE,
          overall_rating REAL DEFAULT 0,
          technique_rating REAL DEFAULT 0,
          originality_rating REAL DEFAULT 0,
          emotion_rating REAL DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id, artwork_id)
        )
      `);

      // Créer les index
      await db.query(`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`);
      await db.query(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`);
      await db.query(`CREATE INDEX IF NOT EXISTS idx_artworks_metid ON artworks("metID")`);
      await db.query(`CREATE INDEX IF NOT EXISTS idx_artworks_title ON artworks(title)`);
      await db.query(`CREATE INDEX IF NOT EXISTS idx_artworks_artist ON artworks(artist)`);
      await db.query(`CREATE INDEX IF NOT EXISTS idx_artworks_department ON artworks(department)`);
      
      console.log('✅ [db.js] Tables PostgreSQL créées/vérifiées');
    } catch (err) {
      console.error('❌ [db.js] Erreur création tables PostgreSQL:', err);
    }
  };

  initPostgres();

  // Wrapper pour garder la même interface (async)
  db.prepare = (sql) => {
    return {
      get: async (...params) => {
        const res = await db.query(sql, params);
        return res.rows[0];
      },
      all: async (...params) => {
        const res = await db.query(sql, params);
        return res.rows;
      },
      run: async (...params) => {
        const res = await db.query(sql, params);
        return { changes: res.rowCount };
      }
    };
  };

} else {
  console.log('✅ [db.js] Connexion à SQLite (développement local)');
  
  // SQLite pour le développement local
  db = new Database('database.db');
  
  // Créer les tables SQLite
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS artworks (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      metID INTEGER UNIQUE,
      title TEXT,
      artist TEXT,
      artistDisplayName TEXT,
      artistDisplayBio TEXT,
      artistNationality TEXT,
      artistBeginDate TEXT,
      artistEndDate TEXT,
      image TEXT,
      primaryImage TEXT,
      primaryImageSmall TEXT,
      date TEXT,
      objectDate TEXT,
      objectBeginDate TEXT,
      objectEndDate TEXT,
      medium TEXT,
      dimensions TEXT,
      objectURL TEXT,
      creditLine TEXT,
      culture TEXT,
      department TEXT,
      classification TEXT,
      period TEXT,
      dynasty TEXT,
      reign TEXT,
      portfolio TEXT,
      repository TEXT,
      accessionNumber TEXT,
      additionalImages TEXT,
      favorite INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS user_favorites (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      artwork_id INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (artwork_id) REFERENCES artworks(id) ON DELETE CASCADE,
      UNIQUE(user_id, artwork_id)
    )
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS artwork_ratings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      artwork_id INTEGER NOT NULL,
      overall_rating REAL DEFAULT 0,
      technique_rating REAL DEFAULT 0,
      originality_rating REAL DEFAULT 0,
      emotion_rating REAL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY (artwork_id) REFERENCES artworks(id) ON DELETE CASCADE,
      UNIQUE(user_id, artwork_id)
    )
  `);

  console.log('✅ [db.js] Tables SQLite créées/vérifiées');
}

module.exports = db;
