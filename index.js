const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const app = express();
const db = new sqlite3.Database('./db.sqlite');

app.use(cors());
app.use(express.json()); // Replacing deprecated body-parser

// Create table if not exists
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    nama TEXT,
    public_key TEXT
  )`);
});

const SECRET_KEY = 'SECRET_KEY';

// Register user (manual, untuk testing)
app.post('/api/register', (req, res) => {
  const { username, password, nama } = req.body;

  if (!username || !password || !nama) {
    return res.status(400).json({ message: 'Register failed' });
  } 
  db.run(
    `INSERT INTO users (username, password, nama) VALUES (?, ?, ?)`,
    [username.toLowerCase(), password, nama],
    function (err) {
      if (err) return res.status(400).json({ message: 'Username sudah dipakai' });
      res.json({ id: this.lastID });
    }
  );
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT id, username, nama, password FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).json({ message: 'Database error' });
    if (!user) return res.status(401).json({ message: 'Username atau password salah' });

    // cek password sederhana (sebaiknya hash password pakai bcrypt)
    if (password !== user.password) {
      return res.status(401).json({ message: 'Username atau password salah' });
    }

    const token = jwt.sign(
      { user_id: user.id, username: user.username, nama: user.nama },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({ token, userId: user.id, nama: user.nama });
  });
});


app.get('/api/me', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Missing or invalid Authorization header' });
  }

  const token = authHeader.split(' ')[1];

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
    // decoded berisi payload token, misal { user_id: ..., iat: ..., exp: ... }
    res.json(decoded);
  });
});

app.post('/api/generate-keypair', async (req, res) => {
  try {
    // Authentication check
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.user_id || decoded.id;

    const publicKey = req.body.publicKey

    if (!publicKey) return res.status(400).json({ message: 'Public key and userId are required' });

    // Store in database
    db.run(`UPDATE users SET public_key = ? WHERE id = ?`, 
      [publicKey, userId],
      function(err) {
        if (err) /* handle error */;
        res.json({ userId });
      }
    );
  } catch (err) {
    console.error('Key generation error:', err);
    res.status(401).json({ error: 'Invalid token or system error' });
  }
});

function formatToPem(key) {
  const formatted = key.match(/.{1,64}/g)?.join('\n'); // pecah jadi baris 64 karakter
  return `-----BEGIN PUBLIC KEY-----\n${formatted}\n-----END PUBLIC KEY-----`;
}

function verifySignature({ userId, timestamp, signature, publicKey }) {
  const data = `${userId}:${timestamp}`;
  const pem = formatToPem(publicKey)
  return crypto
    .createVerify('SHA256')
    .update(data)
    .end()
    .verify(pem, signature, 'base64');
}

app.post('/api/biometric-login', (req, res) => {
  const { userId, timestamp, signature } = req.body;
  
  if (!userId || !timestamp || !signature) {
    return res.status(400).json({ message: 'Invalid request: missing fields' });
  }

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - timestamp) > 30) {
    return res.status(400).json({ message: 'Request expired' });
  }

  db.get(`SELECT id, username, nama, public_key FROM users WHERE id = ?`, [userId], (err, user) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: 'Internal server error' });
    }
    if (!user || !user.public_key) {
      return res.status(404).json({ message: 'User or public key not found' });
    }

    const isValid = verifySignature({
      userId,
      timestamp,
      signature,
      publicKey: user.public_key,
    });

    if (!isValid) { 
      return res.status(401).json({ message: 'Invalid signature' });
    }

    const token = jwt.sign(
      { user_id: user.id, username: user.username, nama: user.nama },
      SECRET_KEY,
      { expiresIn: '1h' }
    );
    
    res.json({ token, userId: user.id, nama: user.nama });
  });
});


app.listen(3040, '0.0.0.0', () => console.log('🚀 Server running on http://localhost:3040'));
console.log('🚀 Server is starting...');