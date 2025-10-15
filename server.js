const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = 3001;

// middleware
app.use(express.json());
app.use(cors());

// database setup
const db = new sqlite3.Database('./password_manager.db');

// create tables
db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS stored_passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    username TEXT NOT NULL,
    encrypted_password TEXT NOT NULL,
    url TEXT,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
  )`);
});

// JWT Secret (change this in env)
const JWT_SECRET = 'your-super-secret-jwt-key-change-in-production';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// simple encryption/decryption for stored passwords
const ENCRYPTION_KEY = crypto.randomBytes(32); // randomly generate a 256-bit key (32 bytes)
const ALGORITHM = 'aes-256-gcm'; // this algorithm is a symmetric encryption algorithm that combines the Advanced Encryption Standard (AES) with a 256-bit key

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipher(ALGORITHM, ENCRYPTION_KEY);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();
  return iv.toString('hex') + ':' + authTag.toString('hex') + ':' + encrypted;
}

function decrypt(encryptedData) {
  try {
    const parts = encryptedData.split(':');
    const iv = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const encrypted = parts[2];
    
    const decipher = crypto.createDecipher(ALGORITHM, ENCRYPTION_KEY);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (error) {
    return null;
  }
}

// routes

// user registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    if (password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters long' });
    }
    
    // hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // insert user into database
    db.run(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, passwordHash],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE constraint failed')) {
            return res.status(400).json({ error: 'Username or email already exists' });
          }
          return res.status(500).json({ error: 'Database error' });
        }

        // Generate JWT token
        const token = jwt.sign(
          { id: this.lastID, username },
          JWT_SECRET,
          { expiresIn: '10m' }
        );

        res.status(201).json({
          message: 'User created successfully',
          token,
          user: { id: this.lastID, username, email }
        });
      }
    );
  } catch (error) {
    res.status(500).json({ error: 'Server error' });
  }
});

// user login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // validate input
  if (!username || !password) {
    return res.status(400).json({ error: 'All fields are required' });
  }

  // find user in database
  db.get(
    'SELECT * FROM users WHERE username = ? OR email = ?',
    [username, username],
    async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      try {
        const validPassword = await bcrypt.compare(password, user.password_hash);
        
        if (!validPassword) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign(
          { id: user.id, username: user.username },
          JWT_SECRET,
          { expiresIn: '24h' }
        );

        res.json({
          message: 'Login successful',
          token,
          user: { id: user.id, username: user.username, email: user.email }
        });
      } catch (error) {
        res.status(500).json({ error: 'Server error' });
      }
    }
  );
});
 
// get all stored passwords for a user
app.get('/api/passwords', authenticateToken, (req, res) => {
  db.all(
    'SELECT * FROM stored_passwords WHERE user_id = ? ORDER BY service_name',
    [req.user.id],
    (err, passwords) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      // Decrypt passwords before sending
      const decryptedPasswords = passwords.map(pwd => ({
        ...pwd,
        password: decrypt(pwd.encrypted_password)
      }));

      res.json(decryptedPasswords);
    }
  );
});

// add new password
app.post('/api/passwords', authenticateToken, (req, res) => {
  const { service_name, username, password, url, notes } = req.body;

  if (!service_name || !username || !password) {
    return res.status(400).json({ error: 'Service name, username, and password are required' });
  }

  const encryptedPassword = encrypt(password);

  db.run(
    'INSERT INTO stored_passwords (user_id, service_name, username, encrypted_password, url, notes) VALUES (?, ?, ?, ?, ?, ?)',
    [req.user.id, service_name, username, encryptedPassword, url || '', notes || ''],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      res.status(201).json({
        message: 'Password saved successfully',
        id: this.lastID
      });
    }
  );
});

// update password
app.put('/api/passwords/:id', authenticateToken, (req, res) => {
  const { service_name, username, password, url, notes } = req.body;
  const passwordId = req.params.id;

  if (!service_name || !username || !password) {
    return res.status(400).json({ error: 'Service name, username, and password are required' });
  }

  const encryptedPassword = encrypt(password);

  db.run(
    'UPDATE stored_passwords SET service_name = ?, username = ?, encrypted_password = ?, url = ?, notes = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
    [service_name, username, encryptedPassword, url || '', notes || '', passwordId, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Password not found' });
      }

      res.json({ message: 'Password updated successfully' });
    }
  );
});

// Delete password
app.delete('/api/passwords/:id', authenticateToken, (req, res) => {
  const passwordId = req.params.id;

  db.run(
    'DELETE FROM stored_passwords WHERE id = ? AND user_id = ?',
    [passwordId, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'Password not found' });
      }

      res.json({ message: 'Password deleted successfully' });
    }
  );
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Password Manager API is running' });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Database initialized successfully');
});