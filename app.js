const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const mysql = require('mysql2');
const dotenv = require('dotenv');
require('dotenv').config();

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'mood_tracker_db'
});

db.connect(err => {
  if (err) {
    console.error('Database connection error:', err);
  } else {
    console.log('Connected to the database.');
  }
});

// User registration
app.post('/api/register', (req, res) => {
  const { username, email, password } = req.body;

  // Hash password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ error: 'Server error' });
    }

    // Insert user into database
    const sql = 'INSERT INTO users (username, email, password) VALUES (?, ?, ?)';
    db.query(sql, [username, email, hashedPassword], (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Error registering user' });
      }
      res.status(201).json({ message: 'User registered successfully' });
    });
  });
});

// User login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;

  const sql = 'SELECT * FROM users WHERE email = ?';
  db.query(sql, [email], (err, result) => {
    if (err || result.length === 0) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = result[0];
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(400).json({ error: 'Invalid credentials' });
      }

      // Generate JWT token
      const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
        expiresIn: '1h'
      });

      res.status(200).json({ message: 'Login successful', token });
    });
  });
});

// Get user moods (protected route)
app.get('/api/moods', (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const userId = decoded.id;
    const sql = 'SELECT * FROM moods WHERE user_id = ?';
    db.query(sql, [userId], (err, moods) => {
      if (err) {
        return res.status(500).json({ error: 'Error fetching moods' });
      }
      res.status(200).json(moods);
    });
  });
});

// Post new mood (protected route)
app.post('/api/moods', (req, res) => {
  const token = req.headers['authorization'];
  const { mood, note } = req.body;

  if (!token) {
    return res.status(403).json({ error: 'Unauthorized' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ error: 'Unauthorized' });
    }

    const userId = decoded.id;
    const sql = 'INSERT INTO moods (user_id, mood, note) VALUES (?, ?, ?)';
    db.query(sql, [userId, mood, note], (err, result) => {
      if (err) {
        return res.status(500).json({ error: 'Error saving mood' });
      }
      res.status(201).json({ message: 'Mood saved successfully' });
    });
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
