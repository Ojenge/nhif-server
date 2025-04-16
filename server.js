const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken');
const app = express();
const port = 5000;
// const SECRET = 'your_secret_key_here';


app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Hermione#1989',
  database: 'nhif'
});

db.connect(err => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL database');
});

// READ
app.get('/api/inpatient', (req, res) => {
  db.query('SELECT * FROM inpatient', (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

// UPDATE
app.put('/api/inpatient/:doc_no', (req, res) => {
  const doc_no = req.params.doc_no;
  const updates = req.body;
  const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
  const values = Object.values(updates);

  db.query(`UPDATE inpatient SET ${fields} WHERE doc_no = ?`, [...values, doc_no], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Inpatient record updated', result });
  });
});

// DELETE
app.delete('/api/inpatient/:doc_no', (req, res) => {
  const doc_no = req.params.doc_no;
  db.query('DELETE FROM inpatient WHERE doc_no = ?', [doc_no], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Inpatient record deleted', result });
  });
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});

// OUTPATIENT ROUTES
app.get('/api/outpatient', (req, res) => {
  db.query('SELECT * FROM outpatient', (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

app.put('/api/outpatient/:doc_no', (req, res) => {
  const doc_no = req.params.doc_no;
  const updates = req.body;
  const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
  const values = Object.values(updates);
  db.query(`UPDATE outpatient SET ${fields} WHERE doc_no = ?`, [...values, doc_no], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Outpatient record updated', result });
  });
});

app.delete('/api/outpatient/:doc_no', (req, res) => {
  const doc_no = req.params.doc_no;
  db.query('DELETE FROM outpatient WHERE doc_no = ?', [doc_no], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Outpatient record deleted', result });
  });
});

// OVERSEAS ROUTES
app.get('/api/overseas', (req, res) => {
  db.query('SELECT * FROM overseas', (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

app.put('/api/overseas/:doc_no', (req, res) => {
  const doc_no = req.params.doc_no;
  const updates = req.body;
  const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
  const values = Object.values(updates);
  db.query(`UPDATE overseas SET ${fields} WHERE doc_no = ?`, [...values, doc_no], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Overseas record updated', result });
  });
});

app.delete('/api/overseas/:doc_no', (req, res) => {
  const doc_no = req.params.doc_no;
  db.query('DELETE FROM overseas WHERE doc_no = ?', [doc_no], (err, result) => {
    if (err) return res.status(500).json({ error: err });
    res.json({ message: 'Overseas record deleted', result });
  });
});


const jwt = require('jsonwebtoken');
const SECRET = 'your_secret_key_here';

// Middleware to verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ error: 'No token provided' });

  const token = authHeader.split(' ')[1];
  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}


// Login route with JWT
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.query('SELECT * FROM users WHERE username = ?', [username], async (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: 'User not found' });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(403).json({ error: 'Invalid password' });

    const token = jwt.sign({ username: user.username, role: user.role }, SECRET, { expiresIn: '1h' });
    res.json({ token, username: user.username, role: user.role });
  });
});


// Signup route
app.post('/api/signup', async (req, res) => {
  const { username, password, role } = req.body;

  try {
    const hash = await bcrypt.hash(password, 10);
    db.query('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)',
      [username, hash, role],
      (err, result) => {
        if (err) return res.status(500).json({ error: err });
        res.json({ message: 'User created', result });
      });
  } catch (err) {
    res.status(500).json({ error: 'Signup failed' });
  }
});
// Add to server.js (near the bottom)

app.get('/api/analytics/claims-by-county', (req, res) => {
  const sql = `
    SELECT county_name, 'inpatient' AS type, SUM(claim_tot) AS total
    FROM inpatient GROUP BY county_name
    UNION ALL
    SELECT county_name, 'outpatient' AS type, SUM(claim_amount) AS total
    FROM outpatient GROUP BY county_name
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});

app.get('/api/analytics/claims-by-hospital', (req, res) => {
  const sql = `
    SELECT hosp_level, 'inpatient' AS type, SUM(claim_tot) AS total
    FROM inpatient GROUP BY hosp_level
    UNION ALL
    SELECT hosp_level, 'outpatient' AS type, SUM(claim_amount) AS total
    FROM outpatient GROUP BY hosp_level
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err });
    res.json(results);
  });
});




