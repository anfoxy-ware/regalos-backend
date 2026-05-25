require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });

const app = express();
app.use(cors());
app.use(express.json());

// Configurar Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

// Pool de conexiones MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: { rejectUnauthorized: false }
});

// ──────────────────────────────────────────────────────────────
//  OBTENER FECHA ACTUAL EN REPÚBLICA DOMINICANA (UTC-4)
// ──────────────────────────────────────────────────────────────
function getTodayRD() {
  const now = new Date();
  const formatter = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Santo_Domingo',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
  return formatter.format(now); // formato YYYY-MM-DD
}

// ──────────────────────────────────────────────────────────────
//  MIDDLEWARES
// ──────────────────────────────────────────────────────────────
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No autorizado' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [rows] = await pool.query(
      'SELECT id, username, role, start_date, end_date FROM users WHERE id = ?',
      [decoded.id]
    );
    if (rows.length === 0) throw new Error();
    req.user = rows[0];
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Token inválido' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Acceso denegado' });
  }
  next();
};

// ──────────────────────────────────────────────────────────────
//  LOGIN
// ──────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      return res.status(401).json({ message: 'Credenciales inválidas' });
    }
    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        start_date: user.start_date,
        end_date: user.end_date
      }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// ──────────────────────────────────────────────────────────────
//  REGALOS DEL USUARIO (GET)
// ──────────────────────────────────────────────────────────────
app.get('/api/gifts', authMiddleware, async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT * FROM gifts WHERE user_id = ? ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al obtener regalos' });
  }
});

// ──────────────────────────────────────────────────────────────
//  CREAR REGALO (sin budget, con validación de fecha RD)
// ──────────────────────────────────────────────────────────────
app.post('/api/gifts', authMiddleware, upload.single('image'), async (req, res) => {
  const { title, description, category } = req.body;
  const userId = req.user.id;
  const todayRD = getTodayRD();

  // 1. Validar período activo
  if (todayRD < req.user.start_date || todayRD > req.user.end_date) {
    return res.status(400).json({ message: 'Fuera del período permitido' });
  }

  // 2. Validar que no haya subido un regalo hoy (en zona RD)
  const [existing] = await pool.query(
    `SELECT id FROM gifts 
     WHERE user_id = ? 
     AND DATE(CONVERT_TZ(created_at, '+00:00', '-04:00')) = ?`,
    [userId, todayRD]
  );
  if (existing.length > 0) {
    return res.status(400).json({ message: 'Ya subiste un regalo hoy' });
  }

  // 3. Subir imagen a Cloudinary (si existe)
  let imageUrl = null;
  if (req.file) {
    try {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
          { folder: 'regalos' },
          (error, result) => {
            if (error) reject(error);
            else resolve(result);
          }
        );
        stream.end(req.file.buffer);
      });
      imageUrl = result.secure_url;
    } catch (err) {
      console.error('Error subiendo imagen:', err);
      return res.status(500).json({ message: 'Error al subir la imagen' });
    }
  }

  // 4. Insertar en BD (sin budget)
  const [result] = await pool.query(
    'INSERT INTO gifts (user_id, title, description, image_url, category) VALUES (?, ?, ?, ?, ?)',
    [userId, title, description, imageUrl, category || 'Otro']
  );
  const [newGift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [result.insertId]);
  res.status(201).json(newGift[0]);
});

// ──────────────────────────────────────────────────────────────
//  ELIMINAR REGALO
// ──────────────────────────────────────────────────────────────
app.delete('/api/gifts/:id', authMiddleware, async (req, res) => {
  const giftId = req.params.id;
  try {
    const [gift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
    if (gift.length === 0) {
      return res.status(404).json({ message: 'No existe' });
    }
    if (gift[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'No autorizado' });
    }
    await pool.query('DELETE FROM gifts WHERE id = ?', [giftId]);
    res.status(204).send();
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al eliminar' });
  }
});

// ──────────────────────────────────────────────────────────────
//  EDITAR REGALO (sin budget)
// ──────────────────────────────────────────────────────────────
app.put('/api/gifts/:id', authMiddleware, async (req, res) => {
  const { title, description, category } = req.body;
  const giftId = req.params.id;
  try {
    const [gift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
    if (gift.length === 0) {
      return res.status(404).json({ message: 'No existe' });
    }
    if (gift[0].user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'No autorizado' });
    }
    await pool.query(
      'UPDATE gifts SET title = ?, description = ?, category = ? WHERE id = ?',
      [title, description, category, giftId]
    );
    const [updated] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
    res.json(updated[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al actualizar' });
  }
});

// ──────────────────────────────────────────────────────────────
//  ESTADO DEL DÍA (si puede subir otro regalo hoy)
// ──────────────────────────────────────────────────────────────
app.get('/api/gifts/today-status', authMiddleware, async (req, res) => {
  const todayRD = getTodayRD();
  try {
    const [existing] = await pool.query(
      `SELECT id FROM gifts 
       WHERE user_id = ? 
       AND DATE(CONVERT_TZ(created_at, '+00:00', '-04:00')) = ?`,
      [req.user.id, todayRD]
    );
    const canUpload = existing.length === 0 && todayRD >= req.user.start_date && todayRD <= req.user.end_date;
    res.json({ canUpload });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al consultar estado' });
  }
});

// ──────────────────────────────────────────────────────────────
//  ADMIN: USUARIOS
// ──────────────────────────────────────────────────────────────
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT id, username, role, start_date, end_date, created_at FROM users');
  res.json(rows);
});

app.post('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { username, password, role, start_date, end_date } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const [result] = await pool.query(
    'INSERT INTO users (username, password, role, start_date, end_date) VALUES (?, ?, ?, ?, ?)',
    [username, hashed, role, start_date, end_date]
  );
  const [newUser] = await pool.query('SELECT id, username, role, start_date, end_date FROM users WHERE id = ?', [result.insertId]);
  res.status(201).json(newUser[0]);
});

app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { start_date, end_date, role, password } = req.body;
  const userId = req.params.id;
  let query = 'UPDATE users SET start_date = ?, end_date = ?, role = ?';
  let params = [start_date, end_date, role];
  if (password) {
    const hashed = await bcrypt.hash(password, 10);
    query += ', password = ?';
    params.push(hashed);
  }
  query += ' WHERE id = ?';
  params.push(userId);
  await pool.query(query, params);
  const [updated] = await pool.query('SELECT id, username, role, start_date, end_date FROM users WHERE id = ?', [userId]);
  res.json(updated[0]);
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.status(204).send();
});

// ──────────────────────────────────────────────────────────────
//  ADMIN: REGALOS (globales)
// ──────────────────────────────────────────────────────────────
app.get('/api/admin/gifts', authMiddleware, adminMiddleware, async (req, res) => {
  const [rows] = await pool.query(
    'SELECT g.*, u.username FROM gifts g JOIN users u ON g.user_id = u.id ORDER BY g.created_at DESC'
  );
  res.json(rows);
});

app.put('/api/admin/gifts/:id/favorite', authMiddleware, adminMiddleware, async (req, res) => {
  const giftId = req.params.id;
  const [gift] = await pool.query('SELECT favorite FROM gifts WHERE id = ?', [giftId]);
  if (gift.length === 0) return res.status(404).json({ message: 'No existe' });
  const newFavorite = !gift[0].favorite;
  await pool.query('UPDATE gifts SET favorite = ? WHERE id = ?', [newFavorite, giftId]);
  res.json({ id: giftId, favorite: newFavorite });
});

// ──────────────────────────────────────────────────────────────
//  INICIAR SERVIDOR
// ──────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✅ Servidor corriendo en puerto ${PORT}`));