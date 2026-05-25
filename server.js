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
  ssl: {
    rejectUnauthorized: false   // Esto evita la verificación estricta del certificado (útil para desarrollo)
    // Para mayor seguridad, puedes descargar el CA de TiDB Cloud y referenciarlo:
    // ca: fs.readFileSync('/path/to/ca.pem')
  }
});

// Middleware para verificar token JWT
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No autorizado' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [rows] = await pool.query('SELECT id, username, role, start_date, end_date FROM users WHERE id = ?', [decoded.id]);
    if (rows.length === 0) throw new Error();
    req.user = rows[0];
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token inválido' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  next();
};

// Ruta login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(401).json({ message: 'Credenciales inválidas' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Credenciales inválidas' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, start_date: user.start_date, end_date: user.end_date } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Obtener regalos del usuario
app.get('/api/gifts', authMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM gifts WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
  res.json(rows);
});

// Subir regalo (con imagen)
app.post('/api/gifts', authMiddleware, upload.single('image'), async (req, res) => {
  const { title, description, category, budget } = req.body;
  const userId = req.user.id;
  const today = new Date().toISOString().slice(0,10);
  // Verificar rango de fechas
  if (today < req.user.start_date || today > req.user.end_date) {
    return res.status(400).json({ message: 'Fuera del período permitido' });
  }
  // Verificar si ya subió hoy
  const [existing] = await pool.query('SELECT id FROM gifts WHERE user_id = ? AND DATE(created_at) = CURDATE()', [userId]);
  if (existing.length > 0) {
    return res.status(400).json({ message: 'Ya subiste un regalo hoy' });
  }
  let imageUrl = null;
  if (req.file) {
    const result = await new Promise((resolve, reject) => {
      const stream = cloudinary.uploader.upload_stream({ folder: 'regalos' }, (error, result) => {
        if (error) reject(error);
        else resolve(result);
      });
      stream.end(req.file.buffer);
    });
    imageUrl = result.secure_url;
  }
  const [result] = await pool.query(
    'INSERT INTO gifts (user_id, title, description, image_url, category, budget) VALUES (?, ?, ?, ?, ?, ?)',
    [userId, title, description, imageUrl, category, budget || 0]
  );
  const [newGift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [result.insertId]);
  res.status(201).json(newGift[0]);
});

// Eliminar regalo
app.delete('/api/gifts/:id', authMiddleware, async (req, res) => {
  const giftId = req.params.id;
  const [gift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
  if (gift.length === 0) return res.status(404).json({ message: 'No existe' });
  if (gift[0].user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'No autorizado' });
  }
  await pool.query('DELETE FROM gifts WHERE id = ?', [giftId]);
  res.status(204).send();
});

// Editar regalo
app.put('/api/gifts/:id', authMiddleware, async (req, res) => {
  const { title, description, category, budget } = req.body;
  const giftId = req.params.id;
  const [gift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
  if (gift.length === 0) return res.status(404).json({ message: 'No existe' });
  if (gift[0].user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'No autorizado' });
  }
  await pool.query('UPDATE gifts SET title = ?, description = ?, category = ?, budget = ? WHERE id = ?', [title, description, category, budget, giftId]);
  const [updated] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
  res.json(updated[0]);
});

// Estado de hoy (si puede subir)
app.get('/api/gifts/today-status', authMiddleware, async (req, res) => {
    const [existing] = await pool.query('SELECT id FROM gifts WHERE user_id = ? AND DATE(created_at) = CURDATE()', [req.user.id]);
    const canUpload = true;
  res.json({ canUpload });
});

// ADMIN: Obtener todos los usuarios
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT id, username, role, start_date, end_date, created_at FROM users');
  res.json(rows);
});

// ADMIN: Crear usuario
app.post('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { username, password, role, start_date, end_date } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const [result] = await pool.query('INSERT INTO users (username, password, role, start_date, end_date) VALUES (?, ?, ?, ?, ?)', [username, hashed, role, start_date, end_date]);
  const [newUser] = await pool.query('SELECT id, username, role, start_date, end_date FROM users WHERE id = ?', [result.insertId]);
  res.status(201).json(newUser[0]);
});

// ADMIN: Actualizar usuario
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

// ADMIN: Eliminar usuario
app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.status(204).send();
});

// ADMIN: Obtener todos los regalos
app.get('/api/admin/gifts', authMiddleware, adminMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT g.*, u.username FROM gifts g JOIN users u ON g.user_id = u.id ORDER BY g.created_at DESC');
  res.json(rows);
});

// ADMIN: Marcar favorito
app.put('/api/admin/gifts/:id/favorite', authMiddleware, adminMiddleware, async (req, res) => {
  const giftId = req.params.id;
  const [gift] = await pool.query('SELECT favorite FROM gifts WHERE id = ?', [giftId]);
  if (gift.length === 0) return res.status(404).json({ message: 'No existe' });
  const newFavorite = !gift[0].favorite;
  await pool.query('UPDATE gifts SET favorite = ? WHERE id = ?', [newFavorite, giftId]);
  res.json({ id: giftId, favorite: newFavorite });
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));