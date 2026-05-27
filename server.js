require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const upload = multer({ storage: multer.memoryStorage() });
const { google } = require('googleapis');
const cron = require('node-cron');

const app = express();
app.use(cors());
app.use(express.json());

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  ssl: { rejectUnauthorized: false },
  dateStrings: true
});

// ─────────────────────────────────────────────
//   CONFIGURACIÓN DE CORREO (GMAIL API - HTTP)
// ─────────────────────────────────────────────
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  'https://developers.google.com/oauthplayground'
);

oauth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_REFRESH_TOKEN
});

// Función para obtener fecha actual en República Dominicana
function getTodayRD() {
  const now = new Date();
  return now.toLocaleDateString('en-CA', { timeZone: 'America/Santo_Domingo' });
}

// Middlewares de autenticación
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No autorizado' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [rows] = await pool.query('SELECT id, username, role, start_date, end_date, email FROM users WHERE id = ?', [decoded.id]);
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

// ─────────────────────────────────────────────
//  RUTAS DE AUTENTICACIÓN, REGALOS, ETC.
// ─────────────────────────────────────────────
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) return res.status(401).json({ message: 'Credenciales inválidas' });
    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: 'Credenciales inválidas' });
    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role, start_date: user.start_date, end_date: user.end_date, email: user.email } });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

app.get('/api/gifts', authMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM gifts WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
  res.json(rows);
});

app.post('/api/gifts', authMiddleware, upload.single('image'), async (req, res) => {
  const { title, description, category, dateRD } = req.body;
  const userId = req.user.id;
  const startDateStr = new Date(req.user.start_date).toISOString().slice(0, 10);
  const endDateStr = new Date(req.user.end_date).toISOString().slice(0, 10);
  if (dateRD < startDateStr || dateRD > endDateStr) {
    return res.status(400).json({ message: 'Fuera del período permitido' });
  }
  const [existing] = await pool.query('SELECT id FROM gifts WHERE user_id = ? AND date_rd = ?', [userId, dateRD]);
  if (existing.length > 0) {
    return res.status(400).json({ message: 'Ya subiste un regalo hoy' });
  }
  let imageUrl = null;
  if (req.file) {
    try {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream({ folder: 'regalos' }, (error, result) => {
          if (error) reject(error);
          else resolve(result);
        });
        stream.end(req.file.buffer);
      });
      imageUrl = result.secure_url;
    } catch (err) {
      console.error('Error subiendo imagen:', err);
      return res.status(500).json({ message: 'Error al subir la imagen' });
    }
  }
  const [result] = await pool.query(
    'INSERT INTO gifts (user_id, title, description, image_url, category, date_rd) VALUES (?, ?, ?, ?, ?, ?)',
    [userId, title, description, imageUrl, category || 'Otro', dateRD]
  );
  const [newGift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [result.insertId]);
  res.status(201).json(newGift[0]);
});

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

app.put('/api/gifts/:id', authMiddleware, async (req, res) => {
  const { title, description, category } = req.body;
  const giftId = req.params.id;
  const [gift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
  if (gift.length === 0) return res.status(404).json({ message: 'No existe' });
  if (gift[0].user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'No autorizado' });
  }
  await pool.query('UPDATE gifts SET title = ?, description = ?, category = ? WHERE id = ?', [title, description, category, giftId]);
  const [updated] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
  res.json(updated[0]);
});

app.get('/api/gifts/today-status', authMiddleware, async (req, res) => {
  const dateRD = req.query.dateRD;
  if (!dateRD) return res.status(400).json({ message: 'Falta dateRD' });
  const [existing] = await pool.query('SELECT id FROM gifts WHERE user_id = ? AND date_rd = ?', [req.user.id, dateRD]);
  const startDateStr = new Date(req.user.start_date).toISOString().slice(0, 10);
  const endDateStr = new Date(req.user.end_date).toISOString().slice(0, 10);
  const canUpload = existing.length === 0 && dateRD >= startDateStr && dateRD <= endDateStr;
  res.json({ canUpload });
});

// ─────────────────────────────────────────────
//  EMAIL: ACTUALIZAR EMAIL DEL USUARIO
// ─────────────────────────────────────────────
app.put('/api/users/email', authMiddleware, async (req, res) => {
  const { email } = req.body;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ message: 'Email inválido' });
  }
  await pool.query('UPDATE users SET email = ? WHERE id = ?', [email, req.user.id]);
  const [updated] = await pool.query('SELECT email FROM users WHERE id = ?', [req.user.id]);
  res.json({ email: updated[0].email });
});

app.put('/api/admin/users/:id/email', authMiddleware, adminMiddleware, async (req, res) => {
  const { email } = req.body;
  const userId = req.params.id;
  if (!email || !email.includes('@')) {
    return res.status(400).json({ message: 'Email inválido' });
  }
  await pool.query('UPDATE users SET email = ? WHERE id = ?', [email, userId]);
  res.json({ message: 'Email actualizado' });
});

// ─────────────────────────────────────────────
//  FUNCIÓN PARA ENVIAR CORREO (NODEMAILER)
// ─────────────────────────────────────────────
async function sendReminderEmail(userEmail, username, todayDate) {
  try {
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Estructura del correo estándar RFC 2822 requerida por la API de Google
    const rawMessage = Buffer.from(
      `From: "Regalos Diarios" <${process.env.GMAIL_USER}>\r\n` +
      `To: ${userEmail}\r\n` +
      `Subject: =?utf-8?B?${Buffer.from(`🌟 ¿Olvidaste tu regalo de hoy? - ${todayDate}`).toString('base64')}?=\r\n` +
      `MIME-Version: 1.0\r\n` +
      `Content-Type: text/html; charset=utf-8\r\n\r\n` +
      `<div style="font-family: 'Jost', Arial; max-width: 500px; margin: auto; padding: 20px; border: 1px solid #f0e1cc; border-radius: 20px; background: #fef7e8;">` +
      `  <div style="text-align: center;">` +
      `    <div style="font-size: 48px;">🎁</div>` +
      `    <h2 style="color: #8C3A4D;">¡Hola, ${username}!</h2>` +
      `    <p style="color: #4A2E22;">Hoy es <strong>${todayDate}</strong> y aún no has dejado tu regalo diario.</p>` +
      `    <p>Entra a <a href="${process.env.FRONTEND_URL}" style="color: #C49A2F;">tu jardín de deseos</a> y comparte un pequeño antojo.</p>` +
      `    <p style="font-size: 12px; color: #7A5C50;">Si ya lo hiciste, ignora este mensaje. ¡Gracias por participar!</p>` +
      `  </div>` +
      `</div>`
    );

    // La API de Gmail exige que el string esté codificado en Base64 URL Safe
    const encodedMessage = rawMessage.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    // Hacemos la petición por el puerto 443 (HTTP), el cual Render NO bloquea
    const response = await gmail.users.messages.send({
      userId: 'me',
      requestBody: {
        raw: encodedMessage,
      },
    });

    console.log(`✅ Recordatorio enviado vía API de Gmail a ${userEmail} (ID: ${response.data.id})`);
  } catch (error) {
    console.error(`❌ Error enviando vía API a ${userEmail}:`, error);
  }
}

// ─────────────────────────────────────────────
//  CRON DIARIO (8:00 AM HORA RD)
// ─────────────────────────────────────────────
cron.schedule('30 10 * * *', async () => {
  console.log('Ejecutando recordatorios diarios a las 10:30 AM...');
  const todayRD = getTodayRD();
  
  try {
    // 1. Buscamos solo usuarios que NO hayan recibido el correo hoy
    const [users] = await pool.query(
      `SELECT id, username, email FROM users 
       WHERE email IS NOT NULL AND email != '' 
       AND start_date <= ? AND end_date >= ?
       AND (last_reminder_sent IS NULL OR last_reminder_sent < ?)`,
      [todayRD, todayRD, todayRD]
    );

    for (const user of users) {
      const [existing] = await pool.query(
        'SELECT id FROM gifts WHERE user_id = ? AND date_rd = ?',
        [user.id, todayRD]
      );

      if (existing.length === 0) {
        await sendReminderEmail(user.email, user.username, todayRD);
        
        // 2. IMPORTANTE: Guardamos en la BD que ya se le envió el correo hoy
        await pool.query(
          'UPDATE users SET last_reminder_sent = ? WHERE id = ?', 
          [todayRD, user.id]
        );
      }
    }
    console.log('Recordatorios completados.');
  } catch (error) {
    console.error('Error en cron de recordatorios:', error);
  }
}, { timezone: "America/Santo_Domingo" });

// ─────────────────────────────────────────────
//  ADMIN: USUARIOS Y REGALOS GLOBALES
// ─────────────────────────────────────────────
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT id, username, role, start_date, end_date, email, created_at FROM users');
  res.json(rows);
});

app.post('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { username, password, role, start_date, end_date, email } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const [result] = await pool.query(
    'INSERT INTO users (username, password, role, start_date, end_date, email) VALUES (?, ?, ?, ?, ?, ?)',
    [username, hashed, role, start_date, end_date, email || null]
  );
  const [newUser] = await pool.query('SELECT id, username, role, start_date, end_date, email FROM users WHERE id = ?', [result.insertId]);
  res.status(201).json(newUser[0]);
});

app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { start_date, end_date, role, password, email } = req.body;
  const userId = req.params.id;
  let query = 'UPDATE users SET start_date = ?, end_date = ?, role = ?';
  let params = [start_date, end_date, role];
  if (password) {
    const hashed = await bcrypt.hash(password, 10);
    query += ', password = ?';
    params.push(hashed);
  }
  if (email !== undefined) {
    query += ', email = ?';
    params.push(email);
  }
  query += ' WHERE id = ?';
  params.push(userId);
  await pool.query(query, params);
  const [updated] = await pool.query('SELECT id, username, role, start_date, end_date, email FROM users WHERE id = ?', [userId]);
  res.json(updated[0]);
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.status(204).send();
});

app.get('/api/admin/gifts', authMiddleware, adminMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT g.*, u.username FROM gifts g JOIN users u ON g.user_id = u.id ORDER BY g.created_at DESC');
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

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));