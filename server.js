require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');
const nodemailer = require('nodemailer'); // <-- NUEVO: Para enviar correos
const cron = require('node-cron'); // <-- NUEVO: Para tareas programadas
const upload = multer({ storage: multer.memoryStorage() });

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

// --- CONFIGURACIÓN DE CORREOS ---
const transporter = nodemailer.createTransport({
  service: 'gmail', // Puedes cambiarlo si usas Outlook, Yahoo, etc.
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Función para obtener la fecha actual en República Dominicana (UTC-4)
const getTodayRD = () => {
  const now = new Date();
  now.setHours(now.getHours() - 4);
  return now.toISOString().slice(0, 10);
};

// Lógica principal de recordatorios
const sendDailyReminders = async () => {
  console.log('Iniciando revisión de recordatorios diarios...');
  try {
    const todayStr = getTodayRD();
    
    // 1. Buscar usuarios con correo y recordatorios activados
    const [users] = await pool.query(
      'SELECT id, username, email, start_date, end_date FROM users WHERE email IS NOT NULL AND email != "" AND reminders_enabled = 1'
    );

    let correosEnviados = 0;

    for (const user of users) {
      const startStr = new Date(user.start_date).toISOString().slice(0, 10);
      const endStr = new Date(user.end_date).toISOString().slice(0, 10);

      // 2. Verificar si están dentro de sus fechas permitidas
      if (todayStr >= startStr && todayStr <= endStr) {
        
        // 3. Verificar si YA subieron un regalo hoy
        const [gifts] = await pool.query(
          'SELECT id FROM gifts WHERE user_id = ? AND date_rd = ?',
          [user.id, todayStr]
        );

        // 4. Si no tienen regalos hoy, les mandamos el correo
        if (gifts.length === 0) {
          const mailOptions = {
            from: `"Diario de Regalos" <${process.env.EMAIL_USER}>`,
            to: user.email,
            subject: '¡No olvides subir tu momento de hoy! 🎁',
            html: `
              <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
                <h2 style="color: #d81b60;">¡Hola ${user.username}!</h2>
                <p>Notamos que aún no has registrado tu momento o regalo del día de hoy.</p>
                <p>No dejes que se te escape el día. Entra ahora y guarda ese bonito recuerdo antes de que termine la jornada.</p>
                <br>
                <a href="https://tu-pagina-web.com" style="background-color: #d81b60; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block;">Ir a mi Diario</a>
                <br><br>
                <p style="color: #777; font-size: 12px;">Si ya no deseas recibir estos correos, avísale al administrador.</p>
              </div>
            `
          };

          await transporter.sendMail(mailOptions);
          console.log(`Recordatorio enviado con éxito a: ${user.email}`);
          correosEnviados++;
        }
      }
    }
    console.log(`Revisión terminada. Se enviaron ${correosEnviados} correos hoy.`);
    return correosEnviados;
  } catch (error) {
    console.error('Error al enviar los recordatorios:', error);
    throw error;
  }
};

// Programar tarea automática (Cron Job) - Se ejecuta todos los días a las 19:00 (7 PM)
cron.schedule('0 19 * * *', () => {
  sendDailyReminders();
});

// Middleware de autenticación
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No autorizado' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const [rows] = await pool.query('SELECT id, username, role, start_date, end_date, email, reminders_enabled FROM users WHERE id = ?', [decoded.id]);
    if (rows.length === 0) throw new Error();
    req.user = rows[0];
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token inválido' });
  }
};

// Middleware Admin
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
    
    res.json({ 
      token, 
      user: { 
        id: user.id, 
        username: user.username, 
        role: user.role, 
        start_date: user.start_date, 
        end_date: user.end_date,
        email: user.email, 
        reminders_enabled: user.reminders_enabled 
      } 
    });
  } catch (error) {
    console.error("Error en login:", error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Obtener regalos del usuario
app.get('/api/gifts', authMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT * FROM gifts WHERE user_id = ? ORDER BY created_at DESC', [req.user.id]);
  res.json(rows);
});

// Crear regalo
app.post('/api/gifts', authMiddleware, upload.single('image'), async (req, res) => {
  const { title, description, category, dateRD } = req.body;
  const userId = req.user.id;

  const startDateStr = new Date(req.user.start_date).toISOString().slice(0, 10);
  const endDateStr = new Date(req.user.end_date).toISOString().slice(0, 10);

  if (dateRD < startDateStr || dateRD > endDateStr) {
    return res.status(400).json({ message: 'Fuera del período permitido' });
  }

  const [existing] = await pool.query(
    'SELECT id FROM gifts WHERE user_id = ? AND date_rd = ?',
    [userId, dateRD]
  );
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

// Estado del día
app.get('/api/gifts/today-status', authMiddleware, async (req, res) => {
  const dateRD = req.query.dateRD;
  if (!dateRD) {
    return res.status(400).json({ message: 'Falta el parámetro dateRD' });
  }
  
  const [existing] = await pool.query(
    'SELECT id FROM gifts WHERE user_id = ? AND date_rd = ?',
    [req.user.id, dateRD]
  );
  
  const startDateStr = new Date(req.user.start_date).toISOString().slice(0, 10);
  const endDateStr = new Date(req.user.end_date).toISOString().slice(0, 10);

  const canUpload = existing.length === 0 && dateRD >= startDateStr && dateRD <= endDateStr;
  
  res.json({ canUpload });
});

// ADMIN: Obtener todos los usuarios
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT id, username, role, start_date, end_date, email, reminders_enabled, created_at FROM users');
  res.json(rows);
});

// ADMIN: Crear usuario
app.post('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { username, password, role, start_date, end_date, email, reminders_enabled } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  
  const isEnabled = reminders_enabled !== undefined ? reminders_enabled : true; 

  const [result] = await pool.query(
    'INSERT INTO users (username, password, role, start_date, end_date, email, reminders_enabled) VALUES (?, ?, ?, ?, ?, ?, ?)', 
    [username, hashed, role, start_date, end_date, email || null, isEnabled]
  );
  const [newUser] = await pool.query(
    'SELECT id, username, role, start_date, end_date, email, reminders_enabled FROM users WHERE id = ?', 
    [result.insertId]
  );
  res.status(201).json(newUser[0]);
});

// ADMIN: Editar usuario
app.put('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { start_date, end_date, role, password, email, reminders_enabled } = req.body;
  const userId = req.params.id;
  
  let query = 'UPDATE users SET start_date = ?, end_date = ?, role = ?, email = ?, reminders_enabled = ?';
  const isEnabled = reminders_enabled !== undefined ? reminders_enabled : true;
  let params = [start_date, end_date, role, email || null, isEnabled];
  
  if (password) {
    const hashed = await bcrypt.hash(password, 10);
    query += ', password = ?';
    params.push(hashed);
  }
  query += ' WHERE id = ?';
  params.push(userId);
  
  await pool.query(query, params);
  const [updated] = await pool.query('SELECT id, username, role, start_date, end_date, email, reminders_enabled FROM users WHERE id = ?', [userId]);
  res.json(updated[0]);
});

app.delete('/api/admin/users/:id', authMiddleware, adminMiddleware, async (req, res) => {
  await pool.query('DELETE FROM users WHERE id = ?', [req.params.id]);
  res.status(204).send();
});

// ADMIN: regalos globales
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

// --- RUTA SECRETA PARA PROBAR CORREOS MANUALMENTE ---
app.post('/api/admin/trigger-reminders', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const enviados = await sendDailyReminders();
    res.json({ message: `Revisión completada. Se enviaron ${enviados} correos.` });
  } catch (error) {
    res.status(500).json({ message: 'Error al enviar correos', error: error.message });
  }
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));