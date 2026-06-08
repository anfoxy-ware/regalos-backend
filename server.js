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

// ─────────────────────────────────────────────
//   MIDDLEWARES
// ─────────────────────────────────────────────
const authMiddleware = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No autorizado' });
  }
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
const [rows] = await pool.query('SELECT id, username, role, start_date, end_date, email, reminders_enabled, reminder_time_930, reminder_time_1330, reminder_time_1930 FROM users WHERE id = ?', [decoded.id]);    if (rows.length === 0) throw new Error();
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
//  RUTAS DE AUTENTICACIÓN Y PERFIL
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
    
res.json({ 
  token, 
  user: { 
    id: user.id, username: user.username, role: user.role, 
    start_date: user.start_date, end_date: user.end_date, email: user.email,
    reminders_enabled: user.reminders_enabled,
    reminder_time_930: user.reminder_time_930,
    reminder_time_1330: user.reminder_time_1330,
    reminder_time_1930: user.reminder_time_1930
  } 
});
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});
app.put('/api/users/profile', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    const { username, email, password, reminders_enabled, reminder_time_930, reminder_time_1330, reminder_time_1930 } = req.body; 

    if (!username) return res.status(400).json({ message: 'El nombre es obligatorio' });

    let updateQuery = `UPDATE users SET 
      username = ?, email = ?, reminders_enabled = ?, 
      reminder_time_930 = ?, reminder_time_1330 = ?, reminder_time_1930 = ?`;
    
    let queryParams = [
      username, email || null, reminders_enabled ? 1 : 0,
      reminder_time_930 ? 1 : 0, reminder_time_1330 ? 1 : 0, reminder_time_1930 ? 1 : 0
    ];

    if (password) {
      const saltRounds = 10;
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      updateQuery += ', password = ?';
      queryParams.push(hashedPassword);
    }

    updateQuery += ' WHERE id = ?';
    queryParams.push(userId);

    await pool.query(updateQuery, queryParams);

    res.json({
      id: userId, username, email,
      reminders_enabled: reminders_enabled ? 1 : 0,
      reminder_time_930: reminder_time_930 ? 1 : 0,
      reminder_time_1330: reminder_time_1330 ? 1 : 0,
      reminder_time_1930: reminder_time_1930 ? 1 : 0,
      role: req.user.role 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al actualizar perfil' });
  }
});

// ─────────────────────────────────────────────
//  RUTAS DE REGALOS
// ─────────────────────────────────────────────
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
//  FUNCIÓN PARA ENVIAR CORREO (GMAIL API)
// ─────────────────────────────────────────────
async function sendReminderEmail(userEmail, username, todayDate) {
  try {
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // 1. Codificación segura del asunto para evitar problemas con emojis o acentos
    const subjectBase64 = `=?utf-8?B?${Buffer.from(`🌟 ¿Olvidaste tu regalo de hoy? - ${todayDate}`).toString('base64')}?=`;

    // 2. Diseño HTML premium optimizado para móviles y computadoras
    const emailHtml = `
  <div style="background-color: #f8f9fa; padding: 40px 10px; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; min-height: 100%; margin: 0;">
    <div style="max-width: 460px; margin: 0 auto; background-color: #fef7e8; border: 1px solid #f0e1cc; border-radius: 28px; padding: 40px 30px; text-align: center; box-shadow: 0 4px 16px rgba(74, 46, 34, 0.04);">
      
      <div style="margin-bottom: 25px; line-height: 0;">
        <img src="https://res.cloudinary.com/dxruvfevj/image/upload/v1780843124/favicon_mzumzo.png" 
             alt="Jardín de Deseos" 
             style="width: 130px; height: auto; display: inline-block; max-width: 100%;">
      </div>
      
      <div style="margin-bottom: 20px;">
        <div style="display: inline-block; background-color: #F4D1D7; color: #8C3A4D; font-size: 14px; font-weight: bold; padding: 6px 16px; border-radius: 50px; letter-spacing: 0.02em;">
          🔥 ¡No pierdas tu racha! Mantén tu jardín lleno de magia.
        </div>
      </div>
      
      <h2 style="color: #8C3A4D; font-size: 24px; font-weight: 700; margin: 0 0 16px 0; line-height: 1.3;">
        ¡Hola, ${username}!
      </h2>
      
      <p style="color: #4A2E22; font-size: 16px; line-height: 1.6; margin: 0 0 24px 0;">
        Hoy es <strong style="color: #8C3A4D;">${todayDate}</strong> y tu rinconcito en el jardín aún está esperando el detalle de hoy. No dejes pasar el día sin añadir tu regalo diario.
      </p>
      
      <div style="margin: 30px 0;">
        <a href="${process.env.FRONTEND_URL || '#'}" 
           target="_blank" 
           style="display: inline-block; background-color: #8C3A4D; color: #ffffff; text-decoration: none; padding: 15px 35px; border-radius: 50px; font-size: 16px; font-weight: bold; box-shadow: 0 4px 12px rgba(140, 58, 77, 0.25);">
          Ir a mi Jardín de Deseos ✨
        </a>
      </div>
      
      <hr style="border: 0; border-top: 1px solid #f0e1cc; margin: 30px 0;">
      
      <p style="font-size: 11px; color: #7A5C50; line-height: 1.6; margin: 0;">
        Enviado con 🤍 desde tu rincón favorito en <strong>Jardín de Deseos</strong>.<br>
        Recibes este recordatorio automático porque tienes activos los avisos en este horario.<br>
        Puedes ajustar tus preferencias de turnos o desactivar las alertas en cualquier momento desde tu Perfil en la aplicación.
      </p>
      
    </div>
  </div>
`;

    // 3. Unión limpia del estándar MIME (Cabeceras + Cuerpo HTML)
    const emailLines = [
      `From: "Regalos Diarios" <${process.env.GMAIL_USER}>`,
      `To: ${userEmail}`,
      `Subject: ${subjectBase64}`,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=utf-8',
      '', // Línea en blanco obligatoria que separa las cabeceras del contenido HTML
      emailHtml
    ];

    const rawMessage = Buffer.from(emailLines.join('\r\n'));

    // 4. Codificación Base64 segura para la API de Gmail
    const encodedMessage = rawMessage.toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    // 5. Envío del mensaje
    const response = await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw: encodedMessage },
    });

    console.log(`✅ Recordatorio enviado a ${userEmail} (ID: ${response.data.id})`);
  } catch (error) {
    console.error(`❌ Error enviando a ${userEmail}:`, error);
  }
}// ─────────────────────────────────────────────
//  FUNCIÓN CORE PARA RECORDATORIOS POR HORA (9:30, 13:30, 19:30)
// ─────────────────────────────────────────────
async function procesarRecordatoriosPorHora(columnaHora, etiquetaHora) {
  console.log(`⏱️ Ejecutando verificación para horario: ${etiquetaHora}`);
  const todayRD = getTodayRD();

  try {
    // 1. Buscamos usuarios activos que tengan este horario marcado = 1
    // ELIMINADA la validación de last_reminder_sent para no bloquear los turnos
    const [users] = await pool.query(
      `SELECT id, username, email FROM users 
       WHERE email IS NOT NULL AND email != '' 
       AND reminders_enabled = 1
       AND ${columnaHora} = 1
       AND start_date <= ? AND end_date >= ?`,
      [todayRD, todayRD]
    );

    for (const user of users) {
      // 2. LA ÚNICA CONDICIÓN: Verificar si ya subió un regalo hoy en la BD
      const [existing] = await pool.query(
        'SELECT id FROM gifts WHERE user_id = ? AND date_rd = ?',
        [user.id, todayRD]
      );

      // 3. Si NO hay regalo, se envía el recordatorio correspondiente a la hora
      if (existing.length === 0) {
        await sendReminderEmail(user.email, user.username, todayRD);
        console.log(`📩 Aviso de las ${etiquetaHora} enviado a ${user.username}`);
        
        // ¡ELIMINADO el UPDATE a last_reminder_sent! 
        // No necesitamos guardar si se envió correo, solo nos importa si hay regalo.
      } else {
        // Opcional: Un log para confirmar que el sistema detectó el regalo
        console.log(`✨ ${user.username} ya tiene su regalo hoy. Omitiendo alerta de las ${etiquetaHora}.`);
      }
    }
    console.log(`✅ Turno de las ${etiquetaHora} finalizado.`);
  } catch (error) {
    console.error(`❌ Error en bloque de las ${etiquetaHora}:`, error);
  }
}

// CRON 1: 09:30 AM hora RD
cron.schedule('30 9 * * *', () => {
  procesarRecordatoriosPorHora('reminder_time_930', '09:30 AM');
}, { timezone: "America/Santo_Domingo" });

// CRON 2: 13:30 PM (1:30 PM) hora RD
cron.schedule('30 13 * * *', () => {
  procesarRecordatoriosPorHora('reminder_time_1330', '13:30 PM');
}, { timezone: "America/Santo_Domingo" });

// CRON 3: 19:30 PM (7:30 PM) hora RD
cron.schedule('30 19 * * *', () => {
  procesarRecordatoriosPorHora('reminder_time_1930', '19:30 PM');
}, { timezone: "America/Santo_Domingo" });

// ─────────────────────────────────────────────
//  ADMIN: USUARIOS Y REGALOS GLOBALES
// ─────────────────────────────────────────────
app.get('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const [rows] = await pool.query('SELECT id, username, role, start_date, end_date, email, reminders_enabled, created_at FROM users');
  res.json(rows);
});

app.post('/api/admin/users', authMiddleware, adminMiddleware, async (req, res) => {
  const { username, password, role, start_date, end_date, email } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const [result] = await pool.query(
    'INSERT INTO users (username, password, role, start_date, end_date, email) VALUES (?, ?, ?, ?, ?, ?)',
    [username, hashed, role, start_date, end_date, email || null]
  );
  const [newUser] = await pool.query('SELECT id, username, role, start_date, end_date, email, reminders_enabled FROM users WHERE id = ?', [result.insertId]);
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
  const [updated] = await pool.query('SELECT id, username, role, start_date, end_date, email, reminders_enabled FROM users WHERE id = ?', [userId]);
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

app.put('/api/gifts/:id/favorite', authMiddleware, async (req, res) => {
  const giftId = req.params.id;
  try {
    const [gift] = await pool.query('SELECT favorite FROM gifts WHERE id = ?', [giftId]);
    if (gift.length === 0) return res.status(404).json({ message: 'No existe' });
    
    const newFavorite = !gift[0].favorite;
    await pool.query('UPDATE gifts SET favorite = ? WHERE id = ?', [newFavorite, giftId]);
    res.json({ id: giftId, favorite: newFavorite });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error en el servidor' });
  }
});

// Endpoint para mantener el servidor despierto (sin necesidad de autenticación)
app.get('/ping', (req, res) => {
  res.status(200).send('OK');
});
// Iniciar servidor
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));