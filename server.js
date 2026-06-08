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
const rateLimit = require('express-rate-limit');

const app = express();

// ─────────────────────────────────────────────
//   SEGURIDAD Y CONFIGURACIÓN BÁSICA
// ─────────────────────────────────────────────
app.use(cors({
  origin: 'https://regalame-un-dia.netlify.app', 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true
}));
app.use(express.json());

// Prevención de fuerza bruta en el Login
const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 15, // Límite de 15 intentos por minuto por IP
  message: { message: "Demasiados intentos. Por favor, inténtalo de nuevo en un minuto." }
});

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
//   CONFIGURACIÓN DE CORREO Y UTILIDADES
// ─────────────────────────────────────────────
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  'https://developers.google.com/oauthplayground'
);

oauth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_REFRESH_TOKEN
});

function getTodayRD() {
  const now = new Date();
  return now.toLocaleDateString('en-CA', { timeZone: 'America/Santo_Domingo' });
}

async function generateUniqueJoinCode() {
  let isUnique = false;
  let code = '';
  while (!isUnique) {
    code = Math.random().toString(36).substring(2, 8).toUpperCase();
    const [existing] = await pool.query('SELECT id FROM gardens WHERE join_code = ?', [code]);
    if (existing.length === 0) {
      isUnique = true;
    }
  }
  return code;
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
    const [rows] = await pool.query(
      'SELECT id, username, role, start_date, end_date, email, reminders_enabled, reminder_time_930, reminder_time_1330, reminder_time_1930 FROM users WHERE id = ?', 
      [decoded.id]
    );
    if (rows.length === 0) throw new Error();
    req.user = rows[0];
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token inválido o sesión expirada' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acceso denegado' });
  next();
};

const checkGardenMembership = async (req, res, next) => {
  // Usamos '?.' para que si req.body no existe (ej. en peticiones GET), no crashee
  const gardenId = req.params?.gardenId || req.body?.garden_id || req.query?.garden_id;
  
  // Si no hay ID, pasamos al siguiente middleware (útil para listar TODOS los regalos globalmente)
  if (!gardenId) return next();

  try {
    const [membership] = await pool.query(
      'SELECT role FROM garden_members WHERE user_id = ? AND garden_id = ?',
      [req.user.id, gardenId]
    );

    if (membership.length === 0) {
      return res.status(403).json({ message: 'Acceso denegado. No eres miembro de este jardín.' });
    }

    req.gardenRole = membership[0].role;
    req.gardenId = gardenId;
    next();
  } catch (error) {
    console.error("Error en checkGardenMembership:", error);
    res.status(500).json({ message: 'Error interno al validar permisos del jardín.' });
  }
};

// ─────────────────────────────────────────────
//  RUTAS DE AUTENTICACIÓN Y PERFIL
// ─────────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, async (req, res) => {
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

app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  
  if (!username || !email || !password) {
    return res.status(400).json({ message: 'Todos los campos son obligatorios' });
  }
  if (password.length < 6) {
    return res.status(400).json({ message: 'La contraseña debe tener al menos 6 caracteres' });
  }

  try {
    const [existing] = await pool.query(
      'SELECT id FROM users WHERE username = ? OR email = ?', 
      [username, email]
    );
    
    if (existing.length > 0) {
      return res.status(400).json({ message: 'El usuario o el correo ya están en uso' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const startDate = getTodayRD();
    const endDate = new Date();
    endDate.setFullYear(endDate.getFullYear() + 1);
    const endDateStr = endDate.toISOString().slice(0, 10);

    await pool.query(
      'INSERT INTO users (username, email, password, role, start_date, end_date) VALUES (?, ?, ?, ?, ?, ?)',
      [username, email, hashedPassword, 'user', startDate, endDateStr]
    );

    res.status(201).json({ message: 'Cuenta creada con éxito' });
  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({ message: 'Error interno del servidor' });
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

    if (password && password.trim().length > 0) {
      if (password.length < 6) return res.status(400).json({ message: "La contraseña debe tener al menos 6 caracteres" });
      const hashed = await bcrypt.hash(password, 10);
      updateQuery += ', password = ?';
      queryParams.push(hashed);
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
//  RUTAS DE JARDINES
// ─────────────────────────────────────────────
app.post('/api/gardens', authMiddleware, async (req, res) => {
  const { name } = req.body;
  let { start_date, end_date } = req.body;
  const creator_id = req.user.id; 

  if (!name) return res.status(400).json({ message: 'El nombre del jardín es obligatorio' });

  const join_code = await generateUniqueJoinCode();

  if (!start_date) start_date = getTodayRD();
  if (!end_date) {
    const defaultEnd = new Date();
    defaultEnd.setFullYear(defaultEnd.getFullYear() + 1);
    end_date = defaultEnd.toISOString().slice(0, 10);
  }

  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();

    const [gardenResult] = await connection.query(
      'INSERT INTO gardens (name, join_code, start_date, end_date, creator_id) VALUES (?, ?, ?, ?, ?)',
      [name, join_code, start_date, end_date, creator_id]
    );
    const gardenId = gardenResult.insertId;

    await connection.query(
      'INSERT INTO garden_members (user_id, garden_id, role) VALUES (?, ?, ?)',
      [creator_id, gardenId, 'admin']
    );

    await connection.commit();
    
    res.status(201).json({ 
      message: 'Jardín creado y listo para compartir',
      garden: { id: gardenId, name, join_code } 
    });
  } catch (error) {
    await connection.rollback();
    console.error("Error creando jardín:", error);
    res.status(500).json({ message: 'Error interno al crear el jardín' });
  } finally {
    connection.release();
  }
});

app.post('/api/gardens/join', authMiddleware, async (req, res) => {
  const { join_code } = req.body;
  const userId = req.user.id;

  if (!join_code) return res.status(400).json({ message: 'El código de invitación es obligatorio.' });

  try {
    const [gardens] = await pool.query('SELECT id, name, end_date FROM gardens WHERE join_code = ?', [join_code.trim().toUpperCase()]);
    if (gardens.length === 0) return res.status(404).json({ message: 'Código inválido. No se encontró ningún jardín.' });

    const garden = gardens[0];
    const today = getTodayRD(); 

    if (today > garden.end_date) return res.status(400).json({ message: 'Este jardín ya ha cerrado su temporada.' });

    const [alreadyMember] = await pool.query('SELECT 1 FROM garden_members WHERE user_id = ? AND garden_id = ?', [userId, garden.id]);
    if (alreadyMember.length > 0) return res.status(400).json({ message: 'Ya formas parte de este jardín.' });

    await pool.query('INSERT INTO garden_members (user_id, garden_id, role) VALUES (?, ?, ?)', [userId, garden.id, 'member']);

    res.status(200).json({
      message: '¡Te has unido al jardín con éxito! 🎉',
      garden: { id: garden.id, name: garden.name }
    });
  } catch (error) {
    console.error("Error al unirse al jardín:", error);
    res.status(500).json({ message: 'Error interno al procesar la solicitud.' });
  }
});

app.get('/api/gardens', authMiddleware, async (req, res) => {
  try {
    const [userGardens] = await pool.query(
      `SELECT g.id, g.name, g.join_code, g.start_date, g.end_date, gm.role 
       FROM gardens g
       JOIN garden_members gm ON g.id = gm.garden_id
       WHERE gm.user_id = ?
       ORDER BY g.created_at DESC`,
      [req.user.id]
    );
    res.json(userGardens);
  } catch (error) {
    console.error("Error al obtener jardines:", error);
    res.status(500).json({ message: 'Error interno al obtener los entornos.' });
  }
});

app.delete('/api/gardens/:id/leave', authMiddleware, async (req, res) => {
  const gardenId = req.params.id;
  const userId   = req.user.id;

  try {
    const [garden] = await pool.query('SELECT creator_id FROM gardens WHERE id = ?', [gardenId]);
    if (garden.length === 0) return res.status(404).json({ message: 'Jardín no encontrado' });

    await pool.query('DELETE FROM garden_members WHERE user_id = ? AND garden_id = ?', [userId, gardenId]);
    res.status(204).send();
  } catch (error) {
    console.error("Error al salir del jardín:", error);
    res.status(500).json({ message: 'Error interno al procesar la solicitud.' });
  }
});

// ─────────────────────────────────────────────
//  RUTAS DE REGALOS
// ─────────────────────────────────────────────
app.get('/api/gifts', authMiddleware, checkGardenMembership, async (req, res) => {
  const gardenId = req.gardenId; 
  try {
    let rows;
    if (gardenId) {
      [rows] = await pool.query('SELECT * FROM gifts WHERE user_id = ? AND garden_id = ? ORDER BY date_rd DESC', [req.user.id, gardenId]);
    } else {
      [rows] = await pool.query('SELECT * FROM gifts WHERE user_id = ? ORDER BY date_rd DESC', [req.user.id]);
    }
    res.json(rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al obtener regalos' });
  }
});

// ¡CORRECCIÓN VITAL AQUÍ!: upload.single('image') debe ir ANTES de checkGardenMembership 
// para que multer procese el req.body primero y pueda encontrar el garden_id.
app.post('/api/gifts', authMiddleware, upload.single('image'), checkGardenMembership, async (req, res) => {
  const { title, description, category, dateRD } = req.body;
  const garden_id = req.gardenId;
  const userId = req.user.id;

  if (!garden_id) return res.status(400).json({ message: 'Debes seleccionar un jardín' });

  try {
    const [gardenRows] = await pool.query('SELECT start_date, end_date FROM gardens WHERE id = ?', [garden_id]);
    if (!gardenRows.length) return res.status(404).json({ message: 'Jardín no encontrado' });

    const { start_date, end_date } = gardenRows[0];
    if (dateRD < start_date || dateRD > end_date) {
      return res.status(400).json({ message: 'Fuera del período de este jardín' });
    }

    const [existing] = await pool.query(
      'SELECT id FROM gifts WHERE user_id = ? AND garden_id = ? AND date_rd = ?',
      [userId, garden_id, dateRD]
    );
    if (existing.length > 0) return res.status(400).json({ message: 'Ya subiste un regalo hoy en este jardín' });

    let imageUrl = null;
    if (req.file) {
      const result = await new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream({ folder: 'regalos' }, (error, result) => {
          if (error) reject(error); else resolve(result);
        });
        stream.end(req.file.buffer);
      });
      imageUrl = result.secure_url;
    }

    const [result] = await pool.query(
      'INSERT INTO gifts (user_id, garden_id, title, description, image_url, category, date_rd) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [userId, garden_id, title, description, imageUrl, category || 'Otro', dateRD]
    );

    const [newGift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [result.insertId]);
    res.status(201).json(newGift[0]);
  } catch (err) {
    console.error('Error creando regalo:', err);
    res.status(500).json({ message: 'Error interno al guardar el regalo' });
  }
});

app.get('/api/gifts/today-status', authMiddleware, checkGardenMembership, async (req, res) => {
  const { dateRD } = req.query;
  const garden_id = req.gardenId;

  if (!dateRD) return res.status(400).json({ message: 'Falta dateRD' });
  if (!garden_id) return res.json({ canUpload: false, reason: 'no_garden' });

  try {
    const [gardenRows] = await pool.query('SELECT start_date, end_date FROM gardens WHERE id = ?', [garden_id]);
    if (!gardenRows.length) return res.json({ canUpload: false, reason: 'garden_not_found' });

    const { start_date, end_date } = gardenRows[0];
    const inRange = dateRD >= start_date && dateRD <= end_date;

    const [existing] = await pool.query(
      'SELECT id FROM gifts WHERE user_id = ? AND garden_id = ? AND date_rd = ?',
      [req.user.id, garden_id, dateRD]
    );

    res.json({ canUpload: inRange && existing.length === 0 });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Error al verificar estado' });
  }
});

app.put('/api/gifts/:id', authMiddleware, async (req, res) => {
  const { title, description, category } = req.body;
  const giftId = req.params.id;
  const [gift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
  
  if (!gift.length) return res.status(404).json({ message: 'No existe' });
  if (gift[0].user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'No autorizado' });
  }
  
  await pool.query('UPDATE gifts SET title = ?, description = ?, category = ? WHERE id = ?', [title, description, category, giftId]);
  const [updated] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
  res.json(updated[0]);
});

app.delete('/api/gifts/:id', authMiddleware, async (req, res) => {
  const giftId = req.params.id;
  const [gift] = await pool.query('SELECT * FROM gifts WHERE id = ?', [giftId]);
  
  if (!gift.length) return res.status(404).json({ message: 'No existe' });
  if (gift[0].user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ message: 'No autorizado' });
  }
  
  await pool.query('DELETE FROM gifts WHERE id = ?', [giftId]);
  res.status(204).send();
});

// Endpoint unificado para marcar como favorito
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

// ─────────────────────────────────────────────
//  FUNCIÓN PARA ENVIAR CORREO (GMAIL API)
// ─────────────────────────────────────────────
async function sendReminderEmail(userEmail, username, todayDate) {
  try {
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const subjectBase64 = `=?utf-8?B?${Buffer.from(`🌟 ¿Olvidaste tu regalo de hoy? - ${todayDate}`).toString('base64')}?=`;
    const emailHtml = `
      <div style="background-color: #f8f9fa; padding: 40px 10px; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; min-height: 100%; margin: 0;">
        <div style="max-width: 460px; margin: 0 auto; background-color: #fef7e8; border: 1px solid #f0e1cc; border-radius: 28px; padding: 40px 30px; text-align: center; box-shadow: 0 4px 16px rgba(74, 46, 34, 0.04);">
          <div style="margin-bottom: 25px; line-height: 0;">
            <img src="https://res.cloudinary.com/dxruvfevj/image/upload/v1780843124/favicon_mzumzo.png" alt="Jardín de Deseos" style="width: 130px; height: auto; display: inline-block; max-width: 100%;">
          </div>
          <div style="margin-bottom: 20px;">
            <div style="display: inline-block; background-color: #F4D1D7; color: #8C3A4D; font-size: 14px; font-weight: bold; padding: 6px 16px; border-radius: 50px; letter-spacing: 0.02em;">
              🔥 ¡No pierdas tu racha! Mantén tu jardín lleno de magia.
            </div>
          </div>
          <h2 style="color: #8C3A4D; font-size: 24px; font-weight: 700; margin: 0 0 16px 0; line-height: 1.3;">¡Hola, ${username}!</h2>
          <p style="color: #4A2E22; font-size: 16px; line-height: 1.6; margin: 0 0 24px 0;">
            Hoy es <strong style="color: #8C3A4D;">${todayDate}</strong> y tu rinconcito en el jardín aún está esperando el detalle de hoy. No dejes pasar el día sin añadir tu regalo diario.
          </p>
          <div style="margin: 30px 0;">
            <a href="${process.env.FRONTEND_URL || '#'}" target="_blank" style="display: inline-block; background-color: #8C3A4D; color: #ffffff; text-decoration: none; padding: 15px 35px; border-radius: 50px; font-size: 16px; font-weight: bold; box-shadow: 0 4px 12px rgba(140, 58, 77, 0.25);">
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
      </div>`;

    const emailLines = [
      `From: "Regalos Diarios" <${process.env.GMAIL_USER}>`,
      `To: ${userEmail}`,
      `Subject: ${subjectBase64}`,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=utf-8',
      '',
      emailHtml
    ];
    const encodedMessage = Buffer.from(emailLines.join('\r\n')).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

    const response = await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw: encodedMessage },
    });
    console.log(`✅ Recordatorio enviado a ${userEmail} (ID: ${response.data.id})`);
  } catch (error) {
    console.error(`❌ Error enviando a ${userEmail}:`, error);
  }
}

// ─────────────────────────────────────────────
//  CRON JOB - RECORDATORIOS (ACTUALIZADO A JARDINES)
// ─────────────────────────────────────────────
async function procesarRecordatoriosPorHora(columnaHora, etiquetaHora) {
  console.log(`⏱️ Ejecutando verificación para horario: ${etiquetaHora}`);
  const todayRD = getTodayRD();

  try {
    const [users] = await pool.query(
      `SELECT DISTINCT u.id, u.username, u.email 
       FROM users u
       JOIN garden_members gm ON u.id = gm.user_id
       JOIN gardens g ON gm.garden_id = g.id
       WHERE u.email IS NOT NULL AND u.email != '' 
       AND u.reminders_enabled = 1
       AND u.${columnaHora} = 1
       AND g.start_date <= ? AND g.end_date >= ?`,
      [todayRD, todayRD]
    );

    for (const user of users) {
      const [existing] = await pool.query(
        'SELECT id FROM gifts WHERE user_id = ? AND date_rd = ?',
        [user.id, todayRD]
      );
      if (existing.length === 0) {
        await sendReminderEmail(user.email, user.username, todayRD);
        console.log(`📩 Aviso de las ${etiquetaHora} enviado a ${user.username}`);
      } else {
        console.log(`✨ ${user.username} ya tiene su regalo hoy. Omitiendo alerta de las ${etiquetaHora}.`);
      }
    }
    console.log(`✅ Turno de las ${etiquetaHora} finalizado.`);
  } catch (error) {
    console.error(`❌ Error en bloque de las ${etiquetaHora}:`, error);
  }
}

cron.schedule('30 9 * * *',  () => procesarRecordatoriosPorHora('reminder_time_930', '09:30 AM'), { timezone: "America/Santo_Domingo" });
cron.schedule('30 13 * * *', () => procesarRecordatoriosPorHora('reminder_time_1330', '13:30 PM'), { timezone: "America/Santo_Domingo" });
cron.schedule('30 19 * * *', () => procesarRecordatoriosPorHora('reminder_time_1930', '19:30 PM'), { timezone: "America/Santo_Domingo" });

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

// ─────────────────────────────────────────────
//  INICIO DEL SERVIDOR
// ─────────────────────────────────────────────
app.get('/ping', (req, res) => res.status(200).send('OK'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en puerto ${PORT}`));