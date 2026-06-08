require('dotenv').config();
const { google } = require('googleapis');

// Inicializamos el cliente de OAuth2 con las variables de tu .env
const oauth2Client = new google.auth.OAuth2(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  'https://developers.google.com/oauthplayground'
);

// Le pasamos el token que ya sabemos que funciona
oauth2Client.setCredentials({
  refresh_token: process.env.GOOGLE_REFRESH_TOKEN
});

/**
 * Función reutilizable para enviar correos
 */
async function enviarCorreoPersonalizado(destinatario, asunto, mensajeHtml) {
  try {
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Soportar caracteres especiales en el asunto (como emojis o tildes)
    const asuntoBase64 = `=?utf-8?B?${Buffer.from(asunto).toString('base64')}?=`;

    // Estructura del correo en formato MIME
    // Cambiado "Sistema de Alertas" por la identidad de tu app "Jardín de Deseos ✨"
    const emailLines = [
      `From: "Jardín de Deseos ✨" <${process.env.GMAIL_USER}>`,
      `To: ${destinatario}`,
      `Subject: ${asuntoBase64}`,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=utf-8',
      '',
      mensajeHtml
    ];

    const emailRaw = emailLines.join('\r\n');
    
    // Codificación Base64 segura para URLs (exigida por la API de Gmail)
    const encodedEmail = Buffer.from(emailRaw)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    console.log(`⏳ Enviando mensaje premium a <${destinatario}>...`);

    const response = await gmail.users.messages.send({
      userId: 'me',
      requestBody: {
        raw: encodedEmail
      }
    });

    console.log(`✅ ¡Mensaje enviado con éxito! ID del correo: ${response.data.id}`);

  } catch (error) {
    console.error('❌ Hubo un error al intentar enviar el correo:');
    if (error.response && error.response.data) {
      console.error(error.response.data);
    } else {
      console.error(error.message);
    }
  }
}

// ─────────────────────────────────────────────────────────────────
// CONFIGURA AQUÍ EL MENSAJE QUE QUIERES ENVIAR (VISTA PREMIUM)
// ─────────────────────────────────────────────────────────────────

const para = "frandy9991@gmail.com"; // Tu correo de pruebas asignado
const asuntoDelCorreo = "Tu rinconcito en el jardín te espera ✨";

// Variables de prueba simuladas para el entorno del script
const username = "Mariana";
const streak = 5;
const todayDate = "Domingo, 7 de Junio";

// Plantilla HTML oficial con la paleta e identidad visual
const cuerpoDelCorreo = `
  <div style="background-color: #f8f9fa; padding: 40px 10px; font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; min-height: 100%; margin: 0;">
    <div style="max-width: 460px; margin: 0 auto; background-color: #fef7e8; border: 1px solid #f0e1cc; border-radius: 28px; padding: 40px 30px; text-align: center; box-shadow: 0 4px 16px rgba(74, 46, 34, 0.04);">
      
      <div style="margin-bottom: 25px; line-height: 0;">
        <img src="https://res.cloudinary.com/dxruvfevj/image/upload/v1780843124/favicon_mzumzo.png" 
             alt="Jardín de Deseos" 
             style="width: 130px; height: auto; display: inline-block; max-width: 100%;">
      </div>
      
      <div style="margin-bottom: 20px;">
        <div style="display: inline-block; background-color: #F4D1D7; color: #8C3A4D; font-size: 14px; font-weight: bold; padding: 6px 16px; border-radius: 50px; letter-spacing: 0.02em;">
          🔥 Racha actual: ${streak} días cultivando magia
        </div>
      </div>
      
      <h2 style="color: #8C3A4D; font-size: 24px; font-weight: 700; margin: 0 0 16px 0; line-height: 1.3;">
        ¡Hola, ${username}!
      </h2>
      
      <p style="color: #4A2E22; font-size: 16px; line-height: 1.6; margin: 0 0 24px 0;">
        Hoy es <strong style="color: #8C3A4D;">${todayDate}</strong> y tu rinconcito en el jardín aún está esperando el detalle de hoy. No dejes pasar el día sin añadir tu regalo diario.
      </p>
      
      <div style="margin: 30px 0;">
        <a href="https://regalame-un-dia.netlify.app" 
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

// Ejecutamos el envío directo
enviarCorreoPersonalizado(para, asuntoDelCorreo, cuerpoDelCorreo);