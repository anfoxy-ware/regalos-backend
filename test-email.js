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
    const emailLines = [
      `From: "Sistema de Alertas" <${process.env.GMAIL_USER}>`,
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

    console.log(`⏳ Enviando mensaje a <${destinatario}>...`);

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
// CONFIGURA AQUÍ EL MENSAJE QUE QUIERES ENVIAR
// ─────────────────────────────────────────────────────────────────

const para = "jjpre123@gmail.com";
const asuntoDelCorreo = "¡Mensaje personalizado desde el script! 📩";

// Puedes usar etiquetas HTML para que se vea limpio y ordenado
const cuerpoDelCorreo = `
  <div style="font-family: Arial, sans-serif; padding: 20px; background-color: #f4f4f7; border-radius: 8px; max-width: 500px; margin: auto;">
    <h2 style="color: #333333; text-align: center;">¡Hola Insensible! 👋</h2>
    <p style="color: #555555; font-size: 16px; line-height: 1.5;">
      Este es un mensaje real enviado de forma dinámica utilizando el script de Node.js y la API de Gmail.
    </p>
    <div style="background-color: #ffffff; padding: 15px; border-left: 4px solid #4CAF50; margin: 20px 0; border-radius: 4px;">
      <strong>Estado del sistema:</strong> ¡Tokens activos y funcionando al 100% :D! 🚀
    </div>
    <p style="color: #777777; font-size: 12px; text-align: center; margin-top: 30px;">
      Este correo fue generado automáticamente por tu servidor de pruebas, lo que no se puede probar es cuanto dps haces, en el recount no apareces.
    </p>
  </div>
`;

// Ejecutamos la función con tus datos
enviarCorreoPersonalizado(para, asuntoDelCorreo, cuerpoDelCorreo);