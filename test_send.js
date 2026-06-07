// test-email.js
const nodemailer = require('nodemailer');

// Configura el transporter con tus credenciales
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'lumineth2017@gmail.com',     // Reemplaza con tu Gmail
    pass: 'zddznaktsracweav'          // Contraseña de aplicación (sin espacios)
  }
});

async function testEmail() {
  try {
    const info = await transporter.sendMail({
      from: `"Prueba" <lumineth2017@gmail.com>`,
      to: 'frandydanieldelacruzarias@gmail.com',  // Cámbialo por un correo real (puede ser el mismo Gmail)
      subject: 'Prueba desde Node.js',
      html: '<p>✅ Si ves esto, el email funciona correctamente.</p>'
    });
    console.log('✅ Correo enviado con éxito:', info.messageId);
  } catch (error) {
    console.error('❌ Error al enviar:', error);
  }
}

testEmail();