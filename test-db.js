require('dotenv').config();
const mysql = require('mysql2/promise');

async function testConnection() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
      ssl: {
        rejectUnauthorized: false    // Configuración específica para TLS
      }
    });
    
    console.log('✅ Conectado a TiDB Cloud con TLS');
    const [rows] = await connection.query('SELECT 1+1 AS result');
    console.log('✅ Consulta de prueba exitosa:', rows);
    await connection.end();
  } catch (error) {
    console.error('❌ Error de conexión:', error.message);
  }
}

testConnection();