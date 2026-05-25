require('dotenv').config();
const mysql = require('mysql2/promise');

async function testConnection() {
  try {
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      port: process.env.DB_PORT,   // ← añade esta línea
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD,
      database: process.env.DB_NAME,
    });
    console.log('✅ Conectado');
    const [rows] = await connection.query('SELECT 1+1 AS result');
    console.log(rows);
    await connection.end();
  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

testConnection();