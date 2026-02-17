// db.js
require('dotenv').config();
const mysql = require('mysql2');

const pool = mysql.createPool({
  host: process.env.DB_HOST || 'mysql.railaway.app',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'kRCOoUEexQoCVionwmTpWtyeCFSbxrkB ',
  database: process.env.DB_NAME || 'railway',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

module.exports = pool.promise();