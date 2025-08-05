const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('app.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user'
  )`);
});

module.exports = db;
