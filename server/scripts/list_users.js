const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const dbPath = path.join(__dirname, '..', 'db', 'auth.db');

const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY, (err) => {
  if (err) {
    console.error('DB open error', err);
    process.exit(1);
  }
});

db.all('SELECT id, email, role, createdAt FROM users', (err, rows) => {
  if (err) {
    console.error('Query error', err);
    process.exit(1);
  }
  console.log(JSON.stringify(rows, null, 2));
  db.close();
});
