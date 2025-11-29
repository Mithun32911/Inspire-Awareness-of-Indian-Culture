const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const email = process.argv[2];
if (!email) {
  console.error('Usage: node scripts/delete_user.js user@example.com');
  process.exit(1);
}
const dbPath = path.join(__dirname, '..', 'db', 'auth.db');
const db = new sqlite3.Database(dbPath, (err) => { if (err) { console.error('DB open error', err); process.exit(1);} });

db.run('DELETE FROM users WHERE lower(email)=lower(?)', [email], function(err) {
  if (err) {
    console.error('Delete error', err);
    process.exit(1);
  }
  console.log(`Deleted ${this.changes} row(s) for email ${email}`);
  db.close();
});
