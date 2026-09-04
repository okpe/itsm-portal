const FormData = require('form-data');
const Mailgun = require('mailgun.js');
const db = require('./database');

const mailgun = new Mailgun(FormData);

// Configure Mailgun Client
const mg = mailgun.client({
  username: 'api',
  key: process.env.MAILGUN_API_KEY || 'YOUR_MAILGUN_API_KEY' // e.g., 'key-123456789...'
});

const DOMAIN = process.env.MAILGUN_DOMAIN || 'YOUR_MAILGUN_DOMAIN'; // e.g., 'sandboxXXXXX.mailgun.org'
const APP_URL = process.env.APP_URL || 'http://localhost:3000';

function getNextResolver(callback) {
  const resolvers = db.all("SELECT id FROM users WHERE role IN ('resolver', 'admin') ORDER BY id ASC");
  if (!resolvers.length) return callback(null);

  const row = db.get("SELECT value FROM system_state WHERE key = 'last_assigned_user_id'");
  let lastId = row ? row.value : 0;
  let nextResolver = resolvers.find(r => r.id > lastId);
  if (!nextResolver) nextResolver = resolvers[0];

  db.run("UPDATE system_state SET value = ? WHERE key = 'last_assigned_user_id'", [nextResolver.id]);
  callback(nextResolver.id);
}

function sendEmail(to, subject, html) {
  mg.messages.create(DOMAIN, {
    from: `IT Helpdesk <tickets@${DOMAIN}>`,
    to: [to],
    subject: subject,
    html: html
  })
  .then(msg => console.log(`[+] Email sent successfully to ${to}:`, msg.id))
  .catch(err => console.error("[-] Mailgun Send Error:", err.message));
}

module.exports = { sendEmail, getNextResolver, APP_URL };