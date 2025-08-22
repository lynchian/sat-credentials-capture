import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { config as loadEnv } from 'dotenv';
import pg from 'pg';
import dns from 'node:dns';
import crypto from 'node:crypto';

loadEnv();

// Prefer IPv4 to avoid IPv6 timeouts on some networks
try { dns.setDefaultResultOrder?.('ipv4first'); } catch {}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const { DATABASE_URL, PGP_SECRET, PORT = 3000 } = process.env;
if (!DATABASE_URL) throw new Error('Missing DATABASE_URL');
if (!PGP_SECRET) throw new Error('Missing PGP_SECRET');

// Some environments append sslmode=require in the URL which may conflict with custom ssl options.
// Strip sslmode from URL and enforce our own TLS options.
const sanitizedConnStr = DATABASE_URL.replace(/\?sslmode=require$/i, '');

const pool = new pg.Pool({
  connectionString: sanitizedConnStr,
  ssl: { rejectUnauthorized: false },
  max: 3,
  idleTimeoutMillis: 10_000,
  connectionTimeoutMillis: 5_000,
});

async function ensureDb() {
  // Create minimal table (no extensions required) and make schema compatible
  await pool.query(`
    create table if not exists sat_credentials (
      id bigserial primary key,
      rfc text not null,
      password_enc text not null,
      iv text,
      created_at timestamptz not null default now()
    );
  `);
  // Add missing column if table existed from previous version
  await pool.query(`alter table sat_credentials add column if not exists iv text`);
  // Migrate password_enc to text if it was bytea (ignore errors if already text)
  try {
    await pool.query(`alter table sat_credentials alter column password_enc type text using encode(password_enc, 'base64')`);
  } catch {}
}

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/credentials', async (req, res) => {
  try {
    const { rfc, password } = req.body ?? {};
    if (!rfc || !password) {
      return res.status(400).json({ ok: false, error: 'RFC and password are required' });
    }
    // lazily ensure schema on first write; quick failure if DB down
    try {
      await ensureDb();
    } catch (e) {
      console.error('DB ensure error:', e?.message || e);
      return res.status(503).json({ ok: false, error: 'Base de datos no disponible. Intenta más tarde.' });
    }
    // Encrypt on server with AES-256-GCM (no DB extensions required)
    const iv = crypto.randomBytes(12);
    const key = crypto.scryptSync(PGP_SECRET, 'sat-cred-salt', 32);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(String(password), 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const payload = Buffer.concat([enc, tag]).toString('base64');
    try {
      await pool.query(`insert into sat_credentials (rfc, password_enc, iv) values ($1, $2, $3)`, [String(rfc).trim(), payload, iv.toString('base64')]);
    } catch (e) {
      // Fallback for legacy schema without iv column
      if (String(e?.code) === '42703') {
        await pool.query(`insert into sat_credentials (rfc, password_enc) values ($1, $2)`, [String(rfc).trim(), payload]);
      } else {
        throw e;
      }
    }
    return res.json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

app.get('/health', (req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Listening on http://localhost:${PORT}`));


