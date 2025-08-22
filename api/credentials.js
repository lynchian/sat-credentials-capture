import { Pool } from 'pg';
import crypto from 'node:crypto';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL?.replace(/\?sslmode=require$/i, ''),
  ssl: { rejectUnauthorized: false },
  max: 1,
  connectionTimeoutMillis: 5_000,
  idleTimeoutMillis: 10_000,
});

async function ensureDb() {
  await pool.query(`
    create table if not exists sat_credentials (
      id bigserial primary key,
      rfc text not null,
      password_enc text not null,
      iv text,
      created_at timestamptz not null default now()
    );
  `);
  await pool.query(`alter table sat_credentials add column if not exists iv text`);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }
  try {
    const body = typeof req.body === 'object' ? req.body : JSON.parse(req.body || '{}');
    const rfc = String(body?.rfc || '').trim();
    const password = String(body?.password || '');
    if (!rfc || !password) {
      return res.status(400).json({ ok: false, error: 'RFC and password are required' });
    }

    try {
      await ensureDb();
    } catch (e) {
      console.error('DB ensure error:', e?.message || e);
      return res.status(503).json({ ok: false, error: 'Base de datos no disponible. Intenta más tarde.' });
    }

    const iv = crypto.randomBytes(12);
    const key = crypto.scryptSync(process.env.PGP_SECRET || '', 'sat-cred-salt', 32);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const enc = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
    const tag = cipher.getAuthTag();
    const payload = Buffer.concat([enc, tag]).toString('base64');

    try {
      await pool.query(`insert into sat_credentials (rfc, password_enc, iv) values ($1, $2, $3)`, [rfc, payload, iv.toString('base64')]);
    } catch (e) {
      if (String(e?.code) === '42703') {
        await pool.query(`insert into sat_credentials (rfc, password_enc) values ($1, $2)`, [rfc, payload]);
      } else {
        throw e;
      }
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
}


