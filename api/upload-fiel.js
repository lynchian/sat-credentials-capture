import { Pool } from 'pg';
import crypto from 'node:crypto';
import Busboy from 'busboy';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL?.replace(/\?sslmode=require$/i, ''),
  ssl: { rejectUnauthorized: false },
  max: 1,
  connectionTimeoutMillis: 5000,
  idleTimeoutMillis: 10000,
});

async function ensureDb() {
  await pool.query(`
    create table if not exists fiel_uploads (
      id bigserial primary key,
      cer bytea not null,
      key bytea not null,
      password_enc text not null,
      iv text,
      created_at timestamptz not null default now()
    );
  `);
  await pool.query(`alter table fiel_uploads add column if not exists iv text`);
}

export const config = {
  api: {
    bodyParser: false,
  },
};

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ ok: false, error: 'Method Not Allowed' });
  }
  try {
    await ensureDb();
  } catch (e) {
    console.error('DB ensure error:', e?.message || e);
    return res.status(503).json({ ok: false, error: 'Base de datos no disponible' });
  }

  const bb = Busboy({ headers: req.headers });
  let cer = null;
  let key = null;
  let password = '';

  const chunks = { cer: [], key: [] };

  bb.on('file', (name, file) => {
    if (name === 'cer') file.on('data', (d) => chunks.cer.push(d));
    if (name === 'key') file.on('data', (d) => chunks.key.push(d));
  });
  bb.on('field', (name, val) => {
    if (name === 'password') password = String(val || '');
  });
  bb.on('finish', async () => {
    try {
      cer = Buffer.concat(chunks.cer);
      key = Buffer.concat(chunks.key);
      if (!cer?.length || !key?.length || !password) {
        return res.status(400).json({ ok: false, error: 'Faltan archivos o contraseña' });
      }
      const iv = crypto.randomBytes(12);
      const cryptKey = crypto.scryptSync(process.env.PGP_SECRET || '', 'sat-cred-salt', 32);
      const cipher = crypto.createCipheriv('aes-256-gcm', cryptKey, iv);
      const enc = Buffer.concat([cipher.update(password, 'utf8'), cipher.final()]);
      const tag = cipher.getAuthTag();
      const payload = Buffer.concat([enc, tag]).toString('base64');

      await pool.query(
        `insert into fiel_uploads (cer, key, password_enc, iv) values ($1, $2, $3, $4)`,
        [cer, key, payload, iv.toString('base64')],
      );
      return res.status(200).json({ ok: true });
    } catch (e) {
      console.error(e);
      return res.status(500).json({ ok: false, error: 'Server error' });
    }
  });
  req.pipe(bb);
}


