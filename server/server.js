// server.js — Node 18+ (ESM)
import express from 'express';
import session from 'express-session';
import FileStoreFactory from 'session-file-store';
import bcrypt from 'bcrypt';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import csurf from 'csurf';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import bodyParser from 'body-parser';
import { Octokit } from '@octokit/rest';

const __dirname = new URL('.', import.meta.url).pathname;
const app = express();
const FileStore = FileStoreFactory(session);

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'replace_with_long_random';
const ADMIN_HASH = process.env.ADMIN_HASH || '';
const GH_PAT = process.env.GH_PAT || '';
const GITHUB_REPO = process.env.GITHUB_REPO || 'tsogbadrakhQQ/777';
const GITHUB_BRANCH = process.env.GITHUB_BRANCH || 'main';

if (!ADMIN_HASH) { console.error('ERROR: set ADMIN_HASH'); process.exit(1); }
if (!GH_PAT) { console.error('ERROR: set GH_PAT'); process.exit(1); }

const octo = new Octokit({ auth: GH_PAT });

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"]
    }
  }
}));

app.use(bodyParser.json({ limit: '200kb' }));

app.use(session({
  store: new FileStore({ path: path.join(os.tmpdir(), 'indrasessions') }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60
  }
}));

const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 8 });
const csrfProtection = csurf({ cookie: false });

app.use(express.static(path.join(process.cwd(), 'public'), { index: false }));

const DATA_FILE = path.join(process.cwd(), 'data.json');

app.get('/api/data', async (req, res) => {
  try {
    const txt = await fs.readFile(DATA_FILE, 'utf8');
    res.type('application/json').send(txt);
  } catch (e) { res.status(500).json({ error: 'Unable to read data' }); }
});

app.post('/login', authLimiter, async (req, res) => {
  try {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ error: 'Missing' });
    const ok = await bcrypt.compare(password, ADMIN_HASH);
    if (!ok) return res.status(401).json({ error: 'Invalid' });
    req.session.isAdmin = true;
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/logout', (req, res) => { req.session.destroy(()=>res.json({ok:true})); });

app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.post('/api/save', csrfProtection, async (req, res) => {
  try {
    if (!req.session?.isAdmin) return res.status(403).json({ error: 'Forbidden' });
    const json = req.body;
    if (typeof json !== 'object' || json === null) return res.status(400).json({ error: 'Invalid JSON' });
    const allowed = new Set(['huvaari','duguilan','szuich','menu','durem','eventuud']);
    for (const k of Object.keys(json)) if (!allowed.has(k)) return res.status(400).json({ error:'Unexpected key '+k });

    const tmp = DATA_FILE + '.tmp';
    await fs.writeFile(tmp, JSON.stringify(json, null, 2), { encoding: 'utf8', mode: 0o600 });
    await fs.rename(tmp, DATA_FILE);

    const [owner, repo] = GITHUB_REPO.split('/');
    const contentEncoded = Buffer.from(JSON.stringify(json, null, 2)).toString('base64');

    let sha = undefined;
    try {
      const current = await octo.repos.getContent({ owner, repo, path: 'data.json', ref: GITHUB_BRANCH });
      if (current && current.data && current.data.sha) sha = current.data.sha;
    } catch (e) { if (e.status !== 404) throw e; }

    const commitMsg = `Admin save: ${new Date().toISOString()}`;
    await octo.repos.createOrUpdateFileContents({
      owner, repo, path: 'data.json',
      message: commitMsg, content: contentEncoded,
      branch: GITHUB_BRANCH, sha
    });

    res.json({ ok: true, commitMsg });
  } catch (e) {
    res.status(500).json({ error: 'Save failed' });
  }
});

app.listen(PORT, ()=> console.log('Server listening on', PORT));
