/**
 * ╔══════════════════════════════════════════════════════╗
 * ║         PURE MOTION — Backend Sécurisé               ║
 * ║         Connexion 2 niveaux :                        ║
 * ║         • Clients : numéro + mot de passe            ║
 * ║         • Admin : email + mot de passe (simple)     ║
 * ╚══════════════════════════════════════════════════════╝
 */

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const crypto     = require('crypto');
const path       = require('path');
const fs         = require('fs');

const app = express();

// ══════════════════════════════════════════
// CONFIGURATION
// ══════════════════════════════════════════
const {
  PORT = 3000,
  ALLOWED_ORIGIN = '*',
  NODE_ENV = 'development',
  ADMIN_TOKEN = 'change_me',
  ANTHROPIC_API_KEY = '',
} = process.env;

// ══════════════════════════════════════════
// STOCKAGE — PostgreSQL (durable) avec repli fichier
// Si DATABASE_URL est défini → PostgreSQL (données permanentes).
// Sinon → fichier local (utile en développement).
// ══════════════════════════════════════════
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'pm_data.json');
const DATABASE_URL = process.env.DATABASE_URL || '';
const USE_PG = !!DATABASE_URL;

let STORE = { clients: {}, stats: {}, calendar: {}, posts: {}, publications: {}, tasks: { items: [] }, prospects: { items: [] } };

// Complète les clés manquantes (migration douce)
function ensureShape() {
  if (!STORE.clients) STORE.clients = {};
  if (!STORE.stats) STORE.stats = {};
  if (!STORE.calendar) STORE.calendar = {};
  if (!STORE.posts) STORE.posts = {};
  if (!STORE.tasks) STORE.tasks = { items: [] };
  if (!STORE.prospects) STORE.prospects = { items: [] };
  if (!STORE.publications) STORE.publications = {};
  if (!STORE.objectives) STORE.objectives = { items: [] };
  if (!STORE.documents) STORE.documents = {};
  if (!STORE.sessions) STORE.sessions = {};
}

// ── Connexion PostgreSQL ──
let pool = null;
if (USE_PG) {
  const { Pool } = require('pg');
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }  // requis par la plupart des hébergeurs (Render, Neon, Supabase)
  });
  pool.on('error', (e) => console.error('❌ Erreur pool PostgreSQL :', e.message));
}

// ── Chargement initial ──
async function loadStore() {
  if (USE_PG) {
    try {
      // Crée la table si elle n'existe pas
      await pool.query('CREATE TABLE IF NOT EXISTS pm_store (id INT PRIMARY KEY, data JSONB NOT NULL, updated_at TIMESTAMPTZ DEFAULT now())');
      const r = await pool.query('SELECT data FROM pm_store WHERE id = 1');
      if (r.rows.length && r.rows[0].data) {
        STORE = r.rows[0].data;
        ensureShape();
        console.log('✅ Données chargées depuis PostgreSQL');
      } else {
        ensureShape();
        await savePgNow();
        console.log('🆕 Base PostgreSQL initialisée (vide)');
      }
    } catch (e) {
      console.error('❌ Erreur chargement PostgreSQL :', e.message);
      ensureShape();
    }
    return;
  }
  // Repli fichier
  try {
    if (fs.existsSync(DATA_FILE)) {
      STORE = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      ensureShape();
      console.log('✅ Données chargées depuis le fichier (mode local)');
    } else {
      ensureShape();
    }
  } catch (e) {
    console.warn('⚠️ Fichier illisible, démarrage à vide :', e.message);
    ensureShape();
  }
}

// ── Sauvegarde immédiate en base ──
async function savePgNow() {
  if (!pool) return;
  await pool.query(
    'INSERT INTO pm_store (id, data, updated_at) VALUES (1, $1, now()) ON CONFLICT (id) DO UPDATE SET data = $1, updated_at = now()',
    [JSON.stringify(STORE)]
  );
}

// ── Sauvegarde différée (regroupe les écritures) ──
let saveTimer = null;
function saveStore() {
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    try {
      if (USE_PG) {
        await savePgNow();
      } else {
        if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
        fs.writeFileSync(DATA_FILE, JSON.stringify(STORE, null, 2), 'utf8');
      }
    } catch (e) {
      console.error('❌ Erreur sauvegarde :', e.message);
    }
  }, 400);
}

// loadStore() est appelé dans start() en fin de fichier (asynchrone)

// ══════════════════════════════════════════
// HACHAGE DES MOTS DE PASSE (sans dépendance externe)
// Utilise scrypt natif de Node.js — sécurisé
// ══════════════════════════════════════════
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const testHash = crypto.scryptSync(password, salt, 64).toString('hex');
  // Comparaison à temps constant (anti timing-attack)
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(testHash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// ══════════════════════════════════════════
// BASE DE DONNÉES UTILISATEURS (en mémoire)
// En production : remplacer par PostgreSQL/MongoDB
//
// activated = false → le client doit créer son mot de passe
// activated = true  → le client se connecte avec son mot de passe
// ══════════════════════════════════════════
const USERS = {
  // ── ADMIN (toi) — connexion simple email + mot de passe ──
  'admin@puremotion.ci': {
    role: 'admin',
    name: 'Pure Motion Admin',
    phone: process.env.ADMIN_PHONE || '+22507058281',
    passwordHash: hashPassword(process.env.ADMIN_PASSWORD || 'PureMotionAdmin2026!'),
    activated: true,
  },
};

// ══════════════════════════════════════════
// CLIENTS RÉELS
// clientKey = identifiant qui relie le compte à ses données (stats, calendrier)
// activated: false → le client crée son mot de passe à la 1ère connexion
// activated: true + passwordHash → mot de passe défini par l'admin
// ══════════════════════════════════════════
function makeClient({ name, clientKey, email, phone, password }) {
  const internalId = email ? email.toLowerCase() : `${phone.replace('+','')}@client.puremotion.ci`;
  USERS[internalId] = {
    role: 'client',
    name,
    clientKey,
    email: email ? email.toLowerCase() : null,
    phone: phone || null,
    passwordHash: password ? hashPassword(password) : null,
    activated: !!password,
  };
}

// Aucun client par défaut — tu les crées depuis "Gestion des accès".
// (makeClient reste disponible si tu veux en pré-remplir un jour.)

// Restaure les clients créés précédemment (appelé au démarrage après loadStore)
function restoreClients() {
  if (STORE.clients && typeof STORE.clients === 'object') {
    Object.entries(STORE.clients).forEach(([id, u]) => {
      USERS[id] = u;
    });
    console.log(`✅ ${Object.keys(STORE.clients).length} compte(s) client restauré(s)`);
  }
  // Restaure le mot de passe admin personnalisé (s'il a été changé dans les paramètres)
  if (STORE.adminOverride && STORE.adminOverride.passwordHash) {
    const adminEntry = Object.entries(USERS).find(([id, u]) => u.role === 'admin');
    if (adminEntry) {
      adminEntry[1].passwordHash = STORE.adminOverride.passwordHash;
      console.log('✅ Mot de passe admin personnalisé restauré');
    }
  }
  reindexAll();
}

// Persiste l'état actuel des clients (hors admin) dans STORE
function persistClients() {
  STORE.clients = {};
  Object.entries(USERS).forEach(([id, u]) => {
    if (u.role !== 'admin') STORE.clients[id] = u;
  });
  saveStore();
}

// Index par téléphone ET par email (les clients se connectent par l'un ou l'autre)
const USERS_BY_PHONE = {};
const USERS_BY_EMAIL = {};

function reindexAll() {
  for (const k in USERS_BY_PHONE) delete USERS_BY_PHONE[k];
  for (const k in USERS_BY_EMAIL) delete USERS_BY_EMAIL[k];
  Object.entries(USERS).forEach(([id, u]) => {
    if (u.phone) USERS_BY_PHONE[u.phone] = id;
    if (u.email) USERS_BY_EMAIL[u.email.toLowerCase()] = id;
  });
}

// Retrouve un utilisateur par email OU téléphone
function findUser(identifier) {
  if (!identifier) return null;
  const id = identifier.trim().toLowerCase();
  if (USERS_BY_EMAIL[id]) return { key: USERS_BY_EMAIL[id], user: USERS[USERS_BY_EMAIL[id]] };
  if (USERS_BY_PHONE[identifier.trim()]) return { key: USERS_BY_PHONE[identifier.trim()], user: USERS[USERS_BY_PHONE[identifier.trim()]] };
  if (USERS[id]) return { key: id, user: USERS[id] };
  return null;
}

reindexAll();

// Codes d'invitation temporaires pour la 1ère connexion client
const INVITES = {};

// ══════════════════════════════════════════
// MIDDLEWARES
// ══════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: ALLOWED_ORIGIN === '*' ? '*' : ALLOWED_ORIGIN.split(','), methods: ['GET','POST'] }));
app.use(express.json({ limit: '12mb' }));
app.use(express.urlencoded({ extended: true }));
// Le service worker ne doit JAMAIS être mis en cache par le navigateur,
// sinon les mises à jour de l'application n'arrivent jamais.
app.get('/sw.js', (req, res) => {
  const f = path.join(__dirname, 'public', 'sw.js');
  if (!fs.existsSync(f)) return res.status(404).end();
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Service-Worker-Allowed', '/');
  res.type('application/javascript');
  return res.sendFile(f);
});

app.use(express.static(path.join(__dirname, 'public')));

// ── Rate limiting ──
const loginLimiter = rateLimit({ windowMs: 10*60*1000, max: 20, message: { success:false, error:'Trop de tentatives. Réessayez dans 10 minutes.' } });
const otpLimiter   = rateLimit({ windowMs: 10*60*1000, max: 5,  message: { success:false, error:'Trop de codes envoyés. Réessayez dans 10 minutes.' } });
app.use(rateLimit({ windowMs: 15*60*1000, max: 200 }));

// ══════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════
function validPhone(p)  { return /^\+[1-9]\d{7,14}$/.test(p); }
function validPw(p)     { return p && p.length >= 6; }
function maskPhone(p)   { return p ? p.slice(0,4) + '****' + p.slice(-2) : ''; }
function maskEmail(e)   { const [l,d]=e.split('@'); return l.slice(0,2)+'***@'+d; }
function makeToken(id)  { return Buffer.from(`${id}:${Date.now()}:${crypto.randomBytes(8).toString('hex')}`).toString('base64'); }

// ══════════════════════════════════════════
// SESSIONS & PERMISSIONS
// Le serveur doit savoir QUI parle, pas seulement "quelqu'un a la clé admin".
// ══════════════════════════════════════════
const SESSION_DAYS = 30;

function createSession(userId) {
  const token = makeToken(userId);
  if (!STORE.sessions) STORE.sessions = {};
  // Purge les sessions expirées au passage
  const now = Date.now();
  Object.entries(STORE.sessions).forEach(([t, s]) => { if (!s || s.expiresAt < now) delete STORE.sessions[t]; });
  STORE.sessions[token] = { userId, createdAt: now, expiresAt: now + SESSION_DAYS*24*60*60*1000 };
  saveStore();
  return token;
}

function destroySession(token) {
  if (STORE.sessions && STORE.sessions[token]) { delete STORE.sessions[token]; saveStore(); }
}

// Identifie l'appelant. Renvoie null si non authentifié.
// { role, user, clientKeys, allClients }
function getAuth(req) {
  // 1) Clé admin maîtresse (rétrocompatible)
  const adminTok = req.headers['x-admin-token']
    || (req.body && req.body.adminToken)
    || (req.query && req.query.admin);
  if (adminTok && adminTok === ADMIN_TOKEN) {
    return { role: 'admin', user: null, userId: 'admin', clientKeys: [], allClients: true };
  }
  // 2) Jeton de session individuel
  const tok = req.headers['x-session-token']
    || (req.body && req.body.sessionToken)
    || (req.query && req.query.s);
  if (!tok) return null;
  const sess = STORE.sessions && STORE.sessions[tok];
  if (!sess || sess.expiresAt < Date.now()) return null;
  const user = USERS[sess.userId];
  if (!user) return null;
  return {
    role: user.role,
    user,
    userId: sess.userId,
    clientKeys: Array.isArray(user.clientKeys) ? user.clientKeys : [],
    allClients: user.role === 'admin'
  };
}

// Personnel de l'agence : admin OU collaborateur
function requireStaff(req, res) {
  const a = getAuth(req);
  if (!a || (a.role !== 'admin' && a.role !== 'collaborateur')) {
    res.status(403).json({ success:false, error:'Accès non autorisé.' });
    return null;
  }
  return a;
}

// Admin seulement (commercial, accès, paramètres)
function requireAdmin(req, res) {
  const a = getAuth(req);
  if (!a || a.role !== 'admin') {
    res.status(403).json({ success:false, error:'Réservé à l\'administrateur.' });
    return null;
  }
  return a;
}

// Ce client est-il autorisé pour cet appelant ?
function canClient(a, clientKey) {
  if (!a) return false;
  if (a.allClients) return true;
  return a.clientKeys.includes(clientKey);
}

// Liste des clientKeys visibles par l'appelant
function visibleClientKeys(a) {
  if (a.allClients) return Object.values(USERS).filter(u=>u.clientKey).map(u=>u.clientKey);
  return a.clientKeys.slice();
}


function log(level, msg, data={}) {
  const safe = { ...data };
  delete safe.password; delete safe.code; delete safe.passwordHash;
  console.log(`[${new Date().toISOString()}] [${level}] ${msg}`, Object.keys(safe).length?JSON.stringify(safe):'');
}

// ══════════════════════════════════════════
// SANTÉ
// ══════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Pure Motion Backend',
    auth: 'email/numéro + mot de passe',
    env: NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// ══════════════════════════════════════════
// CLIENT — VÉRIFIER LE STATUT (email OU téléphone)
// POST /api/client/check
// Body : { identifier }   (email ou numéro)
// ══════════════════════════════════════════
app.post('/api/client/check', loginLimiter, (req, res) => {
  const { identifier } = req.body;
  if (!identifier) {
    return res.status(400).json({ success:false, error:'Entre ton email ou ton numéro.' });
  }
  const found = findUser(identifier);
  if (!found || found.user.role === 'admin') {
    return res.status(404).json({ success:false, error:'Compte introuvable. Contactez Pure Motion.' });
  }
  return res.json({
    success: true,
    activated: found.user.activated,
    name: found.user.name,
    nextStep: found.user.activated ? 'login' : 'create-password'
  });
});

// ══════════════════════════════════════════
// CLIENT — CRÉER SON MOT DE PASSE (1ère connexion)
// POST /api/client/set-password
// Body : { identifier, password }
// ══════════════════════════════════════════
app.post('/api/client/set-password', loginLimiter, (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier) return res.status(400).json({ success:false, error:'Identifiant requis.' });
  if (!validPw(password)) return res.status(400).json({ success:false, error:'Le mot de passe doit faire au moins 6 caractères.' });

  const found = findUser(identifier);
  if (!found || found.user.role === 'admin') return res.status(404).json({ success:false, error:'Compte introuvable.' });
  if (found.user.activated) return res.status(409).json({ success:false, error:'Ce compte a déjà un mot de passe. Connectez-vous.' });

  found.user.passwordHash = hashPassword(password);
  found.user.activated = true;
  persistClients();

  log('INFO', 'Client a créé son mot de passe', { name: found.user.name });

  return res.json({
    success: true,
    activated: true,
    user: { name: found.user.name, role: found.user.role, clientKey: found.user.clientKey },
    sessionToken: createSession(found.key),
    message: 'Mot de passe créé. Bienvenue !'
  });
});

// ══════════════════════════════════════════
// CLIENT — CONNEXION (email OU téléphone + mot de passe)
// POST /api/client/login
// Body : { identifier, password }
// ══════════════════════════════════════════
app.post('/api/client/login', loginLimiter, (req, res) => {
  const { identifier, password } = req.body;
  if (!identifier) return res.status(400).json({ success:false, error:'Identifiant requis.' });
  if (!password) return res.status(400).json({ success:false, error:'Mot de passe requis.' });

  const found = findUser(identifier);
  if (!found || !found.user.activated) {
    return res.status(401).json({ success:false, error:'Identifiant ou mot de passe incorrect.' });
  }
  if (!verifyPassword(password, found.user.passwordHash)) {
    log('WARN', 'Échec connexion client', { name: found.user.name });
    return res.status(401).json({ success:false, error:'Identifiant ou mot de passe incorrect.' });
  }
  if (found.user.role === 'admin') {
    return res.status(403).json({ success:false, error:'Ce compte nécessite la connexion administrateur.' });
  }

  log('INFO', 'Connexion client réussie', { name: found.user.name, role: found.user.role });

  return res.json({
    success: true,
    user: { name: found.user.name, role: found.user.role, clientKey: found.user.clientKey },
    sessionToken: createSession(found.key),
    message: 'Connexion réussie !'
  });
});

// ══════════════════════════════════════════
// ADMIN — CONNEXION SIMPLE (email + mot de passe, sans code)
// POST /api/admin/login
// Body : { email, password }
// ══════════════════════════════════════════
app.post('/api/admin/login', loginLimiter, (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ success:false, error:'Identifiants requis.' });

  const user = USERS[email.toLowerCase()];
  if (!user || user.role !== 'admin' || !verifyPassword(password, user.passwordHash)) {
    log('WARN', 'Échec connexion admin', { email: maskEmail(email) });
    return res.status(401).json({ success:false, error:'Email ou mot de passe incorrect.' });
  }

  log('INFO', 'Connexion admin réussie', { email: maskEmail(email) });
  return res.json({
    success: true,
    user: { name: user.name, role: 'admin', email },
    sessionToken: createSession(email),
    message: 'Connexion administrateur réussie !'
  });
});

// ══════════════════════════════════════════
// ADMIN — CRÉER / INVITER UN CLIENT
// POST /api/admin/clients/create
// Body : { adminToken, name, clientKey, email, phone, password (optionnel), role }
// ══════════════════════════════════════════
app.post('/api/admin/clients/create', (req, res) => {
  const { adminToken, name, clientKey, email, phone, password, role = 'client' } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!name) return res.status(400).json({ success:false, error:'Le nom est requis.' });
  if (!email && !phone) return res.status(400).json({ success:false, error:'Renseigne au moins un email ou un numéro.' });
  if (phone && !validPhone(phone)) return res.status(400).json({ success:false, error:'Numéro invalide. Format : +225XXXXXXXXXX' });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success:false, error:'Email invalide.' });
  if (password && !validPw(password)) return res.status(400).json({ success:false, error:'Le mot de passe doit faire au moins 6 caractères.' });

  if (phone && USERS_BY_PHONE[phone]) return res.status(409).json({ success:false, error:'Ce numéro existe déjà.' });
  if (email && USERS_BY_EMAIL[email.toLowerCase()]) return res.status(409).json({ success:false, error:'Cet email existe déjà.' });

  const internalId = email ? email.toLowerCase() : `${phone.replace('+','')}@client.puremotion.ci`;
  const estCollab = role === 'collaborateur';
  const key = clientKey || (name.toLowerCase().replace(/[^a-z0-9]/g,'').slice(0,12) + Date.now().toString().slice(-4));

  USERS[internalId] = {
    role: estCollab ? 'collaborateur' : 'client',
    name,
    // Un collaborateur n'EST pas un client : pas de clientKey propre,
    // sinon il apparaîtrait dans les sélecteurs de clients.
    // Il reçoit à la place une liste de clients assignés.
    clientKey: estCollab ? null : key,
    clientKeys: estCollab ? [] : undefined,
    email: email ? email.toLowerCase() : null,
    phone: phone || null,
    passwordHash: password ? hashPassword(password) : null,
    activated: !!password,
  };
  reindexAll();
  persistClients();

  log('INFO', estCollab ? 'Collaborateur créé' : 'Client créé', { name, activated: !!password });

  const how = password
    ? 'Le mot de passe a été défini. Le client peut se connecter immédiatement.'
    : 'Le client créera son mot de passe à sa première connexion.';

  return res.json({
    success: true,
    message: `${name} ajouté. ${how}`,
    client: { name, clientKey:key, email:email||null, phone:phone||null, role, activated: !!password }
  });
});

// ══════════════════════════════════════════
// ADMIN — RÉINITIALISER LE MOT DE PASSE D'UN CLIENT
// POST /api/admin/clients/reset
// Body : { adminToken, identifier, newPassword (optionnel) }
// Sans newPassword → le compte redevient "à activer" (le client recrée son mdp)
// ══════════════════════════════════════════
app.post('/api/admin/clients/reset', (req, res) => {
  const { adminToken, identifier, newPassword } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!identifier) return res.status(400).json({ success:false, error:'Identifiant du client requis.' });

  const found = findUser(identifier);
  if (!found || found.user.role === 'admin') return res.status(404).json({ success:false, error:'Client introuvable.' });

  if (newPassword) {
    if (!validPw(newPassword)) return res.status(400).json({ success:false, error:'Mot de passe trop court (min 6).' });
    found.user.passwordHash = hashPassword(newPassword);
    found.user.activated = true;
    persistClients();
    log('INFO', 'Mot de passe client réinitialisé (défini par admin)', { name: found.user.name });
    return res.json({ success:true, message:`Nouveau mot de passe défini pour ${found.user.name}.` });
  } else {
    found.user.passwordHash = null;
    found.user.activated = false;
    persistClients();
    log('INFO', 'Mot de passe client réinitialisé (à recréer)', { name: found.user.name });
    return res.json({ success:true, message:`${found.user.name} devra recréer son mot de passe à la prochaine connexion.` });
  }
});

// ══════════════════════════════════════════
// ADMIN — SUPPRIMER UN CLIENT (efface TOUTES ses données)
// POST /api/admin/clients/delete
// Body : { adminToken, identifier }
// ══════════════════════════════════════════
app.post('/api/admin/clients/delete', (req, res) => {
  const { adminToken, identifier } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!identifier) return res.status(400).json({ success:false, error:'Identifiant du client requis.' });

  const found = findUser(identifier);
  if (!found || found.user.role === 'admin') return res.status(404).json({ success:false, error:'Client introuvable.' });

  const name = found.user.name;
  const clientKey = found.user.clientKey;

  // 1. Supprime le compte
  delete USERS[found.key];
  reindexAll();
  persistClients();

  // 2. Efface ses stats
  if (clientKey && STORE.stats[clientKey]) delete STORE.stats[clientKey];
  if (clientKey && STORE.posts && STORE.posts[clientKey]) delete STORE.posts[clientKey];
  if (clientKey && STORE.documents && STORE.documents[clientKey]) delete STORE.documents[clientKey];
  if (clientKey && STORE.tasks && Array.isArray(STORE.tasks.items)) {
    STORE.tasks.items = STORE.tasks.items.filter(t => t.clientKey !== clientKey);
  }
  // 3. Efface son calendrier
  if (clientKey && STORE.calendar[clientKey]) delete STORE.calendar[clientKey];
  // 4. Efface ses contrats
  if (STORE.contracts) {
    Object.keys(STORE.contracts).forEach(id => {
      if (STORE.contracts[id].clientKey === clientKey) delete STORE.contracts[id];
    });
  }
  saveStore();

  log('INFO', 'Client supprimé avec toutes ses données', { name, clientKey });
  return res.json({ success:true, message:`${name} et toutes ses données ont été définitivement supprimés.` });
});

// ══════════════════════════════════════════
// ADMIN — LISTE DES CLIENTS
// GET /api/admin/clients  (header x-admin-token)
// ══════════════════════════════════════════
app.get('/api/admin/clients', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  const clients = Object.values(USERS)
    .filter(u => u.role !== 'admin')
    // Un collaborateur ne voit que les clients qui lui sont assignés
    .filter(u => a.allClients || (u.clientKey && a.clientKeys.includes(u.clientKey)))
    .map(u => ({ name: u.name, clientKey: u.clientKey, email: u.email, phone: maskPhone(u.phone), role: u.role, activated: u.activated }));
  return res.json({ success:true, count: clients.length, clients });
});

// ══════════════════════════════════════════
// STATS — SAUVEGARDE (admin) & RÉCUPÉRATION
// ══════════════════════════════════════════

// Admin enregistre/remplace les stats d'un client
// POST /api/admin/stats/save
// Body : { adminToken, clientKey, entries:[...], published:bool }
app.post('/api/admin/stats/save', (req, res) => {
  const { adminToken, clientKey, entries, published } = req.body;
  const a = requireStaff(req, res); if (!a) return;
  if (!clientKey) return res.status(400).json({ success:false, error:'clientKey requis.' });
  if (!canClient(a, clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  if (!Array.isArray(entries)) return res.status(400).json({ success:false, error:'entries doit être une liste.' });

  STORE.stats[clientKey] = {
    entries: entries,
    published: !!published,
    updatedAt: Date.now()
  };
  saveStore();
  log('INFO', 'Stats sauvegardées', { clientKey, count: entries.length, published: !!published });
  return res.json({ success:true, message:'Statistiques enregistrées.', count: entries.length, published: !!published });
});

// Admin récupère les stats d'un client (même non publiées)
// GET /api/admin/stats/:clientKey  (header x-admin-token)
app.get('/api/admin/stats/:clientKey', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  if (!canClient(a, req.params.clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  const s = STORE.stats[req.params.clientKey] || { entries:[], published:false };
  return res.json({ success:true, entries: s.entries || [], published: !!s.published, updatedAt: s.updatedAt || null });
});

// Client récupère SES stats (uniquement si publiées)
// GET /api/client/stats/:clientKey
app.get('/api/client/stats/:clientKey', (req, res) => {
  const s = STORE.stats[req.params.clientKey];
  if (!s || !s.published) {
    return res.json({ success:true, entries:[], published:false });
  }
  return res.json({ success:true, entries: s.entries || [], published:true, updatedAt: s.updatedAt || null });
});

// ══════════════════════════════════════════
// PUBLICATIONS (liens de posts par réseau)
// ══════════════════════════════════════════

// Admin enregistre la liste des publications d'un client
// POST /api/admin/publications/save
// Body : { adminToken, clientKey, items:[{id,url,reseau,titre,date}] }
app.post('/api/admin/publications/save', (req, res) => {
  const { adminToken, clientKey, items } = req.body;
  const a = requireStaff(req, res); if (!a) return;
  if (!canClient(a, clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  if (!clientKey) return res.status(400).json({ success:false, error:'clientKey requis.' });
  if (!Array.isArray(items)) return res.status(400).json({ success:false, error:'items doit être une liste.' });

  STORE.publications[clientKey] = { items, updatedAt: Date.now() };
  saveStore();
  log('INFO', 'Publications sauvegardées', { clientKey, count: items.length });
  return res.json({ success:true, message:'Publications enregistrées.', count: items.length });
});

// Admin récupère les publications d'un client
// GET /api/admin/publications/:clientKey  (header x-admin-token)
app.get('/api/admin/publications/:clientKey', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  if (!canClient(a, req.params.clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  const p = STORE.publications[req.params.clientKey] || { items:[] };
  return res.json({ success:true, items: p.items || [] });
});

// Client récupère SES publications (toujours visibles)
// GET /api/client/publications/:clientKey
app.get('/api/client/publications/:clientKey', (req, res) => {
  const p = STORE.publications[req.params.clientKey] || { items:[] };
  return res.json({ success:true, items: p.items || [] });
});

// ══════════════════════════════════════════
// CONTRATS
// ══════════════════════════════════════════
if (!STORE.contracts) STORE.contracts = {};

// Admin crée / met à jour un contrat
// POST /api/admin/contracts/save
app.post('/api/admin/contracts/save', (req, res) => {
  const { adminToken, contract } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!contract || !contract.clientKey || !contract.clientName) {
    return res.status(400).json({ success:false, error:'Informations du contrat incomplètes.' });
  }
  const id = contract.id || ('ct' + Date.now());
  STORE.contracts[id] = {
    id,
    clientKey: contract.clientKey,
    clientName: contract.clientName,
    formule: contract.formule || 'Bronze',
    montant: Number(contract.montant) || 0,
    dateDebut: contract.dateDebut || '',
    dateFin: contract.dateFin || '',
    statut: contract.statut || 'actif',       // actif | resilié | renouvellement
    motifResiliation: contract.motifResiliation || '',
    renouvellement: contract.renouvellement || null, // proposition envoyée au client
    updatedAt: Date.now()
  };
  saveStore();
  log('INFO', 'Contrat enregistré', { id, client: contract.clientName });
  return res.json({ success:true, message:'Contrat enregistré.', id });
});

// Admin liste tous les contrats
// GET /api/admin/contracts  (header x-admin-token)
app.get('/api/admin/contracts', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  // Lecture seule pour les collaborateurs, limitée à leurs clients assignés
  const contracts = Object.values(STORE.contracts || {})
    .filter(ct => canClient(a, ct.clientKey));
  return res.json({ success:true, count: contracts.length, contracts });
});

// Admin résilie un contrat (avec motif)
// POST /api/admin/contracts/terminate
app.post('/api/admin/contracts/terminate', (req, res) => {
  const { adminToken, id, motif } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!id || !STORE.contracts[id]) return res.status(404).json({ success:false, error:'Contrat introuvable.' });
  STORE.contracts[id].statut = 'resilié';
  STORE.contracts[id].motifResiliation = motif || 'Non précisé';
  STORE.contracts[id].dateResiliation = new Date().toISOString().split('T')[0];
  STORE.contracts[id].updatedAt = Date.now();
  saveStore();
  log('INFO', 'Contrat résilié', { id, motif });
  return res.json({ success:true, message:'Contrat résilié.' });
});

// Admin envoie une proposition de renouvellement au client
// POST /api/admin/contracts/renew
app.post('/api/admin/contracts/renew', (req, res) => {
  const { adminToken, id, renouvellement } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!id || !STORE.contracts[id]) return res.status(404).json({ success:false, error:'Contrat introuvable.' });
  STORE.contracts[id].renouvellement = {
    formule: renouvellement.formule,
    montant: Number(renouvellement.montant) || 0,
    nouvelleDateFin: renouvellement.nouvelleDateFin || '',
    message: renouvellement.message || '',
    envoyeLe: new Date().toISOString().split('T')[0],
    statut: 'en_attente'   // en_attente | accepté | refusé
  };
  STORE.contracts[id].statut = 'renouvellement';
  STORE.contracts[id].updatedAt = Date.now();
  saveStore();
  log('INFO', 'Renouvellement envoyé au client', { id });
  return res.json({ success:true, message:'Proposition de renouvellement envoyée au client.' });
});

// Admin supprime un contrat
// POST /api/admin/contracts/delete
app.post('/api/admin/contracts/delete', (req, res) => {
  const { adminToken, id } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!id || !STORE.contracts[id]) return res.status(404).json({ success:false, error:'Contrat introuvable.' });
  delete STORE.contracts[id];
  saveStore();
  return res.json({ success:true, message:'Contrat supprimé.' });
});

// Client consulte SON contrat + proposition de renouvellement
// GET /api/client/contract/:clientKey
app.get('/api/client/contract/:clientKey', (req, res) => {
  const contracts = Object.values(STORE.contracts || {}).filter(c => c.clientKey === req.params.clientKey);
  return res.json({ success:true, contracts });
});

// Client répond à une proposition de renouvellement
// POST /api/client/contract/respond
app.post('/api/client/contract/respond', (req, res) => {
  const { id, reponse } = req.body; // reponse: 'accepté' | 'refusé'
  if (!id || !STORE.contracts[id] || !STORE.contracts[id].renouvellement) {
    return res.status(404).json({ success:false, error:'Proposition introuvable.' });
  }
  STORE.contracts[id].renouvellement.statut = reponse === 'accepté' ? 'accepté' : 'refusé';
  STORE.contracts[id].updatedAt = Date.now();
  saveStore();
  log('INFO', 'Client a répondu au renouvellement', { id, reponse });
  return res.json({ success:true, message: reponse==='accepté' ? 'Renouvellement accepté.' : 'Renouvellement refusé.' });
});

// ══════════════════════════════════════════
// PROPOSITIONS IA (Anthropic API)
// POST /api/admin/ai/proposal
// Body : { adminToken, clientName, secteur, reseaux, objectif, contexte }
// ══════════════════════════════════════════
app.post('/api/admin/ai/proposal', async (req, res) => {
  const { adminToken, clientName, secteur, reseaux, objectif, contexte } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!ANTHROPIC_API_KEY) {
    return res.status(503).json({ success:false, error:'Clé API IA non configurée. Ajoute ANTHROPIC_API_KEY dans les variables Render.' });
  }
  if (!clientName || !secteur) {
    return res.status(400).json({ success:false, error:'Nom du client et secteur requis.' });
  }

  const prompt = `Tu es un expert en stratégie de contenu social media pour PURE MOTION, une agence ivoirienne (Abidjan) spécialisée dans la vidéo social-first.

CLIENT : ${clientName}
SECTEUR : ${secteur}
RÉSEAUX ANIMÉS : ${(reseaux && reseaux.length) ? reseaux.join(', ') : 'TikTok, Instagram, Facebook'}
OBJECTIF PRINCIPAL : ${objectif || 'Croissance et engagement'}
${contexte ? 'CONTEXTE PARTICULIER : ' + contexte : ''}

Génère une proposition stratégique concrète et actionnable, adaptée au marché ivoirien et ouest-africain. Réponds UNIQUEMENT en JSON valide (sans texte avant ou après, sans backticks) avec cette structure exacte :
{
  "styles_contenu": [ { "titre": "...", "description": "...", "frequence": "..." } ],
  "formats_tendance": [ { "format": "...", "pourquoi": "...", "exemple": "..." } ],
  "idees_hooks": [ "...", "...", "..." ],
  "calendrier_type": [ { "jour": "...", "type": "...", "reseau": "..." } ],
  "conseils_viraux": [ "...", "..." ],
  "recherche_inspiration": [ { "plateforme": "...", "a_chercher": "..." } ]
}

Sois précis, créatif et concret. 3-4 éléments par liste. Adapte au secteur ${secteur} et à la culture locale ivoirienne.`;

  try {
    const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 2000,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!apiRes.ok) {
      const errText = await apiRes.text();
      log('ERROR', 'Erreur API Anthropic', { status: apiRes.status, body: errText.slice(0,200) });
      return res.status(502).json({ success:false, error:'L\'IA n\'a pas pu répondre (erreur '+apiRes.status+'). Vérifie ta clé API et ton crédit.' });
    }

    const data = await apiRes.json();
    let text = (data.content && data.content[0] && data.content[0].text) ? data.content[0].text : '';
    // Nettoie d'éventuels backticks
    text = text.replace(/```json/g,'').replace(/```/g,'').trim();

    let proposal;
    try { proposal = JSON.parse(text); }
    catch(e){
      log('WARN', 'Réponse IA non-JSON', { text: text.slice(0,200) });
      return res.status(502).json({ success:false, error:'L\'IA a répondu dans un format inattendu. Réessaie.' });
    }

    log('INFO', 'Proposition IA générée', { client: clientName });
    return res.json({ success:true, proposal });

  } catch (e) {
    log('ERROR', 'Exception appel IA', { message: e.message });
    return res.status(500).json({ success:false, error:'Erreur technique lors de l\'appel à l\'IA.' });
  }
});

// ══════════════════════════════════════════
// PUBLICATIONS (liens de posts partagés au client)
// ══════════════════════════════════════════

// Admin enregistre les publications d'un client
// POST /api/admin/posts/save
app.post('/api/admin/posts/save', (req, res) => {
  const { adminToken, clientKey, posts } = req.body;
  const a = requireStaff(req, res); if (!a) return;
  if (!clientKey) return res.status(400).json({ success:false, error:'clientKey requis.' });
  if (!canClient(a, clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  if (!Array.isArray(posts)) return res.status(400).json({ success:false, error:'posts doit être une liste.' });

  if (!STORE.posts) STORE.posts = {};
  STORE.posts[clientKey] = { items: posts, updatedAt: Date.now() };
  saveStore();
  log('INFO', 'Publications enregistrées', { clientKey, count: posts.length });
  return res.json({ success:true, message:'Publications enregistrées.', count: posts.length });
});

// Admin récupère les publications d'un client
// GET /api/admin/posts/:clientKey  (header x-admin-token)
app.get('/api/admin/posts/:clientKey', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  if (!canClient(a, req.params.clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  const p = (STORE.posts && STORE.posts[req.params.clientKey]) || { items: [] };
  return res.json({ success:true, posts: p.items || [] });
});

// Client récupère SES publications (uniquement celles marquées visibles)
// GET /api/client/posts/:clientKey
app.get('/api/client/posts/:clientKey', (req, res) => {
  const p = (STORE.posts && STORE.posts[req.params.clientKey]) || { items: [] };
  const visibles = (p.items || []).filter(x => x.published);
  return res.json({ success:true, posts: visibles });
});

// ══════════════════════════════════════════
// PREUVES SOCIALES (agrégées depuis les vraies stats)
// GET /api/admin/social-proof  (header x-admin-token)
// ══════════════════════════════════════════
app.get('/api/admin/social-proof', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;

  // Nom du client depuis sa clé
  const nameByKey = {};
  Object.values(USERS).forEach(u => { if (u.clientKey) nameByKey[u.clientKey] = u.name; });

  const proofs = [];
  let totalVues = 0, totalAbonnes = 0, clientsAvecStats = 0;

  Object.entries(STORE.stats || {}).forEach(([key, s]) => {
    if (!canClient(a, key)) return; // client non assigné
    const entries = (s && s.entries) ? s.entries.slice().sort((a,b)=>String(a.date).localeCompare(String(b.date))) : [];
    if (entries.length < 1) return;

    const first = entries[0];
    const last  = entries[entries.length - 1];
    const clientName = nameByKey[key] || key;
    clientsAvecStats++;

    const num = (v) => Number(v) || 0;
    totalVues    += num(last.views);
    totalAbonnes += num(last.followers);

    const growth = (k) => {
      const a = num(first[k]), b = num(last[k]);
      if (a === 0) return b > 0 ? 100 : 0;
      return ((b - a) / a) * 100;
    };

    const rate = (e) => {
      const v = num(e.views);
      if (v === 0) return 0;
      return ((num(e.likes) + num(e.comments) + num(e.shares)) / v) * 100;
    };

    // Nombre de mois couverts
    const d1 = new Date(first.date), d2 = new Date(last.date);
    const mois = Math.max(1, Math.round((d2 - d1) / (1000*60*60*24*30)));

    proofs.push({
      clientKey: key,
      clientName,
      reseau: last.net || '—',
      vues: num(last.views),
      abonnes: num(last.followers),
      likes: num(last.likes),
      portee: num(last.reach),
      tauxEngagement: Number(rate(last).toFixed(1)),
      croissanceVues: Number(growth('views').toFixed(0)),
      croissanceAbonnes: Number(growth('followers').toFixed(0)),
      moisAccompagnement: mois,
      nbReleves: entries.length,
      derniereMaj: last.date,
      publie: !!s.published
    });
  });

  // Tri : meilleure croissance en premier
  proofs.sort((a,b) => b.croissanceVues - a.croissanceVues);

  return res.json({
    success: true,
    generatedAt: Date.now(),
    resume: {
      clientsAccompagnes: clientsAvecStats,
      totalVues,
      totalAbonnes,
      meilleureCroissance: proofs.length ? proofs[0].croissanceVues : 0
    },
    proofs
  });
});

// ══════════════════════════════════════════
// IA — LECTURE DE CAPTURES D'ÉCRAN DE STATS
// POST /api/admin/ai/read-stats
// Body : { adminToken, images:[{media_type, data(base64)}], reseau }
// Renvoie les chiffres détectés — l'admin valide avant enregistrement
// ══════════════════════════════════════════
app.post('/api/admin/ai/read-stats', async (req, res) => {
  const { adminToken, images, reseau } = req.body;
  const a = requireStaff(req, res); if (!a) return;
  if (!ANTHROPIC_API_KEY) {
    return res.status(503).json({ success:false, error:'Clé API IA non configurée (ANTHROPIC_API_KEY sur Render).' });
  }
  if (!Array.isArray(images) || images.length === 0) {
    return res.status(400).json({ success:false, error:'Aucune image reçue.' });
  }
  if (images.length > 4) {
    return res.status(400).json({ success:false, error:'4 captures maximum à la fois.' });
  }

  const ALLOWED = ['image/png','image/jpeg','image/webp','image/gif'];
  for (const img of images) {
    if (!img || !img.data || !ALLOWED.includes(img.media_type)) {
      return res.status(400).json({ success:false, error:'Format d\'image non supporté (PNG, JPEG, WEBP ou GIF).' });
    }
  }

  const instruction = `Tu analyses des captures d'écran de statistiques de réseaux sociaux${reseau ? ' ('+reseau+')' : ''}.

Lis attentivement TOUS les chiffres visibles et extrais les métriques. Attention aux abréviations : "137K" = 137000, "1,9K" = 1900, "1.2M" = 1200000. Les espaces et virgules françaises séparent les milliers ("93 900" = 93900).

Si plusieurs captures sont fournies, elles concernent le MÊME compte : combine les informations (une capture peut montrer les vues, une autre les abonnés).

Réponds UNIQUEMENT en JSON valide, sans texte ni backticks autour :
{
  "reseau": "TikTok|Instagram|Facebook|YouTube ou null",
  "date": "AAAA-MM-JJ ou null si non visible",
  "views": nombre ou null,
  "followers": nombre ou null,
  "likes": nombre ou null,
  "comments": nombre ou null,
  "reach": nombre ou null,
  "shares": nombre ou null,
  "confiance": "haute|moyenne|basse",
  "remarques": "ce que tu n'as pas pu lire ou ce dont tu n'es pas sûr"
}

Mets null (pas 0) pour toute métrique absente ou illisible. Ne devine jamais un chiffre.`;

  const content = images.map(img => ({
    type: 'image',
    source: { type: 'base64', media_type: img.media_type, data: img.data }
  }));
  content.push({ type: 'text', text: instruction });

  try {
    const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1000,
        messages: [{ role: 'user', content }]
      })
    });

    if (!apiRes.ok) {
      const errText = await apiRes.text();
      log('ERROR', 'Erreur API vision', { status: apiRes.status, body: errText.slice(0,200) });
      return res.status(502).json({ success:false, error:'L\'IA n\'a pas pu lire l\'image (erreur '+apiRes.status+'). Vérifie ta clé API et ton crédit.' });
    }

    const data = await apiRes.json();
    let text = (data.content && data.content[0] && data.content[0].text) ? data.content[0].text : '';
    text = text.replace(/```json/g,'').replace(/```/g,'').trim();

    let stats;
    try { stats = JSON.parse(text); }
    catch(e){
      log('WARN', 'Réponse vision non-JSON', { text: text.slice(0,200) });
      return res.status(502).json({ success:false, error:'L\'IA a répondu dans un format inattendu. Réessaie avec une capture plus nette.' });
    }

    log('INFO', 'Stats lues depuis capture', { reseau: stats.reseau, confiance: stats.confiance });
    return res.json({ success:true, stats });

  } catch (e) {
    log('ERROR', 'Exception lecture capture', { message: e.message });
    return res.status(500).json({ success:false, error:'Erreur technique lors de l\'analyse de l\'image.' });
  }
});

// ══════════════════════════════════════════
// CALENDRIER ÉDITORIAL (publications planifiées)
// ══════════════════════════════════════════

// Admin enregistre le calendrier d'un client
// POST /api/admin/calendar/save
app.post('/api/admin/calendar/save', (req, res) => {
  const { adminToken, clientKey, events } = req.body;
  const a = requireStaff(req, res); if (!a) return;
  if (!clientKey) return res.status(400).json({ success:false, error:'clientKey requis.' });
  if (!canClient(a, clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  if (!Array.isArray(events)) return res.status(400).json({ success:false, error:'events doit être une liste.' });

  STORE.calendar[clientKey] = { events, updatedAt: Date.now() };
  saveStore();
  return res.json({ success:true, count: events.length });
});

// Admin récupère le calendrier d'un client
// GET /api/admin/calendar/:clientKey  (header x-admin-token)
app.get('/api/admin/calendar/:clientKey', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  if (!canClient(a, req.params.clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  const c = STORE.calendar[req.params.clientKey] || { events: [] };
  return res.json({ success:true, events: c.events || [] });
});

// Admin récupère TOUTES les publications d'une date (tous clients)
// GET /api/admin/calendar-day/:date   ex: 2026-07-09
app.get('/api/admin/calendar-day/:date', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  const date = req.params.date;
  const nameByKey = {};
  Object.values(USERS).forEach(u => { if (u.clientKey) nameByKey[u.clientKey] = u.name; });

  const items = [];
  Object.entries(STORE.calendar || {}).forEach(([key, c]) => {
    // Ignore les clients qui n'existent plus
    if (!nameByKey[key]) return;
    // Ignore les clients non assignés à cet utilisateur
    if (!canClient(a, key)) return;
    (c.events || []).forEach(e => {
      if (e.date === date) items.push({ ...e, clientKey: key, clientName: nameByKey[key] });
    });
  });
  items.sort((x,y) => String(x.hour||'').localeCompare(String(y.hour||'')));
  return res.json({ success:true, date, items });
});

// Admin récupère TOUTES les publications de tous les clients (pour le calendrier du dashboard)
// GET /api/admin/calendar-all   (header x-admin-token)
app.get('/api/admin/calendar-all', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  const nameByKey = {};
  Object.values(USERS).forEach(u => { if (u.clientKey) nameByKey[u.clientKey] = u.name; });

  const items = [];
  Object.entries(STORE.calendar || {}).forEach(([key, c]) => {
    if (!nameByKey[key]) return;      // client supprimé
    if (!canClient(a, key)) return;   // client non assigné à cet utilisateur
    (c.events || []).forEach(e => {
      items.push({ ...e, clientKey: key, clientName: nameByKey[key] });
    });
  });
  return res.json({ success:true, items });
});

// Client récupère SON calendrier éditorial (toutes ses publications planifiées)
// GET /api/client/calendar/:clientKey
app.get('/api/client/calendar/:clientKey', (req, res) => {
  const c = STORE.calendar[req.params.clientKey] || { events: [] };
  return res.json({ success:true, events: c.events || [] });
});

// ══════════════════════════════════════════
// TÂCHES (à faire, avec dates)
// ══════════════════════════════════════════

// Une tâche est visible par : l'admin (tout), son créateur,
// ou un collaborateur si elle concerne un de ses clients assignés.
function taskVisible(a, t) {
  if (a.allClients) return true;
  if (t.owner && a.userId && t.owner === a.userId) return true;
  if (t.clientKey) return a.clientKeys.includes(t.clientKey);
  return false; // tâche générale de quelqu'un d'autre → invisible
}

app.post('/api/admin/tasks/save', (req, res) => {
  const { tasks } = req.body;
  const a = requireStaff(req, res); if (!a) return;
  if (!Array.isArray(tasks)) return res.status(400).json({ success:false, error:'tasks doit être une liste.' });

  if (!STORE.tasks) STORE.tasks = {};
  const existing = Array.isArray(STORE.tasks.items) ? STORE.tasks.items : [];
  const me = a.userId || 'admin';

  // Un collaborateur ne renvoie que SES tâches visibles.
  // On conserve donc celles des autres au lieu de les écraser.
  const autres = existing.filter(t => !taskVisible(a, t));
  const miennes = tasks.map(t => {
    // Il ne peut pas créer/déplacer une tâche vers un client non assigné
    if (t.clientKey && !canClient(a, t.clientKey)) return { ...t, clientKey: null };
    return { ...t, owner: t.owner || me };
  });

  STORE.tasks.items = autres.concat(miennes);
  STORE.tasks.updatedAt = Date.now();
  saveStore();
  return res.json({ success:true, count: miennes.length });
});

app.get('/api/admin/tasks', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  const all = (STORE.tasks && STORE.tasks.items) ? STORE.tasks.items : [];
  return res.json({ success:true, tasks: all.filter(t => taskVisible(a, t)) });
});

// ══════════════════════════════════════════
// PROSPECTION — base de prospects
// ══════════════════════════════════════════
app.post('/api/admin/prospects/save', (req, res) => {
  const { adminToken, prospects } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!Array.isArray(prospects)) return res.status(400).json({ success:false, error:'prospects doit être une liste.' });

  if (!STORE.prospects) STORE.prospects = {};
  STORE.prospects.items = prospects;
  STORE.prospects.updatedAt = Date.now();
  saveStore();
  return res.json({ success:true, count: prospects.length });
});

app.get('/api/admin/prospects', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  const p = (STORE.prospects && STORE.prospects.items) ? STORE.prospects.items : [];
  return res.json({ success:true, prospects: p });
});

// ══════════════════════════════════════════
// IA — ANALYSE D'UN PROSPECT
// POST /api/admin/ai/prospect-score
// L'IA note UNIQUEMENT les informations fournies par l'admin.
// Elle n'invente aucune coordonnée.
// ══════════════════════════════════════════
app.post('/api/admin/ai/prospect-score', async (req, res) => {
  const { adminToken, prospect } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!ANTHROPIC_API_KEY) return res.status(503).json({ success:false, error:'Clé API IA non configurée (ANTHROPIC_API_KEY sur Render).' });
  if (!prospect || !prospect.nom || !prospect.secteur) {
    return res.status(400).json({ success:false, error:'Nom et secteur du prospect requis.' });
  }

  const p = prospect;
  const oui = (v) => v ? 'Oui' : 'Non';

  const prompt = `Tu es expert en prospection commerciale pour PURE MOTION, agence Creative Tech à Abidjan (Côte d'Ivoire), spécialisée en vidéo social-first et Community Management.

PROSPECT À ÉVALUER (informations relevées sur le terrain) :
- Nom : ${p.nom}
- Secteur : ${p.secteur}
- Commune : ${p.commune || 'non précisée'}
- Site web : ${oui(p.hasSite)}
- Facebook : ${oui(p.hasFacebook)}
- Instagram : ${oui(p.hasInstagram)}
- TikTok : ${oui(p.hasTiktok)}
- LinkedIn : ${oui(p.hasLinkedin)}
- Nombre d'abonnés (approx.) : ${p.abonnes || 'inconnu'}
- Dernière publication : ${p.dernierPost || 'inconnue'}
- Fréquence de publication : ${p.frequence || 'inconnue'}
- Qualité des visuels : ${p.qualiteVisuels || 'inconnue'}
- Contenu vidéo : ${oui(p.hasVideo)}
- Engagement observé : ${p.engagement || 'inconnu'}
- Note Google : ${p.noteGoogle || 'inconnue'}
- Identité visuelle cohérente : ${oui(p.brandingCoherent)}
- Observations : ${p.notes || 'aucune'}

RÈGLES STRICTES :
- N'invente AUCUNE coordonnée (téléphone, email, nom de dirigeant, adresse).
- Base-toi UNIQUEMENT sur les informations ci-dessus.
- Si une information manque, dis-le dans "informations_manquantes".
- Un prospect avec une présence digitale faible ou abandonnée = forte opportunité pour nous.

Réponds UNIQUEMENT en JSON valide, sans backticks ni texte autour :
{
  "score": nombre entre 0 et 100,
  "etoiles": nombre entre 1 et 5,
  "niveau": "Très forte opportunité|Bonne opportunité|Opportunité moyenne|Faible|Très faible",
  "pourquoi": "2-3 phrases expliquant pourquoi c'est (ou non) un bon prospect",
  "faiblesses_detectees": ["...", "..."],
  "services_recommandes": ["...", "...", "..."],
  "priorite": "Cette semaine|Ce mois|Plus tard",
  "budget_estime": "fourchette en FCFA/mois selon nos formules Bronze 50K / Platinum 80K / Gold 150K",
  "angle_approche": "l'accroche à utiliser pour capter son attention",
  "message_approche": "un message WhatsApp court (4-5 lignes max), professionnel et chaleureux, adapté au contexte ivoirien",
  "informations_manquantes": ["...", "..."]
}

Sois honnête : si le prospect a déjà une excellente présence digitale, le score doit être bas (il a moins besoin de nous).`;

  try {
    const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1500,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!apiRes.ok) {
      const t = await apiRes.text();
      log('ERROR', 'Erreur IA prospect', { status: apiRes.status, body: t.slice(0,200) });
      return res.status(502).json({ success:false, error:'L\'IA n\'a pas pu analyser (erreur '+apiRes.status+').' });
    }

    const data = await apiRes.json();
    let text = (data.content && data.content[0] && data.content[0].text) ? data.content[0].text : '';
    text = text.replace(/```json/g,'').replace(/```/g,'').trim();

    let analyse;
    try { analyse = JSON.parse(text); }
    catch(e){ return res.status(502).json({ success:false, error:'Réponse IA inattendue. Réessaie.' }); }

    log('INFO', 'Prospect analysé', { nom: p.nom, score: analyse.score });
    return res.json({ success:true, analyse });

  } catch (e) {
    log('ERROR', 'Exception analyse prospect', { message: e.message });
    return res.status(500).json({ success:false, error:'Erreur technique.' });
  }
});

// ══════════════════════════════════════════
// IA — STRATÉGIE DE MARCHÉ (Abidjan)
// POST /api/admin/ai/market-strategy
// ══════════════════════════════════════════
app.post('/api/admin/ai/market-strategy', async (req, res) => {
  const { adminToken, secteursCibles } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!ANTHROPIC_API_KEY) return res.status(503).json({ success:false, error:'Clé API IA non configurée.' });

  const prompt = `Tu es expert en intelligence économique et prospection B2B sur le marché ivoirien.

CONTEXTE : PURE MOTION est une agence Creative Tech à Abidjan, spécialisée en vidéo social-first et Community Management. Formules : Bronze 50 000 FCFA/mois, Platinum 80 000 FCFA/mois, Gold 150 000 FCFA/mois.

${secteursCibles ? 'SECTEURS QUI M\'INTÉRESSENT : ' + secteursCibles : ''}

Donne une stratégie de prospection concrète, réaliste et adaptée à Abidjan.

RÈGLE STRICTE : ne cite AUCUN nom d'entreprise réelle, aucun numéro, aucun email. Reste au niveau des secteurs, des communes et des méthodes.

Réponds UNIQUEMENT en JSON valide, sans backticks :
{
  "secteurs_rentables": [
    { "secteur": "...", "pourquoi": "...", "budget_type": "Bronze|Platinum|Gold", "difficulte": "Facile|Moyenne|Difficile" }
  ],
  "communes_prioritaires": [
    { "commune": "...", "profil": "...", "secteurs_dominants": "..." }
  ],
  "ou_trouver_prospects": [
    { "methode": "...", "comment": "..." }
  ],
  "signaux_bon_prospect": ["...", "..."],
  "conseils_conversion": [
    { "conseil": "...", "detail": "..." }
  ],
  "erreurs_a_eviter": ["...", "..."]
}

4-5 éléments par liste. Sois précis sur les réalités d'Abidjan (Cocody, Plateau, Yopougon, Marcory, Treichville, Abobo, Koumassi, Port-Bouët, Bingerville...).`;

  try {
    const apiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 2500,
        messages: [{ role: 'user', content: prompt }]
      })
    });

    if (!apiRes.ok) {
      const t = await apiRes.text();
      return res.status(502).json({ success:false, error:'L\'IA n\'a pas pu répondre (erreur '+apiRes.status+').' });
    }
    const data = await apiRes.json();
    let text = (data.content && data.content[0] && data.content[0].text) ? data.content[0].text : '';
    text = text.replace(/```json/g,'').replace(/```/g,'').trim();

    let strategie;
    try { strategie = JSON.parse(text); }
    catch(e){ return res.status(502).json({ success:false, error:'Réponse IA inattendue. Réessaie.' }); }

    log('INFO', 'Stratégie de marché générée');
    return res.json({ success:true, strategie });

  } catch (e) {
    return res.status(500).json({ success:false, error:'Erreur technique.' });
  }
});

// ══════════════════════════════════════════
// OBJECTIFS PURE MOTION
// ══════════════════════════════════════════
app.post('/api/admin/objectives/save', (req, res) => {
  const { adminToken, objectives } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!Array.isArray(objectives)) return res.status(400).json({ success:false, error:'objectives doit être une liste.' });
  if (!STORE.objectives) STORE.objectives = {};
  STORE.objectives.items = objectives;
  STORE.objectives.updatedAt = Date.now();
  saveStore();
  return res.json({ success:true, count: objectives.length });
});

app.get('/api/admin/objectives', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  const o = (STORE.objectives && STORE.objectives.items) ? STORE.objectives.items : [];
  return res.json({ success:true, objectives: o });
});

// ══════════════════════════════════════════
// PARAMÈTRES — Mot de passe admin & collaborateurs
// ══════════════════════════════════════════

// Changer le mot de passe administrateur
// POST /api/admin/change-password
// Body : { adminToken, currentPassword, newPassword }
app.post('/api/admin/change-password', (req, res) => {
  const { adminToken, currentPassword, newPassword } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!currentPassword || !newPassword) return res.status(400).json({ success:false, error:'Ancien et nouveau mot de passe requis.' });
  if (!validPw(newPassword)) return res.status(400).json({ success:false, error:'Le nouveau mot de passe doit faire au moins 6 caractères.' });

  // Retrouve le compte admin
  const adminEntry = Object.entries(USERS).find(([id, u]) => u.role === 'admin');
  if (!adminEntry) return res.status(500).json({ success:false, error:'Compte admin introuvable.' });
  const [adminId, adminUser] = adminEntry;

  if (!verifyPassword(currentPassword, adminUser.passwordHash)) {
    log('WARN', 'Échec changement mot de passe admin (ancien incorrect)');
    return res.status(401).json({ success:false, error:'Mot de passe actuel incorrect.' });
  }

  adminUser.passwordHash = hashPassword(newPassword);
  // Persiste le hash admin dans STORE pour survivre aux redémarrages
  if (!STORE.adminOverride) STORE.adminOverride = {};
  STORE.adminOverride.passwordHash = adminUser.passwordHash;
  saveStore();

  log('INFO', 'Mot de passe admin changé');
  return res.json({ success:true, message:'Mot de passe administrateur mis à jour.' });
});

// Lister les collaborateurs
// GET /api/admin/collaborators  (header x-admin-token)
app.get('/api/admin/collaborators', (req, res) => {
  const a = requireAdmin(req, res); if (!a) return;
  const collabs = Object.entries(USERS)
    .filter(([id, u]) => u.role === 'collaborateur')
    .map(([id, u]) => ({
      id,
      name: u.name,
      email: u.email || null,
      phone: u.phone || null,
      activated: !!u.activated,
      clientKeys: Array.isArray(u.clientKeys) ? u.clientKeys : []
    }));
  return res.json({ success:true, collaborators: collabs });
});

// Assigner des clients à un collaborateur
// POST /api/admin/collaborators/assign  { adminToken, id, clientKeys:[] }
app.post('/api/admin/collaborators/assign', (req, res) => {
  const a = requireAdmin(req, res); if (!a) return;
  const { id, clientKeys } = req.body;
  if (!id || !USERS[id]) return res.status(404).json({ success:false, error:'Collaborateur introuvable.' });
  if (USERS[id].role !== 'collaborateur') return res.status(400).json({ success:false, error:'Ce compte n\'est pas un collaborateur.' });
  if (!Array.isArray(clientKeys)) return res.status(400).json({ success:false, error:'clientKeys doit être une liste.' });

  // On ne garde que des clés de clients qui existent réellement
  const valides = Object.values(USERS).filter(u => u.clientKey).map(u => u.clientKey);
  USERS[id].clientKeys = clientKeys.filter(k => valides.includes(k));
  persistClients();
  log('INFO', 'Clients assignés', { collaborateur: USERS[id].name, nb: USERS[id].clientKeys.length });
  return res.json({ success:true, clientKeys: USERS[id].clientKeys });
});

// Supprimer un collaborateur
// POST /api/admin/collaborators/delete
// Body : { adminToken, id }
app.post('/api/admin/collaborators/delete', (req, res) => {
  const { adminToken, id } = req.body;
  const a = requireAdmin(req, res); if (!a) return;
  if (!id) return res.status(400).json({ success:false, error:'Identifiant requis.' });

  const user = USERS[id];
  if (!user || user.role !== 'collaborateur') {
    return res.status(404).json({ success:false, error:'Collaborateur introuvable.' });
  }
  const name = user.name;
  delete USERS[id];
  persistClients();
  reindexAll();

  log('INFO', 'Collaborateur supprimé', { name });
  return res.json({ success:true, message:'Collaborateur « '+name+' » supprimé.' });
});

// ══════════════════════════════════════════
// DOCUMENTS (contrats, factures... rattachés à un client)
// Stockés en base64. Limite stricte pour protéger la base.
// STORE.documents = { clientKey: [ {id,name,type,size,data,uploadedAt} ] }
// ══════════════════════════════════════════
const DOC_MAX_BYTES = 5 * 1024 * 1024;        // 5 Mo par document
const DOC_ALLOWED = ['application/pdf','image/png','image/jpeg','image/webp'];

// Admin téléverse un document pour un client
// POST /api/admin/documents/add
app.post('/api/admin/documents/add', (req, res) => {
  const { adminToken, clientKey, name, mediaType, data } = req.body;
  const a = requireStaff(req, res); if (!a) return;
  if (!clientKey) return res.status(400).json({ success:false, error:'clientKey requis.' });
  if (!canClient(a, clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  if (!name || !data) return res.status(400).json({ success:false, error:'Nom et fichier requis.' });
  if (!DOC_ALLOWED.includes(mediaType)) {
    return res.status(400).json({ success:false, error:'Format non supporté (PDF, PNG, JPEG ou WEBP).' });
  }
  // Taille réelle du base64 (approx : 3/4 de la longueur)
  const approxBytes = Math.floor(data.length * 0.75);
  if (approxBytes > DOC_MAX_BYTES) {
    return res.status(400).json({ success:false, error:'Fichier trop lourd (5 Mo maximum).' });
  }

  if (!STORE.documents) STORE.documents = {};
  if (!STORE.documents[clientKey]) STORE.documents[clientKey] = [];
  const doc = {
    id: 'doc' + Date.now(),
    name: String(name).slice(0, 120),
    type: mediaType,
    size: approxBytes,
    data: data,
    uploadedAt: Date.now()
  };
  STORE.documents[clientKey].push(doc);
  saveStore();
  log('INFO', 'Document ajouté', { clientKey, name: doc.name, size: approxBytes });
  // On ne renvoie pas le base64 dans la réponse (inutile, lourd)
  return res.json({ success:true, id: doc.id, name: doc.name });
});

// Admin liste les documents d'un client (métadonnées seulement, sans le contenu)
// GET /api/admin/documents/:clientKey  (header x-admin-token)
app.get('/api/admin/documents/:clientKey', (req, res) => {
  const a = requireStaff(req, res); if (!a) return;
  if (!canClient(a, req.params.clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  const docs = (STORE.documents && STORE.documents[req.params.clientKey]) || [];
  const meta = docs.map(d => ({ id:d.id, name:d.name, type:d.type, size:d.size, uploadedAt:d.uploadedAt }));
  return res.json({ success:true, documents: meta });
});

// Admin supprime un document
// POST /api/admin/documents/delete
app.post('/api/admin/documents/delete', (req, res) => {
  const { adminToken, clientKey, id } = req.body;
  const a = requireStaff(req, res); if (!a) return;
  if (!canClient(a, clientKey)) return res.status(403).json({ success:false, error:'Ce client ne t\'est pas assigné.' });
  if (!STORE.documents || !STORE.documents[clientKey]) return res.status(404).json({ success:false, error:'Document introuvable.' });
  STORE.documents[clientKey] = STORE.documents[clientKey].filter(d => d.id !== id);
  saveStore();
  return res.json({ success:true });
});

// Télécharge un document (admin OU le client concerné)
// GET /api/documents/download/:clientKey/:id
app.get('/api/documents/download/:clientKey/:id', (req, res) => {
  const { clientKey, id } = req.params;
  const isAdmin = req.headers['x-admin-token'] === ADMIN_TOKEN || req.query.admin === ADMIN_TOKEN;
  // Le client accède avec sa clé dans l'URL (déjà secrète et propre à lui)
  const docs = (STORE.documents && STORE.documents[clientKey]) || [];
  const doc = docs.find(d => d.id === id);
  if (!doc) return res.status(404).json({ success:false, error:'Document introuvable.' });

  const buffer = Buffer.from(doc.data, 'base64');
  res.set('Content-Type', doc.type);
  res.set('Content-Disposition', 'inline; filename="' + encodeURIComponent(doc.name) + '"');
  return res.send(buffer);
});

// Client liste SES documents (métadonnées seulement)
// GET /api/client/documents/:clientKey
app.get('/api/client/documents/:clientKey', (req, res) => {
  const docs = (STORE.documents && STORE.documents[req.params.clientKey]) || [];
  const meta = docs.map(d => ({ id:d.id, name:d.name, type:d.type, size:d.size, uploadedAt:d.uploadedAt }));
  return res.json({ success:true, documents: meta });
});

// Renommer un client ou un collaborateur (sans toucher à ses données)
// POST /api/admin/clients/update  { adminToken, id, name }
app.post('/api/admin/clients/update', (req, res) => {
  const a = requireAdmin(req, res); if (!a) return;
  const { id, name } = req.body;
  if (!id || !USERS[id]) return res.status(404).json({ success:false, error:'Compte introuvable.' });
  if (USERS[id].role === 'admin') return res.status(403).json({ success:false, error:'Le compte administrateur ne peut pas être modifié ici.' });
  const propre = String(name || '').trim();
  if (!propre) return res.status(400).json({ success:false, error:'Le nom ne peut pas être vide.' });
  if (propre.length > 80) return res.status(400).json({ success:false, error:'Nom trop long (80 caractères maximum).' });

  const ancien = USERS[id].name;
  USERS[id].name = propre;
  persistClients();
  log('INFO', 'Compte renommé', { ancien, nouveau: propre });
  // La clé de liaison n'est PAS modifiée : stats, calendrier et documents restent rattachés.
  return res.json({ success:true, name: propre });
});

// ══════════════════════════════════════════
// MON COMPTE (session individuelle)
// ══════════════════════════════════════════

// Qui suis-je ? Utilisé par l'interface pour adapter l'affichage au rôle.
// GET /api/me   (header x-session-token)
app.get('/api/me', (req, res) => {
  const a = getAuth(req);
  if (!a) return res.status(401).json({ success:false, error:'Session expirée.' });
  const noms = {};
  Object.values(USERS).forEach(u => { if (u.clientKey) noms[u.clientKey] = u.name; });
  return res.json({
    success: true,
    role: a.role,
    name: a.user ? a.user.name : 'Administrateur',
    allClients: !!a.allClients,
    clientKeys: a.allClients ? Object.keys(noms) : a.clientKeys,
    clients: (a.allClients ? Object.keys(noms) : a.clientKeys).map(k => ({ clientKey:k, name: noms[k] || k }))
  });
});

// Changer MON mot de passe (collaborateur ou admin connecté par session)
// POST /api/me/change-password  { sessionToken, current, next }
app.post('/api/me/change-password', loginLimiter, (req, res) => {
  const a = getAuth(req);
  if (!a || !a.user) return res.status(401).json({ success:false, error:'Session expirée. Reconnecte-toi.' });
  const { current, next } = req.body;
  if (!current || !next) return res.status(400).json({ success:false, error:'Mot de passe actuel et nouveau requis.' });
  if (String(next).length < 6) return res.status(400).json({ success:false, error:'Le nouveau mot de passe doit faire au moins 6 caractères.' });
  if (!verifyPassword(current, a.user.passwordHash)) {
    return res.status(401).json({ success:false, error:'Mot de passe actuel incorrect.' });
  }
  a.user.passwordHash = hashPassword(next);
  persistClients();
  log('INFO', 'Mot de passe changé', { name: a.user.name });
  return res.json({ success:true, message:'Mot de passe mis à jour.' });
});

// Déconnexion : invalide la session côté serveur
// POST /api/logout  { sessionToken }
app.post('/api/logout', (req, res) => {
  const tok = req.headers['x-session-token'] || (req.body && req.body.sessionToken);
  if (tok) destroySession(tok);
  return res.json({ success:true });
});

// ══════════════════════════════════════════
// PAGES TABLEAUX DE BORD
// ══════════════════════════════════════════

// Espace admin / collaborateur
app.get('/admin', (req, res) => {
  const f = path.join(__dirname, 'public', 'admin.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  log('ERROR', 'admin.html introuvable', { path: f });
  return res.redirect('/');
});

// Espace client
app.get('/espace-client', (req, res) => {
  const f = path.join(__dirname, 'public', 'client.html');
  if (fs.existsSync(f)) return res.sendFile(f);
  log('ERROR', 'client.html introuvable', { path: f });
  return res.redirect('/');
});

// ══════════════════════════════════════════
// FRONTEND (fallback → page de connexion)
// ══════════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
    if (err) res.status(200).send('Pure Motion Backend — API en ligne. Frontend non déployé.');
  });
});

app.use((err, req, res, next) => {
  log('ERROR', 'Erreur non gérée', { message: err.message });
  res.status(500).json({ success:false, error:'Erreur interne.' });
});

// ══════════════════════════════════════════
// DÉMARRAGE (asynchrone : attend la base de données)
// ══════════════════════════════════════════
async function start() {
  await loadStore();      // charge depuis PostgreSQL (ou fichier)
  restoreClients();       // réinjecte les comptes clients + réindexe

  app.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════╗');
    console.log('║   🚀 PURE MOTION Backend démarré         ║');
    console.log(`║   → Port    : ${PORT}`);
    console.log(`║   → Env     : ${NODE_ENV}`);
    console.log(`║   → Stockage: ${USE_PG ? 'PostgreSQL (durable ✅)' : 'Fichier local (dev)'}`);
    console.log('╚══════════════════════════════════════════╝');
    console.log('');
  });
}

start().catch((e) => {
  console.error('❌ Démarrage impossible :', e.message);
  process.exit(1);
});
