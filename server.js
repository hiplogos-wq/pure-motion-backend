
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

const app = express();

// ══════════════════════════════════════════
// CONFIGURATION
// ══════════════════════════════════════════
const {
  PORT = 3000,
  ALLOWED_ORIGIN = '*',
  NODE_ENV = 'development',
  ADMIN_TOKEN = 'change_me',
} = process.env;

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

// Index par téléphone (les clients se connectent par numéro)
const USERS_BY_PHONE = {};

function reindexPhones() {
  for (const key in USERS_BY_PHONE) delete USERS_BY_PHONE[key];
  Object.entries(USERS).forEach(([email, u]) => {
    if (u.phone) USERS_BY_PHONE[u.phone] = email;
  });
}

// Codes d'invitation temporaires pour la 1ère connexion client
// { code: { phone, name, expiresAt } }
const INVITES = {};

reindexPhones();

// ══════════════════════════════════════════
// MIDDLEWARES
// ══════════════════════════════════════════
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(cors({ origin: ALLOWED_ORIGIN === '*' ? '*' : ALLOWED_ORIGIN.split(','), methods: ['GET','POST'] }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
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
// CLIENT — VÉRIFIER LE STATUT D'UN NUMÉRO
// POST /api/client/check
// Body : { phone }
// Dit au frontend si le client doit créer son mot de passe ou se connecter
// ══════════════════════════════════════════
app.post('/api/client/check', loginLimiter, (req, res) => {
  const { phone } = req.body;
  if (!phone || !validPhone(phone)) {
    return res.status(400).json({ success:false, error:'Numéro invalide. Format : +225XXXXXXXXXX' });
  }
  const email = USERS_BY_PHONE[phone];
  const user = email ? USERS[email] : null;

  if (!user) {
    return res.status(404).json({ success:false, error:'Ce numéro n\'est pas enregistré. Contactez Pure Motion.' });
  }
  // Le compte existe : doit-il créer son mot de passe ?
  return res.json({
    success: true,
    activated: user.activated,
    name: user.name,
    nextStep: user.activated ? 'login' : 'create-password'
  });
});

// ══════════════════════════════════════════
// CLIENT — CRÉER SON MOT DE PASSE (1ère connexion)
// POST /api/client/set-password
// Body : { phone, password }
// ══════════════════════════════════════════
app.post('/api/client/set-password', loginLimiter, (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !validPhone(phone)) return res.status(400).json({ success:false, error:'Numéro invalide.' });
  if (!validPw(password)) return res.status(400).json({ success:false, error:'Le mot de passe doit faire au moins 6 caractères.' });

  const email = USERS_BY_PHONE[phone];
  const user = email ? USERS[email] : null;
  if (!user) return res.status(404).json({ success:false, error:'Numéro introuvable.' });
  if (user.activated) return res.status(409).json({ success:false, error:'Ce compte a déjà un mot de passe. Connectez-vous.' });

  // Enregistre le mot de passe haché et active le compte
  user.passwordHash = hashPassword(password);
  user.activated = true;

  log('INFO', 'Client a créé son mot de passe', { phone: maskPhone(phone), name: user.name });

  const sessionToken = makeToken(phone);
  return res.json({
    success: true,
    activated: true,
    user: { name: user.name, role: user.role, phone: maskPhone(phone) },
    sessionToken,
    message: 'Mot de passe créé. Bienvenue !'
  });
});

// ══════════════════════════════════════════
// CLIENT — CONNEXION (numéro + mot de passe, SANS code)
// POST /api/client/login
// Body : { phone, password }
// ══════════════════════════════════════════
app.post('/api/client/login', loginLimiter, (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !validPhone(phone)) return res.status(400).json({ success:false, error:'Numéro invalide.' });
  if (!password) return res.status(400).json({ success:false, error:'Mot de passe requis.' });

  const email = USERS_BY_PHONE[phone];
  const user = email ? USERS[email] : null;

  if (!user || !user.activated) {
    return res.status(401).json({ success:false, error:'Numéro ou mot de passe incorrect.' });
  }
  if (!verifyPassword(password, user.passwordHash)) {
    log('WARN', 'Échec connexion client', { phone: maskPhone(phone) });
    return res.status(401).json({ success:false, error:'Numéro ou mot de passe incorrect.' });
  }

  // Si c'est un admin, on le redirige vers la route admin dédiée
  if (user.role === 'admin') {
    return res.status(403).json({ success:false, error:'Ce compte nécessite la connexion administrateur.' });
  }

  log('INFO', 'Connexion client réussie', { phone: maskPhone(phone), name: user.name, role: user.role });

  const sessionToken = makeToken(phone);
  return res.json({
    success: true,
    user: { name: user.name, role: user.role, phone: maskPhone(phone) },
    sessionToken,
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
    sessionToken: makeToken(email),
    message: 'Connexion administrateur réussie !'
  });
});

// ══════════════════════════════════════════
// ADMIN — CRÉER / INVITER UN CLIENT
// POST /api/admin/clients/create
// Body : { adminToken, name, phone, role }
// Le client pourra ensuite créer son mot de passe à la 1ère connexion
// ══════════════════════════════════════════
app.post('/api/admin/clients/create', (req, res) => {
  const { adminToken, name, phone, role = 'client' } = req.body;
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  if (!name || !phone || !validPhone(phone)) {
    return res.status(400).json({ success:false, error:'Nom et numéro valides requis. Format numéro : +225XXXXXXXXXX' });
  }
  if (USERS_BY_PHONE[phone]) {
    return res.status(409).json({ success:false, error:'Ce numéro existe déjà.' });
  }

  // Crée un identifiant interne basé sur le téléphone
  const internalEmail = `${phone.replace('+','')}@client.puremotion.ci`;
  USERS[internalEmail] = {
    role: role === 'collaborateur' ? 'collaborateur' : 'client',
    name,
    phone,
    passwordHash: null,    // pas encore de mot de passe
    activated: false,      // le client doit l'activer
    isAdmin: false,
  };
  reindexPhones();

  log('INFO', 'Client créé (en attente d\'activation)', { name, phone: maskPhone(phone), role });

  return res.json({
    success: true,
    message: `${name} ajouté. Il pourra créer son mot de passe à sa première connexion avec son numéro.`,
    client: { name, phone, role, activated: false }
  });
});

// ══════════════════════════════════════════
// ADMIN — LISTE DES CLIENTS
// GET /api/admin/clients  (header x-admin-token)
// ══════════════════════════════════════════
app.get('/api/admin/clients', (req, res) => {
  if (req.headers['x-admin-token'] !== ADMIN_TOKEN) {
    return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  }
  const clients = Object.values(USERS)
    .filter(u => u.role !== 'admin')
    .map(u => ({ name: u.name, phone: maskPhone(u.phone), role: u.role, activated: u.activated }));
  return res.json({ success:true, count: clients.length, clients });
});

// ══════════════════════════════════════════
// FRONTEND (fallback)
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
// DÉMARRAGE
// ══════════════════════════════════════════
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   🚀 PURE MOTION Backend démarré         ║');
  console.log(`║   → Port    : ${PORT}`);
  console.log(`║   → Env     : ${NODE_ENV}`);
  console.log(`║   → Clients : numéro + mot de passe`);
  console.log(`║   → Admin   : email + mot de passe (simple)`);
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
  console.log('📡 Routes :');
  console.log('   POST /api/client/check          (statut numéro)');
  console.log('   POST /api/client/set-password   (1ère connexion)');
  console.log('   POST /api/client/login          (connexion client)');
  console.log('   POST /api/admin/login           (connexion admin)');
  console.log('   POST /api/admin/clients/create  (ajouter un client)');
  console.log('   GET  /api/admin/clients         (liste clients)');
  console.log('   GET  /api/health');
  console.log('');
});
