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
// STOCKAGE FICHIER JSON (persistance simple)
// ⚠️ Sur Render gratuit, effacé à chaque redéploiement.
//    Pour la production durable → migrer vers PostgreSQL.
// ══════════════════════════════════════════
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'pm_data.json');

// Structure : { clients:{...}, stats:{clientKey:[...]}, calendar:{clientKey:[...]} }
let STORE = { clients: {}, stats: {}, calendar: {}, publications: {} };

function loadStore() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      STORE = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      if (!STORE.clients) STORE.clients = {};
      if (!STORE.stats) STORE.stats = {};
      if (!STORE.calendar) STORE.calendar = {};
      if (!STORE.posts) STORE.posts = {};
      if (!STORE.publications) STORE.publications = {};
      console.log('✅ Données chargées depuis le fichier');
    }
  } catch (e) {
    console.warn('⚠️ Impossible de charger les données, démarrage à vide :', e.message);
    STORE = { clients: {}, stats: {}, calendar: {}, publications: {} };
  }
}

let saveTimer = null;
function saveStore() {
  // Sauvegarde différée (évite d'écrire trop souvent)
  if (saveTimer) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    try {
      if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(DATA_FILE, JSON.stringify(STORE, null, 2), 'utf8');
    } catch (e) {
      console.error('❌ Erreur sauvegarde données :', e.message);
    }
  }, 400);
}

loadStore();

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

// Les 3 clients de démarrage — MODIFIE ces infos avec les vraies coordonnées
makeClient({ name:'Soleil Communication', clientKey:'soleil', phone:'+22507000001', email:'soleil@client.ci' });
makeClient({ name:'Maquis Chez Fanta', clientKey:'fanta', phone:'+22507000002', email:'fanta@client.ci' });
makeClient({ name:'Boutique Élégance CI', clientKey:'elegance', phone:'+22507000003', email:'elegance@client.ci' });

// Restaure les clients créés précédemment (persistés dans le fichier)
// Ils écrasent les clients de démo s'ils ont le même identifiant (données à jour)
if (STORE.clients && typeof STORE.clients === 'object') {
  Object.entries(STORE.clients).forEach(([id, u]) => {
    USERS[id] = u;
  });
  console.log(`✅ ${Object.keys(STORE.clients).length} compte(s) client restauré(s)`);
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
    sessionToken: makeToken(found.key),
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
    sessionToken: makeToken(found.key),
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
// Body : { adminToken, name, clientKey, email, phone, password (optionnel), role }
// ══════════════════════════════════════════
app.post('/api/admin/clients/create', (req, res) => {
  const { adminToken, name, clientKey, email, phone, password, role = 'client' } = req.body;
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  if (!name) return res.status(400).json({ success:false, error:'Le nom est requis.' });
  if (!email && !phone) return res.status(400).json({ success:false, error:'Renseigne au moins un email ou un numéro.' });
  if (phone && !validPhone(phone)) return res.status(400).json({ success:false, error:'Numéro invalide. Format : +225XXXXXXXXXX' });
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ success:false, error:'Email invalide.' });
  if (password && !validPw(password)) return res.status(400).json({ success:false, error:'Le mot de passe doit faire au moins 6 caractères.' });

  if (phone && USERS_BY_PHONE[phone]) return res.status(409).json({ success:false, error:'Ce numéro existe déjà.' });
  if (email && USERS_BY_EMAIL[email.toLowerCase()]) return res.status(409).json({ success:false, error:'Cet email existe déjà.' });

  const internalId = email ? email.toLowerCase() : `${phone.replace('+','')}@client.puremotion.ci`;
  const key = clientKey || (name.toLowerCase().replace(/[^a-z0-9]/g,'').slice(0,12) + Date.now().toString().slice(-4));

  USERS[internalId] = {
    role: role === 'collaborateur' ? 'collaborateur' : 'client',
    name,
    clientKey: key,
    email: email ? email.toLowerCase() : null,
    phone: phone || null,
    passwordHash: password ? hashPassword(password) : null,
    activated: !!password,
  };
  reindexAll();
  persistClients();

  log('INFO', 'Client créé', { name, activated: !!password });

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
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
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
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
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
  if (req.headers['x-admin-token'] !== ADMIN_TOKEN) {
    return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  }
  const clients = Object.values(USERS)
    .filter(u => u.role !== 'admin')
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
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  if (!clientKey) return res.status(400).json({ success:false, error:'clientKey requis.' });
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
  if (req.headers['x-admin-token'] !== ADMIN_TOKEN) {
    return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  }
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
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
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
  if (req.headers['x-admin-token'] !== ADMIN_TOKEN) {
    return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  }
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
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
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
  if (req.headers['x-admin-token'] !== ADMIN_TOKEN) {
    return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  }
  const contracts = Object.values(STORE.contracts || {});
  return res.json({ success:true, count: contracts.length, contracts });
});

// Admin résilie un contrat (avec motif)
// POST /api/admin/contracts/terminate
app.post('/api/admin/contracts/terminate', (req, res) => {
  const { adminToken, id, motif } = req.body;
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
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
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
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
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
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
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
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
  if (adminToken !== ADMIN_TOKEN) return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  if (!clientKey) return res.status(400).json({ success:false, error:'clientKey requis.' });
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
  if (req.headers['x-admin-token'] !== ADMIN_TOKEN) {
    return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  }
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
  if (req.headers['x-admin-token'] !== ADMIN_TOKEN) {
    return res.status(403).json({ success:false, error:'Accès non autorisé.' });
  }

  // Nom du client depuis sa clé
  const nameByKey = {};
  Object.values(USERS).forEach(u => { if (u.clientKey) nameByKey[u.clientKey] = u.name; });

  const proofs = [];
  let totalVues = 0, totalAbonnes = 0, clientsAvecStats = 0;

  Object.entries(STORE.stats || {}).forEach(([key, s]) => {
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

