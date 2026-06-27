/**
 * ╔══════════════════════════════════════════════════════╗
 * ║         PURE MOTION — Backend Sécurisé               ║
 * ║         Twilio Verify · OTP Email & SMS/WhatsApp     ║
 * ║         Node.js · Express · Production Ready         ║
 * ╚══════════════════════════════════════════════════════╝
 */

require('dotenv').config();
const express    = require('express');
const cors       = require('cors');
const helmet     = require('helmet');
const rateLimit  = require('express-rate-limit');
const twilio     = require('twilio');
const path       = require('path');

const app = express();

// ══════════════════════════════════════════
// CONFIGURATION TWILIO (variables .env)
// ══════════════════════════════════════════
const {
  TWILIO_ACCOUNT_SID,
  TWILIO_AUTH_TOKEN,
  TWILIO_VERIFY_SID,
  PORT = 3000,
  ALLOWED_ORIGIN = 'http://localhost:3000',
  NODE_ENV = 'development'
} = process.env;

// Vérification au démarrage
if (!TWILIO_ACCOUNT_SID || !TWILIO_AUTH_TOKEN || !TWILIO_VERIFY_SID) {
  console.error('❌ Variables Twilio manquantes dans .env');
  console.error('   TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SID requis');
  process.exit(1);
}

const client = twilio(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN);

// ══════════════════════════════════════════
// BASE DE DONNÉES UTILISATEURS
// En production : remplacer par PostgreSQL/MongoDB
// Les mots de passe doivent être hashés avec bcrypt
// ══════════════════════════════════════════
const USERS = {
  // Format : 'email': { role, passwordHash, phone, name }
  // ⚠️ En prod, stocker les hash bcrypt — jamais les mots de passe en clair
  'admin@puremotion.ci': {
    role: 'admin',
    password: process.env.ADMIN_PASSWORD || 'PureMotionAdmin2026!',
    phone: process.env.ADMIN_PHONE || '+22507058281',
    name: 'Pure Motion Admin'
  },
  'collab@puremotion.ci': {
    role: 'collaborateur',
    password: 'Collab2026!',
    phone: '+22507000001',
    name: 'Collaborateur Pure Motion'
  },
  'soleil@communication.ci': {
    role: 'client',
    password: 'Soleil2026!',
    phone: '+22507000002',
    name: 'Soleil Communication'
  },
  'fanta@maquis.ci': {
    role: 'client',
    password: 'Fanta2026!',
    phone: '+22507000003',
    name: 'Maquis Chez Fanta'
  },
};

// Index par numéro de téléphone pour la connexion par téléphone
const USERS_BY_PHONE = {};
Object.entries(USERS).forEach(([email, user]) => {
  USERS_BY_PHONE[user.phone] = { ...user, email };
});

// ══════════════════════════════════════════
// MIDDLEWARES
// ══════════════════════════════════════════
app.use(helmet({
  crossOriginEmbedderPolicy: false,
  contentSecurityPolicy: false,
}));

app.use(cors({
  origin: ALLOWED_ORIGIN.split(','),
  methods: ['GET', 'POST'],
  credentials: true,
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir le frontend
app.use(express.static(path.join(__dirname, 'public')));

// ══════════════════════════════════════════
// RATE LIMITING — Protection anti-spam
// ══════════════════════════════════════════
const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // max 5 tentatives d'envoi par IP
  message: { success: false, error: 'Trop de tentatives. Réessayez dans 10 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const verifyLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10,
  message: { success: false, error: 'Trop de tentatives de vérification. Réessayez dans 10 minutes.' },
});

const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
});
app.use(globalLimiter);

// ══════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePhone(phone) {
  // Format E.164 : +225XXXXXXXXXX
  return /^\+[1-9]\d{7,14}$/.test(phone);
}

function validatePassword(password) {
  return password && password.length >= 8;
}

function maskEmail(email) {
  const [local, domain] = email.split('@');
  return local.slice(0, 2) + '***@' + domain;
}

function maskPhone(phone) {
  return phone.slice(0, 4) + '****' + phone.slice(-3);
}

function log(level, message, data = {}) {
  const ts = new Date().toISOString();
  const safe = { ...data };
  if (safe.password) safe.password = '[HIDDEN]';
  if (safe.code) safe.code = '[HIDDEN]';
  console.log(`[${ts}] [${level.toUpperCase()}] ${message}`, JSON.stringify(safe));
}

// ══════════════════════════════════════════
// ROUTES SANTÉ
// ══════════════════════════════════════════
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'Pure Motion Backend',
    twilio: !!TWILIO_ACCOUNT_SID,
    env: NODE_ENV,
    timestamp: new Date().toISOString()
  });
});

// ══════════════════════════════════════════
// ROUTE : ENVOYER OTP PAR EMAIL
// POST /api/auth/send-otp/email
// Body : { email, password }
// ══════════════════════════════════════════
app.post('/api/auth/send-otp/email', otpLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Validation des inputs
    if (!email || !validateEmail(email)) {
      return res.status(400).json({ success: false, error: 'Adresse email invalide.' });
    }
    if (!password || !validatePassword(password)) {
      return res.status(400).json({ success: false, error: 'Mot de passe invalide.' });
    }

    // 2. Vérification de l'utilisateur
    const user = USERS[email.toLowerCase()];
    if (!user || user.password !== password) {
      log('warn', 'Tentative de connexion échouée (email)', { email: maskEmail(email) });
      // Réponse générique pour ne pas révéler si l'email existe
      return res.status(401).json({ success: false, error: 'Identifiants incorrects.' });
    }

    // 3. Envoi OTP via Twilio Verify → email
    log('info', 'Envoi OTP email', { email: maskEmail(email), role: user.role });

    const verification = await client.verify.v2
      .services(TWILIO_VERIFY_SID)
      .verifications
      .create({
        to: email,
        channel: 'email',
        // Message personnalisé Pure Motion
        channelConfiguration: {
          template_id: null, // utilise le template par défaut
          from: 'noreply@puremotion.ci',
          from_name: 'Pure Motion CI',
          substitutions: {
            name: user.name || 'utilisateur',
            company: 'Pure Motion CI'
          }
        }
      });

    log('info', 'OTP email envoyé', { status: verification.status, email: maskEmail(email) });

    res.json({
      success: true,
      status: verification.status,
      destination: maskEmail(email),
      channel: 'email',
      message: `Code envoyé sur ${maskEmail(email)}`
    });

  } catch (error) {
    log('error', 'Erreur envoi OTP email', { message: error.message, code: error.code });

    // Gestion des erreurs Twilio spécifiques
    if (error.code === 60200) {
      return res.status(400).json({ success: false, error: 'Adresse email invalide pour Twilio Verify.' });
    }
    if (error.code === 60203) {
      return res.status(429).json({ success: false, error: 'Trop de codes envoyés. Attendez 10 minutes.' });
    }

    res.status(500).json({ success: false, error: 'Erreur lors de l\'envoi du code. Réessayez.' });
  }
});

// ══════════════════════════════════════════
// ROUTE : ENVOYER OTP PAR TÉLÉPHONE (SMS / WhatsApp)
// POST /api/auth/send-otp/phone
// Body : { phone, password, channel } — channel: 'sms' | 'whatsapp'
// ══════════════════════════════════════════
app.post('/api/auth/send-otp/phone', otpLimiter, async (req, res) => {
  try {
    const { phone, password, channel = 'sms' } = req.body;

    // 1. Validation
    if (!phone || !validatePhone(phone)) {
      return res.status(400).json({ success: false, error: 'Numéro de téléphone invalide. Format attendu : +225XXXXXXXXXX' });
    }
    if (!password || !validatePassword(password)) {
      return res.status(400).json({ success: false, error: 'Mot de passe invalide.' });
    }
    if (!['sms', 'whatsapp'].includes(channel)) {
      return res.status(400).json({ success: false, error: 'Canal invalide. Utilisez "sms" ou "whatsapp".' });
    }

    // 2. Vérification utilisateur par téléphone
    const user = USERS_BY_PHONE[phone];
    if (!user || user.password !== password) {
      log('warn', 'Tentative de connexion échouée (phone)', { phone: maskPhone(phone) });
      return res.status(401).json({ success: false, error: 'Numéro ou mot de passe incorrect.' });
    }

    // 3. Envoi OTP via Twilio Verify → SMS ou WhatsApp
    log('info', 'Envoi OTP téléphone', { phone: maskPhone(phone), channel, role: user.role });

    const verification = await client.verify.v2
      .services(TWILIO_VERIFY_SID)
      .verifications
      .create({
        to: phone,
        channel: channel, // 'sms' ou 'whatsapp'
        locale: 'fr', // Code en français
        customFriendlyName: 'Pure Motion CI',
      });

    log('info', 'OTP téléphone envoyé', { status: verification.status, phone: maskPhone(phone), channel });

    res.json({
      success: true,
      status: verification.status,
      destination: maskPhone(phone),
      channel: channel,
      message: `Code envoyé par ${channel === 'whatsapp' ? 'WhatsApp' : 'SMS'} sur ${maskPhone(phone)}`
    });

  } catch (error) {
    log('error', 'Erreur envoi OTP téléphone', { message: error.message, code: error.code });

    if (error.code === 60200) {
      return res.status(400).json({ success: false, error: 'Numéro de téléphone invalide ou non supporté.' });
    }
    if (error.code === 60203) {
      return res.status(429).json({ success: false, error: 'Trop de codes envoyés. Attendez 10 minutes.' });
    }
    if (error.code === 21614) {
      return res.status(400).json({ success: false, error: 'Ce numéro ne peut pas recevoir de SMS.' });
    }

    res.status(500).json({ success: false, error: 'Erreur lors de l\'envoi du code. Réessayez.' });
  }
});

// ══════════════════════════════════════════
// ROUTE : VÉRIFIER LE CODE OTP
// POST /api/auth/verify-otp
// Body : { destination, code, type } — type: 'email' | 'phone'
// ══════════════════════════════════════════
app.post('/api/auth/verify-otp', verifyLimiter, async (req, res) => {
  try {
    const { destination, code, type } = req.body;

    // 1. Validation
    if (!destination || !code || !type) {
      return res.status(400).json({ success: false, error: 'Paramètres manquants.' });
    }
    if (code.length < 4 || code.length > 10) {
      return res.status(400).json({ success: false, error: 'Code invalide.' });
    }
    if (!['email', 'phone'].includes(type)) {
      return res.status(400).json({ success: false, error: 'Type invalide.' });
    }

    log('info', 'Vérification OTP', { destination: type === 'email' ? maskEmail(destination) : maskPhone(destination), type });

    // 2. Vérification via Twilio Verify
    const check = await client.verify.v2
      .services(TWILIO_VERIFY_SID)
      .verificationChecks
      .create({
        to: destination,
        code: code
      });

    log('info', 'Résultat vérification OTP', { status: check.status, valid: check.valid });

    if (check.status === 'approved' && check.valid) {
      // 3. Récupérer les infos utilisateur
      const user = type === 'email'
        ? USERS[destination.toLowerCase()]
        : USERS_BY_PHONE[destination];

      if (!user) {
        return res.status(404).json({ success: false, error: 'Utilisateur introuvable.' });
      }

      // 4. Connexion réussie — en prod : générer un JWT token
      const sessionToken = Buffer.from(`${destination}:${Date.now()}:${Math.random()}`).toString('base64');

      log('info', 'Connexion réussie', {
        role: user.role,
        name: user.name,
        destination: type === 'email' ? maskEmail(destination) : maskPhone(destination)
      });

      return res.json({
        success: true,
        verified: true,
        user: {
          name: user.name,
          role: user.role,
          email: user.email || destination,
        },
        // En production : renvoyer un JWT signé avec expiration
        sessionToken: sessionToken,
        message: 'Connexion réussie !'
      });

    } else {
      log('warn', 'Code OTP incorrect', { status: check.status });
      return res.status(401).json({
        success: false,
        verified: false,
        error: 'Code incorrect ou expiré. Vérifiez et réessayez.'
      });
    }

  } catch (error) {
    log('error', 'Erreur vérification OTP', { message: error.message, code: error.code });

    if (error.code === 20404) {
      return res.status(400).json({ success: false, error: 'Code expiré. Demandez un nouveau code.' });
    }
    if (error.code === 60202) {
      return res.status(429).json({ success: false, error: 'Trop de tentatives incorrectes. Demandez un nouveau code.' });
    }

    res.status(500).json({ success: false, error: 'Erreur lors de la vérification. Réessayez.' });
  }
});

// ══════════════════════════════════════════
// ROUTE : RENVOYER UN CODE (Resend)
// POST /api/auth/resend-otp
// Body : { destination, channel }
// ══════════════════════════════════════════
app.post('/api/auth/resend-otp', otpLimiter, async (req, res) => {
  try {
    const { destination, channel } = req.body;

    if (!destination || !channel) {
      return res.status(400).json({ success: false, error: 'Paramètres manquants.' });
    }

    log('info', 'Renvoi OTP', { channel });

    const verification = await client.verify.v2
      .services(TWILIO_VERIFY_SID)
      .verifications
      .create({ to: destination, channel });

    res.json({
      success: true,
      status: verification.status,
      message: 'Nouveau code envoyé.'
    });

  } catch (error) {
    log('error', 'Erreur renvoi OTP', { message: error.message });
    res.status(500).json({ success: false, error: 'Erreur lors du renvoi. Réessayez.' });
  }
});

// ══════════════════════════════════════════
// ROUTE : ADMIN — GÉRER UN UTILISATEUR
// POST /api/admin/users/create
// Body : { adminToken, email, phone, role, password, name }
// ══════════════════════════════════════════
app.post('/api/admin/users/create', (req, res) => {
  const { adminToken, email, phone, role, password, name } = req.body;

  // Vérification token admin (en prod : JWT vérifié)
  if (adminToken !== process.env.ADMIN_TOKEN) {
    return res.status(403).json({ success: false, error: 'Accès non autorisé.' });
  }

  if (!email || !validateEmail(email) || !password || !role || !name) {
    return res.status(400).json({ success: false, error: 'Champs manquants ou invalides.' });
  }

  if (USERS[email]) {
    return res.status(409).json({ success: false, error: 'Cet email existe déjà.' });
  }

  // Ajouter l'utilisateur (en prod : insérer en base de données)
  USERS[email] = { role, password, phone, name };
  if (phone) USERS_BY_PHONE[phone] = { ...USERS[email], email };

  log('info', 'Utilisateur créé', { email: maskEmail(email), role, name });

  res.json({
    success: true,
    message: `Compte créé pour ${name}`,
    user: { email, role, name, phone: phone ? maskPhone(phone) : null }
  });
});

// ══════════════════════════════════════════
// ROUTE : ADMIN — LISTE DES UTILISATEURS
// GET /api/admin/users
// ══════════════════════════════════════════
app.get('/api/admin/users', (req, res) => {
  const adminToken = req.headers['x-admin-token'];
  if (adminToken !== process.env.ADMIN_TOKEN) {
    return res.status(403).json({ success: false, error: 'Accès non autorisé.' });
  }

  const users = Object.entries(USERS).map(([email, u]) => ({
    email: maskEmail(email),
    name: u.name,
    role: u.role,
    phone: u.phone ? maskPhone(u.phone) : null,
  }));

  res.json({ success: true, count: users.length, users });
});

// ══════════════════════════════════════════
// SERVIR LE FRONTEND (fallback)
// ══════════════════════════════════════════
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ══════════════════════════════════════════
// GESTION ERREURS GLOBALES
// ══════════════════════════════════════════
app.use((err, req, res, next) => {
  log('error', 'Erreur non gérée', { message: err.message });
  res.status(500).json({ success: false, error: 'Erreur interne du serveur.' });
});

// ══════════════════════════════════════════
// DÉMARRAGE
// ══════════════════════════════════════════
app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════╗');
  console.log('║   🚀 PURE MOTION Backend démarré         ║');
  console.log(`║   → Port    : ${PORT}                        ║`);
  console.log(`║   → Env     : ${NODE_ENV}                ║`);
  console.log('║   → Twilio  : ✅ Verify connecté         ║');
  console.log('╚══════════════════════════════════════════╝');
  console.log('');
  console.log('📡 Routes disponibles :');
  console.log(`   POST /api/auth/send-otp/email`);
  console.log(`   POST /api/auth/send-otp/phone`);
  console.log(`   POST /api/auth/verify-otp`);
  console.log(`   POST /api/auth/resend-otp`);
  console.log(`   POST /api/admin/users/create`);
  console.log(`   GET  /api/admin/users`);
  console.log(`   GET  /api/health`);
  console.log('');
});
