# 🚀 Pure Motion Backend — Guide de déploiement

Backend sécurisé qui gère l'envoi et la vérification des codes OTP via **Twilio Verify**.

---

## 📋 Ce que fait ce backend

- Reçoit les demandes de connexion du frontend
- Vérifie le mot de passe de l'utilisateur
- Appelle **Twilio Verify** pour envoyer un code OTP sur l'email OU le téléphone (SMS / WhatsApp)
- Vérifie le code saisi par l'utilisateur
- Confirme la connexion si tout est valide

---

## ⚙️ Installation en local (test)

```bash
# 1. Installer les dépendances
npm install

# 2. Copier le fichier .env
cp .env.example .env

# 3. Remplir les vraies valeurs dans .env
# (voir section Configuration ci-dessous)

# 4. Démarrer
npm run dev    # développement avec rechargement auto
npm start      # production
```

---

## 🔑 Configuration — Récupérer tes clés Twilio

### Étape 1 : Account SID et Auth Token
1. Va sur **console.twilio.com**
2. Sur la page d'accueil → copie **Account SID** et **Auth Token**
3. Colle dans `.env`

### Étape 2 : Créer un Service Verify
1. Dans le menu gauche → **Verify** → **Services**
2. Clique **Create new Service**
3. Nom : `Pure Motion CI`
4. Active **SMS**, **Email**, **WhatsApp**
5. Copie le **Service SID** (format : `VA...`)
6. Colle dans `.env` → `TWILIO_VERIFY_SID`

### Étape 3 : Activer WhatsApp (optionnel)
1. Dans Twilio → **Messaging** → **Try it out** → **Send a WhatsApp message**
2. Suis les instructions pour activer le sandbox WhatsApp

---

## 🌐 Déploiement gratuit sur Render.com

C'est la solution recommandée — gratuit, simple, rapide.

### Étape 1 : Prépare le code
```bash
# Crée un repo GitHub
git init
git add .
git commit -m "Pure Motion backend v1"
git remote add origin https://github.com/TON_USERNAME/pure-motion-backend.git
git push -u origin main
```

### Étape 2 : Déploie sur Render
1. Va sur **render.com** → **New** → **Web Service**
2. Connecte ton repo GitHub
3. Paramètres :
   - **Name** : `pure-motion-api`
   - **Runtime** : `Node`
   - **Build Command** : `npm install`
   - **Start Command** : `npm start`
4. Dans **Environment Variables**, ajoute :
   - `TWILIO_ACCOUNT_SID` = ta valeur
   - `TWILIO_AUTH_TOKEN` = ta valeur
   - `TWILIO_VERIFY_SID` = ta valeur
   - `ADMIN_TOKEN` = ton token secret
   - `NODE_ENV` = `production`
   - `ALLOWED_ORIGIN` = l'URL de ton frontend
5. Clique **Create Web Service**

Ton API sera accessible sur : `https://pure-motion-api.onrender.com`

---

## 🔌 Connecter le frontend au backend

Dans le fichier `pure_motion_login.html`, remplace la section `CONFIG` :

```javascript
const BACKEND_URL = 'https://pure-motion-api.onrender.com';
```

Et dans les fonctions `sendEmailOTP()`, `sendPhoneOTP()`, `verifyOTP()` :

```javascript
// Au lieu de : twilioSendOTP() en simulation
const response = await fetch(`${BACKEND_URL}/api/auth/send-otp/email`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ email, password })
});
const data = await response.json();
```

---

## 📡 Routes API disponibles

| Méthode | Route | Description |
|---------|-------|-------------|
| `GET` | `/api/health` | Vérifier que le serveur tourne |
| `POST` | `/api/auth/send-otp/email` | Envoyer OTP par email |
| `POST` | `/api/auth/send-otp/phone` | Envoyer OTP par SMS/WhatsApp |
| `POST` | `/api/auth/verify-otp` | Vérifier le code saisi |
| `POST` | `/api/auth/resend-otp` | Renvoyer un nouveau code |
| `POST` | `/api/admin/users/create` | Créer un utilisateur (admin) |
| `GET` | `/api/admin/users` | Lister les utilisateurs (admin) |

---

## 🔒 Sécurité

- ✅ Rate limiting : 5 envois OTP par IP / 10 min
- ✅ Helmet : headers sécurisés
- ✅ CORS : origines contrôlées
- ✅ Masquage : emails et téléphones masqués dans les logs
- ✅ Mots de passe jamais loggés
- ✅ Variables sensibles en `.env` uniquement
- ⚠️ En production : hasher les mots de passe avec **bcrypt**
- ⚠️ En production : utiliser un vrai JWT avec expiration

---

## 🆘 Support

Pure Motion CI — puremotionci@gmail.com — +225 07-05-82-88-10
