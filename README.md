
<p align="center">
    <picture>
        <img src="/docs/assets/logo-label@600px.png" alt="OpenClaw">
    </picture>
</p>

# Servagent

Servagent est un serveur MCP (Model Context Protocol) permettant a une IA distante de prendre le controle total d'un serveur Linux : execution de commandes, gestion de fichiers, administration de services, etc.

## Transports

Le serveur expose deux transports MCP simultanement :

| Transport | Endpoint | Clients |
|---|---|---|
| **Streamable HTTP** | `/mcp` | Claude Desktop, Claude Code, LM Studio, clients modernes |
| **SSE** (legacy) | `/sse` + `/messages/` | Clients anciens |
| **File Upload** | `POST /upload` | Tout client HTTP (curl, scripts, etc.) |

## Fonctionnalites

| Outil | Description |
|---|---|
| `execute_command` | Executer n'importe quelle commande shell (bash, python, etc.) |
| `read_file` / `write_file` / `edit_file` | Lire, ecrire et modifier des fichiers |
| `read_file_binary` / `write_file_binary` | Transfert de fichiers binaires (base64) |
| `upload_file` | Copier un fichier d'un chemin a un autre sur le serveur distant |
| `list_directory` | Lister le contenu d'un repertoire |
| `move_path` / `copy_path` / `delete_path` | Deplacer, copier et supprimer fichiers/dossiers |
| `list_processes` / `kill_process` | Gestion des processus |
| `tail_file` | Tail/follow de fichiers de log ou journalctl (debug a distance) |
| `system_info` / `network_info` | Informations systeme et reseau |
| `service_action` | Gestion des services systemd (start/stop/restart/status) |
| `get_environment` | Variables d'environnement |

Chaque outil est annote avec des `ToolAnnotations` MCP (read-only, destructif, idempotent) pour guider les clients IA. Les instructions du serveur incluent des regles anti-boucle, de gestion d'erreurs et de workflow.

## Prerequis

- Linux (Ubuntu/Debian, RHEL/CentOS, etc.)
- Python >= 3.10
- Acces root pour l'installation en tant que service

## Installation one-liner

Installez directement depuis votre serveur avec une seule commande :

```bash
# Installation HTTP simple (par IP)
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash

# Installation HTTPS avec Let's Encrypt
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- votre-domaine.com

# Installation avec droits sudo complets + HTTPS
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- --full-access votre-domaine.com

# Installer une version specifique
curl -sSfL https://raw.githubusercontent.com/servagent/servagent/main/install-remote.sh | sudo bash -s -- --version v0.2.0
```

Le script telecharge automatiquement la derniere release (ou la branche `main` si aucune release n'existe), extrait l'archive et lance l'installation.

## Installation depuis un clone git

Si vous preferez cloner le depot manuellement :

```bash
# 1. Cloner le depot
git clone https://github.com/Servagent/servagent.git
cd servagent

# 2a. Installation HTTP simple (par IP)
sudo bash install.sh

# 2b. OU installation HTTPS directe avec Let's Encrypt
sudo bash install.sh votre-domaine.com

# 2c. OU installation avec droits sudo complets (sans question interactive)
sudo bash install.sh --full-access votre-domaine.com
```

Le script effectue automatiquement :
- Creation d'un utilisateur systeme `servagent`
- Installation dans `/opt/servagent` avec un virtualenv
- Generation d'une cle API (affichee une seule fois, **notez-la**)
- Creation et activation du service systemd
- **Si un domaine est fourni** : certificat Let's Encrypt, HTTPS sur port 443, renouvellement auto
- **Question interactive** pour accorder les droits sudo complets (ou `--full-access` pour automatiser)

```bash
# Verifier le statut
sudo systemctl status servagent

# Consulter les logs
sudo journalctl -u servagent -f
```

Le serveur demarre automatiquement a la fin de l'installation :
- Sans domaine : `http://<ip-serveur>:8765/mcp` (Streamable HTTP) ou `/sse` (SSE)
- Avec domaine : `https://votre-domaine.com/mcp` (Streamable HTTP) ou `/sse` (SSE)

## Installation manuelle (developpement)

```bash
# Creer un virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Installer le projet
pip install -e .

# Configurer
cp .env.example .env
# Editer .env pour definir SERVAGENT_API_KEY

# Lancer
servagent
```

## Desinstallation

Pour supprimer completement Servagent du serveur :

```bash
sudo bash uninstall.sh              # Interactif (confirmation requise)
sudo bash uninstall.sh -y           # Non-interactif (sans confirmation)
sudo bash uninstall.sh --keep-certs # Conserver les certificats Let's Encrypt
```

Le script supprime automatiquement :
- Le service systemd et le timer de renouvellement certbot
- La configuration Nginx (si applicable)
- Le fichier sudoers (`/etc/sudoers.d/servagent`)
- Le repertoire d'application (`/opt/servagent` : virtualenv, `.env`, sources)
- L'utilisateur systeme `servagent`
- Les certificats Let's Encrypt (sauf avec `--keep-certs`)

> **Note** : Les packages systeme (certbot, python3, nginx) ne sont pas supprimes car ils peuvent etre utilises par d'autres services.

## Mise a jour

Apres avoir clone le projet sur le serveur, utilisez le script de mise a jour :

```bash
sudo bash update.sh            # Met a jour depuis la branche courante
sudo bash update.sh develop    # Met a jour depuis une branche specifique
sudo bash update.sh --force    # Force la reinstallation meme si deja a jour
```

Le script effectue automatiquement :
1. `git pull` pour recuperer les derniers changements
2. Copie des sources vers `/opt/servagent/`
3. Reinstallation du package en mode editable (`pip install -e`) dans le virtualenv
4. Redemarrage du service
5. Verification que le service tourne correctement

Si aucun changement n'est detecte, le script s'arrete sans redemarrer le service. En cas de probleme, une commande de rollback est affichee en fin d'execution.

## Configuration

Toutes les options sont configurables via variables d'environnement ou fichier `.env` :

| Variable | Defaut | Description |
|---|---|---|
| `SERVAGENT_HOST` | `0.0.0.0` | Interface d'ecoute |
| `SERVAGENT_PORT` | `8765` | Port d'ecoute |
| `SERVAGENT_API_KEY` | _(vide)_ | Cle API (Bearer token). **Obligatoire en production.** |
| `SERVAGENT_WORK_DIR` | _(cwd)_ | Repertoire de travail par defaut |
| `SERVAGENT_COMMAND_TIMEOUT` | `300` | Timeout des commandes (secondes) |
| `SERVAGENT_MAX_OUTPUT_SIZE` | `1000000` | Taille max des sorties (octets) |
| `SERVAGENT_UPLOAD_MAX_SIZE` | `100000000` | Taille max des fichiers uploades (octets, 100 Mo) |
| `SERVAGENT_TLS_CERTFILE` | _(vide)_ | Chemin vers le certificat TLS (fullchain.pem) |
| `SERVAGENT_TLS_KEYFILE` | _(vide)_ | Chemin vers la cle privee TLS (privkey.pem) |
| `SERVAGENT_TOOLS` | `execute_command,upload_file` | Outils a exposer (liste separee par des virgules, ou `all`) |
| `SERVAGENT_LOG_LEVEL` | `INFO` | Niveau de log |
| `SERVAGENT_OAUTH_ISSUER_URL` | _(vide)_ | URL OAuth issuer (inclure `/mcp`). Active OAuth si defini. |
| `SERVAGENT_OAUTH_CLIENT_ID` | _(vide)_ | Client ID operateur : client OAuth statique + protection de `/mcp/register` |
| `SERVAGENT_OAUTH_CLIENT_SECRET` | _(vide)_ | Client Secret associe (les deux doivent etre definis ensemble) |
| `SERVAGENT_OAUTH_DB_PATH` | `~/.servagent/oauth.db` | Chemin de la base SQLite OAuth |

## HTTPS avec Let's Encrypt

Le TLS est integre directement dans `install.sh`. Il suffit de passer le domaine en argument (voir Installation rapide).

**Prerequis** : le domaine doit pointer vers l'IP du serveur et le port 80 doit etre ouvert pour le challenge HTTP-01 de Let's Encrypt.

Pour activer HTTPS sur un serveur deja installe en HTTP :

```bash
sudo bash setup-tls.sh votre-domaine.com
```

### Alternative : Nginx reverse proxy

Si vous preferez passer par Nginx (utile si d'autres services web tournent sur le meme serveur) :

```bash
# 1. Installer Nginx et Certbot
sudo apt install nginx certbot python3-certbot-nginx

# 2. Obtenir un certificat Let's Encrypt
sudo certbot --nginx -d votre-domaine.com

# 3. Copier la configuration nginx
sudo cp nginx.conf.example /etc/nginx/sites-available/servagent
# Editer le fichier pour remplacer 'your-domain.com' par votre domaine

# 4. Activer et recharger
sudo ln -s /etc/nginx/sites-available/servagent /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

L'endpoint MCP sera alors accessible en HTTPS : `https://votre-domaine.com/mcp`

> **Note** : Derriere un reverse proxy, configurez `SERVAGENT_HOST=127.0.0.1` pour que le serveur desactive automatiquement la protection DNS-rebinding du SDK MCP (Nginx gere deja la validation du header Host).

## Connexion depuis un client MCP

### Streamable HTTP (Claude Desktop, Claude Code, LM Studio)

```json
{
  "mcpServers": {
    "servagent": {
      "type": "streamable-http",
      "url": "https://votre-domaine.com/mcp",
      "headers": {
        "Authorization": "Bearer VOTRE_CLE_API"
      }
    }
  }
}
```

### SSE (clients legacy)

```json
{
  "mcpServers": {
    "servagent": {
      "type": "sse",
      "url": "https://votre-domaine.com/sse",
      "headers": {
        "Authorization": "Bearer VOTRE_CLE_API"
      }
    }
  }
}
```

### Test avec curl

```bash
# Health check (le endpoint MCP repond aux requetes POST)
curl -X POST https://votre-domaine.com/mcp \
  -H "Authorization: Bearer VOTRE_CLE_API" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
```

### Upload de fichiers

L'endpoint `POST /upload` permet d'envoyer des fichiers vers le serveur distant via `multipart/form-data`. Il est protege par le meme Bearer token que les endpoints MCP.

```bash
# Envoyer un fichier vers le serveur
curl -X POST https://votre-domaine.com/upload \
  -H "Authorization: Bearer VOTRE_CLE_API" \
  -F "file=@mon-fichier.tar.gz" \
  -F "path=/opt/app/mon-fichier.tar.gz" \
  -F "create_dirs=true"
```

Champs du formulaire :
- `file` (requis) : le fichier a envoyer
- `path` (requis) : chemin de destination sur le serveur distant
- `create_dirs` (optionnel, defaut `true`) : creer les repertoires parents si necessaire

La taille maximale est configurable via `SERVAGENT_UPLOAD_MAX_SIZE` (defaut : 100 Mo).

## Authentification

Le serveur supporte deux mecanismes d'authentification qui coexistent :

| Mecanisme | Protege | Configuration |
|---|---|---|
| **Bearer token** (`API_KEY`) | `/mcp`, `/sse`, `/messages/`, `/upload` | `SERVAGENT_API_KEY` |
| **OAuth 2.0** | `/mcp` (via access token), `/mcp/register` (via Basic Auth) | `SERVAGENT_OAUTH_*` |

Les deux mecanismes fonctionnent en parallele. Le Bearer token donne un acces direct a tous les endpoints. OAuth permet un flux d'enregistrement et d'autorisation standard.

Les endpoints `/.well-known/` (decouverte OAuth, RFC 8414 / RFC 9728) sont toujours accessibles sans authentification.

## OAuth 2.0 (Streamable HTTP)

En plus de l'authentification par Bearer token simple, le serveur supporte OAuth 2.0 pour le endpoint `/mcp`. Cela permet aux applications MCP compatibles de se connecter via le protocole standard OAuth (authorization code + PKCE, RFC 7636).

### Activer OAuth

```bash
# 1. Generer les credentials operateur
bash generate-oauth-credentials.sh              # Afficher les credentials
bash generate-oauth-credentials.sh --write      # Ecrire directement dans .env
```

```bash
# Dans .env — l'URL DOIT inclure le chemin /mcp
SERVAGENT_OAUTH_ISSUER_URL=https://votre-domaine.com/mcp

# Credentials operateur (double usage : client OAuth statique + protection de /mcp/register)
SERVAGENT_OAUTH_CLIENT_ID=servagent-xxxxxxxxxxxxxxxx
SERVAGENT_OAUTH_CLIENT_SECRET=un-secret-fort-genere-aleatoirement
```

Quand OAuth est active :
- **`/mcp`** est protege par OAuth (le SDK MCP gere les tokens) **ou** par le Bearer token (`API_KEY`)
- **`/mcp/register`** est protege par HTTP Basic Auth avec `CLIENT_ID:CLIENT_SECRET`
- **`/sse`**, **`/messages/`**, **`/upload`** restent proteges par le Bearer token simple (`API_KEY`)
- **`/.well-known/`** est toujours accessible sans authentification (decouverte OAuth)

### Matrice d'authentification

| Endpoint | Bearer API_KEY | OAuth access_token | Basic CLIENT_ID:SECRET |
|---|---|---|---|
| `/.well-known/*` | - | - | - (public) |
| `/mcp` | oui | oui | - |
| `/mcp/register` | - | - | **requis** |
| `/sse` | oui | - | - |
| `/messages/` | oui | - | - |
| `/upload` | oui | - | - |

### Double usage du CLIENT_ID / CLIENT_SECRET

Les credentials operateur (`CLIENT_ID` / `CLIENT_SECRET`) servent a deux choses :

1. **Client OAuth statique** : Au demarrage, le serveur pre-enregistre ces credentials comme un client OAuth valide dans la base SQLite (via `ensure_static_client()`). Cela permet aux interfaces comme Claude.ai et ChatGPT d'utiliser le CLIENT_ID/SECRET directement dans le flux OAuth (authorize → token) **sans appeler `/mcp/register`**. Les redirect URIs des plateformes connues (Claude.ai, ChatGPT) sont pre-configurees automatiquement.

2. **Protection de `/mcp/register`** : Les memes credentials protegent l'endpoint d'enregistrement dynamique via HTTP Basic Auth. Les clients programmatiques (scripts, SDK) peuvent s'enregistrer pour obtenir leur propre `client_id`/`client_secret`.

Les deux modes coexistent : le client statique fonctionne pour les UIs (Claude.ai, ChatGPT, etc.), et l'enregistrement dynamique fonctionne pour les scripts et SDK.

### Connexion depuis Claude.ai

1. Sur Claude.ai, aller dans **Parametres** → **Connecteurs** → **Ajouter un connecteur personnalise**
2. Remplir les champs :
   - **Nom** : `servagent` (ou le nom de votre choix)
   - **URL du serveur MCP distant** : `https://votre-domaine.com/mcp`
   - **ID client OAuth** : la valeur de `SERVAGENT_OAUTH_CLIENT_ID`
   - **Secret client OAuth** : la valeur de `SERVAGENT_OAUTH_CLIENT_SECRET`
3. Valider — Claude.ai effectue automatiquement le flux OAuth (decouverte → autorisation → token)

### Connexion depuis ChatGPT

1. Sur ChatGPT, aller dans **Parametres** → **Connecteurs** → **Ajouter un connecteur personnalise**
2. Remplir les champs :
   - **Nom** : `servagent`
   - **URL du serveur MCP** : `https://votre-domaine.com/mcp`
   - **Client ID** : la valeur de `SERVAGENT_OAUTH_CLIENT_ID`
   - **Client Secret** : la valeur de `SERVAGENT_OAUTH_CLIENT_SECRET`
3. Valider — ChatGPT effectue le flux OAuth avec sa redirect URI (`https://chatgpt.com/connector_platform_oauth_redirect`)

### Endpoints OAuth (sous `/mcp`)

| Endpoint | Description |
|---|---|
| `/.well-known/oauth-authorization-server` | Metadata OAuth (RFC 8414) |
| `/.well-known/oauth-protected-resource` | Metadata ressource protegee (RFC 9728) |
| `/authorize` | Endpoint d'autorisation |
| `/token` | Echange de code/refresh token |
| `/register` | Enregistrement dynamique de clients (RFC 7591) |
| `/revoke` | Revocation de tokens (RFC 7009) |

> **Note** : Les URLs de decouverte `/.well-known/` sont accessibles a la fois au niveau racine du domaine et sous `/mcp`. Des redirections 307 au niveau racine redirigent vers le sous-app `/mcp` pour assurer la compatibilite avec tous les clients MCP.

### Flux OAuth (enregistrement dynamique)

Pour les clients programmatiques qui passent par l'enregistrement dynamique :

```bash
# 1. Enregistrer un client (HTTP Basic Auth avec CLIENT_ID:CLIENT_SECRET)
curl -X POST https://votre-domaine.com/mcp/register \
  -u "MON_CLIENT_ID:MON_CLIENT_SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:3000/callback"],
    "client_name": "Mon App",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "client_secret_post"
  }'
# → retourne client_id + client_secret dynamiques
```

Ensuite le flux OAuth standard se deroule normalement :

1. Le client decouvre les endpoints via `GET /.well-known/oauth-authorization-server/mcp` (ou `/mcp/.well-known/oauth-authorization-server`)
2. Le client obtient un authorization code via `/mcp/authorize` (avec PKCE)
3. Le client echange le code contre un access token via `POST /mcp/token`
4. Le client utilise l'access token pour appeler `/mcp`

Le serveur utilise un modele d'auto-approbation : tout client enregistre (statique ou dynamique) est considere comme autorise.

Les access tokens expirent apres 1 heure. Les refresh tokens durent 30 jours avec rotation automatique.

### Stockage

Les clients et tokens OAuth sont persistes dans une base SQLite (defaut : `~/.servagent/oauth.db`). Les donnees survivent aux redemarrages du serveur. Le client statique est re-enregistre (upsert) a chaque demarrage.

## Skills

Les skills permettent d'enrichir le contexte envoye au LLM avec des informations specifiques a votre serveur : domaines heberges, credentials SMTP, services disponibles, etc. Chaque skill est un repertoire contenant un fichier `SKILL.md` dont le contenu est injecte dans les instructions MCP.

Le repertoire `skills/` se trouve a la racine du projet (en dev) ou dans `/opt/servagent/skills/` (en production). Son contenu est ignore par git (`.gitignore`) car il peut contenir des informations sensibles propres a chaque serveur.

### Structure

```
skills/
├── .gitkeep
├── webserver/
│   └── SKILL.md
├── smtp/
│   └── SKILL.md
└── docker/
    └── SKILL.md
```

### Exemple : `skills/webserver/SKILL.md`

```markdown
# webserver
Domain: monserveur.fr (points to this server)
Web root: /var/www/monserveur.fr
Nginx config: /etc/nginx/sites-available/monserveur.fr
SSL: Let's Encrypt, auto-renew via certbot timer
```

### Exemple : `skills/smtp/SKILL.md`

```markdown
# smtp
This server can send emails via SMTP.
- Host: smtp.gmail.com
- Port: 587
- User: bot@monserveur.fr
- Password: xxxx-xxxx-xxxx
- Use: `msmtp` or `swaks` CLI (already installed)
```

Le contenu de chaque `SKILL.md` est injecte tel quel dans les instructions MCP sous une section `## Skills`. Si le fichier commence par un heading markdown (`#`), il est utilise tel quel. Sinon, un heading `### nom_du_dossier` est ajoute automatiquement.

## Securite

> **AVERTISSEMENT** : Ce serveur donne un controle total sur la machine hote. Securisez-le correctement.

- **Toujours** definir `SERVAGENT_API_KEY` en production
- **Toujours** utiliser TLS (`setup-tls.sh` ou Nginx) en production
- Restreindre l'acces au port via firewall (`ufw`, `iptables`)
- Le service tourne sous un utilisateur dedie (`servagent`)
- Par defaut, l'utilisateur n'a **pas** de droits sudo (`NoNewPrivileges=true`)
- L'option `--full-access` (ou la question interactive) accorde `sudo NOPASSWD: ALL` via `/etc/sudoers.d/servagent` et desactive `NoNewPrivileges`

## Structure du projet

```
servagent/
  src/servagent/
    __init__.py        # Version
    config.py          # Configuration (pydantic-settings)
    auth.py            # Middleware d'authentification (Bearer + Basic Auth + OAuth)
    oauth_provider.py  # Provider OAuth 2.0 avec stockage SQLite + client statique
    tools.py           # Tous les outils MCP
    server.py          # Point d'entree, app Starlette + MCP (Streamable HTTP + SSE + .well-known)
  skills/              # Repertoire de skills (contenu en .gitignore)
    .gitkeep
  pyproject.toml                  # Metadata et dependances
  install.sh                      # Script d'installation Linux (depuis un clone git)
  install-remote.sh               # Script d'installation one-liner (curl | bash)
  uninstall.sh                    # Script de desinstallation complete
  setup-tls.sh                    # Setup HTTPS avec Let's Encrypt
  generate-oauth-credentials.sh   # Generateur de CLIENT_ID / CLIENT_SECRET
  nginx.conf.example              # Configuration Nginx (optionnel)
  .env.example                    # Template de configuration
```

## Licence

MIT
