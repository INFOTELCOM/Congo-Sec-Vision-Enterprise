# Congo Sec Vision Enterprise
**INFOTELCOM — Plateforme SOC de laboratoire**  
Version source : 0.5.1 (API 0.3.1 / Android 0.4.1)

API FastAPI, console web, agents Windows/Linux et application Android native Java.

> **État :** version de laboratoire. La console utilise Supabase Auth avec des comptes individuels et un contrôle d'accès API par rôles (`admin`, `analyst`, `incident_responder`, `viewer`). Le MFA et le SSO ne sont pas activés par défaut. Ne pas exposer l'API directement sur Internet.

## Arborescence
- `app/` : API FastAPI et interface web servie par l'API.
- `web/` : console statique publiée sur GitHub Pages.
- `android/` : application Android native Java.
- `desktop/` : application de bureau Tauri 2 (Windows, Linux, macOS).
- `agent/` : agent de collecte.
- `deploy/` : configurations HTTPS, cloud, AD et installation des agents.
- `tests/` : tests automatisés.
- `.github/workflows/` : tests, publication Pages, compilation APK et image Docker.

## Lancer le laboratoire
Prérequis : Docker Desktop (Windows) ou Docker Engine + Compose (Linux).

1. Copier `.env.example` vers `.env` et remplacer les deux jetons par des valeurs longues, uniques et différentes.
2. Lancer `docker compose up -d --build`.
3. Vérifier `http://127.0.0.1:8081/api/health`.
4. Ouvrir `http://127.0.0.1:8081` et se connecter avec un compte Supabase existant. Attribuer `csv_role: admin` au compte administrateur dans **Authentication → Users → App Metadata**. Voir [la configuration Supabase Auth et RBAC](docs/SUPABASE-AUTH-RBAC.md).

La publication locale est liée à `127.0.0.1` par défaut. Pour un laboratoire VMware, définir explicitement `SOC_BIND_IP` dans `.env` avec l'adresse de l'interface privée appropriée. Ne pas utiliser `0.0.0.0` sans filtrage réseau. Ne jamais exécuter `docker compose down -v` : cela supprime les données persistantes.

## Console web GitHub Pages
Dans **Settings → Pages**, choisir **GitHub Actions** comme source. Le workflow publie le dossier `web/`. Définir la variable Actions `API_BASE_URL` avec l'URL HTTPS publique de l'API (ex. `https://api.example.org`). Sans cette API, Pages peut afficher les fichiers statiques, mais les données SOC ne seront pas accessibles.

GitHub Pages n'héberge ni FastAPI, ni base de données, ni agents. Le workflow Pages doit être exécuté après activation de Pages.

## API cloud / VPS
Un déploiement cloud est décrit dans [deploy/cloud/README.md](deploy/cloud/README.md). Il exige un VPS Linux, un nom de domaine dont le DNS pointe vers ce VPS, les ports TCP 80/443 ouverts, Docker Compose et des secrets configurés dans le fichier `.env` du serveur. Le workflow Docker publie une image GHCR lors d'une publication de version (tag `v*`). La configuration cloud utilise cette image et Caddy pour TLS.

## Application Desktop
Le projet Tauri 2 et le workflow `.github/workflows/desktop.yml` préparent des installateurs Windows (MSI/EXE), Linux (DEB/AppImage, utilisables sur Ubuntu et Kali selon les dépendances système) et macOS (DMG). Lancer le workflow depuis **Actions → Build desktop applications**. Les fichiers sont publiés comme artefacts de build pendant 30 jours. Les premières compilations doivent être validées sur chaque OS ; les binaires ne sont pas encore signés pour distribution publique.

L'application nécessite les variables GitHub `SUPABASE_URL` et `SUPABASE_PUBLISHABLE_KEY`. Pour les fonctions SOC, `API_BASE_URL` doit pointer vers un backend FastAPI HTTPS opérationnel.

## Android APK
Le workflow **Build Android APK** compile un APK debug et le publie comme artifact GitHub Actions (conservation 30 jours). Lancer manuellement depuis **Actions → Build Android APK → Run workflow** ou modifier un fichier sous `android/`. Ce n'est pas un APK release signé. Une signature de production nécessite une clé privée stockée dans les secrets GitHub, jamais dans le dépôt.

## Tests locaux
```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

## Limites connues
- SQLite convient au laboratoire ; PostgreSQL, sauvegardes et migrations sont à prévoir pour une exploitation durable.
- Authentification individuelle via Supabase Auth et contrôle d'accès API par rôles ; MFA et SSO non activés par défaut.
- Les rôles de la table d'équipe restent un registre d'affichage ; les permissions effectives sont pilotées par `app_metadata.csv_role` dans Supabase.
- Les approbations n'exécutent aucune commande.
- Les correspondances NVD et constats de détection sont des signaux à valider, pas des preuves automatiques.
- Pas de notifications push mobiles dans cette version.
- Une revue de sécurité, des tests multi-OS/charge et un plan de reprise sont nécessaires avant production.

## Sécurité
Ne committer jamais `.env`, jetons, clés API, certificats privés, données réelles ou sauvegardes. N'enrôler que des systèmes dont l'administration est autorisée.


## Activer la surveillance réelle des endpoints

La console ne reçoit des métriques que lorsqu'un agent est lancé sur chaque machine autorisée. Le backend doit être en ligne et la variable serveur `AGENT_ENROLLMENT_TOKEN` doit correspondre au jeton fourni lors du premier enrôlement.

### Windows (PowerShell)

Depuis le dépôt cloné sur la machine à surveiller :

```powershell
py -m pip install -r agent/requirements.txt
$server = "https://congo-sec-vision-enterprise.onrender.com"
$enrollment = Read-Host "Jeton d'enrôlement configuré côté serveur"
py agent/agent.py --server $server --enrollment-token $enrollment --interval 60
```

Laisser le processus tourner. L'agent envoie un inventaire puis un heartbeat toutes les 60 secondes. Le jeton propre à l'agent est conservé dans `%PROGRAMDATA%\\CongoSecVision\\agent-token.json`, ce qui évite de créer un nouvel actif à chaque redémarrage. Exécuter PowerShell en administrateur pour une collecte plus complète des journaux système et logiciels.

### Linux (Debian/Ubuntu)

```bash
python3 -m pip install -r agent/requirements.txt
sudo install -d -m 700 /var/lib/congo-sec-vision
sudo python3 agent/agent.py --server https://congo-sec-vision-enterprise.onrender.com --enrollment-token "JETON_D_ENROLEMENT" --interval 60
```

Le jeton agent est conservé dans `/var/lib/congo-sec-vision/agent-token.json` avec des permissions restrictives. Pour une surveillance continue, exécuter l'agent comme service systemd après validation du premier lancement.

### Vérification

Après le premier heartbeat, ouvrir **Actifs & machines** puis **Vue générale** et cliquer sur **Actualiser**. La machine doit apparaître avec son hostname, son OS, ses adresses IP et ses métriques. Le statut « En ligne » dépend d'un heartbeat reçu dans les 3 dernières minutes. Les événements collectés apparaissent dans **Menaces & événements**. N'enrôler que des machines que vous êtes autorisé à administrer.


## Découverte réseau autorisée (première brique SOC)

L'API expose une découverte ICMP ponctuelle et authentifiée : `POST /api/network/discovery` avec `{"cidr":"192.168.50.0/24"}`. Seuls les réseaux privés sont acceptés et chaque scan est limité à 256 adresses. Les rôles `admin` et `analyst` peuvent lancer un scan ; les résultats sont consultables via `GET /api/network/discovery`. Cette fonction ne déploie aucun agent, ne contourne aucun pare-feu et ne transforme pas un hôte découvert en actif enrôlé. Les machines qui bloquent ICMP peuvent ne pas apparaître. Utiliser uniquement sur un réseau dont l'administration est autorisée.


## Surveillance automatique du réseau depuis les agents

Les agents d'extrémité détectent les interfaces IPv4 actives à chaque cycle de collecte et calculent eux-mêmes leurs sous-réseaux privés : aucun CIDR ni aucune adresse IP fixe ne doit être configuré. Lorsqu'un nouveau sous-réseau apparaît, l'agent lance une découverte ICMP bornée (maximum 256 adresses par sous-réseau) et transmet les hôtes joignables à l'API. Le scan est limité à une exécution par sous-réseau et par agent toutes les 10 minutes ; un changement de sous-réseau déclenche une découverte du nouveau réseau. Les observations sont consultables via `GET /api/network/discovery`.

**Limites de sécurité et de couverture :** seuls les hôtes répondant au ping sont détectés ; les réseaux privés plus grands que 256 adresses sont ignorés pour le moment. La découverte d'un équipement ne donne pas accès à son inventaire logiciel : l'analyse CVE détaillée d'un poste nécessite que l'agent y soit installé et enrôlé, ou qu'une méthode d'inventaire authentifiée et autorisée soit configurée pour cet équipement. Aucun agent n'est déployé à distance et aucune correction n'est appliquée automatiquement.
