# Congo Sec Vision Enterprise
**INFOTELCOM — Plateforme SOC de laboratoire**  
Version source : 0.5.1 (API 0.3.1 / Android 0.4.1)

API FastAPI, console web, agents Windows/Linux et application Android native Java.

> **État :** version de laboratoire. L'authentification repose sur un jeton administrateur partagé. MFA, SSO et RBAC effectif ne sont pas implémentés. Ne pas exposer l'API directement sur Internet.

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
4. Ouvrir `http://127.0.0.1:8081` et utiliser le jeton administrateur défini dans `.env`.

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
- Jeton administrateur partagé ; pas de MFA, SSO ni authentification individuelle/RBAC.
- Les rôles d'équipe sont informatifs.
- Les approbations n'exécutent aucune commande.
- Les correspondances NVD et constats de détection sont des signaux à valider, pas des preuves automatiques.
- Pas de notifications push mobiles dans cette version.
- Une revue de sécurité, des tests multi-OS/charge et un plan de reprise sont nécessaires avant production.

## Sécurité
Ne committer jamais `.env`, jetons, clés API, certificats privés, données réelles ou sauvegardes. N'enrôler que des systèmes dont l'administration est autorisée.
