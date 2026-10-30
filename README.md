# Congo Sec Vision Enterprise
**INFOTELCOM — Plateforme SOC de laboratoire**  
Version source : 0.5.0 (API 0.3.1 / Android 0.4.1)

Congo Sec Vision Enterprise regroupe une API FastAPI, une console web, des agents Windows/Linux et une application Android native Java.

> **État du projet :** version de laboratoire. Ne pas exposer l’API directement sur Internet. L'authentification actuelle repose encore sur un jeton administrateur partagé ; MFA, SSO et RBAC effectif ne sont pas implémentés.

## Dépôt
- `app/` : API FastAPI et interface servie par l'API.
- `web/` : console web statique destinée à GitHub Pages.
- `android/` : projet Android natif Java.
- `agent/` : agent de collecte Windows/Linux.
- `deploy/` : configurations laboratoire, cloud, HTTPS et déploiement des agents.
- `tests/` : tests automatisés API.

## Lancer le laboratoire (Docker)
1. Installer Docker Desktop (Windows) ou Docker Engine + Compose (Linux).
2. Copier `.env.example` vers `.env` si le fichier modèle existe dans la livraison ; définir des secrets uniques et conserver `.env` hors Git.
3. Depuis la racine, lancer `docker compose up -d --build`.
4. Consulter les journaux avec `docker compose logs -f`.
5. Vérifier `/api/health` sur l'adresse locale configurée.

Ne pas utiliser `docker compose down -v` : cela supprimerait les volumes persistants.

## Console web GitHub Pages
Le workflow **Deploy web to GitHub Pages** publie le contenu du dossier `web/`. Dans GitHub, ouvrir **Settings → Pages → Build and deployment**, puis sélectionner **GitHub Actions** comme source. La console statique nécessite une API accessible en HTTPS. Définir la variable de dépôt `API_BASE_URL` (Settings → Secrets and variables → Actions → Variables) avec l'URL HTTPS publique de l'API. Sans API configurée, l'interface ne peut pas interroger le SOC.

GitHub Pages héberge uniquement les fichiers statiques : il n'héberge ni FastAPI, ni base de données, ni agents.

## APK Android
Le workflow **Build Android APK** compile l'application avec JDK 17 et Android SDK. Le fichier APK de débogage est publié comme artifact GitHub Actions après compilation. La génération d'un APK release signé nécessite une clé de signature privée ; ne jamais committer cette clé ou ses mots de passe.

## Tests
```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

## Limites connues
- SQLite : laboratoire ; prévoir PostgreSQL, sauvegardes et migrations pour une exploitation durable.
- Jeton administrateur partagé : pas de MFA, SSO ni comptes individuels/RBAC complet.
- Les rôles d'équipe sont informatifs.
- Les approbations de workflow n'exécutent aucune commande.
- Les alertes/vulnérabilités sont des signaux à valider, pas des verdicts automatiques.
- Les notifications push mobiles ne sont pas disponibles dans cette version.
- Une revue de sécurité, des tests multi-OS, des tests de charge et un plan de reprise sont requis avant production.

## Sécurité
Ne publiez jamais `.env`, clés API, jetons, certificats privés, données de production ou sauvegardes. Toute collecte doit être autorisée par le propriétaire des systèmes.
