# Congo Sec Vision Enterprise

Plateforme SOC de supervision et de réponse aux incidents — INFOTELCOM.

> **État de publication : amorçage du dépôt.** Le dépôt GitHub vient d'être initialisé avec cette documentation. Le code applicatif complet (API FastAPI, interface Web, agent Windows/Linux et projet Android) doit encore être importé depuis l'archive de livraison avant activation des déploiements.

## Architecture cible

- **Web** : GitHub Pages (interface statique).
- **API** : FastAPI conteneurisée, hébergée sur un serveur cloud/VPS avec HTTPS.
- **Images** : GitHub Container Registry (GHCR).
- **Android** : APK compilé par GitHub Actions et publié dans GitHub Releases.
- **Agents** : collecte Windows/Linux vers l'API HTTPS.
- **Données** : base persistante sur l'infrastructure API ; ne jamais versionner les données SOC ou les secrets.

## Livraison source

Importer à la racine du dépôt le contenu de l'archive :
`Congo-Sec-Vision-Enterprise-GitHub-Ready-0.5.0.zip`.

Extraire le dossier interne `Congo-Sec-Vision-Enterprise-Mobile-0.4.1/` et transférer **son contenu** à la racine du dépôt (README, app/, agent/, android/, deploy/, tests/, .github/, Dockerfile, docker-compose.yml, requirements*.txt et fichiers de configuration).

Ne pas importer de fichier `.env`, de clé privée, de jeton, de base de données réelle ni de journaux contenant des données sensibles.

## Publication après import

1. Dans **Settings → Pages**, choisir **GitHub Actions** comme source.
2. Vérifier les workflows sous `.github/workflows/`.
3. Ajouter les variables/secrets nécessaires dans **Settings → Secrets and variables → Actions**.
4. Déployer l'API sur un VPS ; GitHub Pages ne peut pas héberger le serveur FastAPI.
5. Configurer l'URL HTTPS publique de l'API dans la configuration Web et Android.
6. Vérifier les tests, le build Android et les contrôles de santé avant d'annoncer la mise en production.

## Sécurité

- Ne jamais exposer l'API SOC sans HTTPS et authentification.
- Conserver les secrets uniquement dans les variables d'environnement du serveur ou les GitHub Actions Secrets.
- Ne pas ouvrir les ports de collecte à Internet sans filtrage, authentification des agents et journalisation.
- Sauvegarder les données persistantes avant toute migration.

Voir [DEPLOYMENT-GITHUB.md](DEPLOYMENT-GITHUB.md) pour le plan de déploiement.
