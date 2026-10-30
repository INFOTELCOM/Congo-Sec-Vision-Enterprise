# Déploiement cloud (VPS Linux)

Cette procédure déploie l'API derrière Caddy avec HTTPS automatique.

## Prérequis
- VPS Linux avec Docker Engine et le plugin Docker Compose.
- Un nom de domaine (par exemple `api.example.org`) dont les enregistrements DNS A/AAAA pointent vers le VPS.
- Ports entrants TCP 80 et 443 ouverts. Ne pas publier le port 8080 de l'API sur Internet.
- Image GHCR publiée par le workflow `Build and publish API image` (publier un tag Git `v0.5.1`, par exemple).

## Installation
1. Copier `deploy/cloud/docker-compose.yml` et `deploy/cloud/Caddyfile` dans un même dossier sur le VPS.
2. Créer dans ce dossier un fichier `.env` contenant :
   ```dotenv
   SOC_DOMAIN=api.example.org
   ACME_EMAIL=admin@example.org
   ADMIN_TOKEN=un-secret-long-aleatoire
   AGENT_ENROLLMENT_TOKEN=un-autre-secret-long-et-different
   DATABASE_PATH=/data/congo_sec_vision.db
   ALLOWED_ORIGINS=https://infotelcom.github.io
   ```
3. Vérifier que le paquet GHCR est public, ou configurer un `docker login ghcr.io` sur le VPS avec un compte autorisé en lecture.
4. Exécuter `docker compose pull` puis `docker compose up -d`.
5. Vérifier `https://api.example.org/api/health`.
6. Dans GitHub → Settings → Secrets and variables → Actions → Variables, définir `API_BASE_URL=https://api.example.org`, puis relancer le workflow Pages.

## Données et sécurité
- Les volumes `csvg_data`, `caddy_data` et `caddy_config` sont persistants. Ne pas lancer `docker compose down -v`.
- Sauvegarder régulièrement le volume de données et tester la restauration.
- Restreindre SSH, mettre à jour le VPS et surveiller les journaux.
- L'application utilise encore un jeton administrateur partagé et SQLite : ce déploiement reste un environnement de validation, pas une plateforme SOC de production durcie.
