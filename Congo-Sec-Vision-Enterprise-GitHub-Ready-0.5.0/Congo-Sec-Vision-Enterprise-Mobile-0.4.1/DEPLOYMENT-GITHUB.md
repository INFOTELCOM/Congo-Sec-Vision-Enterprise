# Publication GitHub — Congo Sec Vision Enterprise

## Architecture retenue

- Dépôt : `INFOTELCOM/Congo-Sec-Vision-Enterprise` (à créer dans l'organisation si absent).
- Web : GitHub Pages, URL de projet attendue `https://infotelcom.github.io/Congo-Sec-Vision-Enterprise/`.
- API : conteneur FastAPI publié dans GHCR, à exécuter sur un VPS Linux public.
- TLS API : Caddy obtient et renouvelle automatiquement le certificat Let's Encrypt pour `SOC_DOMAIN`.
- Android : GitHub Actions compile un APK debug et le publie comme artefact téléchargeable.

GitHub Pages fournit HTTPS pour le site, mais pas pour l'API. Le certificat API est émis par Caddy sur le serveur cloud. Le nom `infotelcom.github.io` est le domaine GitHub Pages ; il ne peut pas être utilisé comme domaine de l'API.

## Avant la première publication

1. Créer le dépôt public `INFOTELCOM/Congo-Sec-Vision-Enterprise` (ou choisir un dépôt vide existant).
2. Importer le contenu de ce dossier à la racine, sur la branche `main`.
3. Dans Settings > Pages, choisir **GitHub Actions** comme source de publication.
4. Dans Settings > Secrets and variables > Actions > Variables, créer `API_BASE_URL` avec l'URL HTTPS de l'API, par exemple `https://api.votre-domaine.fr`.
5. Configurer un VPS Ubuntu/Debian avec Docker Engine et Docker Compose plugin. Faire pointer l'enregistrement DNS A de `api.votre-domaine.fr` vers l'IP publique du VPS et autoriser TCP 80/443.
6. Sur le VPS, copier `deploy/cloud/docker-compose.yml`, `deploy/cloud/Caddyfile` et `deploy/cloud/.env.example` dans un dossier de déploiement. Créer `.env`, choisir `SOC_DOMAIN`, `ACME_EMAIL`, des secrets uniques pour `ADMIN_TOKEN` et `AGENT_ENROLLMENT_TOKEN`, puis définir `ALLOWED_ORIGINS=https://infotelcom.github.io`.
7. Rendre l'image GHCR publique dans les paramètres du package, ou configurer une authentification GHCR sur le VPS. Puis lancer `docker compose pull && docker compose up -d`.
8. Vérifier `https://api.votre-domaine.fr/api/health`, puis ouvrir le site GitHub Pages et se connecter avec le `ADMIN_TOKEN`. Dans Android, saisir la même URL HTTPS et le même jeton.

## Sécurité / données

- Ne jamais committer `.env`, jetons, clés LLM, clés NVD ou données SOC. `.gitignore` exclut `.env`, bases SQLite et caches Python.
- Le volume Docker `csvg_data` conserve la base SQLite lors des mises à jour. Ne pas lancer `docker compose down -v`.
- Les agents distants doivent utiliser l'URL HTTPS publique de l'API et leur jeton d'agent ; ne pas exposer le port interne 8080.
- Le front-end utilise `API_BASE_URL` pour appeler l'API cross-origin ; CORS est limité à `ALLOWED_ORIGINS`.
- L'API actuelle (0.3.1) utilise encore un jeton administrateur partagé. Les rôles de l'équipe ne constituent pas encore un RBAC effectif ; MFA/SSO et notifications push ne sont pas implémentés. Voir `android/README.md`.

## Workflows inclus

- `pages.yml` : publie le tableau de bord web sur GitHub Pages.
- `backend-image.yml` : construit et publie l'image Docker dans GitHub Container Registry (GHCR).
- `android.yml` : compile l'APK debug et l'enregistre comme artefact GitHub Actions.

Ces workflows ne créent pas le dépôt, le VPS, le DNS ni les secrets à votre place. Le premier déploiement de l'API nécessite donc un VPS et un domaine API dont vous contrôlez le DNS.
