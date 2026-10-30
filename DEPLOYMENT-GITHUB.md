# Déploiement GitHub — Congo Sec Vision Enterprise

## 1. Console web (GitHub Pages)
Le workflow `.github/workflows/pages.yml` publie le dossier `web/`.
Dans **Settings → Pages**, choisir **GitHub Actions** comme source de publication.
Créer la variable Actions `API_BASE_URL` avec l'URL HTTPS publique de l'API (ex. `https://soc-api.example.com`). Ne pas utiliser l'adresse privée du laboratoire VMware.

GitHub Pages ne fournit que l'hébergement statique. L'API FastAPI, la base de données et les agents doivent fonctionner sur un serveur séparé.

## 2. API cloud
Utiliser `deploy/cloud/docker-compose.yml` avec un VPS Linux, un nom DNS et les ports 80/443 accessibles. Configurer les variables/secrets sur le serveur. Vérifier la persistance des volumes et les sauvegardes. Ne pas publier le port applicatif directement sur Internet ; Caddy doit terminer TLS et relayer vers l'API.

Le fichier cloud est un modèle à vérifier et adapter à l'environnement réel avant mise en production. Ne pas copier les secrets dans GitHub.

## 3. Android
Le workflow `.github/workflows/android.yml` compile un APK de debug et le conserve comme artifact Actions. Télécharger l'artifact depuis l'exécution du workflow. Un APK release signé demande une clé privée stockée dans GitHub Actions Secrets (non incluse).

## 4. Vérifications obligatoires
- Confirmer `/api/health` depuis l'extérieur via HTTPS.
- Configurer `API_BASE_URL` avec la même API.
- Vérifier les règles CORS et les origines autorisées.
- Tester connexion, actifs, événements, incidents et export.
- Vérifier les journaux et la restauration des sauvegardes.
- Ne pas exposer un SOC de laboratoire sans authentification individuelle, contrôle d'accès, durcissement et revue de sécurité.
