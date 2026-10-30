# Déploiement Render — Congo Sec Vision Enterprise

Ce dépôt contient un Blueprint Render pour héberger l'API FastAPI en HTTPS.

## Déploiement

1. Connecter le dépôt GitHub `INFOTELCOM/Congo-Sec-Vision-Enterprise` à Render.
2. Dans Render, choisir **New → Blueprint** et sélectionner ce dépôt.
3. Render détecte `render.yaml`. Vérifier le service `congo-sec-vision-api` et confirmer la création.
4. Attendre le déploiement puis vérifier :
   `https://congo-sec-vision-api.onrender.com/api/health`
   (le sous-domaine exact est celui attribué par Render).
5. Copier l'URL HTTPS réelle du service dans GitHub → Settings → Secrets and variables → Actions → Variables, sous le nom `API_BASE_URL`, puis relancer le workflow Pages.

## Persistance et coût

Le Blueprint utilise le plan Starter et un disque persistant de 1 Go monté dans `/data`. C'est volontaire : le disque éphémère d'un service web ne convient pas à la base SQLite de cette application. Le plan et le disque Render sont payants ; vérifier le tarif affiché dans Render avant de confirmer.

## Secrets

Render génère `ADMIN_TOKEN` et `AGENT_ENROLLMENT_TOKEN` côté serveur. Ne jamais les copier dans le code du site, dans GitHub Pages, ni dans l'APK. Le premier est actuellement encore utilisé par l'interface existante pour l'authentification administrateur ; le second sert à l'enrôlement des agents.

## État de l'authentification

Ce fichier prépare l'hébergement persistant et HTTPS. Il ne transforme pas à lui seul l'authentification actuelle par jeton partagé en comptes individuels e-mail/mot de passe. Cette migration doit être finalisée et testée séparément avant de distribuer l'application à des utilisateurs. Ne pas présenter le service comme prêt pour une utilisation publique multi-utilisateur tant que cette migration n'est pas terminée.
