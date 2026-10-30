# Déploiement GitHub — Congo Sec Vision Enterprise

## 1. Dépôt

Le dépôt cible est `INFOTELCOM/Congo-Sec-Vision-Enterprise`, branche `main`.

Le dépôt a été créé vide. Avant d'activer les workflows, importer le code complet de l'archive GitHub Ready 0.5.0 à la racine du dépôt. Les workflows ne peuvent pas publier une application dont les sources ne sont pas présentes.

## 2. Site Web

GitHub Pages héberge uniquement les fichiers statiques. Une fois le dossier Web et le workflow Pages importés :
- ouvrir Settings → Pages ;
- choisir GitHub Actions ;
- attendre une exécution réussie dans Actions.

URL Pages attendue : `https://infotelcom.github.io/Congo-Sec-Vision-Enterprise/`.

Le certificat HTTPS de Pages couvre ce site. Il ne couvre pas l'API.

## 3. API et données SOC

Déployer le conteneur FastAPI sur un VPS ou une plateforme compatible Docker. Utiliser Caddy ou un reverse proxy équivalent pour obtenir HTTPS. Configurer la base et les volumes persistants. Ne pas utiliser GitHub Pages comme serveur API.

## 4. Android

Après import du projet Android et du workflow correspondant, lancer le workflow Android dans Actions. Vérifier que le build aboutit et publier l'APK comme artefact ou GitHub Release. L'APK doit pointer vers l'URL HTTPS réelle de l'API.

## 5. Variables et secrets

Les noms exacts des variables doivent être vérifiés dans les fichiers de configuration importés. Ne pas créer de valeurs fictives. Ne jamais committer de fichier `.env` réel, de mot de passe, de clé API ou de certificat privé.

## 6. Contrôles avant mise en production

- Tests backend réussis.
- API joignable uniquement via HTTPS.
- Authentification et rôles vérifiés.
- Données persistantes et sauvegardes vérifiées.
- Agent Windows/Linux enrôlé avec un secret individuel.
- Site Web et Android connectés à la même API.
- APK installé et testé sur un appareil réel.
