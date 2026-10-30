# Congo Sec Vision Mobile 0.4.0

Application Android native Java connectée à l'API SOC 0.3.1.

## Compilation
- Android Studio récent, JDK 17, Android SDK Platform 35.
- Ouvrir le dossier `android/` (celui qui contient `settings.gradle`).
- Synchroniser Gradle puis Build > Build APK(s).
- APK debug : `app/build/outputs/apk/debug/app-debug.apk`.

## Connexion
L'application exige une URL HTTPS distante et le jeton ADMIN_TOKEN. Le jeton est chiffré avec Android Keystore. Ne placez jamais de jeton dans le code source. L'adresse locale HTTP `10.2.2.1:8081` fonctionne depuis le PC hôte mais ne doit pas être utilisée par un téléphone distant : configurez un reverse proxy HTTPS avec certificat de confiance et accès réseau approprié.

## Modules
Accueil, actifs, événements, constats IA, incidents (création / changement de statut), analyse IA, synchronisation NVD, diagnostics, topologie, vulnérabilités, approbations (consultation), workflows (consultation), équipe (consultation), audit, export CSV, statut de sécurité et paramètres. Les actions appellent les endpoints existants de l'API.

## Limites héritées de l'API 0.3.1
Le backend utilise un jeton administrateur partagé. Les rôles de l'équipe ne sont pas encore un RBAC effectif ; MFA, SSO et notifications push ne sont pas implémentés. Les approbations ne déclenchent aucune commande. L'analyse IA reste en `local-rules` si aucun fournisseur LLM n'est configuré. La synchronisation CVE produit des candidats à valider, pas des vulnérabilités confirmées.
