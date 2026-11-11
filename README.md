# Congo Sec Vision Enterprise
**INFOTELCOM — Plateforme SOC de laboratoire**  
Version source : 0.5.1 (API 0.3.1 / Android 0.4.1)

API FastAPI, console web, agents Windows/Linux et application Android native Java.

> **État :** branche d'amélioration en validation. Les routes SOC privilégiées vérifient une session Supabase et un rôle serveur `app_metadata.role=admin`. Le RBAC granulaire, MFA, PostgreSQL et les contrôles de production restent à achever. Ne pas exposer l'API directement sur Internet.

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
4. Ouvrir `http://127.0.0.1:8081`, se connecter avec un compte Supabase dont `app_metadata.role` vaut `admin` (voir la section « Autoriser un administrateur Supabase »). Le jeton `AGENT_ENROLLMENT_TOKEN` sert uniquement à l'enrôlement initial des agents.

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
- Rôle administrateur Supabase requis pour les routes privilégiées ; MFA et permissions granulaires par rôle restent à configurer.
- Les rôles d'équipe sont informatifs.
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


## Intelligence CVE — NVD, EPSS et CISA KEV

La branche d'amélioration ajoute au moteur CVE :
- pagination NVD 2.0 avec reprise bornée et temporisation configurable ;
- lecture des métriques CVSS 4.0 / 3.1 / 3.0 / 2.0, vecteur, CWE, CPE, références, dates, SSVC v2.0.3 et déclarations affected ;
- évaluation récursive des nœuds CPE AND/OR et des bornes de versions, en mode conservateur ;
- enrichissement EPSS (FIRST) et indicateur CISA Known Exploited Vulnerabilities (KEV) ;
- filtres CVE par gravité, éditeur, produit, CWE, CVSS, EPSS, KEV et statut ;
- historique des changements, assignation analyste, tags, abonnements éditeur/produit et alertes dans la console.

**Interprétation :** un résultat CPE est un candidat à vérifier, pas une preuve d'exploitabilité. EPSS est une estimation probabiliste, CVSS mesure la sévérité technique et KEV signale une exploitation connue. Le contexte de l'actif, les avis éditeurs et les correctifs rétroportés doivent être vérifiés.


Les alertes actuellement implémentées sont des notifications internes à la console, créées lors de la découverte d'une nouvelle CVE correspondant à un abonnement. L'envoi e-mail, Slack, Teams ou webhook n'est pas encore implémenté ; les abonnements ne doivent donc pas être considérés comme un service de notification externe.

### Autoriser un administrateur Supabase

Les routes SOC privilégiées exigent maintenant un rôle défini côté serveur dans `app_metadata`. Sur le compte administrateur uniquement, définir dans Supabase Auth `app_metadata.role = "admin"` (ou `app_metadata.roles = ["admin"]`). Ne pas placer ce rôle dans `user_metadata`, qui est modifiable par l'utilisateur. Les comptes sans rôle administrateur reçoivent HTTP 403. Prévoir un compte de secours et tester le rôle avant le déploiement.

### Synchronisation

Par défaut, le worker traite un lot toutes les 15 minutes (minimum configurable de 5 minutes). Ajuster `CVE_SYNC_INTERVAL_MINUTES`, `CVE_SYNC_BATCH_SIZE`, `CVE_SYNC_PRODUCT_INTERVAL_SECONDS`, `NVD_API_KEY` et `NVD_REQUEST_INTERVAL_SECONDS` selon la taille de l'inventaire et les limites NVD. La fraîcheur dépend du volume d'inventaire, des quotas NVD et de la durée de chaque lot : il s'agit d'une synchronisation périodique, pas d'un flux instantané. Les enrichissements EPSS/KEV sont facultatifs : une indisponibilité de ces services ne doit pas empêcher l'import NVD.

## Conditions bloquantes avant production

Cette branche améliore le moteur CVE et le triage, mais **ne constitue pas encore une autorisation de mise en production**. Les éléments suivants doivent être validés ou achevés :
- remplacer SQLite par PostgreSQL avec migrations versionnées, sauvegardes chiffrées et test de restauration ;
- implémenter les permissions effectives par rôle (admin, analyste, lecteur, répondant), MFA et gestion de session ;
- sécuriser l'enrôlement et la rotation des secrets agents, rate limiting, audit immuable et gestion des secrets ;
- exécuter les tests d'intégration sur NVD/EPSS/KEV, les tests de charge, de reprise et les tests multi-OS ;
- valider l'interface, le déploiement HTTPS, les sauvegardes et les procédures d'incident sur une infrastructure cible.

Ne pas exposer directement une instance non validée sur Internet. Les actions de remédiation restent manuelles et soumises à validation.
