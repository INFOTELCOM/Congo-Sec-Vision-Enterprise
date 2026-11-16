# Congo Sec Vision Enterprise
**INFOTELCOM — Plateforme SOC de laboratoire**  
Version source : 0.5.1 (API 0.3.1 / Android 0.4.1)

API FastAPI, console web, agents Windows/Linux et application Android native Java.

> **État :** branche d'amélioration en validation. Les routes SOC vérifient une session Supabase et des rôles serveur dans `app_metadata` (`csv_role`, `role` ou `roles`). Les connecteurs hyperviseurs et la découverte réseau sont en lecture seule / bornés. Les modules historiques restent sur SQLite ; la migration complète vers PostgreSQL, le MFA et plusieurs contrôles de production restent à achever. Ne pas exposer l'API directement sur Internet.

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
4. Ouvrir `http://127.0.0.1:8081`, se connecter avec un compte Supabase dont `app_metadata.csv_role` ou `app_metadata.role` vaut `admin` (voir docs/SUPABASE-AUTH-RBAC.md). Le jeton `AGENT_ENROLLMENT_TOKEN` sert uniquement à l'enrôlement initial des agents.

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
- SQLite conserve les modules SOC historiques ; Supabase PostgreSQL stocke déjà l'inventaire des hyperviseurs. La migration des autres domaines est progressive et non encore terminée.
- Rôles Supabase granulaires appliqués côté API ; MFA et vérification du niveau d'assurance AAL2 restent à intégrer.
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


## Machines virtuelles

L'agent Windows/Linux tente de reconnaître si le système invité fonctionne dans une VM (VMware, VirtualBox, Hyper-V, KVM/QEMU, Xen, Parallels et environnements cloud courants). Le résultat est transmis dans l'inventaire et affiché dans **Actifs & machines** sous la forme « VM · fournisseur ».

Cette détection est une heuristique exécutée depuis le système invité : elle peut retourner « non détectée » sur certains environnements et ne constitue pas une preuve de l'hyperviseur. Elle ne donne pas accès à l'état d'alimentation, aux snapshots, aux consoles, à la configuration ou à l'administration de l'hyperviseur.

Pour superviser une VM, installer l'agent dans le système invité comme sur un poste physique et autoriser sa connexion HTTPS vers l'API SOC. En complément, les connecteurs centraux VMware, Proxmox, VirtualBox et Hyper-V sont intégrés dans la branche et exposent uniquement les inventaires en lecture seule. Leur état réel dépend des variables d'environnement, de la connectivité réseau et des droits des comptes techniques. Suivre la procédure de mise en service dans `docs/HYPERVISORS.md`. Aucun démarrage, arrêt, suppression, reconfiguration ou snapshot n'est déclenché par ces connecteurs.

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

Les routes SOC exigent un rôle défini côté serveur dans `app_metadata`. Attribuer explicitement l'un des rôles suivants dans Supabase Auth (champ `app_metadata.role`, ou tableau `app_metadata.roles`) :
- `admin` : administration complète, audit, équipe, workflows et validations ;
- `analyst` : lecture SOC, synchronisation et triage CVE, analyse IA, événements, diagnostics, incidents et export ;
- `viewer` : lecture seule des données SOC ;
- `incident_responder` : lecture SOC, gestion des incidents et demandes d'approbation.

Le rôle `owner` est normalisé en `admin`. Ne jamais placer ces rôles dans `user_metadata`, qui est modifiable par l'utilisateur. Les comptes sans rôle reconnu reçoivent HTTP 403. Les permissions sont vérifiées côté API à chaque requête ; le registre local de l'équipe ne confère aucun droit d'accès. Prévoir un compte administrateur de secours et tester chaque profil avant le déploiement.

### Synchronisation

Par défaut, le worker traite un lot toutes les 15 minutes (minimum configurable de 5 minutes). Ajuster `CVE_SYNC_INTERVAL_MINUTES`, `CVE_SYNC_BATCH_SIZE`, `CVE_SYNC_PRODUCT_INTERVAL_SECONDS`, `NVD_API_KEY` et `NVD_REQUEST_INTERVAL_SECONDS` selon la taille de l'inventaire et les limites NVD. La fraîcheur dépend du volume d'inventaire, des quotas NVD et de la durée de chaque lot : il s'agit d'une synchronisation périodique, pas d'un flux instantané. Les exécutions manuelles et planifiées sont sérialisées pour éviter deux scans simultanés du même curseur. Les jetons d'agent sont stockés sous forme d'empreintes SHA-256 ; les anciens jetons en clair sont migrés au démarrage. Les enrichissements EPSS/KEV sont facultatifs : une indisponibilité de ces services ne doit pas empêcher l'import NVD.

## Conditions bloquantes avant production

Cette branche améliore le moteur CVE et le triage, mais **ne constitue pas encore une autorisation de mise en production**. Les éléments suivants doivent être validés ou achevés :
- remplacer SQLite par PostgreSQL avec migrations versionnées, sauvegardes chiffrées et test de restauration ;
- implémenter les permissions effectives par rôle (admin, analyste, lecteur, répondant), MFA et gestion de session ;
- sécuriser l'enrôlement et la rotation des secrets agents, rate limiting, audit immuable et gestion des secrets ;
- exécuter les tests d'intégration sur NVD/EPSS/KEV, les tests de charge, de reprise et les tests multi-OS ;
- valider l'interface, le déploiement HTTPS, les sauvegardes et les procédures d'incident sur une infrastructure cible.

Ne pas exposer directement une instance non validée sur Internet. Les actions de remédiation restent manuelles et soumises à validation.

## Hyperviseurs et virtualisation

La console dispose d'une rubrique Hyperviseurs pour synchroniser en lecture seule les inventaires VMware vSphere, Proxmox VE, VirtualBox et Hyper-V. Les identifiants des hyperviseurs restent côté serveur ; aucun secret n'est transmis au navigateur ni stocké dans Supabase. Voir docs/HYPERVISORS.md et les variables CSV_* dans .env.example.

Les enregistrements d'inventaire sont persistés dans la table soc.hypervisor_inventory du projet Supabase existant. Ajouter le schéma soc dans Project Settings → API → Exposed schemas avant d'utiliser les routes Data API. Les rôles admin/analyst peuvent synchroniser ; les rôles autorisés en lecture peuvent consulter.

## Découverte réseau

La rubrique Découverte réseau rassemble les hôtes détectés par les agents et les scans ICMP manuels. Les scans manuels sont limités aux sous-réseaux privés de 256 adresses maximum et réservés aux rôles admin/analyst. Les agents limitent chaque scan local à une fois par sous-réseau toutes les dix minutes. Cette découverte n'enrôle pas les machines et ne remplace pas un inventaire authentifié.


## Intégration NVD et OpenCVE

Le centre CVE combine désormais deux voies complémentaires :
- **NVD API 2.0** : recherche de CVE, détail, historique, CPE Dictionary et critères CPE Match. La clé `NVD_API_KEY` reste facultative ; sans elle, les requêtes sont temporisées pour respecter le débit public. NVD publie aussi CVSS, CWE, CPE, KEV, SSVC et déclarations de produits affectés lorsqu'ils sont disponibles.
- **OpenCVE API v2** : recherche avancée, détail et historique des changements. Cette intégration nécessite un jeton d'organisation OpenCVE, stocké uniquement dans `OPENCVE_API_TOKEN` sur le serveur. Créer un jeton en lecture seule (ou avec les seuls scopes de lecture disponibles), puis saisir sa valeur directement dans le fichier local `.env`. Ne jamais le coller dans GitHub, le navigateur ou une conversation.

L'interface affiche l'état de chaque source. NVD reste utilisable même si OpenCVE n'est pas configuré ; les erreurs d'OpenCVE n'interrompent pas la consultation NVD. Les routes interactives sont authentifiées par une session Supabase.

## Mise en service réelle des hyperviseurs

Les connecteurs ne sont jamais marqués connectés simplement parce que leurs champs sont remplis : le bouton **Tester les connexions** effectue une vraie lecture de l'inventaire. Les détails des variables manquantes sont affichés dans la console. Configurer les variables `CSV_*` du fichier local `.env` selon `docs/HYPERVISORS.md`, puis recréer uniquement le service API :
```bash
docker compose up -d --no-deps --force-recreate api
```
Le bouton **Synchroniser les hyperviseurs réels** enregistre l'inventaire authentifié dans le schéma Supabase `soc`. Le laboratoire synthétique (`CSV_HYPERVISOR_LAB_MODE=true`) est séparé, désactivé par défaut et ne peut pas être synchronisé comme un inventaire réel.

## Limites des boutons Gouvernance

Le bouton d'ajout d'équipe ajoute une entrée au registre local SQLite ; il ne crée pas un utilisateur Supabase Auth et n'accorde aucun rôle. Les workflows sont enregistrés désactivés et les approbations enregistrent des décisions de gouvernance ; elles n'exécutent volontairement aucune commande distante. Ces limites sont indiquées dans l'interface afin de ne pas présenter une validation administrative comme une remédiation effectuée.
