# Congo Sec Vision Enterprise — SOC de laboratoire

Version de travail : **0.3.1**. Cette archive enrichit le projet existant ; elle n'est pas une certification de sécurité ni une version prête pour exposition Internet.

## Démarrage rapide (Windows)
1. Installer Docker Desktop et démarrer le moteur Docker.
2. Extraire l'archive, ouvrir PowerShell dans `congo-sec-vision/`.
3. Exécuter `Set-ExecutionPolicy -Scope Process Bypass` si nécessaire.
4. Lancer `./setup-windows.ps1`. Le script génère des secrets locaux si `.env` n'existe pas.
5. Ouvrir `http://127.0.0.1:8081` et saisir la valeur `ADMIN_TOKEN` du fichier `.env`.

Linux : `chmod +x setup-linux.sh && ./setup-linux.sh`.

La publication Docker est liée à `127.0.0.1` uniquement. Ne pas modifier cette liaison pour exposer le service directement sur Internet. Pour un accès distant, placer l'API derrière un reverse proxy HTTPS, configurer le pare-feu et revoir l'authentification.

## Modules présents
- **Command Center** : métriques calculées depuis les agents enrôlés, activité et état en ligne/hors ligne.
- **Assets Management** : inventaire des systèmes, interfaces, métriques et logiciels.
- **Threat & Log Intelligence** : événements remontés par les agents et règles locales de détection.
- **Vulnerability Management** : interrogation NVD par nom logiciel. Les résultats sont des candidats `needs-validation`, pas des vulnérabilités confirmées ; vérifier CPE, plages de versions, éditions et avis éditeur.
- **AI Security Analyst** : règles locales ; fournisseur LLM compatible OpenAI optionnel (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`). Les données de logs peuvent être sensibles.
- **Network Intelligence** : relations de sous-réseau déduites des interfaces des agents. Pas de découverte physique de switchs/routeurs ni de capture de paquets.
- **Incident Response** : création, priorité, assignation, état, corrélation de constats en incidents et historique des modifications.
- **Automation & Approvals** : workflows descriptifs et demandes d'approbation. Une approbation est enregistrée mais **n'exécute aucune commande**.
- **Team Management** : registre des membres et rôles proposés. Les rôles ne constituent pas encore un RBAC effectif.
- **Audit** : journal des actions administratives prises en charge par l'API.
- **Reports** : export CSV de l'inventaire.
- **Android** : sources Android natives connectées à l'API ; l'écran affiche les métriques SOC et un aperçu des incidents.

## Agents et déploiement autorisé
L'agent Windows/Linux collecte l'inventaire, les interfaces, les métriques et un sous-ensemble de journaux accessibles. Le déploiement sur Windows peut être fait avec `deploy/install-agent.ps1` ou via GPO dans `deploy/ad/`. Linux utilise `deploy/install-agent.sh` et systemd.

Le déploiement automatique ne peut pas être déclenché par la simple présence d'une machine sur un réseau. Il requiert un mécanisme d'administration autorisé (GPO/AD, Intune, SSH/Ansible ou outil de gestion). Les machines inconnues doivent être inventoriées puis mises en attente d'autorisation. Tester la GPO sur une OU pilote et protéger le secret d'enrôlement dans SYSVOL ; pour la production, préférer un enrôlement par certificat ou jetons courts à usage limité.

Agent :
```bash
python -m pip install -r agent/requirements.txt
python agent/agent.py --server https://soc.example.com --enrollment-token TOKEN --interval 60
```
HTTP est accepté par l'agent uniquement pour `localhost`/`127.0.0.1` en laboratoire ; HTTPS est requis pour les serveurs distants.

## Collecte et analyse IA — version 0.3.1
- L'agent conserve son identifiant/jeton d'agent dans `C:\ProgramData\CongoSecVision\agent-state.json` (Windows) ou `/var/lib/congo-sec-vision-agent/state.json` (Linux). Protéger ce fichier : il contient un jeton d'accès individuel.
- Le compte de service Windows est `SYSTEM` afin de pouvoir lire le journal Security ; vérifier les stratégies d'audit Windows et les permissions des journaux. L'agent ne modifie pas les stratégies d'audit.
- Debian utilise `journalctl`; pour lire les journaux système, lancer le service avec les droits nécessaires. La collecte dépend des journaux effectivement activés et conservés sur l'hôte.
- L'analyse locale utilise des règles de détection déterministes sur les événements réellement reçus. Elle fournit des signaux à investiguer, pas un verdict automatique de compromission.
- L'analyse IA par LLM nécessite un fournisseur compatible OpenAI configuré dans `.env` (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` si requis). Sans ces paramètres, le mode reste `local-rules` ; aucun modèle externe n'est simulé.
- Les événements Windows Security peuvent contenir des noms de comptes, adresses IP et détails d'administration. Limiter l'accès à l'API et à la base, et valider la politique de conservation avant usage hors laboratoire.

## Android Mobile 0.4.1
Application Android native Java : tableau de bord, actifs, événements, constats IA, incidents (création et changement de statut), analyse IA, synchronisation CVE, diagnostics, topologie, vulnérabilités, approbations, workflows, équipe, audit, export CSV et paramètres. Ouvrir `android/` dans Android Studio (JDK 17, SDK 35), puis Build > Build APK. Le jeton est chiffré avec Android Keystore. L'application exige HTTPS pour les serveurs distants. Les notifications push, MFA, SSO et comptes mobiles individuels ne sont pas implémentés dans l'API 0.3.1.

## Limites de sécurité à connaître
- Authentification actuelle : un jeton administrateur partagé ; **MFA, SSO et authentification multi-utilisateur ne sont pas implémentés**.
- Les rôles d'équipe sont un registre informatif, pas des permissions appliquées à chaque route.
- SQLite est prévu pour le laboratoire ; prévoir PostgreSQL, sauvegardes et migrations contrôlées avant production.
- Le journal d'audit est dans la même base modifiable, il n'est pas inviolable.
- Pas de remédiation distante/automatique ; les validations sont une étape de gouvernance uniquement.
- Pas de moteur de corrélation SIEM avancé, d'EPSS, de CPE validé, de SNMP/NetFlow ou d'agent signé dans cette version.
- Ne pas exposer directement l'API à Internet. Faire une revue de sécurité, tests de charge, tests multi-OS, durcissement des secrets et plan de reprise avant tout usage réel.

## Tests automatisés\nDepuis ce dossier : `python -m pip install -r requirements-dev.txt` puis `python -m unittest discover -s tests -v`. Ces tests couvrent les endpoints de santé/authentification, le cycle de vie d'incident, les approbations sans exécution et le journal d'audit.\n\n## Laboratoire conseillé
1. Démarrer l'API localement avec Docker.
2. Enrôler une VM Windows et une VM Linux de ton laboratoire, avec autorisation.
3. Vérifier leurs heartbeats et l'inventaire dans **Actifs & machines**.
4. Envoyer des journaux de test bénins et vérifier **Menaces & événements** puis **Analyse IA**.
5. Créer un incident et tester ses transitions de statut.
6. Créer une demande d'approbation et vérifier que son traitement ne lance aucune commande.
7. Tester l'export CSV et examiner le journal d'audit.


## HTTPS mobile 0.4.1
Le fichier `docker-compose.yml` ajoute Caddy comme reverse proxy TLS automatique. Voir `deploy/README-HTTPS-MOBILE.md` : un domaine public, DNS correct, ports 80/443 et routeur correctement configuré sont obligatoires. L'API reste publiée sur `10.2.2.1:8081` pour le segment VMware ; le mobile passe par `https://SOC_DOMAIN`. Les volumes `csvg_data`, `caddy_data` et `caddy_config` sont persistants. Ne jamais utiliser `docker compose down -v`.

Cette livraison ne prétend pas activer MFA, comptes individuels/RBAC ou notifications push : ils nécessitent des développements backend et des identifiants Firebase qui ne sont pas fournis. Les limites sont détaillées dans `deploy/README-HTTPS-MOBILE.md`.
