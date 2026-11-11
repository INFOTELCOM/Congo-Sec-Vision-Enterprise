# Déploiement cloud (VPS Linux)

Cette procédure prépare le déploiement de l'API derrière Caddy avec HTTPS automatique. Le déploiement réel ne doit être lancé qu'après validation des tests, du domaine, du serveur et de la procédure de restauration.

## Prérequis
- VPS Linux avec Docker Engine et le plugin Docker Compose.
- Nom de domaine dont les enregistrements DNS A/AAAA pointent vers le VPS.
- Ports entrants TCP 80 et 443 ouverts. Ne pas publier le port 8080 de l'API sur Internet.
- Image GHCR construite depuis la branche/release validée.

## Installation
1. Copier deploy/cloud/docker-compose.yml et deploy/cloud/Caddyfile dans un dossier dédié.
2. Créer un fichier .env protégé (permissions chmod 600) avec les variables de production :
   SOC_DOMAIN=api.example.org
   ACME_EMAIL=admin@example.org
   AGENT_ENROLLMENT_TOKEN=<secret-long-aleatoire>
   DATABASE_PATH=/data/congo_sec_vision.db
   SUPABASE_URL=https://<project-ref>.supabase.co
   SUPABASE_PUBLISHABLE_KEY=<publishable-key>
   ALLOWED_ORIGINS=https://infotelcom.github.io
3. Ajouter uniquement les variables des hyperviseurs réellement utilisés (voir docs/HYPERVISORS.md). Les identifiants doivent être des comptes techniques en lecture seule.
4. Vérifier les accès GHCR, puis exécuter docker compose pull et docker compose up -d.
5. Vérifier /api/health, /api/health/ready, les journaux, les connexions Supabase et une synchronisation hyperviseur contrôlée.
6. Mettre à jour API_BASE_URL dans les variables GitHub Actions du workflow Pages, puis publier le frontend validé.

## Supabase existant
- Le backend conserve la session de l'utilisateur : il utilise la clé publishable et le JWT de la session, jamais une clé service_role.
- La migration supabase/migrations/20261111110000_hypervisor_inventory.sql crée uniquement soc.hypervisor_inventory, avec RLS et politiques de lecture/écriture par rôle.
- Dans Supabase Dashboard → Project Settings → API → Exposed schemas, ajouter soc. La Data API utilise Accept-Profile: soc pour la lecture et Content-Profile: soc pour l'écriture.
- Les secrets VMware/Proxmox/Hyper-V restent côté serveur dans le gestionnaire de secrets ou dans le fichier d'environnement protégé. VirtualBox utilise VBoxManage sur l'hôte qui exécute l'API.
- La migration de l'ensemble des données historiques SQLite vers PostgreSQL n'est pas effectuée par cette étape. Elle nécessite une sauvegarde du volume de production, un export contrôlé, une migration vérifiée et un plan de retour arrière avant bascule.

## Sauvegardes et retour arrière
- Avant mise à jour, sauvegarder le volume csvg_data et vérifier la lisibilité de la sauvegarde.
- Ne jamais exécuter docker compose down -v sur l'environnement qui contient les données.
- Conserver l'image précédente et le fichier de configuration précédent pour rollback.
- Tester la restauration sur un environnement distinct avant la bascule de production.

## Contrôles de mise en production
- HTTPS valide, DNS correct, port 8080 non exposé, SSH restreint.
- Variables et secrets présents sans être imprimés dans les logs.
- RLS et politiques testées avec les rôles admin, analyst, incident_responder et viewer.
- Authentification, endpoints historiques, synchronisation CVE et connecteurs hyperviseurs validés.
- Charge, sauvegarde/restauration, journaux et supervision testés.
- Aucun déploiement production automatique depuis une branche de travail.

## État de la migration
Le code de cette branche conserve SQLite pour les modules historiques qui y écrivent encore. L'inventaire hyperviseur est le premier module à persister directement dans le schéma Supabase soc. La migration des actifs, événements, CVE, incidents, audits et workflows doit être menée module par module avec double lecture/validation et sauvegarde, sans bascule destructive.
