# Supabase — Congo Sec Vision Enterprise

Projet Supabase : `gyxbkutmgcnsmytodfst`  
Région : `eu-west-1`  
Schéma SOC : `soc` (exposé à la Data API après configuration PostgREST)

## Modèle de données SOC

Le schéma `soc` héberge les données opérationnelles de la plateforme : profils et rôles, actifs, inventaire des hyperviseurs, événements, vulnérabilités par actif, incidents, logiciels, résultats d'analyse, audit, équipes, approbations et workflows.

La table `soc.hypervisor_inventory` conserve l'inventaire collecté auprès des fournisseurs VMware, Proxmox, VirtualBox et Hyper-V. Les connecteurs et l'API d'ingestion sont côté backend ; la création de la table ne signifie pas qu'un hyperviseur est déjà authentifié ou joignable.

## Référentiel CVE NVD + OpenCVE

La table `soc.cve_intelligence` conserve le référentiel central par identifiant CVE, distinct de `soc.vulnerabilities` qui représente les vulnérabilités associées à un actif.

- `nvd_payload` : réponse détaillée NVD.
- `opencve_payload` : détails OpenCVE.
- `opencve_history` : page d'historique OpenCVE récupérée.
- `sources` : sources ayant fourni les données.
- Les horodatages de récupération permettent de savoir quand chaque source a été actualisée.

Les endpoints de détail combiné NVD/OpenCVE et les endpoints OpenCVE enregistrent leurs résultats dans ce référentiel. La recherche de catalogue OpenCVE met en cache les entrées CVE renvoyées (jusqu'à 100 par page). L'historique paginé conserve la page consultée ; les appels ultérieurs peuvent actualiser cette page.

## Authentification, rôles et sécurité

- Les utilisateurs s'authentifient avec Supabase Auth.
- Les autorisations SOC sont vérifiées par rôles applicatifs issus de `app_metadata`, jamais depuis des métadonnées modifiables par l'utilisateur.
- Rôles pris en charge : `admin`, `analyst`, `viewer`, `incident_responder`.
- RLS est activé sur les tables du schéma exposé.
- Pour `soc.cve_intelligence`, les rôles SOC autorisés peuvent lire ; les administrateurs et analystes peuvent insérer/mettre à jour ; seuls les administrateurs peuvent supprimer.
- Le backend utilise la clé publishable avec le JWT de l'utilisateur pour les opérations Data API, afin que les politiques RLS restent appliquées.
- Ne jamais placer une clé `service_role`, un secret Supabase, `OPENCVE_API_TOKEN` ou des identifiants d'hyperviseur dans Git, le navigateur, l'APK Android ou l'application desktop.

## Secrets et connexions réelles

Configurer `OPENCVE_API_TOKEN` dans le gestionnaire de secrets de l'environnement backend. Les paramètres VMware/Proxmox/Hyper-V et le jeton du collecteur VirtualBox doivent également être configurés dans le runtime serveur approprié. Une table Supabase et des connecteurs présents dans le code ne prouvent pas qu'une connexion réelle est établie : chaque fournisseur doit être testé avec ses propres URL, droits, certificats et identifiants.

## Migrations

Les migrations incrémentales appliquées au projet sont conservées dans `database/migrations/`. La migration CVE/OpenCVE et sa migration de précision RLS correspondent aux versions Supabase :

- `20261116073821_cve_intelligence_opencve_catalog.sql`
- `20261116073937_cve_intelligence_policy_precision.sql`

`schema.sql` est le socle historique initial ; les migrations incrémentales décrivent les évolutions appliquées ensuite. Vérifier les politiques RLS et les grants après toute évolution du schéma.

## État et limites

La table `soc.cve_intelligence` a été créée et vérifiée. Elle est actuellement vide tant qu'une recherche ou consultation CVE ne l'a pas alimentée via l'API. Les données SOC historiques SQLite ne sont pas automatiquement migrées par ces changements. La configuration des secrets backend et les tests de connexions réelles OpenCVE/hyperviseurs restent des opérations distinctes.
