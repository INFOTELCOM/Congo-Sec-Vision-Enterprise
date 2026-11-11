# Intégrations Congo Sec Vision

## OpenCVE API v2

OpenCVE est une intégration serveur facultative. Elle ne nécessite aucun jeton dans le navigateur.

1. Créer un jeton d'organisation OpenCVE avec au minimum le scope `catalog:read` (ou un jeton Community en lecture seule).
2. Ajouter dans le fichier local `.env` :
   ```dotenv
   OPENCVE_API_TOKEN=opc_org.<token_id>.<secret>
   OPENCVE_API_BASE_URL=https://app.opencve.io/api/v2
   ```
3. Recréer le conteneur API.
4. Dans le Centre de vulnérabilités, vérifier l'état OpenCVE puis utiliser la syntaxe de recherche avancée, par exemple `vendor:microsoft AND cvss31>=9`.

Les API v2 OpenCVE utilisent des jetons d'organisation Bearer. Ne jamais committer le vrai jeton. La fonction de recherche lit le catalogue et ne modifie ni l'organisation ni les projets OpenCVE.

## VMware, Proxmox et Hyper-V

Les connecteurs sont exécutés depuis le conteneur API et fonctionnent en lecture seule. Renseigner uniquement les variables qui correspondent à des infrastructures réellement disponibles dans le fichier local `.env` :

```dotenv
CSV_VMWARE_URL=https://vcenter.example.tld
CSV_VMWARE_USERNAME=compte-inventaire-lecture-seule
CSV_VMWARE_PASSWORD=...
CSV_VMWARE_VERIFY_TLS=true

CSV_PROXMOX_URL=https://pve.example.tld:8006
CSV_PROXMOX_TOKEN_ID=compte@pve!csvg
CSV_PROXMOX_TOKEN_SECRET=...
CSV_PROXMOX_VERIFY_TLS=true

CSV_HYPERV_HOST=hyperv.example.tld
CSV_HYPERV_USERNAME=DOMAINE\compte-inventaire
CSV_HYPERV_PASSWORD=...
CSV_HYPERV_TRANSPORT=ntlm
```

Créer des comptes techniques limités à la lecture de l'inventaire. Ne pas désactiver la validation TLS en production. Les adresses ci-dessus sont des exemples, pas des serveurs préconfigurés.

## VirtualBox sous Windows avec API dans Docker/WSL

Le binaire `VBoxManage` de Windows n'existe pas dans l'image Docker Linux. Utiliser le collecteur hôte PowerShell :

1. Générer un jeton aléatoire côté WSL : `openssl rand -hex 32`.
2. Ajouter le résultat dans le fichier local `.env` sous `CSV_VBOX_COLLECTOR_TOKEN=`.
3. Ajouter ce même nom de variable dans `.env` (le secret n'est pas versionné), puis recréer le conteneur API.
4. Depuis PowerShell Windows, lancer :
   ```powershell
   .\scripts\virtualbox-host-collector.ps1 -ApiUrl http://127.0.0.1:8081
   ```
5. Le script demande le jeton sans l'afficher, exécute uniquement `VBoxManage list vms --long` et transmet l'inventaire à l'API locale.

Le collecteur ne démarre, n'arrête, ne supprime et ne reconfigure aucune VM. La synchronisation vers Supabase reste une action séparée et requiert une session SOC autorisée.

## Limites opérationnelles explicites

- Les connecteurs réels ne peuvent être validés qu'avec un endpoint joignable et un compte technique valide.
- Le laboratoire synthétique ne représente jamais des VM réelles et reste désactivé par défaut.
- Les workflows et approbations de la version laboratoire enregistrent des brouillons/décisions ; ils n'exécutent aucune remédiation distante.
- L'ajout au registre local « Équipe & rôles » ne crée pas un utilisateur Supabase Auth et ne modifie pas `app_metadata`.
