# Configurer les hyperviseurs de Congo Sec Vision

Les connecteurs VMware, Proxmox, VirtualBox et Hyper-V sont intégrés en lecture seule. Ils interrogent l'inventaire, puis les administrateurs/analystes peuvent synchroniser les résultats vers `soc.hypervisor_inventory` dans le projet Supabase existant. Aucun Start/Stop/Delete/Set, snapshot ou changement de configuration d'une VM n'est disponible.

## Avant de commencer

1. Utiliser des comptes techniques distincts avec les droits strictement nécessaires à la lecture des inventaires.
2. Conserver tous les identifiants dans le fichier local `.env`. Ne jamais les placer dans Git, dans la configuration du navigateur, ni dans un message.
3. Vérifier que le conteneur API peut joindre les hyperviseurs sur le réseau et que les certificats TLS sont approuvés.
4. Après chaque modification de `.env`, recréer uniquement l'API :

```bash
docker compose up -d --no-deps --force-recreate api
docker compose ps
```

Le tableau **Hyperviseurs** affiche les variables manquantes et les instructions de chaque fournisseur, sans jamais afficher les valeurs des secrets. Le bouton **Tester les connexions** effectue un véritable inventaire en lecture seule ; le fait que les variables soient renseignées ne suffit pas à déclarer le fournisseur connecté.

## VMware vCenter / vSphere

Prérequis : vCenter joignable en HTTPS et API REST activée. Les routes utilisées sont `POST /api/session` puis `GET /api/vcenter/vm`.

Créer un compte de service dédié (par exemple `csv-inventory`) et un rôle vCenter personnalisé limité à la consultation de l'inventaire et des propriétés VM nécessaires. Ne pas attribuer le rôle Administrator. Assigner le rôle au périmètre datacenter/vCenter approprié avec propagation aux objets à inventorier.

Variables à renseigner dans le `.env` local :

```dotenv
CSV_VMWARE_URL=https://vcenter.exemple.local
CSV_VMWARE_USERNAME=csv-inventory@vsphere.local
CSV_VMWARE_PASSWORD=VALEUR_LOCALE_PRIVEE
CSV_VMWARE_VERIFY_TLS=true
```

Le connecteur ouvre une session, lit les machines virtuelles et ferme la session. En cas de certificat interne, installer la CA dans le conteneur API ; garder `CSV_VMWARE_VERIFY_TLS=true`.

## Proxmox VE

Prérequis : API Proxmox joignable en HTTPS (port 8006 par défaut).

Créer un compte technique et un API Token dédié au SOC. Attribuer au chemin `/` le rôle intégré `PVEAuditor` (ou un rôle personnalisé strictement équivalent limité à la lecture). Respecter la séparation de privilèges du token et ne lui accorder aucun droit d'administration.

```dotenv
CSV_PROXMOX_URL=https://pve.exemple.local:8006
CSV_PROXMOX_TOKEN_ID=csv-inventory@pve!soc
CSV_PROXMOX_TOKEN_SECRET=VALEUR_LOCALE_PRIVEE
CSV_PROXMOX_VERIFY_TLS=true
```

Le connecteur utilise uniquement `GET /api2/json/cluster/resources?type=vm`. En cas de certificat auto-signé, installer la CA de votre cluster dans l'image/conteneur.

## VirtualBox sur Windows avec WSL2/Docker

Dans le déploiement Docker/WSL standard, le conteneur n'a pas accès au binaire Windows `VBoxManage.exe`. Utiliser le collecteur hôte fourni : `scripts/virtualbox-host-collector.ps1`. Il exécute uniquement :

```powershell
VBoxManage.exe list vms --long
```

### 1. Créer un jeton dédié

Dans Ubuntu/WSL, générer un jeton aléatoire :

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Placer sa valeur uniquement dans le `.env` local :

```dotenv
CSV_VBOX_COLLECTOR_TOKEN=JETON_LOCAL_A_GARDER_SECRET
```

Recréer le service API :

```bash
docker compose up -d --no-deps --force-recreate api
```

### 2. Lancer le collecteur depuis Windows

Ouvrir PowerShell Windows dans le dossier du dépôt et exécuter :

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\virtualbox-host-collector.ps1 -ApiUrl http://127.0.0.1:8081
```

Le script détecte `VBoxManage.exe`, demande le jeton de manière masquée et transmet les noms, UUID, états, CPU et mémoire. Il ne démarre ni n'arrête aucune VM. Le collecteur peut être relancé après un changement de l'inventaire VirtualBox.

Après la première remontée, **Tester les connexions** doit indiquer « Connecté ». Si le jeton est configuré mais qu'aucun relevé n'a été reçu, le statut indique une attente plutôt qu'une connexion réelle.

## Hyper-V

Prérequis : WinRM HTTPS opérationnel sur le port 5986, résolution DNS, certificat serveur de confiance depuis le conteneur API et module Hyper-V disponible au compte distant.

Configurer WinRM avec HTTPS. Utiliser un compte restreint ou un endpoint JEA limité aux commandes de lecture quand cela est possible. Le connecteur exécute uniquement `Get-VM` et sélectionne les propriétés d'inventaire.

```dotenv
CSV_HYPERV_HOST=https://hyperv.exemple.local:5986/wsman
CSV_HYPERV_USERNAME=DOMAINE\csv-inventory
CSV_HYPERV_PASSWORD=VALEUR_LOCALE_PRIVEE
CSV_HYPERV_TRANSPORT=ntlm
```

Le connecteur refuse WinRM en HTTP (port 5985). Pour une CA interne, installer cette CA dans le conteneur API ; ne pas contourner la validation TLS.

## Tester et synchroniser

1. Recréer le service API après modification du `.env`.
2. Se connecter à Congo Sec Vision avec un compte Supabase ayant le rôle `admin` ou `analyst`.
3. Ouvrir **Hyperviseurs** et vérifier les paramètres manquants.
4. Cliquer **Tester les connexions**. Cette opération ne persiste aucun nouvel inventaire.
5. Corriger réseau, TLS ou permissions jusqu'à obtenir un statut « Connecté ».
6. Cliquer **Synchroniser les hyperviseurs réels** pour écrire les machines réelles dans la table Supabase `soc.hypervisor_inventory`.

Les rôles en lecture peuvent consulter l'inventaire ; seuls admin/analyst peuvent tester les connexions et synchroniser. Les données de laboratoire sont présentées séparément.

## Laboratoire synthétique (sans hyperviseur)

Pour tester les composants d'affichage sans se connecter à une infrastructure réelle :

```dotenv
CSV_HYPERVISOR_LAB_MODE=true
```

Puis recréer le service API et ouvrir la page Hyperviseurs. Les machines fictives sont étiquetées **SIMULATED**, ne sont pas écrites dans Supabase et ne sont jamais fusionnées avec l'inventaire réel. Remettre `false` après les essais.
