# Accès mobile HTTPS — Congo Sec Vision 0.4.1

## Ce que cette configuration fait
- Caddy termine TLS et obtient/renouvelle automatiquement un certificat public ACME.
- L'application Android doit utiliser `https://SOC_DOMAIN` (sans `:8081`).
- L'API de laboratoire reste publiée sur `10.2.2.1:8081` pour le segment VMware.
- Le volume `csvg_data` est conservé. Caddy utilise ses propres volumes persistants pour les certificats.

## Prérequis indispensables
1. Posséder un nom de domaine (ex. `soc.mondomaine.fr`).
2. Créer un enregistrement DNS A vers l'IP publique du routeur ; configurer AAAA uniquement si IPv6 est correctement routé.
3. Le routeur doit transférer TCP 80 et 443 vers l'adresse LAN du PC hôte. UDP 443 est facultatif (HTTP/3).
4. Le PC doit rester allumé et Docker Desktop démarré.
5. Vérifier que le FAI/routeur ne bloque pas les ports 80/443 et que l'IP publique n'est pas derrière CGNAT.

## Mise en place sous Windows
Depuis la racine du projet :

```powershell
Copy-Item .env.example .env
notepad .env
```

Dans `.env`, définir `ADMIN_TOKEN` et `AGENT_ENROLLMENT_TOKEN` avec deux secrets aléatoires distincts (au moins 32 caractères), puis `SOC_DOMAIN` et `ACME_EMAIL`. Ne jamais partager `.env`. Si les jetons du précédent ZIP ont été exposés, les remplacer avant démarrage.

Démarrer sans supprimer les volumes :

```powershell
docker compose config
docker compose up -d --build
docker compose ps
docker compose logs --tail 100 caddy
```

Ne jamais exécuter `docker compose down -v` : cela supprimerait les données persistantes.

Vérifier depuis le PC :

```powershell
Invoke-RestMethod https://SOC_DOMAIN/api/health
```

Le certificat n'est émis que lorsque le DNS public pointe vers le routeur et que Caddy peut recevoir les validations ACME sur le port 80/443. Remplacer `SOC_DOMAIN` dans la commande par le domaine réel.

## Pare-feu Windows
Le script `configure-mobile-firewall.ps1` propose une règle 8081 limitée au réseau VMware et 80/443 limités au sous-réseau mobile. **Modifier `MobileTrustedSubnet`** pour correspondre au réseau Wi-Fi réel avant exécution en PowerShell administrateur. Il ne faut pas désactiver le pare-feu. Pour un accès Internet hors LAN, une revue dédiée des règles et du routeur est obligatoire.

## Application Android
Dans l'écran de connexion, saisir :
- Serveur : `https://SOC_DOMAIN`
- Jeton : valeur `ADMIN_TOKEN` de `.env`

Le jeton est chiffré localement via Android Keystore. Il reste néanmoins un jeton administrateur partagé : cette version ne fournit pas encore des comptes individuels, MFA ni permissions RBAC effectives. Pour une utilisation multi-utilisateur/production, il faut d'abord migrer l'authentification vers des comptes nominatifs et des sessions à durée limitée.

## Machines VMware et certificat
Les agents distants imposent HTTPS. Si le domaine public ne résout pas vers l'hôte depuis le réseau VMware, utiliser une résolution DNS interne/split-DNS du domaine vers `10.2.2.1` sur les VMs. Le nom d'hôte TLS doit rester `SOC_DOMAIN` afin que le certificat public corresponde. Ne pas désactiver la validation TLS et ne pas remplacer l'URL par une adresse IP.

## Téléphone sur le Wi-Fi local
Le téléphone doit résoudre `SOC_DOMAIN` vers l'adresse de l'hôte ou le routeur doit supporter le NAT loopback. À défaut, configurer un DNS local (split-DNS) qui renvoie le nom de domaine vers l'IP LAN de l'hôte. L'application doit toujours utiliser le nom DNS HTTPS, jamais `http://10.2.2.1:8081`.

## Limites non masquées
- Firebase Cloud Messaging n'est pas activé : il faut un projet Firebase, `google-services.json` et une clé serveur/compte de service côté backend. Aucun faux push n'est simulé.
- MFA et authentification multi-comptes ne sont pas présents dans l'API 0.3.1.
- Le rôle d'équipe est une métadonnée, pas une autorisation RBAC appliquée aux endpoints.
- L'API conserve un jeton admin partagé. HTTPS protège le transport, mais ne remplace pas une authentification utilisateur.
