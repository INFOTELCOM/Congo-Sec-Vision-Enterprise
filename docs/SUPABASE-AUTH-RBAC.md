# Authentification et rôles — Congo Sec Vision

## Principe

La console utilise **Supabase Auth** pour la connexion par e-mail et mot de passe. Il n'existe pas de formulaire d'inscription public. Les comptes sont créés et administrés depuis Supabase.

Le navigateur conserve une session Supabase et transmet son access token à l'API dans l'en-tête `Authorization: Bearer <access_token>`. L'API valide le jeton auprès de l'endpoint Auth `/auth/v1/user` avant d'autoriser une requête protégée.

La clé `SUPABASE_PUBLISHABLE_KEY` est une clé publique destinée au client. **Ne jamais exposer une clé `service_role` ou une clé secrète dans le navigateur, le dépôt Git ou l'application Android.**

## Attribuer un rôle

Dans le Dashboard Supabase du projet Congo Sec Vision :

1. Ouvrir **Authentication → Users**.
2. Sélectionner l'utilisateur existant.
3. Modifier ses **App Metadata** (métadonnées administrateur, non les User Metadata).
4. Ajouter une propriété `csv_role` avec l'une des valeurs ci-dessous.
5. Enregistrer, puis demander à l'utilisateur de se déconnecter et de se reconnecter afin d'obtenir un JWT actualisé.

Exemple pour le compte administrateur existant :

```json
{
  "csv_role": "admin"
}
```

Exemples de rôles :

- `admin` — administration complète.
- `analyst` — supervision, analyse, diagnostics, CVE et traitement des incidents.
- `incident_responder` — consultation opérationnelle et gestion du cycle de vie des incidents.
- `viewer` — consultation en lecture seule des vues SOC autorisées.

Les rôles doivent être stockés dans **App Metadata** car les utilisateurs ne peuvent pas modifier eux-mêmes ces métadonnées. Ne jamais utiliser `user_metadata` pour décider des permissions.

Un compte sans rôle explicite est traité comme `viewer`. Un rôle inconnu est refusé.

## Matrice des permissions API

| Fonction | Admin | Analyste | Réponse incident | Lecture seule |
|---|---:|---:|---:|---:|
| Vue générale, actifs, événements, CVE et topologie (GET) | Oui | Oui | Oui | Oui |
| Constats IA et incidents (GET) | Oui | Oui | Oui | Oui |
| Journal d'audit | Oui | Oui | Non | Non |
| Export CSV | Oui | Oui | Non | Non |
| Équipe et rôles | Oui | Non | Non | Non |
| Workflows (lecture) | Oui | Oui | Non | Non |
| Analyse IA, synchronisation CVE, diagnostics | Oui | Oui | Non | Non |
| Créer / modifier des incidents | Oui | Oui | Oui | Non |
| Demander une approbation | Oui | Oui | Oui | Non |
| Approuver / refuser une demande | Oui | Non | Non | Non |
| Créer des membres et workflows | Oui | Non | Non | Non |

Les routes d'enrôlement et de heartbeat des agents restent protégées par leur jeton d'enrôlement ou leur jeton d'agent dédié, et non par une session humaine Supabase. Les routes de santé restent publiques et ne retournent pas de données sensibles.

## Configuration serveur

Le fichier serveur `.env` doit contenir au minimum :

```dotenv
SUPABASE_URL=https://<project-ref>.supabase.co
SUPABASE_PUBLISHABLE_KEY=sb_publishable_...
AGENT_ENROLLMENT_TOKEN=<secret-long-unique>
DATABASE_PATH=/data/congo_sec_vision.db
```

La clé publishable peut également être utilisée dans la configuration publique du frontend. Le jeton d'enrôlement reste strictement côté serveur.

## Tests

Depuis la racine du dépôt :

```bash
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
```

Les tests couvrent le refus d'un jeton invalide, les droits en lecture seule, les restrictions de l'équipe et les permissions de gestion des incidents.

## Limites et mise en production

Cette intégration fournit une authentification individuelle et un contrôle d'accès API par rôle. Elle ne constitue pas à elle seule une certification de sécurité ni un SOC prêt à exposer sur Internet. Avant production, ajouter et tester notamment le MFA, les sauvegardes, la supervision des sessions, une politique de révocation, une protection contre les tentatives répétées, une journalisation résistante à l'altération et une revue indépendante des permissions.
