# Congo Sec Vision Desktop

Application de bureau Tauri 2 réutilisant l'interface web officielle et l'authentification Supabase.

## Cibles de compilation

- Windows 10/11 : installateurs MSI et NSIS (.exe).
- Ubuntu et Kali Linux : paquets DEB et AppImage.
- macOS : image disque DMG.

Kali Linux et Ubuntu partagent les formats Linux ; le paquet doit être construit sur une distribution Linux compatible et testé sur les versions cibles. La compilation macOS doit être signée/notarisée avant une distribution publique de confiance.

## Compilation locale

Prérequis : Rust stable, Node.js 20+, et dépendances système Tauri 2.

Depuis ce dossier :

```bash
npm install
npm run tauri -- build
```

La configuration web est fournie par `web/config.js` au moment de la compilation. Il faut renseigner dans GitHub Actions les variables `API_BASE_URL`, `SUPABASE_URL` et `SUPABASE_PUBLISHABLE_KEY`. L'API FastAPI doit déjà être déployée en HTTPS ; GitHub Pages ne l'héberge pas.

## Sécurité et distribution

Ne jamais intégrer de clé Supabase `service_role`, de jeton administrateur ou de secret d'enrôlement dans l'application desktop. La clé publishable est publique. Les installateurs produits par les builds CI sont des artefacts de test tant qu'ils ne sont pas signés (certificat de signature Windows et Developer ID/Notarization Apple).
