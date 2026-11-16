// Configuration publique du client web. Ces valeurs ne sont pas des secrets.
// Ne jamais placer ici une clé service_role ou une clé secrète.
// Use the same-origin API for local WSL/Docker, and the hosted API elsewhere.
window.CSV_API_BASE = ["localhost", "127.0.0.1"].includes(window.location.hostname) ? "" : "https://congo-sec-vision-enterprise.onrender.com";
window.CSV_SUPABASE_URL = "https://gyxbkutmgcnsmytodfst.supabase.co";
window.CSV_SUPABASE_PUBLISHABLE_KEY = "sb_publishable_uYCvhXXMKIjijJYGToQ8hg_YggvrK47";
