#!/bin/bash
# Génère le compte du dashboard au premier démarrage (mot de passe aléatoire,
# conservé dans le volume lab-secrets ; affiché par « make password »).
set -euo pipefail
SECRETS=/lab-secrets
umask 077
if [ ! -f "$SECRETS/dashboard_password" ]; then
    python3 -c 'import secrets; print(secrets.token_urlsafe(12))' > "$SECRETS/dashboard_password"
fi
[ -f "$SECRETS/dashboard_secret_key" ] || python3 -c 'import secrets; print(secrets.token_hex(32))' > "$SECRETS/dashboard_secret_key"
python3 - <<'PY'
from werkzeug.security import generate_password_hash
pw = open('/lab-secrets/dashboard_password').read().strip()
open('/home/server/dashboard/auth.conf', 'w').write('admin:' + generate_password_hash(pw) + '\n')
PY
export DASHBOARD_SECRET_KEY="$(cat "$SECRETS/dashboard_secret_key")"
exec python3 /home/server/dashboard/app.py
