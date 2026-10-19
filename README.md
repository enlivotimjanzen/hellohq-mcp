# helloHQ MCP-Server (nur lesend)

Gibt Claude lesenden Zugriff auf die helloHQ-API. Tools:

- `hellohq_list`: Datensätze einer Ressource auflisten (Projects, Companies, Users, Documents, Invoices …)
- `hellohq_get`: einen einzelnen Datensatz bzw. Pfad lesen (nur GET, nur /v1/ und /v2/)

Es gibt bewusst keine Schreib-Tools.

## Lokal starten

```bash
cd hellohq-mcp
npm install
cp .env.example .env
openssl rand -hex 24        # Ausgabe als MCP_SECRET in .env eintragen
# HELLOHQ_API_TOKEN in .env eintragen
npm start
```

Test: `curl http://localhost:3000/health` liefert `{"ok":true}`.

## Von Claude erreichbar machen (Tunnel)

```bash
brew install cloudflared
cloudflared tunnel --url http://localhost:3000
```

Die ausgegebene URL `https://xyz.trycloudflare.com` plus Pfad ergibt die Konnektor-URL:

```
https://xyz.trycloudflare.com/mcp/<dein MCP_SECRET>
```

Diese URL in claude.ai unter Einstellungen > Konnektoren > Benutzerdefinierten Konnektor hinzufügen eintragen.
Behandle die URL wie ein Passwort, sie enthält das Geheimnis.

## Hinweise

- `.env` nie weitergeben. Bei Verdacht auf Leck: MCP_SECRET ändern, Server neu starten, URL neu eintragen.
- helloHQ v2: User-Token mit begrenzten Rechten verwenden (laut Doku werden Nutzerrechte in v2 nicht geprüft).
- Die Tunnel-URL ändert sich bei jedem Neustart von cloudflared.
- Docker: `docker build -t hellohq-mcp .` und mit `--env-file .env -p 3000:3000` starten.
