// helloHQ MCP-Server v2.0
// Zwei Zugänge nebeneinander:
//  1) Alt (Legacy): POST /mcp/<MCP_SECRET> mit gemeinsamem Token (wie v1.1), läuft unverändert weiter.
//  2) Neu (OAuth):  POST /mcp mit Anmeldung pro Person über helloHQ v1 (OAuth 2.0), Rollenprüfung im Server.
import express from "express";
import crypto from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
 
const {
  // Legacy
  HELLOHQ_API_TOKEN,
  MCP_SECRET,
  ENABLE_WRITE = "false",
  WRITE_ALLOWED_RESOURCES = "Projects,Companies,ContactPersons,UserReportings,WorkingTimes,PlannedRevenues",
  HELLOHQ_V2_PARAM_PREFIX = "",
  // Gemeinsam
  HELLOHQ_BASE_URL = "https://api.hellohq.io",
  PORT = "3000",
  // OAuth
  PUBLIC_BASE_URL, // z.B. https://hellohq-mcp.<umgebung>.germanywestcentral.azurecontainerapps.io
  TOKEN_KEY, // mind. 32 Zeichen, verschlüsselt alle Tokens
  HELLOHQ_APP_ID, // {customer-id}-{client-id} aus helloHQ, Admin, API-Apps
  HELLOHQ_APP_SECRET,
  HELLOHQ_AUTH_URL = "https://api.hqlabs.de/Account/Authorize",
  HELLOHQ_TOKEN_URL = "https://api.hqlabs.de/Token",
  // Rollen: {"default":"team","users":{"vorname.nachname":"gf","42":"finance"}}
  ROLES_JSON = '{"default":"team","users":{}}',
  ALLOWED_REDIRECT_HOSTS = "claude.ai,claude.com",
} = process.env;
 
const VERSION = "2.0.0";
 
const LEGACY_ON = Boolean(HELLOHQ_API_TOKEN) && Boolean(MCP_SECRET) && MCP_SECRET.length >= 24;
const OAUTH_ON =
  Boolean(PUBLIC_BASE_URL) && Boolean(TOKEN_KEY) && TOKEN_KEY.length >= 32 && Boolean(HELLOHQ_APP_ID) && Boolean(HELLOHQ_APP_SECRET);
 
if (MCP_SECRET && MCP_SECRET.length < 24) {
  console.error("Fehler: MCP_SECRET ist zu kurz (mind. 24 Zeichen).");
  process.exit(1);
}
if (!LEGACY_ON && !OAUTH_ON) {
  console.error(
    "Fehler: Weder Legacy (HELLOHQ_API_TOKEN + MCP_SECRET) noch OAuth (PUBLIC_BASE_URL, TOKEN_KEY, HELLOHQ_APP_ID, HELLOHQ_APP_SECRET) ist vollständig konfiguriert."
  );
  process.exit(1);
}
 
const BASE = HELLOHQ_BASE_URL.replace(/\/+$/, "");
const PUBLIC = (PUBLIC_BASE_URL || "").replace(/\/+$/, "");
const MAX_CHARS = 60000;
const WRITE_ENABLED = ENABLE_WRITE === "true";
const WRITE_RESOURCES = new Set(WRITE_ALLOWED_RESOURCES.split(",").map((s) => s.trim()).filter(Boolean));
 
// ---------------------------------------------------------------------------------------------
// Gemeinsame Helfer
// ---------------------------------------------------------------------------------------------
 
async function hqRequest(method, path, { query = {}, body, token = HELLOHQ_API_TOKEN } = {}) {
  if (!["GET", "POST", "PUT", "PATCH"].includes(method)) throw new Error("Methode nicht erlaubt.");
  if (!path.startsWith("/")) path = "/" + path;
  if (path.includes("..") || path.includes("//")) throw new Error("Ungültiger Pfad.");
  const url = new URL(BASE + path);
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  if (url.origin !== new URL(BASE).origin) throw new Error("Fremder Host blockiert.");
  const headers = { Authorization: `Bearer ${token}`, Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(url, { method, headers, body: body !== undefined ? JSON.stringify(body) : undefined });
  const text = await res.text();
  if (!res.ok) throw new Error(`helloHQ antwortete mit ${res.status}: ${text.slice(0, 500)}`);
  return { status: res.status, text };
}
 
function asResult(text) {
  let out = text;
  try {
    out = JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    /* kein JSON */
  }
  if (!out) out = "(leere Antwort)";
  if (out.length > MAX_CHARS) out = out.slice(0, MAX_CHARS) + "\n…[gekürzt, bitte mit top/filter eingrenzen]";
  return { content: [{ type: "text", text: out }] };
}
 
function asError(e) {
  return { isError: true, content: [{ type: "text", text: String(e.message || e) }] };
}
 
function auditWrite(entry) {
  console.log(JSON.stringify({ t: new Date().toISOString(), event: "write", ...entry }));
}
 
// ---------------------------------------------------------------------------------------------
// Legacy-Server (gemeinsamer Token, unverändert zu v1.1)
// ---------------------------------------------------------------------------------------------
 
function buildLegacyServer() {
  const server = new McpServer({ name: "hellohq", version: VERSION });
 
  server.registerTool(
    "hellohq_info",
    {
      title: "helloHQ: Fähigkeiten des Servers",
      description: "Zeigt, ob Schreibzugriff aktiv ist und welche Ressourcen beschrieben werden dürfen.",
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () =>
      asResult(
        JSON.stringify({
          version: VERSION,
          modus: "gemeinsamer Zugang",
          schreibzugriff: WRITE_ENABLED,
          schreibbare_ressourcen: WRITE_ENABLED ? [...WRITE_RESOURCES] : [],
          loeschen: false,
          v2_parameter_praefix: HELLOHQ_V2_PARAM_PREFIX || "(keins)",
        })
      )
  );
 
  server.registerTool(
    "hellohq_list",
    {
      title: "helloHQ: Datensätze auflisten",
      description:
        "Listet Datensätze einer helloHQ-Ressource (nur lesen). Beispiele: Projects, Companies, ContactPersons, ContactHistories, Tasks, UserReportings, WorkingTimes, Documents, PlannedRevenues, Users. " +
        "Mit top/skip blätterst du, mit filter/orderby/expand grenzt du ein. v1 = OData, v2 = REST.",
      inputSchema: {
        resource: z.string().regex(/^[A-Za-z0-9_\/]+$/).describe("Ressourcenname, z.B. Projects"),
        version: z.enum(["v1", "v2"]).default("v2").describe("API-Version"),
        filter: z.string().optional().describe("Filterausdruck"),
        orderby: z.string().optional().describe("Sortierung"),
        expand: z.string().optional().describe("Verknüpfte Daten einbeziehen"),
        top: z.number().int().min(1).max(200).default(25).describe("Max. Anzahl Ergebnisse"),
        skip: z.number().int().min(0).default(0).describe("Anzahl zu überspringender Ergebnisse"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ resource, version, filter, orderby, expand, top, skip }) => {
      try {
        const p = version === "v1" ? "$" : HELLOHQ_V2_PARAM_PREFIX;
        const text = (
          await hqRequest("GET", `/${version}/${resource}`, {
            query: { [`${p}filter`]: filter, [`${p}orderby`]: orderby, [`${p}expand`]: expand, [`${p}top`]: top, [`${p}skip`]: skip },
          })
        ).text;
        return asResult(text);
      } catch (e) {
        return asError(e);
      }
    }
  );
 
  server.registerTool(
    "hellohq_get",
    {
      title: "helloHQ: Einzelnen Datensatz oder Pfad lesen",
      description: "Liest einen beliebigen API-Pfad per GET (nur lesen), z.B. /v2/Projects/123 oder /v1/Invoices(456).",
      inputSchema: {
        path: z.string().regex(/^\/v[12]\/[A-Za-z0-9_\/()\-,'.$]+$/).describe("API-Pfad, beginnt mit /v1/ oder /v2/"),
        query: z.record(z.string(), z.string()).optional().describe("Optionale Query-Parameter"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ path, query }) => {
      try {
        return asResult((await hqRequest("GET", path, { query: query ?? {} })).text);
      } catch (e) {
        return asError(e);
      }
    }
  );
 
  if (WRITE_ENABLED) {
    server.registerTool(
      "hellohq_write",
      {
        title: "helloHQ: Daten anlegen oder ändern",
        description:
          "Legt Datensätze an (POST) oder ändert sie (PUT/PATCH) in helloHQ v2. Löschen ist nicht möglich. " +
          `Erlaubte Ressourcen: ${[...WRITE_RESOURCES].join(", ")}. ` +
          "Vor dem Schreiben den Datensatz ansehen und die Änderung dem Nutzer kurz nennen.",
        inputSchema: {
          method: z.enum(["POST", "PUT", "PATCH"]).describe("POST = anlegen, PUT/PATCH = ändern"),
          path: z
            .string()
            .regex(/^\/v2\/[A-Za-z]+(\/[A-Za-z0-9_-]+){0,5}$/)
            .describe("API-Pfad, beginnt mit /v2/"),
          body: z.record(z.string(), z.any()).optional().describe("JSON-Inhalt der Anfrage"),
        },
        annotations: { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true },
      },
      async ({ method, path, body }) => {
        try {
          const resource = path.split("/")[2];
          if (!WRITE_RESOURCES.has(resource)) throw new Error(`Schreiben auf "${resource}" ist nicht freigegeben.`);
          const { status, text } = await hqRequest(method, path, { body: body ?? undefined });
          auditWrite({ mode: "legacy", method, path, status, felder: Object.keys(body ?? {}) });
          return asResult(text || JSON.stringify({ ok: true, status }));
        } catch (e) {
          auditWrite({ mode: "legacy", method, path, fehler: String(e.message || e).slice(0, 200) });
          return asError(e);
        }
      }
    );
  }
  return server;
}
 
// ---------------------------------------------------------------------------------------------
// OAuth: Verschlüsselte, zustandslose Tokens (AES-256-GCM)
// ---------------------------------------------------------------------------------------------
 
const KEY = OAUTH_ON ? crypto.createHash("sha256").update(TOKEN_KEY).digest() : null;
const nowSec = () => Math.floor(Date.now() / 1000);
 
function seal(type, data, ttlSec) {
  const payload = JSON.stringify({ t: type, exp: nowSec() + ttlSec, d: data });
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", KEY, iv);
  const enc = Buffer.concat([c.update(payload, "utf8"), c.final()]);
  return Buffer.concat([iv, c.getAuthTag(), enc]).toString("base64url");
}
 
function unseal(type, blob) {
  try {
    const b = Buffer.from(String(blob), "base64url");
    if (b.length < 30) return null;
    const d = crypto.createDecipheriv("aes-256-gcm", KEY, b.subarray(0, 12));
    d.setAuthTag(b.subarray(12, 28));
    const p = JSON.parse(Buffer.concat([d.update(b.subarray(28)), d.final()]).toString("utf8"));
    if (p.t !== type || p.exp < nowSec()) return null;
    return p.d;
  } catch {
    return null;
  }
}
 
// Autorisierungscodes dürfen nur einmal eingelöst werden (Speicher im Prozess, genügt bei einer Instanz).
const usedCodes = new Map();
function markCodeUsed(code) {
  const h = crypto.createHash("sha256").update(code).digest("hex");
  const t = nowSec();
  for (const [k, exp] of usedCodes) if (exp < t) usedCodes.delete(k);
  if (usedCodes.has(h)) return false;
  usedCodes.set(h, t + 600);
  return true;
}
 
function redirectAllowed(uri) {
  try {
    const u = new URL(uri);
    if (u.protocol === "https:" && ALLOWED_REDIRECT_HOSTS.split(",").map((s) => s.trim()).includes(u.hostname)) return true;
    if (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1")) return true;
  } catch {
    /* ungültig */
  }
  return false;
}
 
// Token-Anfrage an helloHQ (Code gegen Token tauschen oder Refresh)
async function hqToken(params) {
  const basic = "Basic " + Buffer.from(`${HELLOHQ_APP_ID}:${HELLOHQ_APP_SECRET}`).toString("base64");
  const attempts = [
    { url: HELLOHQ_TOKEN_URL, body: new URLSearchParams({ ...params, client_id: HELLOHQ_APP_ID, client_secret: HELLOHQ_APP_SECRET }).toString() },
    { url: HELLOHQ_TOKEN_URL + "?" + new URLSearchParams(params).toString(), body: "" },
  ];
  let last = "unbekannt";
  for (const a of attempts) {
    try {
      const res = await fetch(a.url, {
        method: "POST",
        headers: { Authorization: basic, "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
        body: a.body,
      });
      const text = await res.text();
      if (res.ok) {
        const j = JSON.parse(text);
        if (j.access_token) return j;
        last = "keine access_token-Antwort";
      } else {
        last = String(res.status);
      }
    } catch (e) {
      last = String(e.message || e).slice(0, 80);
    }
  }
  throw new Error(`helloHQ Token-Anfrage fehlgeschlagen (${last})`);
}
 
// ---------------------------------------------------------------------------------------------
// Rollen
// ---------------------------------------------------------------------------------------------
 
let ROLE_CFG = { default: "team", users: {} };
try {
  ROLE_CFG = { default: "team", users: {}, ...JSON.parse(ROLES_JSON) };
} catch {
  console.error("Warnung: ROLES_JSON ist kein gültiges JSON, es gilt die Rolle 'team' für alle.");
}
 
const TEAM_RESOURCES = [
  "Companies", "CompanyTypes", "CompanyTypeToCompanies", "ContactPersons", "ContactHistories", "Projects", "ProjectTasks",
  "ProjectStatuses", "ProjectRoles", "ProjectTemplates", "UserReportings", "Users", "Me", "Files", "CustomFieldDefinitions",
  "TaskTypes", "PublicHolidays", "Leads", "LeadStatuses", "Subsystem", "DocumentTemplates",
];
const FINANCE_RESOURCES = [
  "Quotations", "Invoices", "CreditNotes", "DeliveryNotes", "IncomingInvoices", "PlannedRevenues", "PlannedCosts",
  "ProjectBudgets", "Articles", "ArticleStorages", "FinancesCostTypes", "DocumentConditions", "InternalCompanies",
];
// Begriffe, die in expand/filter/orderby nur für Finanzrollen erlaubt sind
const FINANCE_WORDS = ["quotation", "invoice", "creditnote", "deliverynote", "plannedrevenue", "plannedcost", "projectbudget", "article", "financescosttype", "documentcondition"];
 
const ROLES = {
  team: { all: false, finance: false, res: new Set(TEAM_RESOURCES.map((s) => s.toLowerCase())) },
  finance: { all: false, finance: true, res: new Set([...TEAM_RESOURCES, ...FINANCE_RESOURCES].map((s) => s.toLowerCase())) },
  gf: { all: true, finance: true, res: new Set() },
};
 
function roleFor(userName, userId) {
  const u = ROLE_CFG.users || {};
  const name = String(userName || "").toLowerCase();
  const found = Object.entries(u).find(([k]) => k.toLowerCase() === name || k === String(userId));
  const roleName = found ? found[1] : ROLE_CFG.default;
  return { name: roleName, def: ROLES[roleName] || null };
}
 
function checkResource(role, resource) {
  if (!role.def) throw new Error("Für dich ist keine Rolle eingerichtet.");
  if (role.def.all) return;
  if (!role.def.res.has(String(resource).toLowerCase())) {
    throw new Error(`Kein Zugriff auf "${resource}" mit der Rolle "${role.name}".`);
  }
}
 
function checkText(role, text) {
  if (!role.def) throw new Error("Für dich ist keine Rolle eingerichtet.");
  if (!text || role.def.finance) return;
  const low = String(text).toLowerCase();
  if (FINANCE_WORDS.some((w) => low.includes(w))) {
    throw new Error(`Die Abfrage enthält Finanzdaten, die mit der Rolle "${role.name}" nicht erlaubt sind.`);
  }
}
 
// ---------------------------------------------------------------------------------------------
// OAuth-Server (personenbezogen, v1)
// ---------------------------------------------------------------------------------------------
 
function buildOAuthServer(session, role) {
  const server = new McpServer({ name: "hellohq", version: VERSION });
  const audit = (resource, extra = {}) =>
    console.log(JSON.stringify({ t: new Date().toISOString(), event: "read", user: session.un, role: role.name, resource, ...extra }));
 
  server.registerTool(
    "hellohq_info",
    {
      title: "helloHQ: Wer bin ich und was darf ich",
      description: "Zeigt den angemeldeten helloHQ-Nutzer, die Rolle und die erlaubten Ressourcen. Zuerst aufrufen, wenn unklar ist, was möglich ist.",
      inputSchema: {},
      annotations: { readOnlyHint: true, openWorldHint: false },
    },
    async () =>
      asResult(
        JSON.stringify({
          version: VERSION,
          angemeldet_als: session.un,
          nutzer_id: session.uid,
          rolle: role.name,
          erlaubte_ressourcen: role.def ? (role.def.all ? "alle" : [...role.def.res]) : [],
          api: "v1 (OData)",
          schreibzugriff: false,
        })
      )
  );
 
  server.registerTool(
    "hellohq_list",
    {
      title: "helloHQ: Datensätze auflisten",
      description:
        "Listet Datensätze einer helloHQ-Ressource (nur lesen, API v1, OData). Beispiele: Companies, ContactPersons, ContactHistories, Projects, UserReportings, Users. " +
        "Mit top/skip blätterst du, mit filter/orderby/expand grenzt du ein. Es gelten die Rechte deiner Rolle.",
      inputSchema: {
        resource: z.string().regex(/^[A-Za-z0-9_]+$/).describe("Ressourcenname, z.B. Projects"),
        filter: z.string().optional().describe("OData-Filter, z.B. CompanyId eq 123"),
        orderby: z.string().optional().describe("Sortierung, z.B. CreatedOn desc"),
        expand: z.string().optional().describe("Verknüpfte Daten einbeziehen"),
        top: z.number().int().min(1).max(200).default(25).describe("Max. Anzahl Ergebnisse"),
        skip: z.number().int().min(0).default(0).describe("Anzahl zu überspringender Ergebnisse"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ resource, filter, orderby, expand, top, skip }) => {
      try {
        checkResource(role, resource);
        checkText(role, expand);
        checkText(role, filter);
        checkText(role, orderby);
        audit(resource);
        const { text } = await hqRequest("GET", `/v1/${resource}`, {
          token: session.a,
          query: { $filter: filter, $orderby: orderby, $expand: expand, $top: top, $skip: skip },
        });
        return asResult(text);
      } catch (e) {
        return asError(e);
      }
    }
  );
 
  server.registerTool(
    "hellohq_get",
    {
      title: "helloHQ: Einzelnen Datensatz oder Pfad lesen",
      description: "Liest einen API-Pfad per GET (nur lesen, API v1), z.B. /v1/Projects(123) oder /v1/Companies(456)/Addresses.",
      inputSchema: {
        path: z.string().regex(/^\/v1\/[A-Za-z0-9_\/()\-,'.$]+$/).describe("API-Pfad, beginnt mit /v1/"),
        query: z.record(z.string(), z.string()).optional().describe("Optionale Query-Parameter, z.B. {\"$expand\":\"Addresses\"}"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ path, query }) => {
      try {
        const m = path.match(/^\/v1\/([A-Za-z0-9_]+)/);
        if (!m) throw new Error("Ungültiger Pfad.");
        checkResource(role, m[1]);
        for (const [k, v] of Object.entries(query ?? {})) {
          checkText(role, k);
          checkText(role, v);
        }
        audit(m[1], { path: path.length > 120 ? path.slice(0, 120) : path });
        return asResult((await hqRequest("GET", path, { token: session.a, query: query ?? {} })).text);
      } catch (e) {
        return asError(e);
      }
    }
  );
 
  return server;
}
 
// ---------------------------------------------------------------------------------------------
// Express
// ---------------------------------------------------------------------------------------------
 
const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false, limit: "100kb" }));
 
app.get("/health", (_req, res) => res.json({ ok: true, version: VERSION }));
 
async function handleMcp(req, res, server) {
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
  res.on("close", () => {
    transport.close();
    server.close();
  });
  try {
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (e) {
    console.error("MCP-Fehler:", e.message);
    if (!res.headersSent) res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Interner Fehler" }, id: null });
  }
}
 
if (LEGACY_ON) {
  app.post(`/mcp/${MCP_SECRET}`, (req, res) => handleMcp(req, res, buildLegacyServer()));
  app.all(`/mcp/${MCP_SECRET}`, (_req, res) => res.status(405).set("Allow", "POST").end());
}
 
if (OAUTH_ON) {
  // Metadaten für Claude (Erkennung des Anmeldedienstes)
  app.get(["/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"], (_req, res) =>
    res.json({ resource: `${PUBLIC}/mcp`, authorization_servers: [PUBLIC], bearer_methods_supported: ["header"] })
  );
  app.get(["/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp"], (_req, res) =>
    res.json({
      issuer: PUBLIC,
      authorization_endpoint: `${PUBLIC}/authorize`,
      token_endpoint: `${PUBLIC}/token`,
      registration_endpoint: `${PUBLIC}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
    })
  );
 
  // Registrierung von Clients (zustandslos: die erlaubten Rücksprung-Adressen stecken verschlüsselt in der client_id)
  app.post("/register", (req, res) => {
    const uris = Array.isArray(req.body?.redirect_uris) ? req.body.redirect_uris : [];
    if (!uris.length || uris.length > 10 || !uris.every((u) => typeof u === "string" && redirectAllowed(u))) {
      return res.status(400).json({ error: "invalid_redirect_uri" });
    }
    const client_id = seal("client", { ru: uris }, 365 * 86400);
    res.status(201).json({
      client_id,
      redirect_uris: uris,
      client_name: String(req.body?.client_name || "MCP Client").slice(0, 80),
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
    });
  });
 
  // Schritt 1: Claude schickt die Person hierher, wir leiten weiter zur Anmeldung bei helloHQ
  app.get("/authorize", (req, res) => {
    const q = req.query;
    const client = unseal("client", q.client_id);
    const ru = String(q.redirect_uri || "");
    if (!client || !client.ru.includes(ru)) return res.status(400).type("text").send("Ungültiger Client oder Rücksprung-Adresse.");
    if (q.response_type !== "code" || !q.code_challenge || q.code_challenge_method !== "S256") {
      return res.status(400).type("text").send("Ungültige Anfrage (PKCE S256 erforderlich).");
    }
    const state = seal("st", { ru, st: String(q.state || ""), cc: String(q.code_challenge) }, 600);
    const target = new URL(HELLOHQ_AUTH_URL);
    target.searchParams.set("response_type", "code");
    target.searchParams.set("client_id", HELLOHQ_APP_ID);
    target.searchParams.set("state", state);
    target.searchParams.set("redirect_uri", `${PUBLIC}/oauth/callback`);
    target.searchParams.set("scope", "read_all write_all");
    res.redirect(302, target.toString());
  });
 
  // Schritt 2: helloHQ schickt die Person mit einem Code zurück
  app.get("/oauth/callback", async (req, res) => {
    const st = unseal("st", req.query.state);
    if (!st) return res.status(400).type("text").send("Ungültiger oder abgelaufener Anmeldevorgang. Bitte in Claude erneut verbinden.");
    const back = (params) => {
      const u = new URL(st.ru);
      for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") u.searchParams.set(k, v);
      return u.toString();
    };
    if (req.query.error || !req.query.code) return res.redirect(302, back({ error: "access_denied", state: st.st }));
    try {
      const t = await hqToken({
        grant_type: "authorization_code",
        code: String(req.query.code),
        redirect_uri: `${PUBLIC}/oauth/callback`,
        scope: "read_all write_all",
      });
      const code = seal(
        "code",
        { a: t.access_token, r: t.refresh_token, e: t.expires_in, uid: t.user_id, un: t.user_name, cc: st.cc, ru: st.ru },
        300
      );
      console.log(JSON.stringify({ t: new Date().toISOString(), event: "login", user: t.user_name }));
      res.redirect(302, back({ code, state: st.st }));
    } catch (e) {
      console.error("Anmeldefehler:", e.message);
      res.redirect(302, back({ error: "server_error", state: st.st }));
    }
  });
 
  // Schritt 3: Claude tauscht den Code (oder das Refresh-Token) gegen Tokens
  function issue(a, r, expiresIn, uid, un) {
    const ttl = Math.max(60, Math.min(Number(expiresIn) || 1199, 3600) - 30);
    return {
      access_token: seal("access", { a, uid, un }, ttl),
      token_type: "Bearer",
      expires_in: ttl,
      refresh_token: seal("refresh", { r, uid, un }, 90 * 86400),
    };
  }
 
  app.post("/token", async (req, res) => {
    res.set("Cache-Control", "no-store");
    const b = req.body || {};
    try {
      if (b.grant_type === "authorization_code") {
        const d = unseal("code", b.code);
        if (!d) return res.status(400).json({ error: "invalid_grant" });
        if (!markCodeUsed(String(b.code))) return res.status(400).json({ error: "invalid_grant" });
        if (String(b.redirect_uri || "") !== d.ru) return res.status(400).json({ error: "invalid_grant" });
        const challenge = crypto.createHash("sha256").update(String(b.code_verifier || "")).digest("base64url");
        if (!b.code_verifier || challenge !== d.cc) return res.status(400).json({ error: "invalid_grant" });
        return res.json(issue(d.a, d.r, d.e, d.uid, d.un));
      }
      if (b.grant_type === "refresh_token") {
        const d = unseal("refresh", b.refresh_token);
        if (!d) return res.status(400).json({ error: "invalid_grant" });
        const t = await hqToken({ grant_type: "refresh_token", refresh_token: d.r });
        return res.json(issue(t.access_token, t.refresh_token || d.r, t.expires_in, t.user_id ?? d.uid, t.user_name ?? d.un));
      }
      return res.status(400).json({ error: "unsupported_grant_type" });
    } catch (e) {
      console.error("Token-Fehler:", e.message);
      return res.status(400).json({ error: "invalid_grant" });
    }
  });
 
  // Der eigentliche MCP-Zugang mit Anmeldung
  const unauthorized = (res) =>
    res
      .status(401)
      .set("WWW-Authenticate", `Bearer resource_metadata="${PUBLIC}/.well-known/oauth-protected-resource"`)
      .json({ error: "unauthorized" });
 
  app.post("/mcp", (req, res) => {
    const h = String(req.headers.authorization || "");
    const m = h.match(/^Bearer\s+(.+)$/i);
    const session = m ? unseal("access", m[1]) : null;
    if (!session) return unauthorized(res);
    const role = roleFor(session.un, session.uid);
    return handleMcp(req, res, buildOAuthServer(session, role));
  });
  app.all("/mcp", (_req, res) => res.status(405).set("Allow", "POST").end());
}
 
app.use((_req, res) => res.status(404).end());
 
app.listen(Number(PORT), () => {
  console.log(`helloHQ-MCP ${VERSION} läuft auf Port ${PORT}`);
  console.log(`Zugang gemeinsam (Legacy): ${LEGACY_ON ? "an" : "aus"}, Anmeldung pro Person (OAuth): ${OAUTH_ON ? "an" : "aus"}`);
  if (LEGACY_ON) console.log(`Legacy-Pfad: /mcp/<MCP_SECRET>  (Geheimnis wird nicht ausgegeben)`);
  if (LEGACY_ON) console.log(`Schreibzugriff (Legacy): ${WRITE_ENABLED ? "AN (" + [...WRITE_RESOURCES].join(", ") + ")" : "aus"}`);
});
 
