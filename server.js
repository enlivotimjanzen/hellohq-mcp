// helloHQ MCP-Server (nur lesend)
// Stellt Claude Lese-Zugriff auf die helloHQ-API bereit.
import express from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

const {
  HELLOHQ_API_TOKEN,
  HELLOHQ_BASE_URL = "https://api.hellohq.io",
  MCP_SECRET,
  PORT = "3000",
} = process.env;

if (!HELLOHQ_API_TOKEN) {
  console.error("Fehler: HELLOHQ_API_TOKEN fehlt (siehe .env.example).");
  process.exit(1);
}
if (!MCP_SECRET || MCP_SECRET.length < 24) {
  console.error("Fehler: MCP_SECRET fehlt oder ist zu kurz (mind. 24 Zeichen).");
  process.exit(1);
}

const BASE = HELLOHQ_BASE_URL.replace(/\/+$/, "");
const MAX_CHARS = 60000; // Antworten begrenzen, damit Claude nicht überflutet wird

// Ruft die helloHQ-API ausschließlich per GET auf.
async function hqGet(path, query = {}) {
  if (!path.startsWith("/")) path = "/" + path;
  if (path.includes("..") || path.includes("//")) {
    throw new Error("Ungültiger Pfad.");
  }
  const url = new URL(BASE + path);
  for (const [k, v] of Object.entries(query)) {
    if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
  }
  // Sicherheitsnetz: Anfrage darf nur an den konfigurierten Host gehen.
  if (url.origin !== new URL(BASE).origin) throw new Error("Fremder Host blockiert.");

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${HELLOHQ_API_TOKEN}`,
      Accept: "application/json",
    },
  });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`helloHQ antwortete mit ${res.status}: ${text.slice(0, 500)}`);
  }
  return text;
}

function asResult(text) {
  let out = text;
  try {
    out = JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    /* kein JSON, Rohtext lassen */
  }
  if (out.length > MAX_CHARS) {
    out = out.slice(0, MAX_CHARS) + "\n…[gekürzt, bitte mit top/filter eingrenzen]";
  }
  return { content: [{ type: "text", text: out }] };
}

function asError(e) {
  return { isError: true, content: [{ type: "text", text: String(e.message || e) }] };
}

function buildServer() {
  const server = new McpServer({ name: "hellohq", version: "1.0.0" });

  server.registerTool(
    "hellohq_list",
    {
      title: "helloHQ: Datensätze auflisten",
      description:
        "Listet Datensätze einer helloHQ-Ressource (nur lesen). " +
        "Beispiele für resource: Projects, Companies, Users, Documents, Invoices. " +
        "Mit top/skip blätterst du, mit filter/orderby/expand grenzt du ein. " +
        "Die genaue Syntax hängt von der API-Version ab (v1 = OData, v2 = REST).",
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
        // v1 (OData) nutzt $-Präfix, v2 (REST) nicht.
        const p = version === "v1" ? "$" : "";
        const text = await hqGet(`/${version}/${resource}`, {
          [`${p}filter`]: filter,
          [`${p}orderby`]: orderby,
          [`${p}expand`]: expand,
          [`${p}top`]: top,
          [`${p}skip`]: skip,
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
      description:
        "Liest einen beliebigen API-Pfad per GET (nur lesen), z.B. /v2/Projects/123 oder " +
        "/v1/Invoices(456). Nutze das für einzelne Datensätze oder Endpunkte, die hellohq_list nicht abdeckt.",
      inputSchema: {
        path: z.string().regex(/^\/v[12]\/[A-Za-z0-9_\/()\-,'.$]+$/).describe("API-Pfad, beginnt mit /v1/ oder /v2/"),
        query: z.record(z.string(), z.string()).optional().describe("Optionale Query-Parameter"),
      },
      annotations: { readOnlyHint: true, openWorldHint: true },
    },
    async ({ path, query }) => {
      try {
        return asResult(await hqGet(path, query ?? {}));
      } catch (e) {
        return asError(e);
      }
    }
  );

  return server;
}

const app = express();
app.use(express.json({ limit: "1mb" }));

app.get("/health", (_req, res) => res.json({ ok: true }));

// Das Geheimnis steckt im Pfad: nur wer die vollständige URL kennt, kommt durch.
app.post(`/mcp/${MCP_SECRET}`, async (req, res) => {
  const server = buildServer();
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
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Interner Fehler" }, id: null });
    }
  }
});

// Zustandslos: GET/DELETE sind nicht nötig.
app.all(`/mcp/${MCP_SECRET}`, (_req, res) => res.status(405).set("Allow", "POST").end());

// Alles andere (inkl. falsches Geheimnis) liefert 404, ohne Hinweise.
app.use((_req, res) => res.status(404).end());

app.listen(Number(PORT), () => {
  console.log(`helloHQ-MCP läuft auf Port ${PORT}`);
  console.log(`Pfad: /mcp/<MCP_SECRET>  (Geheimnis wird nicht ausgegeben)`);
});
