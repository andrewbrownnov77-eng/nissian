/**
 * Spec parsers — enumerate the endpoints an application *claims* to have.
 *
 * A crawl only finds what it can reach. To report coverage honestly we also
 * need the ground truth of what exists: an OpenAPI spec, a GraphQL introspection
 * result, or a sitemap. Each parser produces a normalized Endpoint set that the
 * coverage diff can compare against what we actually exercised.
 */

export interface Endpoint {
  method: string;
  /** Path with variable segments normalized to {param}. */
  pathTemplate: string;
  /** Where this endpoint was declared, for the report. */
  source: "openapi" | "graphql" | "sitemap";
  /** Optional note, e.g. a GraphQL operation name or an OpenAPI summary. */
  note?: string;
}

/** Normalize a concrete path so /user/123 and /user/456 collapse to one template. */
export function normalizePath(path: string): string {
  return path
    .split("/")
    .map((seg) => {
      if (/^[0-9]+$/.test(seg)) return "{id}";
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(seg)) return "{uuid}";
      if (/^[0-9a-f]{24,}$/i.test(seg)) return "{hash}";
      return seg;
    })
    .join("/");
}

/** OpenAPI 3.x: paths → methods. Path templates already use {param}. */
export function parseOpenApi(spec: unknown): Endpoint[] {
  const out: Endpoint[] = [];
  const paths = (spec as any)?.paths;
  if (!paths || typeof paths !== "object") return out;

  const METHODS = ["get", "post", "put", "patch", "delete", "head", "options"];
  for (const [path, ops] of Object.entries(paths)) {
    if (!ops || typeof ops !== "object") continue;
    for (const method of METHODS) {
      const op = (ops as any)[method];
      if (op) {
        out.push({
          method: method.toUpperCase(),
          pathTemplate: canonicalizeTemplate(path),
          source: "openapi",
          note: op.summary || op.operationId || undefined,
        });
      }
    }
  }
  return out;
}

/** GraphQL introspection: each query/mutation field becomes a pseudo-endpoint. */
export function parseGraphQLIntrospection(introspection: unknown): Endpoint[] {
  const out: Endpoint[] = [];
  const schema = (introspection as any)?.data?.__schema ?? (introspection as any)?.__schema;
  if (!schema) return out;

  const typeByName = new Map<string, any>();
  for (const t of schema.types ?? []) typeByName.set(t.name, t);

  const roots: Array<["query" | "mutation", string | undefined]> = [
    ["query", schema.queryType?.name],
    ["mutation", schema.mutationType?.name],
  ];
  for (const [kind, typeName] of roots) {
    if (!typeName) continue;
    const type = typeByName.get(typeName);
    for (const field of type?.fields ?? []) {
      out.push({
        method: kind === "mutation" ? "MUTATION" : "QUERY",
        pathTemplate: `graphql:${field.name}`,
        source: "graphql",
        note: field.description || undefined,
      });
    }
  }
  return out;
}

/** sitemap.xml: each <loc> becomes a GET endpoint. */
export function parseSitemap(xml: string): Endpoint[] {
  const out: Endpoint[] = [];
  for (const m of xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)) {
    try {
      const u = new URL(m[1]);
      out.push({ method: "GET", pathTemplate: normalizePath(u.pathname), source: "sitemap" });
    } catch {
      // skip malformed URLs
    }
  }
  return out;
}

/** OpenAPI templates use {name}; normalize the *name* so comparison is stable. */
function canonicalizeTemplate(path: string): string {
  return path.replace(/\{[^}]+\}/g, "{id}");
}

/** De-duplicate endpoints by method+template, keeping the first note seen. */
export function dedupeEndpoints(endpoints: Endpoint[]): Endpoint[] {
  const seen = new Map<string, Endpoint>();
  for (const e of endpoints) {
    const key = `${e.method} ${e.pathTemplate}`;
    if (!seen.has(key)) seen.set(key, e);
  }
  return [...seen.values()];
}
