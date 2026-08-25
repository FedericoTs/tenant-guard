/**
 * Guard: what did you hand an MCP server?
 *
 * An MCP server that touches your database is a standing, invokable connection
 * to it — and the ones that ship for Postgres and Supabase connect with a
 * service role or a personal access token, which **bypass RLS entirely**. Every
 * guarantee the runtime guards in this repo prove is irrelevant on that path.
 * `rls-proof` says so out loud when pointed at such a role: *"identity switch is
 * not enforcing RLS — refusing to report."*
 *
 * That is the honest framing, and it is why this guard is static and narrow. It
 * does not evaluate whether an agent will misuse a tool, and it says nothing
 * about prompt injection or tool poisoning — a hostile server putting
 * instructions in its tool descriptions is a real risk and a different
 * instrument entirely. Claiming otherwise would be pretending to cover something
 * this cannot see.
 *
 * What it CAN see is the config file, which is on disk, is frequently committed,
 * and routinely contains a credential in plain text:
 *
 *   • a service-role key or PAT written inline instead of referenced from the
 *     environment — the single most common finding, and it survives in git
 *     history long after the file is cleaned;
 *   • a Postgres URL handed to a server as a superuser or the `postgres`
 *     account, where a scoped read role would do;
 *   • a Supabase MCP server without `--read-only`, which is what stands between
 *     an agent and `apply_migration` on your production project.
 *
 * Calibration note: an `env` reference (`"${'$'}{SUPABASE_TOKEN}"`, `"env:FOO"`) is the
 * CORRECT shape and is never reported. Firing on those would hit every
 * well-configured project, which is how a guard gets switched off.
 */
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

export const meta = {
  id: 'mcp-config',
  title: 'Credentials and privilege handed to MCP servers',
  why: "An MCP server with a database connection is an invokable path to your data, and the Postgres/Supabase ones connect with a service role or PAT that bypasses RLS — so every isolation proof in this repo is silent on that path. The config file is on disk, is usually committed, and is where the credential ends up in plain text. Static and narrow on purpose: it reads config, it does not evaluate what an agent will do with a tool.",
};

export const DEFAULTS = {
  // Where MCP servers get configured, across the clients people actually use.
  configPaths: [
    '.mcp.json',
    '.cursor/mcp.json',
    '.vscode/mcp.json',
    'claude_desktop_config.json',
    '.claude/settings.json',
    '.claude/settings.local.json',
    '.windsurf/mcp.json',
    'mcp.json',
  ],
  allowlist: [], // server names that are configured this way on purpose
};

// ── what a credential looks like, and what a reference looks like ────

/**
 * A value that REFERENCES a secret rather than containing one.
 *
 * `${VAR}`, `$VAR`, `env:VAR`, and the `${input:...}` form VS Code uses. These
 * are the correct shape and must never be reported — an `env` block is what a
 * well-configured project looks like, and firing on it would make the guard
 * useless on exactly the projects that got it right.
 */
export function isEnvReference(value) {
  const v = String(value ?? '').trim();
  if (!v) return true;
  return /^\$\{[^}]+\}$/.test(v)
    || /^\$[A-Za-z_][A-Za-z0-9_]*$/.test(v)
    || /^env:/i.test(v)
    || /^\$\{input:[^}]+\}$/i.test(v)
    || /^\$\{env:[^}]+\}$/i.test(v);
}

/**
 * Does this literal look like a real credential?
 *
 * Shapes rather than entropy, so the reason is always explainable:
 *   • a Supabase service-role JWT — three base64url segments, and the middle one
 *     decodes to a payload naming the role;
 *   • a Supabase PAT (`sbp_`) or the newer publishable/secret keys;
 *   • a Postgres URL carrying an inline password.
 */
export function classifySecret(value) {
  const v = String(value ?? '');
  if (isEnvReference(v)) return null;

  if (/^sbp_[A-Za-z0-9]{20,}/.test(v)) return { kind: 'supabase-pat', what: 'a Supabase personal access token' };
  if (/^sb_secret_[A-Za-z0-9_-]{10,}/.test(v)) return { kind: 'supabase-secret-key', what: 'a Supabase secret key' };

  // A JWT: header.payload.signature. Decode the payload to say which role.
  const jwt = v.match(/^(eyJ[A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/);
  if (jwt) {
    let role = null;
    try {
      const pad = jwt[2].length % 4 ? '='.repeat(4 - (jwt[2].length % 4)) : '';
      const payload = JSON.parse(Buffer.from(jwt[2].replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64').toString('utf8'));
      role = payload?.role ?? null;
    } catch { /* not a JSON payload; still a literal JWT */ }
    if (role === 'service_role') return { kind: 'service-role-key', what: 'a Supabase SERVICE ROLE key, which bypasses RLS entirely' };
    if (role === 'anon') return { kind: 'anon-key', what: 'a Supabase anon key (public by design, but still a literal credential in a committed file)' };
    return { kind: 'jwt', what: 'a JWT' };
  }

  const pg = v.match(/^postgres(?:ql)?:\/\/([^:/@\s]+):([^@\s]+)@/i);
  if (pg && pg[2] && !isEnvReference(pg[2])) {
    return { kind: 'postgres-url-password', what: `a Postgres connection string with an inline password (user "${pg[1]}")`, user: pg[1] };
  }
  return null;
}

/** A Postgres URL whose user is an administrative account. */
export function adminConnection(value) {
  const m = String(value ?? '').match(/^postgres(?:ql)?:\/\/([^:/@\s]+)[:@]/i);
  if (!m) return null;
  const user = m[1].toLowerCase();
  if (['postgres', 'supabase_admin', 'root', 'admin', 'rds_superuser'].includes(user)) {
    return { user: m[1] };
  }
  return null;
}

// ── reading the configs ──────────────────────────────────────────────

/** Every string leaf in an object, with the path that reached it. */
export function stringLeaves(node, path = []) {
  const out = [];
  if (typeof node === 'string') return [{ path, value: node }];
  if (Array.isArray(node)) {
    node.forEach((v, i) => out.push(...stringLeaves(v, [...path, String(i)])));
    return out;
  }
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) out.push(...stringLeaves(v, [...path, k]));
  }
  return out;
}

/** The MCP server blocks in a parsed config, whatever client wrote it. */
export function extractServers(parsed) {
  const blocks = [parsed?.mcpServers, parsed?.servers, parsed?.mcp?.servers].filter(Boolean);
  const out = [];
  for (const b of blocks) {
    if (!b || typeof b !== 'object') continue;
    for (const [name, cfg] of Object.entries(b)) out.push({ name, cfg });
  }
  return out;
}

/**
 * A Supabase MCP server without `--read-only`.
 *
 * That flag is what stands between an agent and `apply_migration` /
 * `execute_sql` writing to the project. Reported as a NOTE, not a violation:
 * a write-capable server is a legitimate choice for a local branch, and the
 * config alone cannot tell which project it points at.
 */
export function supabaseWriteCapable({ name, cfg }) {
  const args = Array.isArray(cfg?.args) ? cfg.args.map(String) : [];
  const all = [String(cfg?.command ?? ''), ...args].join(' ').toLowerCase();
  if (!/supabase/.test(all) && !/supabase/i.test(name)) return false;
  return !args.some((a) => /^--read-only(=true)?$/i.test(a.trim()));
}

// ── the guard ────────────────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const cwd = cfg.cwd ?? process.cwd();
  const allow = new Set(cfg.allowlist ?? []);

  const found = [];
  for (const rel of cfg.configPaths) {
    const abs = join(cwd, rel);
    if (!existsSync(abs)) continue;
    try {
      if (statSync(abs).isDirectory()) continue;
      found.push({ rel, parsed: JSON.parse(readFileSync(abs, 'utf8')) });
    } catch (err) {
      // A config we cannot read is not a pass. Say which and why.
      found.push({ rel, error: err.message });
    }
  }

  if (found.length === 0) {
    return OK({ skipped: true, reason: 'no MCP config found in this project', summary: 'skipped — no MCP config' });
  }

  const violations = [];
  const notes = [];
  let scanned = 0;

  for (const f of found) {
    if (f.error) {
      notes.push({ where: f.rel, message: `could not parse this MCP config (${String(f.error).slice(0, 100)}) — it was NOT examined, so nothing here is proven about it.` });
      continue;
    }
    scanned++;
    const servers = extractServers(f.parsed);

    // Secrets anywhere in the file, server block or not — a credential in a
    // committed file is the finding regardless of which key holds it.
    for (const leaf of stringLeaves(f.parsed)) {
      const secret = classifySecret(leaf.value);
      if (!secret) continue;
      const at = leaf.path.join('.');
      if (allow.has(at) || leaf.path.some((p) => allow.has(p))) continue;
      if (secret.kind === 'anon-key' || secret.kind === 'jwt') {
        notes.push({ where: `${f.rel} (${at})`, message: `${secret.what}. Move it to an env reference so it is not committed.` });
        continue;
      }
      violations.push({
        where: `${f.rel} (${at})`,
        kind: 'mcp-inline-credential',
        message:
          `this MCP config contains ${secret.what}, written inline rather than referenced from the environment. ` +
          `MCP configs are routinely committed, and a credential in git history outlives any later cleanup of the file — rotation is the only fix once it is pushed. ` +
          (secret.kind === 'service-role-key'
            ? `A service-role key bypasses RLS completely, so every isolation proof in this repo is silent about what this server can reach.`
            : `Anyone who can read this file can act as whatever this credential authorises.`),
        fix:
          `Reference it instead of embedding it:\n` +
          `        "env": { "${String(leaf.path[leaf.path.length - 1] ?? 'TOKEN').toUpperCase()}": "\${YOUR_ENV_VAR}" }\n` +
          `      Then ROTATE the credential — it is in the file's history whether or not you commit the fix — and add this path to .gitignore if it holds anything per-developer.\n` +
          `      If this file is genuinely local-only and never committed, add "${at}" to mcpConfig.allowlist[] with that reason.`,
      });
    }

    for (const s of servers) {
      if (allow.has(s.name)) continue;

      // An administrative Postgres account handed to a server.
      for (const leaf of stringLeaves(s.cfg)) {
        const admin = adminConnection(leaf.value);
        if (!admin) continue;
        violations.push({
          where: `${f.rel} (server "${s.name}")`,
          kind: 'mcp-admin-connection',
          message:
            `MCP server "${s.name}" connects as "${admin.user}", an administrative account. It owns your tables, so it is exempt from their RLS unless FORCE ROW LEVEL SECURITY is set, and it can DROP them. ` +
            `Whatever this server exposes as a tool runs with that authority.`,
          fix:
            `Give it a scoped role instead, and let RLS apply to it:\n` +
            `        CREATE ROLE mcp_reader LOGIN PASSWORD '…';\n` +
            `        GRANT USAGE ON SCHEMA public TO mcp_reader;\n` +
            `        GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_reader;\n` +
            `      Then point tenant-guard at that role to check RLS actually applies to it:\n` +
            `        tenant-guard prove   # with rlsProof.role = "mcp_reader"\n` +
            `      If it comes back "identity switch is not enforcing RLS", the role is still exempt and the tools are unscoped.`,
        });
        break;
      }

      if (supabaseWriteCapable(s)) {
        notes.push({
          where: `${f.rel} (server "${s.name}")`,
          message:
            `Supabase MCP server "${s.name}" is configured without --read-only, so an agent using it can call apply_migration and execute_sql against the project it points at. ` +
            `Fine for a local branch, and worth being deliberate about for anything shared: add "--read-only" to its args.`,
        });
      }
    }
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length > 0
        ? `${violations.length} credential/privilege problem(s) in ${scanned} MCP config(s)`
        : `${scanned} MCP config(s) checked` + (notes.length ? `; ${notes.length} note(s)` : '; nothing inline'),
  };
}
