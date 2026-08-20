/**
 * Guard: capabilities your app role holds that aren't tables.
 *
 * Every other guard asks what the app role can do to your *tables*. This asks
 * what else it can reach — because some grants make the table questions moot.
 *
 * Two families, deliberately at different severities, because they are not the
 * same kind of problem and pretending otherwise is how a tool gets ignored:
 *
 *   1. **RLS-bypassing capability → fails the build.** `dblink` opens a *new
 *      connection*, as whatever role the connection string names, and RLS on that
 *      connection has nothing to do with the caller's. `pg_read_file` and friends
 *      read the filesystem. If `authenticated` can EXECUTE these, tenant isolation
 *      is decorative: a user connects back to the same database as a privileged
 *      role and reads everything. Also here: **direct grants on the `auth`
 *      schema**, where every tenant's email and identity lives.
 *
 *   2. **Data-egress capability → a note, never a failure.** `pg_net.http_post`,
 *      the `http` extension: these let the database make outbound requests. That
 *      is a real risk — SSRF into your network, and exfiltration of whatever the
 *      caller can already see — but it is *not* a cross-tenant read, and this tool
 *      does not fail builds on findings it cannot stand behind as tenant
 *      isolation. It is surfaced, with that distinction stated.
 *
 * Catalog-only: privilege reads, no probing, no transaction. Nothing here is
 * executed — checking whether you *can* call `dblink` by calling it would be an
 * unusually poor idea.
 */
import { safeRole, DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';

export const meta = {
  id: 'role-capabilities',
  title: "Capabilities the app role holds beyond your tables",
  why: "Some grants make every table-level question moot: dblink opens a new connection as another role, so RLS on it has nothing to do with the caller's; file-read functions bypass the database entirely; and a direct grant on the auth schema hands over every tenant's email. Also surfaces outbound-HTTP capability, which is exfiltration rather than cross-tenant read, and says which is which.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: PROOF_DEFAULTS.role,
  allowlist: [], // "schema.function" or "auth.table" deliberately granted
  // Functions whose availability defeats RLS outright: a new connection under a
  // different identity, or a read that never touches the policy layer at all.
  rlsBypassFunctions: [
    'dblink', 'dblink_exec', 'dblink_open', 'dblink_fetch', 'dblink_connect',
    'pg_read_file', 'pg_read_binary_file', 'pg_ls_dir', 'pg_stat_file',
    'lo_import', 'lo_export',
  ],
  // Functions that let the database call out. Real, but egress — not a
  // cross-tenant read — so they are reported as notes.
  egressFunctions: ['http', 'http_get', 'http_post', 'http_put', 'http_delete', 'http_head', 'urlencode'],
  // Tables in the auth schema holding identity data for every tenant.
  authTables: ['users', 'identities', 'sessions', 'refresh_tokens', 'mfa_factors', 'flow_state'],
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Which of `names` the role may EXECUTE, whatever schema they live in. */
export function functionGrantsSql(names, role) {
  const text = `
    select n.nspname as schema,
           p.proname as name,
           pg_catalog.pg_get_function_identity_arguments(p.oid) as args,
           pg_catalog.has_function_privilege($2::text, p.oid, 'EXECUTE') as can_execute
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where p.proname = any($1)
    order by 1, 2`;
  return { text, values: [names, role] };
}

/** Which auth-schema tables the role may SELECT. */
export function authGrantsSql(tables, role) {
  const text = `
    select c.relname as table,
           pg_catalog.has_table_privilege($2::text, c.oid, 'SELECT') as can_select
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'auth'
      and c.relkind in ('r', 'p', 'v', 'm')
      and c.relname = any($1)
    order by 1`;
  return { text, values: [tables, role] };
}

/**
 * Verdict for one reachable function.
 * @returns {{status:'leak'|'note', kind:string, message:string, fix:string}}
 */
export function classifyFunction({ schema, name, args, family, role = 'authenticated' }) {
  const fqn = `${schema}.${name}(${args || ''})`;
  if (family === 'rls-bypass') {
    const why = /^dblink/.test(name)
      ? `dblink opens a NEW database connection as whatever role its connection string names. Row-level security on that connection has nothing to do with the caller's — so a user can connect back to this same database as a privileged role and read every tenant`
      : `this reads data outside the policy layer entirely (the filesystem, or large objects), so no RLS applies to what comes back`;
    return {
      status: 'leak',
      kind: 'rls-bypass',
      message: `"${role}" may EXECUTE ${fqn}. ${why}. Whatever your policies say, this is a way around them`,
      fix: `REVOKE EXECUTE ON FUNCTION ${fqn} FROM ${role}, PUBLIC;\n      (revoking from ${role} alone is a no-op if the grant lives on PUBLIC, which is Postgres's default for every new function.)`,
    };
  }
  return {
    status: 'note',
    kind: 'egress',
    message:
      `"${role}" may EXECUTE ${fqn}, so any logged-in user can make your database issue outbound HTTP requests — SSRF into whatever the database can reach, and exfiltration of anything the caller can already read. ` +
      `Reported as a note rather than a failure: it is not a cross-tenant READ, which is what this tool fails builds on. It is still worth revoking unless you meant it: REVOKE EXECUTE ON FUNCTION ${fqn} FROM ${role}, PUBLIC;`,
    fix: `REVOKE EXECUTE ON FUNCTION ${fqn} FROM ${role}, PUBLIC;`,
  };
}

/** Verdict for a readable auth-schema table. */
export function classifyAuthTable({ table, role = 'authenticated' }) {
  return {
    status: 'leak',
    kind: 'auth-schema',
    message:
      `"${role}" can SELECT auth.${table} directly. That is Supabase's identity store — every tenant's users, emails and identity records in one table, with no tenant column and no policy of yours in front of it. ` +
      `Any logged-in user can read the whole customer list`,
    fix:
      `REVOKE SELECT ON auth.${table} FROM ${role};\n` +
      `      Expose only what the app needs, from your own tables: copy the fields you want into a profiles table with RLS, kept in sync by a trigger on auth.users.`,
  };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;
  const skip = new Set(cfg.allowlist);

  const violations = [];
  const notes = [];
  let scanned = 0;

  const wanted = [...cfg.rlsBypassFunctions, ...cfg.egressFunctions];
  const fg = functionGrantsSql(wanted, role);
  for (const fn of await q(fg.text, fg.values)) {
    if (!(fn.can_execute === true || fn.can_execute === 't')) continue;
    if (skip.has(`${fn.schema}.${fn.name}`) || skip.has(fn.name)) continue;
    scanned++;
    const family = cfg.rlsBypassFunctions.includes(fn.name) ? 'rls-bypass' : 'egress';
    const v = classifyFunction({ schema: fn.schema, name: fn.name, args: fn.args, family, role });
    const where = `${fn.schema}.${fn.name}(${fn.args || ''})`;
    if (v.status === 'leak') violations.push({ where, kind: v.kind, message: v.message, fix: v.fix });
    else notes.push({ where, message: v.message });
  }

  // auth schema — absent on non-Supabase databases, which is not a finding.
  try {
    const ag = authGrantsSql(cfg.authTables, role);
    for (const t of await q(ag.text, ag.values)) {
      if (!(t.can_select === true || t.can_select === 't')) continue;
      if (skip.has(`auth.${t.table}`)) continue;
      scanned++;
      const v = classifyAuthTable({ table: t.table, role });
      violations.push({ where: `auth.${t.table}`, kind: v.kind, message: v.message, fix: v.fix });
    }
  } catch { /* no auth schema — not a Supabase project */ }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length > 0
        ? `${violations.length} capability/capabilities let "${role}" around your policies`
        : `no RLS-bypassing capability reachable by "${role}"` + (notes.length ? `; ${notes.length} note(s)` : ''),
  };
}

/** CLI/programmatic entry: resolve a connection, import `pg`, run the check. */
export async function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const url = cfg.url || process.env[cfg.urlEnv] || process.env.DATABASE_URL;
  if (!url) return OK({ skipped: true, reason: `no database configured — set ${cfg.urlEnv} (or DATABASE_URL)`, summary: 'skipped — no database' });
  let pg;
  try {
    pg = await import('pg');
  } catch {
    return OK({ skipped: true, reason: 'Postgres driver not installed — run `npm i -D pg`', summary: 'skipped — pg not installed' });
  }
  const Client = pg.default?.Client ?? pg.Client;
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    return await check({ query: (text, values) => client.query(text, values), config: cfg });
  } finally {
    await client.end();
  }
}
