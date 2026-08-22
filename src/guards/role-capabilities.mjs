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
 * Reachability takes TWO catalog answers, not one. `has_function_privilege` /
 * `has_table_privilege` answer "is the object privilege there", not "can the role
 * get at it": without USAGE on the containing schema the call or the read is
 * refused outright. Measured in pglite — `grant select on auth.users to
 * authenticated` with no `grant usage on schema auth` gives has_table_privilege =
 * true while the read errors `permission denied for schema auth`. That pair is a
 * latent grant, not a leak, so it is a note: one `GRANT USAGE` away from real, and
 * never a build failure while nothing is reachable.
 *
 * The REVOKE advice is built from the ACL rather than from the role name, because
 * has_*_privilege is membership-transitive and REVOKE is not. Measured: with
 * `grant execute on ext.dblink to db_helpers; grant db_helpers to authenticated`,
 * `REVOKE EXECUTE ... FROM authenticated, PUBLIC` runs clean, reports no error,
 * and the privilege is still there afterwards. So the fix names the grantees that
 * actually hold it — PUBLIC included, which is where a table grant usually hides.
 *
 * Catalog-only: privilege reads, no probing, no transaction. Nothing here is
 * executed — checking whether you *can* call `dblink` by calling it would be an
 * unusually poor idea.
 */
import { safeRole, quoteIdent, DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';

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
  //
  // Only functions that issue the request belong here. `urlencode` was on this
  // list and was wrong: it is pgsql-http's percent-encoder, pure string work, no
  // I/O. It keeps the default PUBLIC EXECUTE that every extension helper keeps,
  // so on a database where outbound HTTP had actually been revoked the guard
  // still printed "any logged-in user can make your database issue outbound HTTP
  // requests" about a function that cannot issue one. pg_net's `net.http_post`
  // is still covered, by the `http_post` name.
  egressFunctions: ['http', 'http_get', 'http_post', 'http_put', 'http_delete', 'http_head'],
  // Tables in the auth schema holding identity data for every tenant.
  authTables: ['users', 'identities', 'sessions', 'refresh_tokens', 'mfa_factors', 'flow_state'],
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/**
 * Which of `names` the role may EXECUTE, whatever schema they live in.
 *
 * Three answers per row, not one: the object privilege, USAGE on the containing
 * schema (without it the call is refused whatever the object ACL says), and the
 * grantees that actually confer EXECUTE on this role — PUBLIC (grantee 0) or a
 * role the target inherits from. That last column is what lets the REVOKE in the
 * fix name something that is really there.
 */
export function functionGrantsSql(names, role) {
  const text = `
    select n.nspname as schema,
           p.proname as name,
           pg_catalog.pg_get_function_identity_arguments(p.oid) as args,
           pg_catalog.has_function_privilege($2::text, p.oid, 'EXECUTE') as can_execute,
           pg_catalog.has_schema_privilege($2::text, n.oid, 'USAGE') as schema_usage,
           p.proacl is null as acl_default,
           (select coalesce(array_agg(distinct g.name), array[]::text[]) from (
              select case when a.grantee = 0 then 'PUBLIC'
                          else pg_catalog.pg_get_userbyid(a.grantee) end as name
                from pg_catalog.aclexplode(p.proacl) a
               where a.privilege_type = 'EXECUTE'
                 and (a.grantee = 0 or pg_catalog.pg_has_role($2::text, a.grantee, 'USAGE'))
            ) g) as grantees
    from pg_catalog.pg_proc p
    join pg_catalog.pg_namespace n on n.oid = p.pronamespace
    where p.proname = any($1)
    order by 1, 2`;
  return { text, values: [names, role] };
}

/** Which auth-schema tables the role may SELECT — same three answers. */
export function authGrantsSql(tables, role) {
  const text = `
    select c.relname as table,
           pg_catalog.has_table_privilege($2::text, c.oid, 'SELECT') as can_select,
           pg_catalog.has_schema_privilege($2::text, n.oid, 'USAGE') as schema_usage,
           c.relacl is null as acl_default,
           (select coalesce(array_agg(distinct g.name), array[]::text[]) from (
              select case when a.grantee = 0 then 'PUBLIC'
                          else pg_catalog.pg_get_userbyid(a.grantee) end as name
                from pg_catalog.aclexplode(c.relacl) a
               where a.privilege_type = 'SELECT'
                 and (a.grantee = 0 or pg_catalog.pg_has_role($2::text, a.grantee, 'USAGE'))
            ) g) as grantees
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'auth'
      and c.relkind in ('r', 'p', 'v', 'm')
      and c.relname = any($1)
    order by 1`;
  return { text, values: [tables, role] };
}

// Grantee names in the ACL are raw catalog identifiers, and a REVOKE naming one
// wrongly does not half-apply — it fails outright. `MyRole` unquoted folds to
// `myrole` and errors 42704; `user` and `group` are grantee keywords. So quote
// anything that is not already a plain lowercase identifier, and never quote
// PUBLIC, which is a keyword in this position and not a role name.
const NEEDS_QUOTES = new Set(['public', 'current_user', 'session_user', 'current_role', 'user', 'group', 'none']);
const identRef = (name) =>
  name === 'PUBLIC' || (/^[a-z_][a-z0-9_$]*$/.test(name) && !NEEDS_QUOTES.has(name))
    ? name
    : quoteIdent(name);

/**
 * Order the grantees for a REVOKE: the role itself first (that is the name the
 * reader is looking for), then whatever it inherits through, PUBLIC last.
 * Deterministic, so the fix text does not shuffle between runs.
 */
function orderGrantees(grantees, role) {
  const seen = [...new Set(grantees.filter((g) => typeof g === 'string' && g.length > 0))];
  const others = seen.filter((g) => g !== role && g !== 'PUBLIC').sort();
  return [
    ...(seen.includes(role) ? [role] : []),
    ...others,
    ...(seen.includes('PUBLIC') ? ['PUBLIC'] : []),
  ];
}

/**
 * The REVOKE line, plus whatever caveat the ACL says it needs.
 *
 * `grantees` is the measured list of who actually confers the privilege on this
 * role; pass null when it was not read and the text falls back to naming the role
 * and PUBLIC, which is the best guess available, and says so. Every name emitted
 * comes out of the catalog — a REVOKE listing a role this database does not have
 * fails with 42704 and applies none of the statement.
 *
 * @returns {string}
 */
export function revokeAdvice({ verb, object, role, grantees = null }) {
  const stmt = (names) => `REVOKE ${verb} ON ${object} FROM ${names.map(identRef).join(', ')};`;
  if (!Array.isArray(grantees)) {
    return (
      `${stmt([role, 'PUBLIC'])}\n` +
      `      (naming ${role} alone is a no-op when the grant lives on PUBLIC — Postgres's default for every new function. ` +
      `And if ${role} holds this through membership in another role, neither name is the one that has it: check with \\du ${role}, then revoke from the role that does, or REVOKE <that role> FROM ${role}.)`
    );
  }
  const ordered = orderGrantees(grantees, role);
  if (ordered.length === 0) {
    return (
      `Nothing in the ACL confers this on ${role}, yet the privilege reads as held — so ${role} is not going through the grant system at all: a SUPERUSER, or the object's owner, whose privileges are implicit. ` +
      `No REVOKE takes that away; change the role instead, once you have confirmed which it is with \\du ${role}:\n` +
      `      ALTER ROLE ${role} NOSUPERUSER;`
    );
  }
  const indirect = ordered.filter((g) => g !== role && g !== 'PUBLIC');
  let out = stmt(ordered);
  if (indirect.length > 0) {
    const via = indirect.join(', ');
    out +=
      `\n      (${role} does not hold this directly — it inherits it through membership in ${via}, and has_*_privilege follows membership while REVOKE does not. ` +
      `Measured: revoking from ${role} alone runs clean, reports no error, and leaves the privilege exactly where it was. ` +
      `If ${via} needs the privilege for its own work, take the membership away instead: REVOKE ${indirect.map(identRef).join(', ')} FROM ${identRef(role)};)`;
  } else if (ordered.length === 1 && ordered[0] === 'PUBLIC') {
    out += `\n      (the grant is on PUBLIC, not on ${role} — revoking from ${role} would run clean and change nothing.)`;
  }
  return out;
}

/**
 * Verdict for one function the role holds the EXECUTE bit on.
 *
 * `schemaUsage === false` downgrades to a note whatever the family: the object
 * privilege is there, the schema is shut, so nothing is reachable and there is
 * nothing to fail a build over. `undefined` means the caller did not measure it,
 * and the old behaviour stands.
 *
 * @returns {{status:'leak'|'note', kind:string, message:string, fix:string}}
 */
export function classifyFunction({
  schema, name, args, family, role = 'authenticated', grantees = null, schemaUsage = undefined,
}) {
  const fqn = `${schema}.${name}(${args || ''})`;
  const revoke = revokeAdvice({ verb: 'EXECUTE', object: `FUNCTION ${fqn}`, role, grantees });

  if (schemaUsage === false) {
    return {
      status: 'note',
      kind: 'latent-capability',
      message:
        `"${role}" is granted EXECUTE on ${fqn}, but holds no USAGE on schema ${schema}, so the call is refused today: "permission denied for schema ${schema}". ` +
        `A note, not a failure — nothing is reachable, and this tool does not fail builds on access that does not exist. ` +
        `It is one GRANT USAGE ON SCHEMA ${schema} away from being real, with the EXECUTE grant already sitting there, so it is worth clearing: ${revoke.split('\n')[0]}`,
      fix: revoke,
    };
  }

  if (family === 'rls-bypass') {
    const why = /^dblink/.test(name)
      ? `dblink opens a NEW database connection as whatever role its connection string names. Row-level security on that connection has nothing to do with the caller's — so a user can connect back to this same database as a privileged role and read every tenant`
      : `this reads data outside the policy layer entirely (the filesystem, or large objects), so no RLS applies to what comes back`;
    return {
      status: 'leak',
      kind: 'rls-bypass',
      message: `"${role}" may EXECUTE ${fqn}. ${why}. Whatever your policies say, this is a way around them`,
      fix: revoke,
    };
  }
  return {
    status: 'note',
    kind: 'egress',
    message:
      `"${role}" may EXECUTE ${fqn}, so any logged-in user can make your database issue outbound HTTP requests — SSRF into whatever the database can reach, and exfiltration of anything the caller can already read. ` +
      `Reported as a note rather than a failure: it is not a cross-tenant READ, which is what this tool fails builds on. It is still worth revoking unless you meant it: ${revoke.split('\n')[0]}`,
    fix: revoke,
  };
}

/** Verdict for an auth-schema table the role holds the SELECT bit on. */
export function classifyAuthTable({
  table, role = 'authenticated', grantees = null, schemaUsage = undefined,
}) {
  const revoke = revokeAdvice({ verb: 'SELECT', object: `auth.${table}`, role, grantees });
  const profiles =
    'Expose only what the app needs, from your own tables: copy the fields you want into a profiles table with RLS, kept in sync by a trigger on auth.users.';

  if (schemaUsage === false) {
    return {
      status: 'note',
      kind: 'latent-capability',
      message:
        `"${role}" is granted SELECT on auth.${table}, but holds no USAGE on schema auth, so the read is refused today: "permission denied for schema auth". ` +
        `A note, not a failure — the identity store is not reachable, and this tool does not fail builds on access that does not exist. ` +
        `One GRANT USAGE ON SCHEMA auth would make it real, with the SELECT grant already sitting there, so clear the grant: ${revoke.split('\n')[0]}`,
      fix: `${revoke}\n      ${profiles}`,
    };
  }

  return {
    status: 'leak',
    kind: 'auth-schema',
    message:
      `"${role}" can SELECT auth.${table} directly. That is Supabase's identity store — every tenant's users, emails and identity records in one table, with no tenant column and no policy of yours in front of it. ` +
      `Any logged-in user can read the whole customer list`,
    fix: `${revoke}\n      ${profiles}`,
  };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

const isTrue = (v) => v === true || v === 't';
const isFalse = (v) => v === false || v === 'f';

/**
 * The grantees for one catalog row, or null when the column is not there (an
 * older server, or a caller passing hand-rolled rows) so the advice falls back to
 * its guess. A null ACL means the built-in default is in force: for functions
 * that is EXECUTE to PUBLIC — the grant people miss, and the one worth naming —
 * for tables it is nothing to PUBLIC at all.
 */
function granteesOf(row, publicByDefault) {
  if (isTrue(row.acl_default)) return publicByDefault ? ['PUBLIC'] : [];
  if (!Array.isArray(row.grantees)) return null;
  return row.grantees;
}

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
    if (!isTrue(fn.can_execute)) continue;
    if (skip.has(`${fn.schema}.${fn.name}`) || skip.has(fn.name)) continue;
    scanned++;
    const family = cfg.rlsBypassFunctions.includes(fn.name) ? 'rls-bypass' : 'egress';
    const v = classifyFunction({
      schema: fn.schema,
      name: fn.name,
      args: fn.args,
      family,
      role,
      grantees: granteesOf(fn, true),
      schemaUsage: isFalse(fn.schema_usage) ? false : undefined,
    });
    const where = `${fn.schema}.${fn.name}(${fn.args || ''})`;
    if (v.status === 'leak') violations.push({ where, kind: v.kind, message: v.message, fix: v.fix });
    else notes.push({ where, message: v.message });
  }

  // auth schema — absent on non-Supabase databases, which is not a finding: the
  // query joins pg_class to pg_namespace, so a database with no auth schema
  // returns zero rows rather than an error. That means this catch only fires on
  // a real failure, and a real failure has to say so — a check that could not run
  // is not a check that passed.
  try {
    const ag = authGrantsSql(cfg.authTables, role);
    for (const t of await q(ag.text, ag.values)) {
      if (!isTrue(t.can_select)) continue;
      if (skip.has(`auth.${t.table}`)) continue;
      scanned++;
      const v = classifyAuthTable({
        table: t.table,
        role,
        grantees: granteesOf(t, false),
        schemaUsage: isFalse(t.schema_usage) ? false : undefined,
      });
      const where = `auth.${t.table}`;
      if (v.status === 'leak') violations.push({ where, kind: v.kind, message: v.message, fix: v.fix });
      else notes.push({ where, message: v.message });
    }
  } catch (err) {
    notes.push({
      where: 'auth.*',
      message:
        `The auth-schema check did not run: ${err?.message ?? err}. Nothing about auth.users was tested here, so treat this run as silent on it, not clear of it. ` +
        `A database with no auth schema does not reach this — that case returns zero rows — so this is a query or permission failure worth looking at.`,
    });
  }

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
