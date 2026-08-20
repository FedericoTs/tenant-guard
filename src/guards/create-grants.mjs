/**
 * Guard: who can plant objects in your database.
 *
 * Threat-model §7.3. `CREATE` on a schema is not a tenant leak by itself — it is
 * the **precondition that turns other things into escalations**, and it is the
 * quietest privilege in Postgres because nothing about it looks like data access.
 *
 * What it enables:
 *
 *   - **Object shadowing.** A `SECURITY DEFINER` function with an unpinned
 *     `search_path` resolves unqualified names through the *caller's* path. A
 *     caller who can CREATE plants a table or function earlier on that path, and
 *     the definer function operates on **their** object while executing as its
 *     owner, with RLS bypassed. That is CVE-2018-1058's shape, and it is why
 *     Postgres 15 stopped granting `CREATE` on `public` to `PUBLIC` by default.
 *   - **Creating schemas outright** (`CREATE` on the *database*) is strictly
 *     stronger: you can make a schema and put it first on the path, rather than
 *     hoping an existing one is writable.
 *
 * **Deliberately not a duplicate of §4.4.** `definer-rpc` already fails when an
 * unpinned definer function exists *and* the app role can CREATE — it reports the
 * function, and the fix is to pin the path. This guard reports the *grant*, whose
 * fix is to revoke it, and covers the three things §4.4 structurally cannot see:
 *
 *   1. the grant when there is **no** definer function yet — a standing
 *      precondition that arms the next one somebody writes without `SET search_path`
 *   2. **`anon`** — §4.4 only ever evaluates the configured app role
 *   3. **`CREATE` on the database**, which is about schemas rather than objects
 *
 * Catalog-only. Nothing is created, and nothing is executed.
 */
import { safeRole, DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';
import { searchPathPinned } from './definer-rpc.mjs';

export const meta = {
  id: 'create-grants',
  title: 'Who can plant objects in your database',
  why: "CREATE on a schema is not a leak by itself — it is the precondition that turns an unpinned SECURITY DEFINER search_path into privilege escalation, because you can only shadow an object if you can create one. It is reported here even when no definer function exists yet, since the grant arms the next one somebody writes; and for the anonymous role and the database itself, neither of which the definer-RPC check evaluates.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: PROOF_DEFAULTS.role,
  schemas: ['public'],
  // Roles that must never be able to create anything. An unauthenticated client
  // planting objects in your database is not a legitimate configuration.
  unauthenticatedRoles: ['anon'],
  allowlist: [], // "schema:role" or "database:role" granted on purpose
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/**
 * Which of these roles hold CREATE on which schemas, and how they hold it.
 *
 * `can_create` is the EFFECTIVE privilege, which is what actually matters — but
 * it is true both for a grant to the role and for a grant to PUBLIC, and those
 * have different fixes. `direct_can_create` separates them, so a role with its
 * own grant is not told to revoke from PUBLIC and left still holding it.
 */
export function schemaCreateGrantsSql(roles, schemas) {
  return {
    text: `
      select
        n.nspname as schema,
        r.rolname as role,
        pg_catalog.has_schema_privilege(r.oid, n.oid, 'CREATE') as can_create,
        coalesce((
          select true from aclexplode(n.nspacl) a
          where a.grantee = 0 and a.privilege_type = 'CREATE' limit 1
        ), false) as public_can_create,
        coalesce((
          select true from aclexplode(n.nspacl) a
          where a.grantee = r.oid and a.privilege_type = 'CREATE' limit 1
        ), false) as direct_can_create
      from pg_catalog.pg_namespace n
      cross join pg_catalog.pg_roles r
      where n.nspname = any($2)
        and r.rolname = any($1)
    `,
    values: [roles, schemas],
  };
}

/** CREATE on the database itself — the right to make new schemas. */
export function databaseCreateGrantsSql(roles) {
  return {
    text: `
      select
        r.rolname as role,
        pg_catalog.has_database_privilege(r.oid, d.oid, 'CREATE') as can_create,
        coalesce((
          select true
          from aclexplode(d.datacl) a
          where a.grantee = 0 and a.privilege_type = 'CREATE'
          limit 1
        ), false) as public_can_create
      from pg_catalog.pg_database d
      cross join pg_catalog.pg_roles r
      where d.datname = current_database()
        and r.rolname = any($1)
    `,
    values: [roles],
  };
}

/** Definer functions and whether their search_path is pinned — the §4.4 link. */
export function definerSearchPathSql(schemas) {
  return {
    text: `
      select n.nspname as schema, p.proname as name, p.proconfig as config
      from pg_catalog.pg_proc p
      join pg_catalog.pg_namespace n on n.oid = p.pronamespace
      where p.prosecdef and n.nspname = any($1)
    `,
    values: [schemas],
  };
}

/** Postgres 15 stopped granting CREATE on `public` to PUBLIC. Used for context only. */
export function serverVersionSql() {
  return { text: `select current_setting('server_version_num')::int as v`, values: [] };
}

/** How many definer functions would be hijackable if someone could plant an object. */
export function unpinnedDefiners(rows) {
  return (rows ?? []).filter((r) => !searchPathPinned(r.config)).map((r) => `${r.schema}.${r.name}`);
}

/**
 * The verdict for one role's CREATE privilege.
 *
 * `anon` and `PUBLIC` fail: neither is a legitimate holder of the right to plant
 * objects, and `PUBLIC` additionally covers every role that will ever exist. The
 * app role is a note — plenty of small projects run migrations as it, so whether
 * it is wrong depends on an architecture SQL cannot see, and the exploitable
 * *combination* is already owned by §4.4.
 */
export function classifyCreateGrant({
  role, scope, where, viaPublic = false, unpinned = [], unauthenticatedRoles = [], serverVersion = 0, appRole = '',
}) {
  const target = scope === 'database' ? `the database (i.e. can create new SCHEMAS)` : `schema "${where}"`;
  const isAnon = unauthenticatedRoles.includes(role);

  // The link to §4.4, stated rather than re-reported as a second failure.
  const armed = unpinned.length > 0
    ? ` There ${unpinned.length === 1 ? 'is' : 'are'} ${unpinned.length} SECURITY DEFINER function(s) here with an unpinned search_path (${unpinned.slice(0, 2).join(', ')}${unpinned.length > 2 ? ', …' : ''}), so this is exploitable NOW — \`tenant-guard rpc\` reports the same root cause from the function side, where the fix is to pin the path instead.`
    : ` No SECURITY DEFINER function currently has an unpinned search_path, so nothing is exploitable today — but this grant arms the next one somebody writes without \`SET search_path\`, and no diff will show a security change when they do.`;

  const revoke = scope === 'database'
    ? `REVOKE CREATE ON DATABASE ${'<your database>'} FROM ${viaPublic ? 'PUBLIC' : role};`
    : `REVOKE CREATE ON SCHEMA ${where} FROM ${viaPublic ? 'PUBLIC' : role};`;
  const fix =
    `${revoke}\n` +
    `      Objects should be created by your migration role, not by the role your app connects as.\n` +
    `      If this is deliberate, add "${scope === 'database' ? 'database' : where}:${viaPublic ? 'PUBLIC' : role}" to createGrants.allowlist[] with a reason.`;

  if (viaPublic) {
    const versionNote = serverVersion > 0 && serverVersion < 150000 && where === 'public'
      ? ` This is the pre-Postgres-15 default: version 15 removed it precisely because of this escalation, so on ${serverVersion} you have to revoke it yourself.`
      : '';
    return {
      status: 'leak',
      kind: 'public-create',
      message:
        `PUBLIC holds CREATE on ${target}, so EVERY role can plant objects there — including roles that ` +
        `do not exist yet.${versionNote}${armed}`,
      fix,
    };
  }

  if (isAnon) {
    return {
      status: 'leak',
      kind: 'anon-create',
      message:
        `the unauthenticated role "${role}" holds CREATE on ${target}. An anonymous client being able to ` +
        `create objects in your database is not a legitimate configuration under any architecture: at ` +
        `minimum it is unbounded writes by strangers, and it is the precondition for shadowing an ` +
        `object that a SECURITY DEFINER function will then run as its owner.${armed}`,
      fix,
    };
  }

  return {
    status: 'note',
    message:
      `"${role}" holds CREATE on ${target}. That is legitimate if this is also the role your migrations ` +
      `run as, and a problem if it is only the role your app connects as — SQL cannot tell which.` +
      `${armed}`,
  };
}

// ── the guard ────────────────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const q = async (text, values) => (await query(text, values)).rows;
  const appRole = safeRole(cfg.role);
  const allow = new Set(cfg.allowlist);

  const roles = [...new Set([appRole, ...cfg.unauthenticatedRoles])];
  const violations = [];
  const notes = [];
  let scanned = 0;

  // Context: which definer functions this grant would arm (§4.4's domain).
  let unpinned = [];
  try {
    const spec = definerSearchPathSql(cfg.schemas);
    unpinned = unpinnedDefiners(await q(spec.text, spec.values));
  } catch { /* optional context, never fatal */ }

  let serverVersion = 0;
  try {
    serverVersion = (await q(serverVersionSql().text, []))[0]?.v ?? 0;
  } catch { /* context only */ }

  const emit = (verdict, where) => {
    if (verdict.status === 'leak') violations.push({ where, kind: verdict.kind, message: verdict.message, fix: verdict.fix });
    else if (verdict.status === 'note') notes.push({ where, message: verdict.message });
  };

  // ── schemas ────────────────────────────────────────────────────────
  const schemaSpec = schemaCreateGrantsSql(roles, cfg.schemas);
  const schemaRows = await q(schemaSpec.text, schemaSpec.values);
  const publicSeen = new Set();
  const schemasSeen = new Set();
  for (const row of schemaRows) {
    // `scanned` counts SCHEMAS, not (schema, role) pairs — the query returns one
    // row per pair, and it is part of the published JSON contract.
    schemasSeen.add(row.schema);

    // A grant to PUBLIC is one finding about the schema, not one per role.
    if (row.public_can_create && !publicSeen.has(row.schema) && !allow.has(`${row.schema}:PUBLIC`)) {
      publicSeen.add(row.schema);
      emit(
        classifyCreateGrant({ role: 'PUBLIC', scope: 'schema', where: row.schema, viaPublic: true, unpinned, serverVersion, appRole, unauthenticatedRoles: cfg.unauthenticatedRoles }),
        `${row.schema}:PUBLIC`,
      );
    }

    // A role may ALSO hold its own grant. Revoking from PUBLIC would not touch
    // it, so it is a separate finding with a separate fix — reported only when
    // the grant is direct, which is what keeps this from doubling up.
    const reportRole = row.public_can_create ? row.direct_can_create : row.can_create;
    if (reportRole && !allow.has(`${row.schema}:${row.role}`)) {
      emit(
        classifyCreateGrant({ role: row.role, scope: 'schema', where: row.schema, unpinned, serverVersion, appRole, unauthenticatedRoles: cfg.unauthenticatedRoles }),
        `${row.schema}:${row.role}`,
      );
    }
  }
  scanned = schemasSeen.size;

  // ── the database itself ────────────────────────────────────────────
  try {
    const dbSpec = databaseCreateGrantsSql(roles);
    const dbRows = await q(dbSpec.text, dbSpec.values);
    let publicDone = false;
    for (const row of dbRows) {
      if (row.public_can_create && !publicDone && !allow.has('database:PUBLIC')) {
        publicDone = true;
        emit(
          classifyCreateGrant({ role: 'PUBLIC', scope: 'database', viaPublic: true, unpinned, serverVersion, appRole, unauthenticatedRoles: cfg.unauthenticatedRoles }),
          'database:PUBLIC',
        );
        continue;
      }
      if (row.public_can_create) continue;
      if (row.can_create && !allow.has(`database:${row.role}`)) {
        emit(
          classifyCreateGrant({ role: row.role, scope: 'database', unpinned, serverVersion, appRole, unauthenticatedRoles: cfg.unauthenticatedRoles }),
          `database:${row.role}`,
        );
      }
    }
  } catch { /* not every deployment exposes pg_database.datacl */ }

  if (scanned === 0) {
    return OK({
      skipped: true,
      reason: 'none of the target schemas exist, or none of the configured roles do',
      summary: 'skipped — nothing to check',
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
        ? `${violations.length} role(s) can plant objects that a definer function would run as its owner`
        : `CREATE privileges checked on ${scanned} schema(s)` + (notes.length ? `; ${notes.length} note(s)` : ''),
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
