/**
 * Guard: what a table created TOMORROW will inherit.
 *
 * Threat-model §7.2. Every other guard in this tool answers a question about the
 * database as it is now. This one is about the database as it will be, because
 * `ALTER DEFAULT PRIVILEGES` makes a green run **conditional** in a way nothing
 * else here reveals:
 *
 *     ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO anon;
 *
 * From that moment, every table created afterwards carries the grant. Postgres
 * never enables row-level security by default, so the day somebody adds a table
 * and forgets `ENABLE ROW LEVEL SECURITY`, it is readable the instant it exists
 * — with no migration, no diff, and no guard failing, because at the time this
 * tool last ran the table did not exist. That is the CVE-2025-48757 shape,
 * pre-armed and waiting for the next `create table`.
 *
 * **It proves rather than infers.** Reading `pg_default_acl` and reasoning about
 * what it implies gets the interaction with schema grants, role membership and
 * `FOR ROLE` wrong in exactly the cases that matter. So instead the guard
 * *creates a table inside a transaction it rolls back* and reads what that table
 * actually inherited. The answer is a fact about this database, not a deduction.
 *
 * **Calibration.** This condition is latent: nothing is exposed until somebody
 * creates a table. It is also, for `anon`/`authenticated` in `public`, the stock
 * configuration of a Supabase project — so failing the build on it would fire on
 * essentially every user of the platform this tool targets, which is how a
 * security tool gets deleted. The default therefore fails only on **PUBLIC**,
 * which is every role that exists or ever will, and is nobody's platform
 * default. Everything else is a **note** that states plainly what the next table
 * will inherit. `failRoles` is the knob for teams that want it stricter.
 */
import { safeRole, DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';

export const meta = {
  id: 'default-privileges',
  title: 'What a table created tomorrow will inherit',
  why: "ALTER DEFAULT PRIVILEGES grants on every table created AFTER it — and Postgres never enables RLS by default. So a green run says nothing about the table somebody adds next week: it arrives already granted, with no policy, exposed the instant it exists, and no migration diff shows a security change. This guard creates a table in a rolled-back transaction and reports what it actually inherited.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: PROOF_DEFAULTS.role,
  schemas: ['public'],
  // Roles whose inherited access fails the build. PUBLIC is every role that
  // exists or ever will; no platform ships that as a default.
  failRoles: ['PUBLIC'],
  // Reported first and worded hardest, but a note by default — see the header.
  unauthenticatedRoles: ['anon'],
  probeTable: 'tg_default_privileges_probe',
  allowlist: [], // "schema" or "schema:role" that inherits on purpose
};

/** Privileges that read or change rows, as opposed to schema-level plumbing. */
const DATA_PRIVILEGES = new Set(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']);
const WRITE_PRIVILEGES = new Set(['INSERT', 'UPDATE', 'DELETE', 'TRUNCATE']);

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** The configured defaults, for explaining a finding rather than deciding it. */
export function defaultAclSql(schemas) {
  return {
    text: `
      select
        pg_get_userbyid(d.defaclrole)                                   as creator,
        coalesce(n.nspname, '(all schemas)')                            as schema,
        d.defaclobjtype                                                 as objtype,
        case when a.grantee = 0 then 'PUBLIC'
             else pg_get_userbyid(a.grantee) end                        as grantee,
        a.privilege_type                                                as privilege
      from pg_default_acl d
      left join pg_namespace n on n.oid = d.defaclnamespace
      cross join lateral aclexplode(d.defaclacl) a
      where n.nspname is null or n.nspname = any($1)
    `,
    values: [schemas],
  };
}

const ident = (name) => {
  if (!/^[A-Za-z_][A-Za-z0-9_$]*$/.test(String(name ?? ''))) {
    throw new Error(`unsafe identifier: ${name}`);
  }
  return name;
};

/** Create the probe table. Only ever run inside a transaction that is rolled back. */
export function probeCreateSql(schema, table) {
  return `create table ${ident(schema)}.${ident(table)} (tenant_guard_probe int)`;
}

/**
 * What the freshly created table inherited: every grantee except its owner
 * (the owner is the role that just created it and always holds everything,
 * which is not a finding), plus whether RLS came on by itself. It never does.
 */
export function probeAclSql(schema, table) {
  return {
    text: `
      select
        case when a.grantee = 0 then 'PUBLIC' else pg_get_userbyid(a.grantee) end as grantee,
        a.privilege_type as privilege,
        pg_get_userbyid(c.relowner) as owner,
        c.relrowsecurity as rls_enabled
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      left join lateral aclexplode(c.relacl) a on true
      where n.nspname = $1 and c.relname = $2
    `,
    values: [schema, table],
  };
}

/** Enabled DDL event triggers, which are the only way to force RLS on new tables. */
export function eventTriggersSql() {
  return {
    text: `
      select t.evtname as name, t.evtenabled as enabled, p.prosrc as body
      from pg_event_trigger t
      join pg_proc p on p.oid = t.evtfoid
      where t.evtevent in ('ddl_command_end', 'sql_drop')
    `,
    values: [],
  };
}

/**
 * Does an event trigger turn RLS on for newly created tables?
 *
 * Read from the function body for the same reason `shadow-tables` does: plpgsql
 * records no catalog dependency for what it executes. 'D' is disabled — a
 * disabled trigger mitigates nothing.
 */
export function forcesRls(rows) {
  return (rows ?? []).some(
    (r) => r.enabled !== 'D' && /enable\s+row\s+level\s+security/i.test(String(r.body ?? '')),
  );
}

/** Collapse the ACL rows into one entry per grantee, dropping the owner. */
export function groupGrants(rows) {
  const owner = rows?.[0]?.owner ?? null;
  const byGrantee = new Map();
  for (const r of rows ?? []) {
    if (!r.grantee || r.grantee === owner) continue;
    if (!byGrantee.has(r.grantee)) byGrantee.set(r.grantee, new Set());
    byGrantee.get(r.grantee).add(r.privilege);
  }
  return [...byGrantee.entries()]
    .map(([grantee, privs]) => ({
      grantee,
      privileges: [...privs].filter((p) => DATA_PRIVILEGES.has(p)).sort(),
      writes: [...privs].some((p) => WRITE_PRIVILEGES.has(p)),
    }))
    .filter((g) => g.privileges.length > 0)
    .sort((a, b) => a.grantee.localeCompare(b.grantee));
}

/**
 * The verdict for one schema.
 *
 * The finding is always about the SAME fact — a table created now arrives
 * granted and unprotected. What changes is who it is granted to, and that is
 * what separates "wrong under any architecture" from "the platform default".
 */
export function classifyInherited({ schema, grants = [], rlsEnabled = false, mitigated = false, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const failRoles = new Set(cfg.failRoles);
  const anon = new Set(cfg.unauthenticatedRoles);

  if (grants.length === 0) {
    return { status: 'ok', message: `a new table in "${schema}" inherits no grants beyond its owner` };
  }

  const describe = (g) => `${g.grantee} (${g.privileges.join(', ')})`;
  const inherited = grants.map(describe).join('; ');

  // The probe already answered this empirically: did the table it created come
  // back with row-level security on? That beats inferring it from an event
  // trigger's body, which cannot tell whether the trigger covers THIS schema —
  // and a trigger scoped to some other schema used to downgrade a real finding.
  if (rlsEnabled) {
    const because = mitigated
      ? 'an enabled DDL event trigger in this database does it'
      : 'something in this database does it — worth knowing what, so it does not get removed';
    return {
      status: 'note',
      message:
        `a new table in "${schema}" inherits ${inherited}, but arrives with row-level security already ` +
        `ENABLED (${because}), so it is not exposed — proven by creating one in a rolled-back transaction. ` +
        `The grants alone would expose the next table without whatever is doing that.`,
    };
  }

  const failing = grants.filter((g) => failRoles.has(g.grantee));
  if (failing.length > 0) {
    return {
      status: 'leak',
      kind: 'inherited-grant',
      message:
        `a table created in "${schema}" right now is granted to ${failing.map(describe).join('; ')} ` +
        `and arrives with row-level security OFF — proven by creating one in a rolled-back transaction. ` +
        `PUBLIC is every role that exists or ever will, including ones added later. The next table ` +
        `somebody adds is exposed the moment it exists, with no migration diff showing a security change.`,
      fix:
        `ALTER DEFAULT PRIVILEGES IN SCHEMA ${schema} REVOKE ALL ON TABLES FROM PUBLIC;\n` +
        `      Grant to the specific roles that need it instead, and note that this only changes what ` +
        `FUTURE tables inherit — run REVOKE ... ON ALL TABLES IN SCHEMA ${schema} FROM PUBLIC for the ` +
        `ones that already exist.\n` +
        `      If this is deliberate, add "${schema}" to defaultPrivileges.allowlist[] with a reason.`,
    };
  }

  const unauth = grants.filter((g) => anon.has(g.grantee));
  const writers = grants.filter((g) => g.writes);
  const lead = unauth.length > 0
    ? `an UNAUTHENTICATED role (${unauth.map((g) => g.grantee).join(', ')}) can reach it`
    : writers.length > 0
      ? `${writers.map((g) => g.grantee).join(', ')} can WRITE to it`
      : 'it is readable by a role other than its owner';

  return {
    status: 'note',
    message:
      `a table created in "${schema}" right now inherits ${inherited} and arrives with row-level ` +
      `security OFF — ${lead}. Nothing is exposed yet, which is why this is a note and not a failure; ` +
      `but this run being green says nothing about the table somebody adds next week. It will arrive ` +
      `granted, unprotected, and with no migration diff showing a security change. ` +
      `Make "enable row level security" part of every create-table migration, or add a ddl_command_end ` +
      `event trigger that does it for you. To fail the build on this instead, add the role to ` +
      `defaultPrivileges.failRoles[].`,
  };
}

// ── the guard ────────────────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const q = async (text, values) => (await query(text, values)).rows;
  const allow = new Set(cfg.allowlist);
  const table = ident(cfg.probeTable);

  const violations = [];
  const notes = [];
  let scanned = 0;

  // Mitigation first, so a database that already forces RLS is never nagged.
  let mitigated = false;
  try {
    mitigated = forcesRls(await q(eventTriggersSql().text, []));
  } catch {
    /* no event-trigger catalog access — treated as unmitigated, which is the safe way round */
  }

  for (const schema of cfg.schemas) {
    if (allow.has(schema)) continue;

    // Create a table and read what it inherited, then throw it away. The
    // transaction is rolled back unconditionally — nothing is left behind.
    let rows;
    try {
      await q('begin', []);
    } catch (err) {
      notes.push({ where: schema, message: `could not open a transaction to probe: ${err.message}` });
      continue;
    }
    try {
      await q(probeCreateSql(schema, table), []);
      const spec = probeAclSql(schema, table);
      rows = await q(spec.text, spec.values);
    } catch (err) {
      try { await q('rollback', []); } catch { /* already aborted */ }
      notes.push({
        where: schema,
        message:
          `could not create a probe table in "${schema}" (${err.message.slice(0, 120)}), so what a new ` +
          `table would inherit is unproven. Run this guard with a role that can CREATE in the schema.`,
      });
      continue;
    }
    try { await q('rollback', []); } catch { /* nothing to undo */ }

    scanned++;
    const verdict = classifyInherited({
      schema,
      grants: groupGrants(rows),
      rlsEnabled: rows?.[0]?.rls_enabled === true,
      mitigated,
      config: cfg,
    });
    if (verdict.status === 'leak') {
      violations.push({ where: schema, kind: verdict.kind, message: verdict.message, fix: verdict.fix });
    } else if (verdict.status === 'note') {
      notes.push({ where: schema, message: verdict.message });
    }
  }

  if (scanned === 0) {
    return OK({
      skipped: true,
      reason: 'could not create a probe table in any target schema — needs CREATE on the schema',
      summary: 'skipped — no schema could be probed',
      notes,
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
        ? `${violations.length} schema(s) grant every future table to a role that must not have it`
        : `${scanned} schema(s) probed for what a new table inherits` + (notes.length ? `; ${notes.length} note(s)` : ''),
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

export { safeRole };
