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
import { searchPathPinned, searchPathSchemas } from './definer-rpc.mjs';

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

/**
 * Quote an identifier only when it needs it.
 *
 * The fix strings are meant to be pasted into psql, so a role called
 * `App Writer` has to come back as `"App Writer"` or the advice is a syntax
 * error. Plain lowercase identifiers are left bare because the existing output
 * (and everybody's muscle memory) reads `FROM anon`, not `FROM "anon"`.
 */
function ident(name) {
  const s = String(name ?? '');
  return /^[a-z_][a-z0-9_]*$/.test(s) ? s : '"' + s.replace(/"/g, '""') + '"';
}

const list = (xs) => xs.map((x) => `"${x}"`).join(', ');

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/**
 * Which of these roles hold CREATE on which schemas, and **how** they hold it.
 *
 * `can_create` is the EFFECTIVE privilege, which is what actually matters — but
 * it is true for four different reasons with four different fixes, and printing
 * one REVOKE for all four is how you ship advice that silently does nothing.
 * Measured: with `grant create on schema public to app_writer; grant app_writer
 * to anon`, `REVOKE CREATE ON SCHEMA public FROM anon` succeeds, emits no error,
 * and leaves `has_schema_privilege('anon','public','CREATE')` true — verified
 * before and after, and `anon` could still `CREATE TABLE public.planted`.
 *
 * So the four provenances are separated here:
 *
 *   • `public_can_create`   — the grant is on PUBLIC; revoke from PUBLIC.
 *   • `direct_can_create`   — the role holds its own grant; revoke from the role.
 *   • `via_memberships`     — it inherits through role membership. `pg_has_role
 *     (…, 'USAGE')` is the right test and not `pg_auth_members` alone: a
 *     `NOINHERIT` member does NOT get the privilege, and measured,
 *     `has_schema_privilege` agrees (noinherit member: privilege false,
 *     pg_has_role USAGE false, pg_has_role MEMBER true). These are the DIRECT
 *     membership edges, because membership is transitive and
 *     `REVOKE <grandparent> FROM <role>` is itself a no-op — measured with
 *     `grant r_top to r_mid; grant r_mid to anon`, anon's only direct parent is
 *     r_mid while the CREATE grant lives on r_top.
 *   • `grant_holders`       — the roles reachable by membership that actually
 *     hold the ACL entry, so the wider "revoke it at the source" fix names a
 *     role that really has it.
 *
 * And two provenances that no REVOKE can touch at all, which is why they are
 * read rather than assumed away: `is_owner` (ownership carries CREATE
 * implicitly and never appears in `nspacl`) and `is_super`.
 */
export function schemaCreateGrantsSql(roles, schemas) {
  return {
    text: `
      select
        n.nspname as schema,
        r.rolname as role,
        pg_catalog.has_schema_privilege(r.oid, n.oid, 'CREATE') as can_create,
        (n.nspowner = r.oid) as is_owner,
        r.rolsuper as is_super,
        coalesce((
          select true from aclexplode(n.nspacl) a
          where a.grantee = 0 and a.privilege_type = 'CREATE' limit 1
        ), false) as public_can_create,
        coalesce((
          select true from aclexplode(n.nspacl) a
          where a.grantee = r.oid and a.privilege_type = 'CREATE' limit 1
        ), false) as direct_can_create,
        coalesce((
          select array_agg(distinct g.rolname order by g.rolname)
          from pg_catalog.pg_roles g
          where g.oid <> r.oid
            and pg_catalog.pg_has_role(r.oid, g.oid, 'USAGE')
            and exists (
              select 1 from aclexplode(n.nspacl) a
              where a.grantee = g.oid and a.privilege_type = 'CREATE'
            )
        ), '{}') as grant_holders,
        coalesce((
          select array_agg(distinct g.rolname order by g.rolname)
          from pg_catalog.pg_auth_members m
          join pg_catalog.pg_roles g on g.oid = m.roleid
          where m.member = r.oid
            and pg_catalog.pg_has_role(r.oid, g.oid, 'USAGE')
            and pg_catalog.has_schema_privilege(g.oid, n.oid, 'CREATE')
        ), '{}') as via_memberships
      from pg_catalog.pg_namespace n
      cross join pg_catalog.pg_roles r
      where n.nspname = any($2)
        and r.rolname = any($1)
    `,
    values: [roles, schemas],
  };
}

/**
 * CREATE on the database itself — the right to make new schemas.
 *
 * Same provenance columns as the schema query, for the same reason: inherited
 * `CREATE ON DATABASE` produces exactly the same dead-end REVOKE. `datname` is
 * selected so the fix can name the real database instead of a `<placeholder>`
 * that will not run.
 */
export function databaseCreateGrantsSql(roles) {
  return {
    text: `
      select
        r.rolname as role,
        d.datname as database,
        pg_catalog.has_database_privilege(r.oid, d.oid, 'CREATE') as can_create,
        (d.datdba = r.oid) as is_owner,
        r.rolsuper as is_super,
        coalesce((
          select true
          from aclexplode(d.datacl) a
          where a.grantee = 0 and a.privilege_type = 'CREATE'
          limit 1
        ), false) as public_can_create,
        coalesce((
          select true
          from aclexplode(d.datacl) a
          where a.grantee = r.oid and a.privilege_type = 'CREATE'
          limit 1
        ), false) as direct_can_create,
        coalesce((
          select array_agg(distinct g.rolname order by g.rolname)
          from pg_catalog.pg_roles g
          where g.oid <> r.oid
            and pg_catalog.pg_has_role(r.oid, g.oid, 'USAGE')
            and exists (
              select 1 from aclexplode(d.datacl) a
              where a.grantee = g.oid and a.privilege_type = 'CREATE'
            )
        ), '{}') as grant_holders,
        coalesce((
          select array_agg(distinct g.rolname order by g.rolname)
          from pg_catalog.pg_auth_members m
          join pg_catalog.pg_roles g on g.oid = m.roleid
          where m.member = r.oid
            and pg_catalog.pg_has_role(r.oid, g.oid, 'USAGE')
            and pg_catalog.has_database_privilege(g.oid, d.oid, 'CREATE')
        ), '{}') as via_memberships
      from pg_catalog.pg_database d
      cross join pg_catalog.pg_roles r
      where d.datname = current_database()
        and r.rolname = any($1)
    `,
    values: [roles],
  };
}

/**
 * Every schema each role can plant in — NOT just the ones being audited.
 *
 * A definer function's pinned `search_path` may name a schema outside
 * `cfg.schemas` (`SET search_path = public, app` while only `public` is
 * audited), and deciding whether that pin holds needs to know about both. The
 * `PUBLIC` row is computed from the ACL rather than `has_schema_privilege`,
 * which takes a role and has no way to express "everybody".
 */
export function writableSchemasSql(roles) {
  return {
    text: `
      select r.rolname as role, n.nspname as schema
        from pg_catalog.pg_namespace n
        cross join pg_catalog.pg_roles r
       where n.nspname not like 'pg\\_%' and n.nspname <> 'information_schema'
         and r.rolname = any($1)
         and pg_catalog.has_schema_privilege(r.oid, n.oid, 'CREATE')
      union all
      select 'PUBLIC' as role, n.nspname as schema
        from pg_catalog.pg_namespace n
       where n.nspname not like 'pg\\_%' and n.nspname <> 'information_schema'
         and exists (
           select 1 from aclexplode(n.nspacl) a
           where a.grantee = 0 and a.privilege_type = 'CREATE'
         )
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

/** How many definer functions have no `SET search_path` clause at all. */
export function unpinnedDefiners(rows) {
  return (rows ?? []).filter((r) => !searchPathPinned(r.config)).map((r) => `${r.schema}.${r.name}`);
}

/**
 * The writable schemas a pin puts AHEAD of the rest of its own path.
 *
 * The presence of a `SET search_path` clause means nothing on its own, and that
 * is exactly what this guard used to test. **Measured**: `public.get_notice()`
 * declared `SECURITY DEFINER SET search_path = public, app`, reading `secrets`
 * unqualified with the real table in `app`, with `CREATE ON SCHEMA public`
 * granted to `anon`. As `anon`: `create table public.secrets(id int)` then
 * `select public.get_notice()` returned the planted table (1) instead of the
 * real one (2). The pin was present and it protected nothing.
 *
 * Only entries BEFORE the last one can shadow anything: resolution walks the
 * path in order, so the final entry is where an unqualified name lands if
 * nothing earlier has it, and there is nothing after it to redirect. And the
 * walk stops at the first schema the role CANNOT plant in — that schema may
 * itself hold the object, and once resolution finds it, nothing later matters.
 *
 * `pg_catalog` never stops the walk: it holds system catalogs and none of your
 * tables, so an unqualified table name never resolves there. That is why
 * `SET search_path = pg_catalog, <yours>` is the canonical fix and why
 * `pg_catalog, public, app` with `public` writable is still hijackable.
 *
 * Deliberately says nothing about `pg_temp`. A missing `pg_temp` is a real hole
 * — `TEMP` is granted to PUBLIC by default, so the hijack needs no CREATE
 * anywhere — but for that reason revoking a CREATE grant does not fix it, and
 * claiming it here would attach "your grant makes this exploitable" to a
 * grant that is not the enabler. That case belongs to `definer-rpc`, which
 * already reports it.
 */
export function pinnedThroughWritable(config, writableSchemas = []) {
  const writable = new Set(writableSchemas);
  const path = searchPathSchemas(config);
  const out = [];
  for (let i = 0; i < path.length - 1; i++) {
    const schema = path[i];
    if (schema.toLowerCase() === 'pg_catalog') continue;
    if (writable.has(schema)) out.push(schema);
    else break;
  }
  return out;
}

/**
 * Split the definer functions in scope into the ones this role can hijack and
 * the ones it cannot. `unpinned` is conclusive; `shadowable` is conditional on
 * where the body's unqualified names actually resolve, which SQL cannot see —
 * and the message says so rather than picking a side.
 */
export function armingDefiners(rows, writableSchemas = []) {
  const unpinned = [];
  const shadowable = [];
  for (const r of rows ?? []) {
    const fqn = `${r.schema}.${r.name}`;
    if (!searchPathPinned(r.config)) { unpinned.push(fqn); continue; }
    const through = pinnedThroughWritable(r.config, writableSchemas);
    if (through.length > 0) {
      const path = searchPathSchemas(r.config);
      shadowable.push({ fn: fqn, through, after: path.slice(through.length).filter((x) => x.toLowerCase() !== 'pg_catalog') });
    }
  }
  return { unpinned, shadowable, total: (rows ?? []).length };
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
  role, scope, where, viaPublic = false, unpinned = [], shadowable = [], definerCount = 0,
  definersKnown = true, writableKnown = true, scannedSchemas = [],
  direct = false, grantHolders = [], viaMemberships = [], isOwner = false, isSuper = false,
  databaseName = null, unauthenticatedRoles = [], serverVersion = 0, appRole = '',
}) {
  const target = scope === 'database' ? `the database (i.e. can create new SCHEMAS)` : `schema "${where}"`;
  const isAnon = unauthenticatedRoles.includes(role);
  const who = viaPublic ? 'every role' : `"${role}"`;
  const scopeLabel = scannedSchemas.length ? list(scannedSchemas) : `the audited schema(s)`;

  // ── the link to §4.4 ────────────────────────────────────────────────
  // Stated rather than re-reported as a second failure — but stated TRUTHFULLY.
  // This sentence used to read "no SECURITY DEFINER function currently has an
  // unpinned search_path, so nothing is exploitable today" whenever every
  // function had a `SET` clause, which is a claim about exploitability decided
  // by a check that only tested for the clause's presence. Measured on a
  // database with a working hijack in progress (pin `public, app`, table in
  // `app`, `public` writable by anon, planted table returned) it printed
  // exactly that sentence. A live escalation described as a future risk is the
  // difference between "fix now" and "backlog".
  let armed;
  if (!definersKnown) {
    armed = ` tenant-guard could not read this database's SECURITY DEFINER functions, so it cannot say whether any is hijackable through this grant — treat that as unknown, not as clear.`;
  } else if (unpinned.length > 0) {
    armed = ` There ${unpinned.length === 1 ? 'is' : 'are'} ${unpinned.length} SECURITY DEFINER function(s) here with an unpinned search_path (${unpinned.slice(0, 2).join(', ')}${unpinned.length > 2 ? ', …' : ''}), so this is exploitable NOW — \`tenant-guard rpc\` reports the same root cause from the function side, where the fix is to pin the path instead.`;
  } else if (shadowable.length > 0) {
    const s = shadowable[0];
    const names = shadowable.slice(0, 2).map((x) => x.fn).join(', ') + (shadowable.length > 2 ? ', …' : '');
    armed = ` ${shadowable.length} SECURITY DEFINER function(s) here (${names}) DO pin search_path — but through ${list(s.through)}, which this grant lets ${who} plant in, ahead of ${s.after.length ? list(s.after) : 'the rest of the path'}. A pin only protects once resolution reaches a schema they cannot plant in, so those pins are worth nothing against ${who} and the hijack may already work TODAY. Measured: a definer function pinned "public, app" reading an unqualified name whose real table lives in "app", with "public" writable, ran the planted table instead. Whether each one is genuinely hijackable depends on which schema its unqualified names resolve to, which the catalog cannot tell you — \`tenant-guard rpc\` decides that from the function side, for your app role only.`;
  } else if (definerCount > 0) {
    armed = writableKnown
      ? ` The ${definerCount} SECURITY DEFINER function(s) in ${scopeLabel} all pin search_path with no schema ${who} can plant in ahead of the rest of their path, so none of them is hijackable through this grant today — but this grant arms the next one somebody writes without \`SET search_path\`, and no diff will show a security change when they do.`
      : ` tenant-guard could not read which schemas ${who} can CREATE in, so it cannot say whether the ${definerCount} SECURITY DEFINER function(s) in ${scopeLabel} pin search_path through a schema ${who} can plant in. This grant also arms the next one somebody writes without \`SET search_path\`, and no diff will show a security change when they do.`;
  } else {
    armed = ` There are no SECURITY DEFINER functions in ${scopeLabel}, so nothing there is hijackable through this grant today — but this grant arms the next one somebody writes without \`SET search_path\`, and no diff will show a security change when they do.`;
  }

  // ── the fix, resolved to the provenance of the privilege ────────────
  // `REVOKE … FROM <role>` is correct for a direct grant and a no-op for every
  // other way of holding CREATE. Which one it is has to be read, not assumed.
  const scopeSql = scope === 'database'
    ? `DATABASE ${databaseName ? ident(databaseName) : '<your database>'}`
    : `SCHEMA ${ident(where)}`;
  const allowKey = `${scope === 'database' ? 'database' : where}:${viaPublic ? 'PUBLIC' : role}`;
  const allowLine = `If this is deliberate, add "${allowKey}" to createGrants.allowlist[] with a reason.`;

  let fix;
  if (viaPublic || direct) {
    fix =
      `REVOKE CREATE ON ${scopeSql} FROM ${viaPublic ? 'PUBLIC' : ident(role)};\n` +
      `      Objects should be created by your migration role, not by the role your app connects as.\n` +
      `      ${allowLine}`;
  } else if (isSuper) {
    fix =
      `${ident(role)} is a SUPERUSER, so every privilege check passes regardless of grants — REVOKE cannot remove this.\n` +
      `      REVOKE CREATE ON ${scopeSql} FROM ${ident(role)}; would succeed and change nothing.\n` +
      `      Have your app connect as a non-superuser role, or ALTER ROLE ${ident(role)} NOSUPERUSER; if nothing depends on it.\n` +
      `      ${allowLine}`;
  } else if (isOwner) {
    fix =
      `${ident(role)} OWNS ${scope === 'database' ? 'this database' : `schema ${ident(where)}`}, and ownership carries CREATE implicitly — it is not in the ACL, so no REVOKE can remove it.\n` +
      `      REVOKE CREATE ON ${scopeSql} FROM ${ident(role)}; would succeed and change nothing.\n` +
      `      Reassign it instead: ALTER ${scope === 'database' ? 'DATABASE' : 'SCHEMA'} ${scope === 'database' ? (databaseName ? ident(databaseName) : '<your database>') : ident(where)} OWNER TO <your migration role>;\n` +
      `      ${allowLine}`;
  } else if (viaMemberships.length > 0 || grantHolders.length > 0) {
    // The measured case: effective CREATE true, no direct grant, no PUBLIC
    // grant. The old fix ran clean and left the privilege in place.
    // `viaMemberships` holds only the DIRECT edges, because membership is
    // transitive and `REVOKE <grandparent> FROM <role>` is itself a no-op:
    // measured with `grant r_top to r_mid; grant r_mid to anon`, anon's only
    // direct parent is r_mid while the ACL entry lives on r_top.
    fix =
      `${ident(role)} has NO grant of its own — it inherits CREATE by being a member of ${list(viaMemberships.length ? viaMemberships : grantHolders)}, so ` +
      `REVOKE CREATE ON ${scopeSql} FROM ${ident(role)}; would succeed, warn at most, and leave the privilege in place (measured: effective CREATE true before, true after).\n` +
      (viaMemberships.length
        ? `      Narrower fix — drop the membership, which affects only ${ident(role)}:\n` +
          viaMemberships.map((g) => `        REVOKE ${ident(g)} FROM ${ident(role)};`).join('\n') + '\n'
        : '') +
      (grantHolders.length
        ? `      Wider fix — revoke the grant at its source. This affects EVERY member of ${list(grantHolders)}, so do not apply it blind if that is your migration role:\n` +
          grantHolders.map((g) => `        REVOKE CREATE ON ${scopeSql} FROM ${ident(g)};`).join('\n') + '\n'
        : '') +
      `      ${allowLine}`;
  } else {
    // Effective privilege with no readable source. Say that, rather than print
    // a REVOKE that may do nothing.
    fix =
      `tenant-guard could not find where this privilege comes from — it is not a direct grant, not a grant to PUBLIC, not ownership, and not role membership.\n` +
      `      Check with: select * from aclexplode((select ${scope === 'database' ? 'datacl from pg_database where datname = current_database()' : `nspacl from pg_namespace where nspname = ${JSON.stringify(String(where))}`}));\n` +
      `      Do not assume REVOKE CREATE ON ${scopeSql} FROM ${ident(role)}; will change anything until you know the source.\n` +
      `      ${allowLine}`;
  }

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
    fix,
  };
}

// ── the guard ────────────────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

/** Postgres returns `text[]` as an array; be defensive about drivers that don't. */
const arr = (v) => (Array.isArray(v) ? v : []);

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
  // Kept as raw rows, because whether a PINNED one is armed depends on which
  // role is being classified — a pin through "public" is worthless to a role
  // that can CREATE in public and solid against one that cannot.
  let definerRows = [];
  let definersKnown = true;
  try {
    const spec = definerSearchPathSql(cfg.schemas);
    definerRows = await q(spec.text, spec.values);
  } catch { definersKnown = false; }

  // Every schema each role can plant in, across the whole database — a pinned
  // path routinely names schemas outside cfg.schemas.
  const writableByRole = new Map();
  let writableKnown = true;
  try {
    const spec = writableSchemasSql(roles);
    for (const row of await q(spec.text, spec.values)) {
      if (!writableByRole.has(row.role)) writableByRole.set(row.role, []);
      writableByRole.get(row.role).push(row.schema);
    }
  } catch { writableKnown = false; }

  let serverVersion = 0;
  try {
    serverVersion = (await q(serverVersionSql().text, []))[0]?.v ?? 0;
  } catch { /* context only */ }

  const armingFor = (role) => (
    definersKnown && writableKnown
      ? armingDefiners(definerRows, writableByRole.get(role) ?? [])
      : { unpinned: definersKnown ? unpinnedDefiners(definerRows) : [], shadowable: [], total: definerRows.length }
  );

  const shared = {
    definerCount: definerRows.length,
    definersKnown,
    writableKnown,
    scannedSchemas: cfg.schemas,
    serverVersion,
    appRole,
    unauthenticatedRoles: cfg.unauthenticatedRoles,
  };

  const emit = (verdict, where) => {
    if (verdict.status === 'leak') violations.push({ where, kind: verdict.kind, message: verdict.message, fix: verdict.fix });
    // Notes carry no `fix` — the output layer renders only where/message for
    // them, so attaching one would be dead weight nobody ever sees.
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
        classifyCreateGrant({
          ...shared, ...armingFor('PUBLIC'),
          role: 'PUBLIC', scope: 'schema', where: row.schema, viaPublic: true,
        }),
        `${row.schema}:PUBLIC`,
      );
    }

    // A role may ALSO hold its own grant. Revoking from PUBLIC would not touch
    // it, so it is a separate finding with a separate fix — reported only when
    // the grant is direct, which is what keeps this from doubling up.
    const reportRole = row.public_can_create ? row.direct_can_create : row.can_create;
    if (reportRole && !allow.has(`${row.schema}:${row.role}`)) {
      emit(
        classifyCreateGrant({
          ...shared, ...armingFor(row.role),
          role: row.role, scope: 'schema', where: row.schema,
          direct: row.direct_can_create === true,
          grantHolders: arr(row.grant_holders),
          viaMemberships: arr(row.via_memberships),
          isOwner: row.is_owner === true,
          isSuper: row.is_super === true,
        }),
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
          classifyCreateGrant({
            ...shared, ...armingFor('PUBLIC'),
            role: 'PUBLIC', scope: 'database', viaPublic: true, databaseName: row.database,
          }),
          'database:PUBLIC',
        );
        continue;
      }
      if (row.public_can_create) continue;
      if (row.can_create && !allow.has(`database:${row.role}`)) {
        emit(
          classifyCreateGrant({
            ...shared, ...armingFor(row.role),
            role: row.role, scope: 'database', databaseName: row.database,
            direct: row.direct_can_create === true,
            grantHolders: arr(row.grant_holders),
            viaMemberships: arr(row.via_memberships),
            isOwner: row.is_owner === true,
            isSuper: row.is_super === true,
          }),
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
