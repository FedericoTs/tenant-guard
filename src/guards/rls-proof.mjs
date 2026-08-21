/**
 * Guard: runtime RLS isolation proof — the tripwire becomes a proof.
 *
 * The three static guards read source text; they catch the obvious leak but
 * cannot *prove* that isolation holds. This one can. Given a database
 * connection it:
 *
 *   1. introspects every table in your schema that carries a tenant column
 *      (organization_id / tenant_id / …), noting whether RLS is even on;
 *   2. as the PRIVILEGED role (which bypasses RLS, like Supabase `service_role`)
 *      finds two real tenant ids that already have data in each table;
 *   3. drops to your non-superuser APP role (e.g. `authenticated`), assumes the
 *      identity of tenant A, and asserts A's session can neither READ nor WRITE
 *      tenant B's rows (SELECT, plus UPDATE/DELETE probes) — then swaps and
 *      checks the other direction. RLS is per-command, so a correct read policy
 *      can leave writes wide open; this catches that.
 *
 * A static scanner can never do this. A test can: if RLS is off, a policy is
 * `USING (true)`, a policy forgot the tenant predicate, the write path is
 * unprotected, or RLS is on with no policy at all (deny-all that only *looks*
 * isolated) — this guard names it and fails your build, on every commit.
 *
 * Before trusting any pass it runs a negative control: a deny-all RLS table that
 * the app role MUST NOT be able to read. If the role can read it, RLS isn't being
 * enforced for this session (a superuser, a BYPASSRLS role, a table owner, or a
 * SET ROLE that didn't take effect) — so every "isolated" result would be a
 * vacuous pass, and the guard fails instead of reporting one.
 *
 * Non-destructive by construction: the whole run is one transaction that is
 * ROLLED BACK, and each write probe is additionally wrapped in its own SAVEPOINT
 * that is rolled back, so nothing is ever committed. (If you have triggers with
 * external side effects, note they still fire inside the rolled-back
 * transaction; set `probeWrites: false` to test reads only.) It needs a Postgres
 * driver (`pg`, an optional peer dependency) and a database URL; with neither it
 * SKIPS, exactly like the other guards on a stack they don't fit.
 *
 * The pure helpers below are I/O-free and unit-tested with zero dependencies;
 * `prove()` takes an injected `query` function so it can be driven by `pg` in
 * production and by an embedded Postgres in tests.
 */

export const meta = {
  id: 'rls-proof',
  title: 'Runtime RLS isolation proof',
  why: "Proves at runtime that a tenant's session cannot read OR write another tenant's rows — catches RLS that is off, permissive, missing the tenant predicate, unprotected on the write path, or enabled with no policy at all, which no source scan can prove.",
};

// ── configuration defaults ───────────────────────────────────────────
export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  tenantColumns: ['organization_id', 'organizationId', 'tenant_id', 'tenantId', 'account_id', 'workspace_id', 'org_id'],
  // The non-superuser role your app queries as. RLS applies to it; it bypasses
  // for the privileged connecting role. Supabase: 'authenticated'.
  role: 'authenticated',
  // SQL run (as `role`) to assume a tenant's identity. `$1` is the tenant id.
  // The default targets the canonical Postgres pattern:
  //   ... USING (tenant_col = current_setting('app.current_tenant'))
  // For Supabase JWT-claim policies, override with e.g. (note the $1::text cast —
  // json_build_object gives Postgres no way to infer the placeholder's type):
  //   ["select set_config('request.jwt.claims', json_build_object('org_id', $1::text)::text, true)"]
  becomeTenant: ["select set_config('app.current_tenant', $1, true)"],
  // Shortcut for the common Supabase case: `claim: "org_id"` (or "team_id" /
  // "account_id") builds the request.jwt.claims becomeTenant for you and sets
  // role to `authenticated` — impersonation via set_config, no JWT secret in CI.
  // An explicit `becomeTenant` overrides it. Use `becomeTenant` (an SQL hook) for
  // apps that derive the tenant via a memberships table.
  claim: null,
  tables: null, // null = autodiscover; or [{ table, schema?, tenantColumn }]
  grandfather: [], // table names deliberately shared/unscoped (reference data)
  sampleLimit: 3, // distinct tenant ids to sample per table
  // Also test the WRITE path: attempt UPDATE/DELETE of another tenant's rows,
  // each inside a rolled-back savepoint. RLS is per-command, so a correct SELECT
  // policy can still leave UPDATE/DELETE open. Set false to test reads only.
  probeWrites: true,
  // Seeding mode. When set, the proof MANUFACTURES two synthetic tenants inside
  // the rolled-back transaction instead of relying on two tenants already having
  // data — so it works on an empty/CI database, and on policies that read a
  // membership table (your seed creates the membership rows). Shape:
  //   seed: {
  //     tenants: ["<id-A>", "<id-B>"],   // optional; default = two generated UUIDs
  //     setup: [                          // run PRIVILEGED once per tenant, $1 = tenant id
  //       "insert into organizations (id) values ($1)",
  //       "insert into memberships (user_id, organization_id) values (gen_random_uuid(), $1)",
  //       "insert into invoices (organization_id, amount) values ($1, 100)"
  //     ]
  //   }
  seed: null,
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Safely double-quote a Postgres identifier. Rejects embedded NULs. */
export function quoteIdent(name) {
  if (typeof name !== 'string' || name.length === 0 || name.includes('\0')) {
    throw new Error(`unsafe identifier: ${JSON.stringify(name)}`);
  }
  return '"' + name.replace(/"/g, '""') + '"';
}

/** `schema.table`, each part quoted. */
export function qualified(schema, table) {
  return `${quoteIdent(schema)}.${quoteIdent(table)}`;
}

/** Validate a role name for interpolation into SET ROLE (no params allowed there). */
export function safeRole(role) {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(role)) {
    throw new Error(`unsafe role name: ${JSON.stringify(role)}`);
  }
  return role;
}

/**
 * Catalog query: every table in `schemas` that has any of `tenantColumns`,
 * with whether RLS is enabled/forced. Uses pg_catalog so it also reports RLS
 * status (information_schema can't). Returns { text, values }.
 */
export function introspectionSql(schemas, tenantColumns, role = 'authenticated') {
  const text = `
    select n.nspname            as schema,
           c.relname            as table,
           a.attname            as column,
           -- the emitted policy has to COMPILE: col = current_setting(...)
           -- raises 42883 on a uuid column, the commonest tenant type there is.
           a.atttypid::regtype::text as column_type,
           c.relrowsecurity     as rls_enabled,
           c.relforcerowsecurity as rls_forced,
           c.relowner::regrole::text as owner_role,
           c.relispartition     as is_partition,
           (c.relkind = 'p')    as is_partitioned_parent,
           -- TRUNCATE ignores RLS entirely: it is gated only by the table
           -- privilege, and GRANT ALL includes it. Read from the catalog, never
           -- probed: a TRUNCATE probe takes an ACCESS EXCLUSIVE lock and is the
           -- one statement you must not fire at a database by surprise.
           pg_catalog.has_table_privilege($3::text, c.oid, 'TRUNCATE') as can_truncate,
           (select count(*) from pg_catalog.pg_policy pol where pol.polrelid = c.oid)::int as policy_count
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    -- 'p' = partitioned parent. Excluding it (as this did) meant a partitioned
    -- tenant table was NEVER scanned, while its partitions — which each hold a
    -- single tenant — reported "only 1 tenant, cannot prove" and the whole thing
    -- came back green. See planTables/prove for the foreign-tenant probe.
    where c.relkind in ('r', 'p')
      and n.nspname = any($1)
      and a.attname = any($2)
    order by n.nspname, c.relname`;
  return { text, values: [schemas, tenantColumns, role] };
}

/**
 * From the introspection rows, one entry per table: the tenant column chosen by
 * the priority order in `tenantColumns`, plus rls flags. Grandfathered tables
 * are dropped.
 */
export function planTables(rows, tenantColumns, grandfather = []) {
  const skip = new Set(grandfather);
  const byTable = new Map();
  for (const r of rows) {
    const key = `${r.schema}.${r.table}`;
    if (skip.has(r.table) || skip.has(key)) continue;
    const prio = tenantColumns.indexOf(r.column);
    if (prio < 0) continue;
    const existing = byTable.get(key);
    if (!existing || prio < existing.prio) {
      byTable.set(key, {
        schema: r.schema,
        table: r.table,
        tenantColumn: r.column,
        tenantColumnType: r.column_type ?? null,
        rlsEnabled: r.rls_enabled === true || r.rls_enabled === 't',
        rlsForced: r.rls_forced === true || r.rls_forced === 't',
        ownerRole: r.owner_role ?? null,
        isPartition: r.is_partition === true || r.is_partition === 't',
        canTruncate: r.can_truncate === true || r.can_truncate === 't',
        isPartitionedParent: r.is_partitioned_parent === true || r.is_partitioned_parent === 't',
        policyCount: r.policy_count == null ? null : Number(r.policy_count),
        prio,
      });
    }
  }
  return [...byTable.values()].map(({ prio, ...t }) => t);
}

/** Privileged query for the distinct tenant ids present in a table (as text). */
export function distinctTenantsSql(schema, table, column, limit) {
  const text =
    `select distinct ${quoteIdent(column)}::text as t ` +
    `from ${qualified(schema, table)} ` +
    `where ${quoteIdent(column)} is not null ` +
    `limit $1`;
  return { text, values: [limit] };
}

/** Restricted-role count of rows belonging to `tenantId` (compared as text). */
export function tenantRowCountSql(schema, table, column, tenantId) {
  const text =
    `select count(*)::int as n ` +
    `from ${qualified(schema, table)} ` +
    `where ${quoteIdent(column)}::text = $1`;
  return { text, values: [tenantId] };
}

/**
 * Restricted-role count of ALL rows the acting tenant can SELECT (no tenant
 * filter). Used by the omitted-tenant probe: a NULL-tenant orphan matches no
 * `col = tenant` filter, so only an unfiltered visible count reveals whether the
 * read policy exposes it to this session.
 */
export function tenantOwnVisibleSql(schema, table) {
  return { text: `select count(*)::int as n from ${qualified(schema, table)}`, values: [] };
}

/**
 * Privileged per-tenant row counts, so a write probe can tell "wrote my own
 * rows" from "wrote another tenant's rows". Returns { text, values:[a,b] }.
 */
export function tenantCountsSql(schema, table, column, tenantA, tenantB) {
  const c = quoteIdent(column);
  const text =
    `select count(*) filter (where ${c}::text = $1)::int as own_a, ` +
    `count(*) filter (where ${c}::text = $2)::int as own_b ` +
    `from ${qualified(schema, table)}`;
  return { text, values: [tenantA, tenantB] };
}

/**
 * Write probe — UPDATE the WHOLE table, reassigning the tenant column to the
 * ACTING tenant (`$1`). Deliberately has NO WHERE clause: a WHERE would have to
 * *read* rows, and a correct SELECT policy would then mask the write (the exact
 * trap where reads look isolated but writes aren't). With no WHERE it affects
 * every row the UPDATE policy lets this tenant touch; compare that to the
 * tenant's own row count — a higher number means it can rewrite (even steal)
 * other tenants' rows. Runs in a rolled-back savepoint; nothing persists.
 */
export function updateProbeSql(schema, table, column, actingTenantId) {
  const c = quoteIdent(column);
  return { text: `update ${qualified(schema, table)} set ${c} = $1`, values: [actingTenantId] };
}

/**
 * Write probe — DELETE the WHOLE table (no WHERE, same masking reason as above).
 * DELETE policies carry only a USING clause, so this cleanly measures how many
 * rows this tenant can delete; more than it owns is a delete leak. Rolled back.
 */
export function deleteProbeSql(schema, table) {
  return { text: `delete from ${qualified(schema, table)}`, values: [] };
}

/**
 * Write probe — INSERT a row that BELONGS TO ANOTHER TENANT (tenant column = the
 * other tenant's id). INSERT is the one write path UPDATE/DELETE probes miss, and
 * it's governed only by a WITH CHECK clause — a table can scope SELECT/UPDATE
 * correctly yet let any session create rows in any tenant. Deliberately NO
 * `RETURNING`: RETURNING re-applies the SELECT policy, and a row that WITH CHECK
 * accepted but SELECT hides then raises the very same "violates row-level security
 * policy" error a WITH CHECK *block* raises — masking the leak. Instead the caller
 * inserts plainly and reads where the row LANDED from the acting tenant's own-row
 * count (see probeInsert). Sets only the tenant column and relies on defaults for
 * the rest — so a table with other NOT NULL columns without defaults yields an
 * INCONCLUSIVE result (a data error, not an RLS block), reported honestly rather
 * than as a pass. Runs in a rolled-back savepoint; nothing persists.
 */
export function insertProbeSql(schema, table, column, otherTenantId) {
  const c = quoteIdent(column);
  return { text: `insert into ${qualified(schema, table)} (${c}) values ($1)`, values: [otherTenantId] };
}

/**
 * Write probe — INSERT a row with NO tenant (the tenant column explicitly NULL).
 * A wrong-tenant probe walks straight past this: the client never *claims* a
 * tenant. A strict policy (`tenant = current`) rejects NULL cleanly — `NULL =
 * 'org_A'` is NULL, not true — but where the column is nullable and the read
 * policy treats NULL as global (`… OR tenant IS NULL`), you get a row nobody owns
 * that every tenant can read. The caller detects it by whether the acting tenant
 * can then SEE the row it just made (own-row count grew) — see probeInsertOmitted.
 * A NOT NULL tenant column makes such orphans schema-impossible (a safe block).
 */
export function insertOmittedProbeSql(schema, table, column) {
  const c = quoteIdent(column);
  return { text: `insert into ${qualified(schema, table)} (${c}) values (NULL)`, values: [] };
}

/**
 * Positive control — INSERT a row belonging to the acting tenant ITSELF.
 *
 * Every other probe here asks "can A touch B's rows". Isolation has a second
 * failure mode and this tool only ever named the first: a policy can be too
 * TIGHT, and that breaks the product silently. The reported shapes were a
 * referral page rendering "A friend" and a balances screen showing blank names —
 * an application writing rows it then cannot read.
 *
 * The control is conclusive because the database itself accepted the row: the
 * WITH CHECK passed, so this row is unambiguously the acting tenant's. If a
 * table the session CAN read does not show it, the read policy is strictly
 * narrower than the write policy. Verified across four shapes — read gated on a
 * column the insert ignores (row written, invisible); symmetric policies (count
 * grows); append-only (own count 0, which is how that legitimate design is told
 * apart); and insert refused outright (42501).
 */
export function insertOwnProbeSql(schema, table, column, ownTenantId) {
  const c = quoteIdent(column);
  return { text: `insert into ${qualified(schema, table)} (${c}) values ($1)`, values: [ownTenantId] };
}

/** Expand the becomeTenant templates into { text, values } for a tenant id. */
export function buildBecomeTenant(templates, tenantId) {
  return templates.map((text) => ({ text, values: [tenantId] }));
}

/**
 * The `claim` shortcut: `claim: "org_id"` (or `{ key, role }`) builds the
 * request.jwt.claims `becomeTenant` and defaults the role to `authenticated`, so
 * CI never needs the JWT secret. An explicitly-configured `becomeTenant` always
 * wins (it's the SQL hook for membership-table apps). Mutates and returns `cfg`.
 * `explicitConfig` is the user's raw config — used only to tell "the user set
 * this" from "this came from DEFAULTS". Shared by every guard that impersonates.
 */
export function applyClaimShortcut(cfg, explicitConfig = {}) {
  if (cfg.claim && explicitConfig.becomeTenant === undefined) {
    const key = typeof cfg.claim === 'string' ? cfg.claim : cfg.claim.key;
    if (!/^[A-Za-z0-9_]+$/.test(key || '')) throw new Error(`unsafe claim key: ${JSON.stringify(key)}`);
    cfg.becomeTenant = [`select set_config('request.jwt.claims', json_build_object('${key}', $1::text)::text, true)`];
    if (typeof cfg.claim === 'object' && cfg.claim.role) cfg.role = cfg.claim.role;
    else if (explicitConfig.role === undefined) cfg.role = 'authenticated';
  }
  return cfg;
}

/**
 * Did a caught error mean the write/read was BLOCKED by the database rather than
 * a real failure? Covers "permission denied" and "new row violates row-level
 * security policy" — both SQLSTATE 42501. A blocked write is a SAFE outcome.
 */
export function isPermissionDenied(err) {
  if (!err) return false;
  if (err.code === '42501') return true;
  return /permission denied|violates row-level security/i.test(err.message || '');
}

/**
 * Specifically: did an INSERT/UPDATE get rejected by a WITH CHECK clause (RLS
 * enforcing the destination tenant)? This is the SAFE, CONCLUSIVE block for the
 * insert probe — distinct from a NOT NULL / foreign-key / check-constraint error,
 * which only means we couldn't build a valid row and proves nothing (inconclusive).
 * Both can share SQLSTATE 42501, so match the specific message. NOTE: also matches
 * the "(USING expression)" variant as a substring — callers that care about the
 * difference must test isRlsUsingViolation FIRST (see probeInsert).
 */
export function isRlsCheckViolation(err) {
  return !!err && /new row violates row-level security policy/i.test(err.message || '');
}

/**
 * Turn one table's measurements into a verdict. A table can leak on the READ
 * path (SELECT) and/or the WRITE path (UPDATE/DELETE) independently, because
 * Postgres RLS is per-command — so a 'leak' verdict carries a `leaks[]` array,
 * one entry per kind, and the caller emits a violation for each.
 * @returns {{ status:'isolated'|'leak'|'no-policy'|'insufficient-data'|'over-restrictive'|'no-access', message?:string, leaks?:Array<{kind:'read'|'write',message:string,fix:string}> }}
 */
/**
 * The comparison to emit in a suggested policy, for a tenant column of this type.
 *
 * `USING (org_id = current_setting('app.current_tenant'))` does not compile when
 * the column is `uuid` — Postgres raises 42883 `operator does not exist: uuid =
 * text`. That is the most common tenant type there is, and it is what this
 * guard's own seed generates, so the headline fix was untestable on the shape it
 * most often reports. Verified: identical policy, `text` column created fine,
 * `uuid` column rejected.
 *
 * `::text` on the column is used rather than a cast on the setting because it
 * works for every type without knowing which one it is — the caller passes the
 * real type when it has it, and gets the exact cast when it does not matter.
 */
export function tenantComparison(col, type) {
  const t = String(type ?? '').toLowerCase();
  if (t === 'uuid') return `${col} = current_setting('app.current_tenant', true)::uuid`;
  if (t === 'text' || t === 'character varying' || t === 'varchar' || t === '') {
    return `${col} = current_setting('app.current_tenant', true)`;
  }
  // int, bigint, citext, a domain — cast the column instead of guessing.
  return `${col}::text = current_setting('app.current_tenant', true)`;
}

export function classifyTableResult({ rlsEnabled, policyCount, ownVisible, crossVisible, writeAffected = 0, insertLeaked = false, orphanLeaked = false, ownInsertInvisible = false, ownInsertRejected = false, tenantCount, noAccess, probedWrites = false }) {
  if (noAccess) {
    return { status: 'no-access', message: `role cannot read this table at all (no SELECT grant) — nothing to prove` };
  }
  if (tenantCount < 2) {
    return { status: 'insufficient-data', message: `only ${tenantCount} tenant(s) of data present — cannot prove cross-tenant isolation until two tenants exist` };
  }
  // RLS on but ZERO policies of any kind => Postgres denies every row to the app
  // role. That reads exactly like isolation (tenant B sees nothing) but the
  // table is unfinished — the moment someone adds a permissive policy it leaks.
  // Detect it explicitly from the catalog rather than inferring from empty reads.
  if (rlsEnabled === true && policyCount === 0) {
    return {
      status: 'no-policy',
      message:
        `RLS is ENABLED but this table has NO policy — Postgres then denies all rows to your app role, which looks identical to correct isolation but means the table is unfinished (and unreadable by the app if it shouldn't be). Isolation is NOT proven here; add a tenant policy or drop RLS if the table is intentionally locked to the service role.`,
    };
  }

  const leaks = [];
  if (crossVisible > 0) {
    const cause = rlsEnabled
      ? `a SELECT policy is permissive or missing the tenant predicate`
      : `ROW LEVEL SECURITY is not enabled on this table`;
    leaks.push({
      kind: 'read',
      message: `tenant A's session READ ${crossVisible} row(s) belonging to tenant B — ${cause}`,
      fix: rlsEnabled
        ? `Scope the read policy by the tenant column, e.g. USING ({cmp}).`
        : `Enable RLS and add a tenant policy:\n  ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;\n  ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;\n  CREATE POLICY tenant_isolation ON {tbl} USING ({cmp});`,
    });
  }
  if (writeAffected > 0) {
    leaks.push({
      kind: 'write',
      message: `tenant A's session made a cross-tenant WRITE affecting ${writeAffected} row(s) — it can UPDATE/DELETE another tenant's rows, or reassign its OWN rows INTO another tenant (a tenant-hop the read policy passes but no WITH CHECK on the destination stops). RLS is per-command; a correct SELECT policy protects none of this`,
      fix: `Adding a policy is NOT enough on its own. Postgres OR-combines permissive policies, so a permissive write policy that is not tenant-scoped keeps granting everything no matter what you add beside it — verified: with a `+ '`' + `USING (true)` + '`' + ` policy present, adding the tenant policy below left exactly as many rows writable as before, and dropping the loose one was what fixed it.\n  1. Find the permissive write policies that are not tenant-scoped:\n       SELECT polname, polcmd, polpermissive, pg_get_expr(polqual, polrelid) AS using_expr\n         FROM pg_policy WHERE polrelid = '{tbl}'::regclass;\n  2. DROP POLICY "<name>" ON {tbl};   -- for each one whose USING does not name {col}\n  3. Then add the scoped policy:\n       CREATE POLICY tenant_all ON {tbl} FOR ALL\n         USING ({cmp})\n         WITH CHECK ({cmp});`,
    });
  }
  if (insertLeaked) {
    leaks.push({
      kind: 'write',
      message: `tenant A's session INSERTed a row belonging to tenant B — it can CREATE rows in another tenant. INSERT is governed only by a WITH CHECK clause; SELECT/UPDATE/DELETE policies don't cover it, so a table can scope reads correctly yet let any session write into any tenant`,
      fix: `Add a WITH CHECK on INSERT — a FOR ALL policy covers it — scoped by the tenant column:\n  CREATE POLICY tenant_all ON {tbl} FOR ALL\n    USING ({cmp})\n    WITH CHECK ({cmp});\n      And check for a permissive INSERT policy that is not tenant-scoped: permissive policies OR together, so one of those keeps letting the insert through whatever you add beside it.\n       SELECT polname, pg_get_expr(polwithcheck, polrelid) FROM pg_policy WHERE polrelid = '{tbl}'::regclass;`,
    });
  }
  if (orphanLeaked) {
    leaks.push({
      kind: 'write',
      message: `tenant A's session INSERTed a row with NO tenant ({col} = NULL) and could then read it back — the column is nullable and the read policy treats NULL as global, so this row is owned by nobody and readable by EVERY tenant. A wrong-tenant check misses it because the client simply omits the tenant`,
      fix: `Make the tenant column NOT NULL, and make the WITH CHECK reject NULL (a bare {col} = current_setting(...) already does, since NULL = x is not true); never write a read policy as "{col} = current OR {col} IS NULL".`,
    });
  }
  if (leaks.length) return { status: 'leak', leaks };

  if (ownVisible === 0) {
    return { status: 'over-restrictive', message: `the tenant session sees none of its own rows either — this table wasn't actually proven (not a leak). Usually the role/becomeTenant config doesn't match your policies; if your policies read a MEMBERSHIP table (org_id IN (select … where user_id = auth.uid())), the impersonated identity also needs a seeded membership row, not just a claim.` };
  }

  // The positive control. Reached only when nothing leaked and the session can
  // read its own rows — so a row it just wrote, and the database accepted,
  // going missing is not ambiguity, it is the read policy being narrower than
  // the write policy. `ownVisible > 0` is what separates this from a legitimate
  // append-only table, where the session cannot read ANY row and the count is 0.
  if (ownInsertInvisible) {
    return {
      status: 'write-read-asymmetry',
      message:
        `tenant A INSERTed a row of its OWN — the database accepted it, so the WITH CHECK passed and the row is unambiguously A's — and then could not read it back. ` +
        `This table IS readable by A (it sees ${ownVisible} of its own rows), so the SELECT policy is strictly narrower than the INSERT policy: the application can create data it cannot then see. ` +
        `Isolation has two failure modes and this is the quiet one — it never leaks anything, it just makes the product render blanks. Not a leak; still a bug.`,
      fix:
        `Make the read and write predicates agree. Usually one of them gained a condition the other never got:\n` +
        `  - a SELECT policy filtering on a column the INSERT leaves at its DEFAULT (status, visibility, published_at) — the row is created outside the policy's window;\n` +
        `  - a FOR ALL policy whose USING is stricter than its WITH CHECK.\n` +
        `      If this table is intentionally append-only, it would not be reported: that shape has no readable rows at all.`,
    };
  }
  if (ownInsertRejected) {
    return {
      status: 'isolated',
      message: `isolated — and note that tenant A could not INSERT a row of its own (the WITH CHECK refused it). Fine for a read-only or service-written table; a bug if the application is supposed to write here.`,
    };
  }

  return {
    status: 'isolated',
    message: probedWrites
      ? `isolated — tenant session can neither read nor write the other tenant's rows`
      : `isolated — tenant session sees its own rows and zero of the other tenant's`,
  };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

/**
 * Run the proof against an injected query function.
 * @param {(text:string, values?:any[]) => Promise<{rows:any[]}>} query
 * @param {object} config  see DEFAULTS
 */
export async function prove({ query, config = {} }) {
  const cfg = applyClaimShortcut({ ...DEFAULTS, ...config }, config);
  const role = safeRole(cfg.role);
  const violations = [];
  const notes = [];
  let scanned = 0;
  let provenCount = 0;

  const q = async (text, values) => (await query(text, values)).rows;

  // Discover the tables to probe (either configured or introspected).
  let plan;
  if (Array.isArray(cfg.tables) && cfg.tables.length) {
    plan = cfg.tables
      .filter((t) => !cfg.grandfather.includes(t.table))
      .map((t) => ({ schema: t.schema ?? cfg.schemas[0] ?? 'public', table: t.table, tenantColumn: t.tenantColumn, rlsEnabled: undefined }));
  } else {
    const introspect = introspectionSql(cfg.schemas, cfg.tenantColumns, role);
    const rows = await q(introspect.text, introspect.values);
    plan = planTables(rows, cfg.tenantColumns, cfg.grandfather);
  }

  if (plan.length === 0) {
    return OK({
      skipped: true,
      reason: `no tables with a tenant column (${cfg.tenantColumns.join(', ')}) found in ${cfg.schemas.join(', ')}`,
      summary: 'skipped — nothing to prove',
    });
  }

  // Seeding mode: manufacture two synthetic tenants inside the rolled-back
  // transaction, so the proof works on an empty database and on membership-based
  // policies (the seed creates the membership rows). Ids default to two UUIDs;
  // pass seed.tenants for non-UUID tenant columns.
  let seededTenants = null;
  if (cfg.seed) {
    if (!Array.isArray(cfg.seed.setup) || cfg.seed.setup.length === 0) {
      return OK({ skipped: true, reason: 'rlsProof.seed is set but seed.setup is empty', summary: 'skipped — empty seed' });
    }
    if (Array.isArray(cfg.seed.tenants) && cfg.seed.tenants.length >= 2) {
      seededTenants = cfg.seed.tenants.slice(0, 2).map(String);
    } else {
      const { randomUUID } = await import('node:crypto');
      seededTenants = [randomUUID(), randomUUID()];
    }
  }

  await query('begin', []);
  try {
    // Seed the two synthetic tenants (privileged) before anything else. Each
    // statement runs once per tenant with $1 = the tenant id; nothing persists.
    if (seededTenants) {
      for (const tid of seededTenants) {
        for (const stmt of cfg.seed.setup) {
          try {
            await query(stmt, [tid]);
          } catch (err) {
            try { await query('rollback', []); } catch { /* ignore */ }
            return {
              id: meta.id,
              ok: false,
              notes,
              scanned: 0,
              violations: [
                {
                  where: '(seed)',
                  message: `seeding failed for tenant "${tid}": ${err.message}`,
                  fix: `Fix rlsProof.seed.setup — each statement runs once per synthetic tenant ($1 = the tenant id), privileged, inside a rolled-back transaction. Order statements so foreign keys resolve (parents before children).`,
                },
              ],
              summary: 'seeding failed — could not manufacture tenants',
            };
          }
        }
      }
    }

    // Pass 1 — PRIVILEGED: get the tenant pair (seeded, or sampled from existing
    // data) plus the per-tenant row counts a write probe needs.
    for (const t of plan) {
      try {
        if (seededTenants) {
          t.tenants = seededTenants;
        } else {
          const d = distinctTenantsSql(t.schema, t.table, t.tenantColumn, cfg.sampleLimit);
          t.tenants = (await q(d.text, d.values)).map((r) => r.t);
        }
        if (t.tenants.length >= 2) {
          const cnt = tenantCountsSql(t.schema, t.table, t.tenantColumn, t.tenants[0], t.tenants[1]);
          const row = (await q(cnt.text, cnt.values))[0];
          t.ownA = row.own_a;
          t.ownB = row.own_b;
        }
      } catch (err) {
        t.introspectError = err.message;
        t.tenants = [];
      }
    }

    // ── negative control: prove the identity switch actually enforces RLS ──
    // Before trusting any pass, confirm this session is genuinely subject to RLS.
    // Create a deny-all table (RLS on + FORCE, no policy) as the privileged role;
    // after dropping to the app role it MUST return zero rows. If it returns any,
    // RLS is not being enforced for this role (a superuser, a BYPASSRLS role, the
    // table owner, or a SET ROLE that didn't take effect) — so every isolation
    // result would be a vacuous pass, and we refuse to report one.
    let canaryReady = false;
    try {
      await query('create temp table tg_identity_canary (x int)', []);
      await query('insert into tg_identity_canary values (1), (2)', []);
      await query('alter table tg_identity_canary enable row level security', []);
      await query('alter table tg_identity_canary force row level security', []);
      await query(`grant select on tg_identity_canary to ${role}`, []);
      canaryReady = true;
    } catch (err) {
      notes.push({ where: '(identity self-check)', message: `could not set up the RLS self-check canary (${err.message}); proceeding, but a vacuous pass can't be fully ruled out` });
    }

    // Pass 2 — RESTRICTED: assume the app role and prove isolation per table.
    await query(`set local role ${role}`, []);

    if (canaryReady) {
      let seen = null;
      try { seen = (await q('select count(*)::int as n from tg_identity_canary', []))[0].n; } catch { /* permission denied => grants/RLS deny => enforced */ }
      if (seen !== null && seen > 0) {
        try { await query('rollback', []); } catch { /* ignore */ }
        return {
          id: meta.id,
          ok: false,
          notes,
          scanned: 0,
          violations: [
            {
              where: `role "${role}"`,
              message: `identity self-check FAILED — a deny-all RLS table returned ${seen} row(s) as this role, so RLS is NOT being enforced for it. Every "isolated" result would be a vacuous pass.`,
              fix: `Set rlsProof.role to your non-superuser app role (e.g. "authenticated") — not a superuser, a BYPASSRLS role, or a table-owner role. If the role name is right, make sure SET ROLE takes effect on your connection (some poolers reset it).`,
            },
          ],
          summary: 'identity switch is not enforcing RLS — refusing to report a vacuous pass',
        };
      }
    }
    const probedWrites = cfg.probeWrites !== false;

    // Every tenant id seen anywhere in the scan. A table holding a single tenant
    // can still be proven by impersonating one of these — see the foreign-tenant
    // probe below. Without this, per-tenant partitions are unprovable by design.
    const allTenants = [...new Set(plan.flatMap((t) => t.tenants || []))];

    // Run one mutating statement inside a savepoint, read the affected-row count,
    // then ROLLBACK TO SAVEPOINT + RELEASE so nothing changes even within this
    // (already rolled-back) transaction — and so later probes see intact data.
    // Any block or error counts as 0 affected: conservative, never invents a leak.
    const probeWrite = async (sql, values) => {
      await query('savepoint tg_w', []);
      try {
        const res = await query(sql, values);
        const affected = res.rowCount ?? res.affectedRows ?? 0;
        await query('rollback to savepoint tg_w', []);
        await query('release savepoint tg_w', []);
        return affected;
      } catch {
        try {
          await query('rollback to savepoint tg_w', []);
          await query('release savepoint tg_w', []);
        } catch { /* ignore */ }
        return 0;
      }
    };

    // INSERT probe — tri-state. Unlike UPDATE/DELETE, an INSERT the WITH CHECK
    // ACCEPTS succeeds silently (affects 1 row), and one it REJECTS raises. We must
    // not use RETURNING to see where the row landed (RETURNING re-applies the
    // SELECT policy and its error is indistinguishable from a WITH CHECK block).
    // So: insert plainly, then read the acting tenant's OWN-visible row count. If
    // the insert succeeded and the acting tenant's own count did NOT grow, the row
    // landed in the OTHER tenant => 'leak'. If it grew, a trigger rewrote the
    // tenant to the acting one => 'blocked'. A WITH CHECK / no-grant rejection =>
    // 'blocked'; a NOT NULL / FK / CHECK / sequence error => 'inconclusive' (we
    // couldn't build a valid row, so we prove nothing — reported as a note).
    const probeInsert = async (insSql, insValues, ownCountSql, ownCountValues) => {
      await query('savepoint tg_i', []);
      try {
        const before = (await q(ownCountSql, ownCountValues))[0].n;
        const res = await query(insSql, insValues);
        const affected = res.rowCount ?? res.affectedRows ?? 0;
        if (affected < 1) {
          await query('rollback to savepoint tg_i', []); await query('release savepoint tg_i', []);
          return { outcome: 'blocked' }; // nothing inserted
        }
        const after = (await q(ownCountSql, ownCountValues))[0].n;
        await query('rollback to savepoint tg_i', []); await query('release savepoint tg_i', []);
        // Own count grew => the new row is visible to the acting tenant, i.e. it
        // landed in the acting tenant (a trigger forced the column). Not a leak.
        return after > before ? { outcome: 'blocked' } : { outcome: 'leak' };
      } catch (err) {
        try { await query('rollback to savepoint tg_i', []); await query('release savepoint tg_i', []); } catch { /* ignore */ }
        if (isRlsCheckViolation(err)) return { outcome: 'blocked' }; // WITH CHECK rejected the destination — good
        // No INSERT privilege on the TARGET itself => this role genuinely can't
        // create rows here; safe and quiet. (A *sequence*/default-value denial is
        // different — the role can insert but couldn't get a value — so it falls
        // through to inconclusive below, not here.)
        if (/permission denied for (table|relation|view)/i.test(err.message || '')) return { outcome: 'blocked' };
        return { outcome: 'inconclusive', reason: err.message };     // NOT NULL / FK / CHECK / unique / sequence usage — couldn't complete a valid insert
      }
    };

    // POSITIVE CONTROL — insert a row belonging to the acting tenant ITSELF and
    // check it can be read back. Every other probe asks "can A touch B's rows";
    // this asks whether A can still see its own, which is the failure mode that
    // breaks a product rather than leaking it.
    //
    // Anything that is not a clean yes/no answers 'inconclusive'. A NOT NULL
    // column, a foreign key, a unique constraint or a missing sequence grant all
    // stop the insert for reasons that say nothing about policy, and reporting
    // those as findings would make the control worthless.
    const probeOwnInsert = async (insSql, insValues, ownCountSql, ownCountValues) => {
      await query('savepoint tg_own', []);
      const undo = async () => {
        try { await query('rollback to savepoint tg_own', []); await query('release savepoint tg_own', []); }
        catch { /* ignore */ }
      };
      try {
        const before = (await q(ownCountSql, ownCountValues))[0].n;
        const res = await query(insSql, insValues);
        const affected = res.rowCount ?? res.affectedRows ?? 0;
        if (affected < 1) { await undo(); return { outcome: 'rejected' }; }
        const after = (await q(ownCountSql, ownCountValues))[0].n;
        await undo();
        // The row was accepted, so the WITH CHECK passed and it is this tenant's.
        // If the own-row count did not grow, the SELECT policy cannot see a row
        // the INSERT policy just allowed.
        return after > before ? { outcome: 'visible' } : { outcome: 'invisible' };
      } catch (err) {
        await undo();
        if (isRlsCheckViolation(err)) return { outcome: 'rejected' }; // WITH CHECK refused its own tenant
        if (/permission denied for (table|relation|view)/i.test(err.message || '')) return { outcome: 'rejected' };
        return { outcome: 'inconclusive', reason: err.message };
      }
    };

    // OMITTED-tenant probe — insert a row with the tenant column NULL and see if
    // the acting tenant can then READ it. Delta logic is INVERTED vs probeInsert:
    // here own-count GROWING means the orphan is visible to this session (and so
    // to every session, since NULL matches no specific tenant) => an everybody-can-
    // read leak. A NOT NULL violation ON THE TENANT COLUMN means orphans are
    // schema-impossible (safe); on any OTHER column it's inconclusive.
    const probeInsertOmitted = async (insSql, insValues, ownCountSql, ownCountValues, tenantColumn) => {
      await query('savepoint tg_o', []);
      try {
        const before = (await q(ownCountSql, ownCountValues))[0].n;
        const res = await query(insSql, insValues);
        const affected = res.rowCount ?? res.affectedRows ?? 0;
        if (affected < 1) {
          await query('rollback to savepoint tg_o', []); await query('release savepoint tg_o', []);
          return { outcome: 'blocked' };
        }
        const after = (await q(ownCountSql, ownCountValues))[0].n;
        await query('rollback to savepoint tg_o', []); await query('release savepoint tg_o', []);
        // Own count grew => this session can see a row it doesn't own (tenant NULL)
        // => the read policy treats NULL as global => every tenant can read it.
        return after > before ? { outcome: 'leak' } : { outcome: 'blocked' };
      } catch (err) {
        try { await query('rollback to savepoint tg_o', []); await query('release savepoint tg_o', []); } catch { /* ignore */ }
        if (isRlsCheckViolation(err)) return { outcome: 'blocked' }; // WITH CHECK rejected the null tenant — good
        // NOT NULL on the TENANT column itself => orphan rows are impossible; safe.
        if (new RegExp(`null value in column "${tenantColumn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`, 'i').test(err.message || '')) return { outcome: 'blocked' };
        if (/permission denied for (table|relation|view)/i.test(err.message || '')) return { outcome: 'blocked' };
        return { outcome: 'inconclusive', reason: err.message };     // some OTHER NOT NULL / FK / sequence — couldn't complete a valid insert
      }
    };

    for (const t of plan) {
      if (t.introspectError) {
        notes.push({ where: `${t.schema}.${t.table}`, message: `could not sample tenants: ${t.introspectError}` });
        continue;
      }
      // Owner-bypass trap: a table's OWNER is exempt from its own RLS unless FORCE
      // ROW LEVEL SECURITY is set. If the probe role owns this table with FORCE
      // off, RLS is silently inert here — the probe can't be trusted (it would
      // "see" every tenant and then blame the SELECT policy, sending you to fix
      // the wrong thing), and the deny-all canary can't catch it because the
      // canary isn't owned by the probe role. Diagnose it precisely instead.
      if (t.rlsEnabled && !t.rlsForced && t.ownerRole && t.ownerRole === role) {
        scanned++;
        notes.push({ where: `${t.schema}.${t.table}`, message: `NOT proven — the probe role "${role}" OWNS this table and FORCE ROW LEVEL SECURITY is off, so the owner bypasses RLS here and the probe is untrustworthy. If your app really connects as this role, this is a real leak: run \`ALTER TABLE ${qualified(t.schema, t.table)} FORCE ROW LEVEL SECURITY;\` — otherwise set rlsProof.role to your actual non-owner app role.` });
        continue;
      }
      if (t.tenants.length < 2) {
        scanned++;
        // A table holding ONE tenant used to be written off as "cannot prove".
        // It can be proven — from the other side: impersonate a tenant that
        // exists ELSEWHERE in the database and see whether this table's rows are
        // visible to them. Anything visible is a cross-tenant read regardless of
        // how many tenants live in this table.
        //
        // This is what makes PARTITIONS provable at all: list-partitioning by
        // tenant means every partition holds exactly one tenant BY CONSTRUCTION,
        // so the two-tenant probe could never fire — and a partitioned table
        // whose partitions are directly readable came back green.
        const mine = t.tenants[0];
        const foreign = allTenants.find((x) => x !== mine);
        if (mine === undefined || foreign === undefined) {
          notes.push({ where: `${t.schema}.${t.table}`, message: classifyTableResult({ rlsEnabled: t.rlsEnabled, policyCount: t.policyCount, tenantCount: t.tenants.length, ownVisible: 0, crossVisible: 0 }).message });
          continue;
        }
        let seen = 0;
        let failed = null;
        try {
          for (const s of buildBecomeTenant(cfg.becomeTenant, foreign)) await query(s.text, s.values);
          const c = tenantRowCountSql(t.schema, t.table, t.tenantColumn, mine);
          seen = (await q(c.text, c.values))[0].n;
        } catch (err) {
          if (!isPermissionDenied(err)) failed = err.message;
        }
        if (failed) {
          notes.push({ where: `${t.schema}.${t.table}`, message: `could not probe — check rlsProof.becomeTenant/role: ${failed}` });
        } else if (seen > 0) {
          const what = t.isPartition
            ? `this PARTITION holds only tenant "${mine}", and a session acting as a DIFFERENT tenant read ${seen} of its row(s) DIRECTLY. RLS on the partitioned parent does NOT govern a partition queried by its own name — the partition needs its own RLS (and PostgREST exposes each partition as its own endpoint)`
            : `a session acting as a different tenant read ${seen} row(s) belonging to tenant "${mine}"`;
          violations.push({
            where: `${t.schema}.${t.table} (${t.tenantColumn})`,
            kind: 'read',
            message: `${what} — a cross-tenant READ`,
            fix: t.isPartition
              ? `Enable and scope RLS on the partition itself (or revoke direct access to it):\n  ALTER TABLE ${qualified(t.schema, t.table)} ENABLE ROW LEVEL SECURITY;\n  ALTER TABLE ${qualified(t.schema, t.table)} FORCE ROW LEVEL SECURITY;\n  CREATE POLICY tenant_isolation ON ${qualified(t.schema, t.table)} USING (${quoteIdent(t.tenantColumn)} = current_setting('app.current_tenant'));\n      Then re-check every existing partition — and make sure new ones get the same treatment when attached.`
              : `Scope the read policy by the tenant column, e.g. USING (${quoteIdent(t.tenantColumn)} = current_setting('app.current_tenant')).`,
            crossVisible: seen,
            rlsEnabled: t.rlsEnabled,
          });
        } else {
          provenCount++;
        }
        continue;
      }
      // Seeding mode: a table the seed didn't populate for both tenants can't be
      // proven — say so, rather than mis-reading it as over-restrictive.
      if (seededTenants && (t.ownA === 0 || t.ownB === 0)) {
        scanned++;
        notes.push({ where: `${t.schema}.${t.table}`, message: `seed created no rows here for both tenants — add an INSERT for this table to rlsProof.seed.setup to prove it` });
        continue;
      }
      const [tenantA, tenantB] = t.tenants;
      scanned++;

      let noAccess = false;
      let probeError = null;
      let ownVisible = 0;
      let crossVisible = 0;
      let writeAffected = 0;
      const insertOutcomes = [];
      const orphanOutcomes = [];
      let ownInsert = null;
      try {
        // become tenant A: read own + the other tenant's rows, then try to write theirs
        for (const s of buildBecomeTenant(cfg.becomeTenant, tenantA)) await query(s.text, s.values);
        const ownA = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantA);
        const crossB = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantB);
        ownVisible = (await q(ownA.text, ownA.values))[0].n;
        crossVisible = (await q(crossB.text, crossB.values))[0].n;
        if (probedWrites) {
          // As tenant A: (1) claim-into-self / delete — anything beyond A's own
          // rows means A touched another tenant's rows; and (2) the tenant-HOP —
          // set the tenant column to B, moving A's OWN rows INTO tenant B. A
          // correct read policy passes it (the row is A's on the way in); with no
          // WITH CHECK on the destination, nothing validates where it lands.
          const uA = updateProbeSql(t.schema, t.table, t.tenantColumn, tenantA); // set = self
          const dA = deleteProbeSql(t.schema, t.table);
          const mA = updateProbeSql(t.schema, t.table, t.tenantColumn, tenantB); // set = other (hop)
          const claimA = Math.max(await probeWrite(uA.text, uA.values), await probeWrite(dA.text, dA.values));
          const moveA = await probeWrite(mA.text, mA.values);
          writeAffected = Math.max(writeAffected, claimA - t.ownA, moveA);
          // (3) INSERT a row belonging to tenant B — the one write path the above
          // miss. Landing is read from tenant A's OWN row count (see probeInsert).
          const iA = insertProbeSql(t.schema, t.table, t.tenantColumn, tenantB);
          const ownCntA = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantA);
          insertOutcomes.push(await probeInsert(iA.text, iA.values, ownCntA.text, ownCntA.values));
          // (4) INSERT with the tenant OMITTED (NULL) — the orphan-readable-by-all
          // case a wrong-tenant probe walks past. Own-visible count grows => leak.
          const oA = insertOmittedProbeSql(t.schema, t.table, t.tenantColumn);
          const ownAllA = tenantOwnVisibleSql(t.schema, t.table);
          orphanOutcomes.push(await probeInsertOmitted(oA.text, oA.values, ownAllA.text, ownAllA.values, t.tenantColumn));
          // (5) The positive control, tenant A only — one direction is enough,
          // and running both would report the same policy asymmetry twice.
          const ownIns = insertOwnProbeSql(t.schema, t.table, t.tenantColumn, tenantA);
          ownInsert = await probeOwnInsert(ownIns.text, ownIns.values, ownCntA.text, ownCntA.values);
        }

        // reverse direction: become tenant B, check reading/writing A's rows
        for (const s of buildBecomeTenant(cfg.becomeTenant, tenantB)) await query(s.text, s.values);
        const crossA = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantA);
        crossVisible = Math.max(crossVisible, (await q(crossA.text, crossA.values))[0].n);
        if (probedWrites) {
          const uB = updateProbeSql(t.schema, t.table, t.tenantColumn, tenantB); // set = self
          const dB = deleteProbeSql(t.schema, t.table);
          const mB = updateProbeSql(t.schema, t.table, t.tenantColumn, tenantA); // set = other (hop)
          const claimB = Math.max(await probeWrite(uB.text, uB.values), await probeWrite(dB.text, dB.values));
          const moveB = await probeWrite(mB.text, mB.values);
          writeAffected = Math.max(writeAffected, claimB - t.ownB, moveB);
          const iB = insertProbeSql(t.schema, t.table, t.tenantColumn, tenantA);
          const ownCntB = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantB);
          insertOutcomes.push(await probeInsert(iB.text, iB.values, ownCntB.text, ownCntB.values));
          const oB = insertOmittedProbeSql(t.schema, t.table, t.tenantColumn);
          const ownAllB = tenantOwnVisibleSql(t.schema, t.table);
          orphanOutcomes.push(await probeInsertOmitted(oB.text, oB.values, ownAllB.text, ownAllB.values, t.tenantColumn));
        }
      } catch (err) {
        if (isPermissionDenied(err)) noAccess = true;
        else probeError = err.message; // e.g. a becomeTenant config error — don't crash the whole proof
      }

      // A becomeTenant/role misconfiguration fails identically for every table,
      // so surface it as a clear note (with the actionable hint) rather than a
      // cryptic crash, and don't pretend the table was proven.
      if (probeError) {
        notes.push({
          where: `${t.schema}.${t.table}`,
          message:
            `could not probe — check rlsProof.becomeTenant/role: ${probeError}` +
            (/determine data type|42P18/i.test(probeError) ? ` (cast the placeholder, e.g. $1::text)` : ''),
        });
        continue;
      }

      // Fold the two-direction insert probes into one verdict: any leak wins;
      // otherwise, if we couldn't build a valid row in either direction, the
      // insert path is INCONCLUSIVE (a note — never silently counted as proven).
      const insertLeaked = insertOutcomes.some((o) => o.outcome === 'leak');
      const orphanLeaked = orphanOutcomes.some((o) => o.outcome === 'leak');
      const insertInconclusive = !insertLeaked && !orphanLeaked &&
        (insertOutcomes.find((o) => o.outcome === 'inconclusive') || orphanOutcomes.find((o) => o.outcome === 'inconclusive'));
      const verdict = classifyTableResult({ rlsEnabled: t.rlsEnabled, policyCount: t.policyCount, ownVisible, crossVisible, writeAffected, insertLeaked, orphanLeaked, ownInsertInvisible: ownInsert?.outcome === 'invisible', ownInsertRejected: ownInsert?.outcome === 'rejected', tenantCount: t.tenants.length, noAccess, probedWrites });
      const tbl = qualified(t.schema, t.table);
      // An otherwise-clean table whose insert path we couldn't exercise: say so,
      // so a green result never overclaims "no write can cross tenants".
      if (verdict.status !== 'leak' && insertInconclusive) {
        notes.push({ where: `${t.schema}.${t.table}`, message: `read/UPDATE/DELETE isolation proven, but an INSERT probe was inconclusive — a minimal row hit: ${insertInconclusive.reason}. Give the app role what the insert needs (e.g. grant usage on the table's sequence, or default/seed the missing NOT NULL columns) to prove INSERT isolation too` });
      }
      if (verdict.status === 'leak') {
        for (const leak of verdict.leaks) {
          // The message needs the same substitution as the fix. It did not get
          // it, so the orphan-leak finding printed a literal "{col}" to the user.
          const fill = (text) => String(text ?? '')
            .split('{cmp}').join(tenantComparison(quoteIdent(t.tenantColumn), t.tenantColumnType))
            .split('{col}').join(quoteIdent(t.tenantColumn))
            .split('{tbl}').join(tbl);
          violations.push({
            where: `${t.schema}.${t.table} (${t.tenantColumn})`,
            kind: leak.kind,
            message: fill(leak.message),
            fix: fill(leak.fix),
            crossVisible,
            writeAffected,
            rlsEnabled: t.rlsEnabled,
          });
        }
      } else if (verdict.status === 'isolated') {
        provenCount++;
      } else {
        notes.push({ where: `${t.schema}.${t.table}`, message: verdict.message });
      }
    }
  } finally {
    // Non-destructive by construction: nothing is committed.
    try { await query('rollback', []); } catch { /* ignore */ }
  }

  // TRUNCATE bypasses RLS completely — it is gated only by the table privilege,
  // and GRANT ALL (Supabase's default for anon/authenticated) includes it. So any
  // logged-in user could wipe every tenant's rows and no policy would stop them.
  // Reported as ONE aggregated note rather than a per-table failure: on a stock
  // Supabase project this is true of every table, and it is only reachable
  // through a SQL channel (PostgREST exposes no TRUNCATE), so failing the build
  // on it would be noise. Latent, worth knowing, not an emergency.
  const truncatable = plan.filter((t) => t.canTruncate).map((t) => `${t.schema}.${t.table}`);
  if (truncatable.length > 0) {
    notes.push({
      where: `role "${role}"`,
      message:
        `"${role}" holds TRUNCATE on ${truncatable.length} tenant table(s) (${truncatable.slice(0, 3).join(', ')}${truncatable.length > 3 ? `, +${truncatable.length - 3} more` : ''}). ` +
        `TRUNCATE ignores RLS entirely — no policy can stop it — so anyone who reaches a SQL channel as this role can wipe EVERY tenant's rows. Usually inherited from GRANT ALL. ` +
        `Not reachable through PostgREST, so this is latent rather than directly exploitable; to close it: REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM ${role};`,
    });
  }

  const proven = provenCount;
  // Count TABLES we could not prove — not notes. Advisory notes (TRUNCATE, the
  // identity self-check) are not tables, and counting them here overstated it.
  const notProven = Math.max(scanned - proven - new Set(violations.map((v) => v.where)).size, 0);
  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length === 0
        ? `${Math.max(proven, 0)}/${scanned} tenant table(s) proven isolated (read + write)` + (notProven > 0 ? `; ${notProven} not proven (see notes)` : '')
        : `${violations.length} cross-tenant leak(s) across ${new Set(violations.map((v) => v.where)).size} table(s)`,
  };
}

/**
 * CLI/programmatic entry: resolve a Postgres connection from the environment,
 * dynamically import `pg`, and run the proof. SKIPS cleanly (never fails the
 * build) when no database URL is configured or `pg` isn't installed — a skip is
 * not a pass, and the CLI says so.
 *
 * @param {object} config  see DEFAULTS, plus optional `url`
 */
export async function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const url = cfg.url || process.env[cfg.urlEnv] || process.env.DATABASE_URL;
  if (!url) {
    return OK({
      skipped: true,
      reason: `no database configured — set ${cfg.urlEnv} (or DATABASE_URL) to a test/staging database to run the proof`,
      summary: 'skipped — no database',
    });
  }

  let pg;
  try {
    pg = await import('pg');
  } catch {
    return OK({
      skipped: true,
      reason: `Postgres driver not installed — run \`npm i -D pg\` to enable the runtime RLS proof`,
      summary: 'skipped — pg not installed',
    });
  }

  const Client = pg.default?.Client ?? pg.Client;
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    const query = (text, values) => client.query(text, values);
    return await prove({ query, config: cfg });
  } finally {
    await client.end();
  }
}
