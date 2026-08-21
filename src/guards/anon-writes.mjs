/**
 * Guard: the unauthenticated write surface. Which tables can `anon` — a visitor
 * with the public key, no login — INSERT / UPDATE / DELETE?
 *
 * This is the class the tenant guards miss. `rls-proof` asks "can tenant A touch
 * tenant B?" and `rls-drift` asks "is this policy in git?" — but a table with no
 * tenant column, writable by `anon`, is neither. It's how a shared cache gets
 * poisoned: the public key ships in every browser bundle, so if `anon` can write
 * the table, anyone can rewrite what every user reads. Almost no table should
 * accept unauthenticated writes.
 *
 * Reliability matters here more than anywhere, because well-secured Supabase apps
 * write policies `TO public USING (auth.uid() = …)` — a static/catalog check
 * can't evaluate that `USING`, so it would false-positive on good code. So:
 *   • RLS OFF + `anon` has a write grant  → anon can write, unambiguously (no
 *     policy to gate it). Flagged from the catalog.
 *   • RLS ON  → we drop to `anon` and actually attempt UPDATE/DELETE, each in a
 *     rolled-back savepoint. Any row affected means the real policy let `anon`
 *     through. This evaluates USING/WITH CHECK for real — no guessing.
 *
 * Before trusting a clean run it uses the same negative control as `rls-proof`:
 * `anon` must NOT be able to read a deny-all table. If it can, `anon` bypasses
 * RLS and the probe results are meaningless — so we abort instead.
 *
 *
 * **Column grants count.** `has_table_privilege` answers only about the TABLE
 * ACL, so `GRANT SELECT (id, body) ON notes TO anon` returns false and the whole
 * relation was skipped — on a table with RLS off, where anon really was reading
 * every tenant's rows. Measured: anon read 2 rows across two tenants and updated
 * 2, and this guard reported ok. `has_any_column_privilege` is the question that
 * matches what the role can actually do; the table-level answer is kept only to
 * tell full exposure from partial in the message.
 *
 * Non-destructive: everything is one rolled-back transaction, writes wrapped in
 * savepoints. Needs `pg` + a database URL; skips cleanly without them. Honest
 * limit: on RLS-ON tables it proves UPDATE/DELETE by probe; a pure INSERT-only
 * anon surface under RLS isn't probed yet (roadmap).
 */
import { quoteIdent, qualified, safeRole, isPermissionDenied } from './rls-proof.mjs';

export const meta = {
  id: 'anon-writes',
  title: 'Unauthenticated (anon) write surface',
  why: 'Flags tables the anonymous role can INSERT/UPDATE/DELETE — the cache-poisoning / tampering class that tenant-isolation checks miss. Almost no table should accept unauthenticated writes.',
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  schemas: ['public'],
  role: 'anon', // the unauthenticated role to test
  allowlist: [], // "schema.table" that intentionally accepts anon writes (a public contact form, etc.)
};

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Does the tested role exist? Returns { text, values }. */
export function roleExistsSql(role) {
  return { text: `select 1 from pg_catalog.pg_roles where rolname = $1`, values: [role] };
}

/**
 * Per-table: RLS state, whether the role holds each write privilege (grant), and
 * a plain column to use for the UPDATE no-op probe. `has_table_privilege` reports
 * the GRANT only (not RLS) — we combine it with rls_enabled in the verdict.
 */
export function surfaceSql(schemas, role) {
  const text = `
    select n.nspname as schema, c.relname as "table",
           c.relrowsecurity as rls_enabled,
           (has_table_privilege($2, format('%I.%I', n.nspname, c.relname), 'INSERT')
             or has_any_column_privilege($2, format('%I.%I', n.nspname, c.relname), 'INSERT')) as can_insert,
           (has_table_privilege($2, format('%I.%I', n.nspname, c.relname), 'UPDATE')
             or has_any_column_privilege($2, format('%I.%I', n.nspname, c.relname), 'UPDATE')) as can_update,
           -- DELETE has no column-level form in Postgres: you cannot GRANT
           -- DELETE (col), so the table answer is the whole answer here.
           has_table_privilege($2, format('%I.%I', n.nspname, c.relname), 'DELETE') as can_delete,
           (select a.attname from pg_catalog.pg_attribute a
              where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped and a.attgenerated = ''
              order by a.attnum limit 1) as probe_col
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    -- 'p' as well as 'r': a PARTITIONED parent is where the grant usually lives,
    -- and excluding it was a live false negative — anon updated every row through
    -- the parent while this guard reported clean. Same class as threat-model 4.7,
    -- which was fixed in rls-proof and never here.
    where c.relkind in ('r', 'p') and n.nspname = any($1)
    order by n.nspname, c.relname`;
  return { text, values: [schemas, role] };
}

const bool = (v) => v === true || v === 't';

/** Normalise a surface row and drop grandfathered/allowlisted tables. */
/**
 * The VIEW write surface — the half of "what can anon write" that no amount of
 * RLS review covers, because a view has no RLS of its own.
 *
 * A view created after `ALTER DEFAULT PRIVILEGES ... GRANT ... ON TABLES` inherits
 * the write grant silently, and unless it was declared `security_invoker = true`
 * it executes as its OWNER — so an UPDATE through it reaches the base table with
 * that table's policies never consulted. Reported from a real run as the worst
 * bug found: `PATCH`/`DELETE` on a public profiles view returned 200.
 *
 * Three catalog facts settle it, and all three are needed:
 *
 *   • `pg_relation_is_updatable(oid, true)` — Postgres's own answer to whether
 *     writes pass through. Non-zero for an auto-updatable view, 0 for one with
 *     an aggregate or a join. Measured: a grant-only check calls those writable
 *     too, so it false-positives on every reporting view in the schema.
 *   • `security_invoker` — with it on, the base table's RLS applies to the
 *     caller and the write is refused. Verified both ways: 1 row affected with
 *     it off, 42501 with it on.
 *   • the role's actual privilege.
 */
export function viewSurfaceSql(schemas, role) {
  return {
    text: `
      select n.nspname as schema,
             c.relname as table,
             c.relkind::text as relkind,
             c.relowner::regrole::text as owner_role,
             pg_catalog.pg_relation_is_updatable(c.oid, true) as updatable_mask,
             coalesce((select option_value from pg_catalog.pg_options_to_table(c.reloptions)
                       where option_name = 'security_invoker'), 'false') as security_invoker,
             (pg_catalog.has_table_privilege($2::text, c.oid, 'INSERT')
               or pg_catalog.has_any_column_privilege($2::text, c.oid, 'INSERT')) as can_insert,
             (pg_catalog.has_table_privilege($2::text, c.oid, 'UPDATE')
               or pg_catalog.has_any_column_privilege($2::text, c.oid, 'UPDATE')) as can_update,
             pg_catalog.has_table_privilege($2::text, c.oid, 'DELETE') as can_delete,
             (select a.attname from pg_catalog.pg_attribute a
               where a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
               order by a.attnum limit 1) as probe_col
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      where c.relkind = 'v' and n.nspname = any($1)
      order by n.nspname, c.relname
    `,
    values: [schemas, role],
  };
}

/** True when `security_invoker` is off, i.e. the view runs as its owner. */
export function runsAsOwner(row) {
  return String(row?.security_invoker ?? 'false').toLowerCase() !== 'true';
}

/**
 * The views worth probing: writes pass through, the view runs as its owner, and
 * the role holds a write privilege. Anything else is silent — a reporting view
 * with a grant it cannot use is not a finding.
 */
export function planViewSurface(rows, allowlist = []) {
  const skip = new Set(allowlist);
  return (rows ?? [])
    .filter((r) => Number(r.updatable_mask ?? 0) !== 0)
    .filter(runsAsOwner)
    .filter((r) => r.can_insert === true || r.can_update === true || r.can_delete === true)
    .filter((r) => !skip.has(r.table) && !skip.has(`${r.schema}.${r.table}`))
    .map((r) => ({
      schema: r.schema,
      table: r.table,
      isView: true,
      ownerRole: r.owner_role ?? null,
      canUpdate: r.can_update === true,
      canDelete: r.can_delete === true,
      canInsert: r.can_insert === true,
      probeCol: r.probe_col ?? null,
    }));
}

/** The verdict for one writable view. */
export function violationForView(v, commands, role) {
  const id = `${v.schema}.${v.table}`;
  return {
    where: id,
    kind: 'anon-writable-view',
    message:
      `"${role}" performed ${commands.join(' and ')} through the view ${id}, and the write reached the base table. ` +
      `A view has no RLS of its own, and this one has security_invoker off, so it executes as its owner (${v.ownerRole ?? 'the view owner'}) The write escapes RLS because that owner is exempt from the base table policies — it owns the table without FORCE ROW LEVEL SECURITY, or is a superuser. On Supabase that is the default, since objects created in the SQL editor are owned by postgres. ` +
      `Proven by probing, in a rolled-back transaction: rows were actually affected. ` +
      `The usual cause is ALTER DEFAULT PRIVILEGES granting writes on TABLES, which covers views created afterwards, so nothing in any migration reads like a security change.`,
    fix:
      `Take the write grant away — a view meant for reading needs only SELECT:\n` +
      `        REVOKE INSERT, UPDATE, DELETE ON ${id} FROM ${role}, authenticated;\n` +
      `      If writes through it are intended, make it run as the CALLER so the base table's RLS applies (Postgres 15+; on 14 and earlier the option does not exist, so the REVOKE is your only choice):\n` +
      `        ALTER VIEW ${id} SET (security_invoker = true);\n` +
      `      Measure what that actually gives you. Verified both ways: if ${role} holds no privilege on the BASE table the write is refused with 42501 — but if it does, which is the usual case here because ALTER DEFAULT PRIVILEGES granted the table too, the write is not refused at all. It silently affects zero rows, since RLS is now evaluated as ${role} and matches nothing. Safe, but silent, which is why the REVOKE is the fix that tells you it worked.\n` +
      `      And check what else inherited it:  ALTER DEFAULT PRIVILEGES IN SCHEMA ${v.schema} REVOKE INSERT, UPDATE, DELETE ON TABLES FROM ${role};`,
  };
}

export function planSurface(rows, allowlist = []) {
  const skip = new Set(allowlist);
  return rows
    .map((r) => ({
      schema: r.schema,
      table: r.table,
      id: `${r.schema}.${r.table}`,
      rlsEnabled: bool(r.rls_enabled),
      canInsert: bool(r.can_insert),
      canUpdate: bool(r.can_update),
      canDelete: bool(r.can_delete),
      probeCol: r.probe_col ?? null,
    }))
    .filter((t) => !skip.has(t.id) && !skip.has(t.table));
}

/** The write commands the role holds a grant for. */
export function grantedWrites(t) {
  const cmds = [];
  if (t.canInsert) cmds.push('INSERT');
  if (t.canUpdate) cmds.push('UPDATE');
  if (t.canDelete) cmds.push('DELETE');
  return cmds;
}

/** No-op whole-table UPDATE (no WHERE — probes the write policy for real). */
export function anonUpdateSql(schema, table, col) {
  const c = quoteIdent(col);
  return `update ${qualified(schema, table)} set ${c} = ${c}`;
}
/** Whole-table DELETE (no WHERE, USING-only). */
/**
 * UPDATE probe for a view. The table probe writes the tenant column back onto
 * itself; a view may not expose one, so this rewrites the view's first column to
 * its own value — a no-op that still has to pass every check a real write does.
 * Rolled back regardless, like every other probe here.
 */
export function viewUpdateSql(schema, table, column) {
  const c = quoteIdent(column);
  return `update ${qualified(schema, table)} set ${c} = ${c}`;
}

export function anonDeleteSql(schema, table) {
  return `delete from ${qualified(schema, table)}`;
}

/** Build a violation for a flagged table. */
export function violationFor(t, commands, viaRls) {
  return {
    where: t.id,
    message:
      `the "${t.role ?? 'anon'}" role can ${commands.join('/')} this table ` +
      (viaRls ? `(a policy permits it — proven by probe)` : `(RLS is OFF, so its write grant is unguarded)`),
    fix:
      `Unauthenticated writes are almost never intended. Either enable RLS with a policy that denies anon writes, or REVOKE ${commands.join(', ')} ON ${qualified(t.schema, t.table)} FROM anon;\n` +
      `      If this table is meant to accept anonymous writes (e.g. a public contact form), add "${t.id}" to anonWrites.allowlist[].`,
    commands,
  };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

/**
 * @param {(text:string, values?:any[]) => Promise<{rows:any[]}>} query
 * @param {object} config  see DEFAULTS
 */
export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;

  // The role must exist to test it.
  if ((await q(roleExistsSql(role).text, [role])).length === 0) {
    return OK({ skipped: true, reason: `role "${role}" does not exist — set anonWrites.role to your unauthenticated role`, summary: `skipped — no "${role}" role` });
  }

  const s = surfaceSql(cfg.schemas, role);
  const plan = planSurface(await q(s.text, s.values), cfg.allowlist).map((t) => ({ ...t, role }));

  // Views are selected from the catalog rather than probed blind: writes must
  // actually pass through, and the view must run as its owner. See viewSurfaceSql.
  let viewPlan = [];
  try {
    const vs = viewSurfaceSql(cfg.schemas, role);
    viewPlan = planViewSurface(await q(vs.text, vs.values), cfg.allowlist);
  } catch { /* older server or no permission on the catalog — tables still checked */ }

  if (plan.length === 0 && viewPlan.length === 0) {
    return OK({ skipped: true, reason: `no tables or writable views in ${cfg.schemas.join(', ')}`, summary: 'skipped — no tables' });
  }

  const violations = [];
  const notes = [];
  let scanned = 0;

  await query('begin', []);
  try {
    // Negative control: drop to the role and confirm it is subject to RLS.
    let canaryReady = false;
    try {
      await query('create temp table tg_anon_canary (x int)', []);
      await query('insert into tg_anon_canary values (1), (2)', []);
      await query('alter table tg_anon_canary enable row level security', []);
      await query('alter table tg_anon_canary force row level security', []);
      await query(`grant select on tg_anon_canary to ${role}`, []);
      canaryReady = true;
    } catch (err) {
      notes.push({ where: '(self-check)', message: `could not set up the RLS self-check canary (${err.message})` });
    }
    await query(`set local role ${role}`, []);
    if (canaryReady) {
      let seen = null;
      try { seen = (await q('select count(*)::int as n from tg_anon_canary', []))[0].n; } catch { /* denied => enforced */ }
      if (seen !== null && seen > 0) {
        try { await query('rollback', []); } catch { /* ignore */ }
        return {
          id: meta.id, ok: false, notes, scanned: 0,
          violations: [{ where: `role "${role}"`, message: `"${role}" can read a deny-all RLS table — it BYPASSES RLS entirely (a superuser / BYPASSRLS role). That is itself critical, and it makes every probe below meaningless.`, fix: `Ensure "${role}" is a normal non-privileged role. In Supabase, anon must not have BYPASSRLS.` }],
          summary: `"${role}" bypasses RLS — aborting`,
        };
      }
    }

    const probeWrite = async (sql) => {
      await query('savepoint tg_a', []);
      try {
        const res = await query(sql, []);
        const n = res.rowCount ?? res.affectedRows ?? 0;
        await query('rollback to savepoint tg_a', []);
        await query('release savepoint tg_a', []);
        return n;
      } catch {
        try { await query('rollback to savepoint tg_a', []); await query('release savepoint tg_a', []); } catch { /* ignore */ }
        return 0;
      }
    };

    for (const t of plan) {
      scanned++;
      if (!t.rlsEnabled) {
        // Unambiguous: no RLS means the write grant is the whole story.
        const cmds = grantedWrites(t);
        if (cmds.length) violations.push(violationFor(t, cmds, false));
        continue;
      }
      // RLS on: probe the real policy as the role. (INSERT-under-RLS not probed yet.)
      const cmds = [];
      if (t.probeCol && t.canUpdate && (await probeWrite(anonUpdateSql(t.schema, t.table, t.probeCol))) > 0) cmds.push('UPDATE');
      if (t.canDelete && (await probeWrite(anonDeleteSql(t.schema, t.table))) > 0) cmds.push('DELETE');
      if (cmds.length) violations.push(violationFor(t, cmds, true));
    }

    // Views. Probed exactly like the tables above, and inside the same
    // transaction, so a clean result means the same thing here as there.
    for (const v of viewPlan) {
      scanned++;
      const cmds = [];
      if (v.canUpdate && v.probeCol && (await probeWrite(viewUpdateSql(v.schema, v.table, v.probeCol))) > 0) cmds.push('UPDATE');
      if (v.canDelete && (await probeWrite(anonDeleteSql(v.schema, v.table))) > 0) cmds.push('DELETE');
      if (cmds.length) violations.push(violationForView(v, cmds, role));
    }
  } finally {
    try { await query('rollback', []); } catch { /* ignore */ }
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length === 0
        ? `${scanned} table(s) checked; none writable by "${role}"`
        : `${violations.length} table(s) writable by "${role}"`,
  };
}

/**
 * CLI/programmatic entry: resolve a Postgres connection, dynamically import `pg`,
 * run the check. Skips cleanly with no database URL or no `pg`.
 */
export async function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const url = cfg.url || process.env[cfg.urlEnv] || process.env.DATABASE_URL;
  if (!url) {
    return OK({ skipped: true, reason: `no database configured — set ${cfg.urlEnv} (or DATABASE_URL)`, summary: 'skipped — no database' });
  }
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
