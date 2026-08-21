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
           has_table_privilege($2, format('%I.%I', n.nspname, c.relname), 'INSERT') as can_insert,
           has_table_privilege($2, format('%I.%I', n.nspname, c.relname), 'UPDATE') as can_update,
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
  if (plan.length === 0) {
    return OK({ skipped: true, reason: `no tables in ${cfg.schemas.join(', ')}`, summary: 'skipped — no tables' });
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
