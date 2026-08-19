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
export function introspectionSql(schemas, tenantColumns) {
  const text = `
    select n.nspname            as schema,
           c.relname            as table,
           a.attname            as column,
           c.relrowsecurity     as rls_enabled,
           c.relforcerowsecurity as rls_forced,
           (select count(*) from pg_catalog.pg_policy pol where pol.polrelid = c.oid)::int as policy_count
    from pg_catalog.pg_class c
    join pg_catalog.pg_namespace n on n.oid = c.relnamespace
    join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    where c.relkind = 'r'
      and n.nspname = any($1)
      and a.attname = any($2)
    order by n.nspname, c.relname`;
  return { text, values: [schemas, tenantColumns] };
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
        rlsEnabled: r.rls_enabled === true || r.rls_enabled === 't',
        rlsForced: r.rls_forced === true || r.rls_forced === 't',
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

/** Expand the becomeTenant templates into { text, values } for a tenant id. */
export function buildBecomeTenant(templates, tenantId) {
  return templates.map((text) => ({ text, values: [tenantId] }));
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
 * Turn one table's measurements into a verdict. A table can leak on the READ
 * path (SELECT) and/or the WRITE path (UPDATE/DELETE) independently, because
 * Postgres RLS is per-command — so a 'leak' verdict carries a `leaks[]` array,
 * one entry per kind, and the caller emits a violation for each.
 * @returns {{ status:'isolated'|'leak'|'no-policy'|'insufficient-data'|'over-restrictive'|'no-access', message?:string, leaks?:Array<{kind:'read'|'write',message:string,fix:string}> }}
 */
export function classifyTableResult({ rlsEnabled, policyCount, ownVisible, crossVisible, writeAffected = 0, tenantCount, noAccess, probedWrites = false }) {
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
        ? `Scope the read policy by the tenant column, e.g. USING ({col} = current_setting('app.current_tenant')).`
        : `Enable RLS and add a tenant policy:\n  ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;\n  ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;\n  CREATE POLICY tenant_isolation ON {tbl} USING ({col} = current_setting('app.current_tenant'));`,
    });
  }
  if (writeAffected > 0) {
    leaks.push({
      kind: 'write',
      message: `tenant A's session WROTE to ${writeAffected} row(s) belonging to tenant B (UPDATE/DELETE) — RLS is per-command, so a correct SELECT policy does not protect writes`,
      fix: `Add write coverage — a FOR ALL policy, or explicit UPDATE/DELETE policies, scoped by the tenant column:\n  CREATE POLICY tenant_all ON {tbl} FOR ALL\n    USING ({col} = current_setting('app.current_tenant'))\n    WITH CHECK ({col} = current_setting('app.current_tenant'));`,
    });
  }
  if (leaks.length) return { status: 'leak', leaks };

  if (ownVisible === 0) {
    return { status: 'over-restrictive', message: `the tenant session sees none of its own rows either — this table wasn't actually proven (not a leak). Usually the role/becomeTenant config doesn't match your policies; if your policies read a MEMBERSHIP table (org_id IN (select … where user_id = auth.uid())), the impersonated identity also needs a seeded membership row, not just a claim.` };
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
  const cfg = { ...DEFAULTS, ...config };
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
    const introspect = introspectionSql(cfg.schemas, cfg.tenantColumns);
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

    for (const t of plan) {
      if (t.introspectError) {
        notes.push({ where: `${t.schema}.${t.table}`, message: `could not sample tenants: ${t.introspectError}` });
        continue;
      }
      if (t.tenants.length < 2) {
        scanned++;
        notes.push({ where: `${t.schema}.${t.table}`, message: classifyTableResult({ rlsEnabled: t.rlsEnabled, policyCount: t.policyCount, tenantCount: t.tenants.length, ownVisible: 0, crossVisible: 0 }).message });
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
      try {
        // become tenant A: read own + the other tenant's rows, then try to write theirs
        for (const s of buildBecomeTenant(cfg.becomeTenant, tenantA)) await query(s.text, s.values);
        const ownA = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantA);
        const crossB = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantB);
        ownVisible = (await q(ownA.text, ownA.values))[0].n;
        crossVisible = (await q(crossB.text, crossB.values))[0].n;
        if (probedWrites) {
          // as tenant A: reassign / delete the whole table; anything beyond A's
          // own rows means A can write another tenant's rows.
          const uA = updateProbeSql(t.schema, t.table, t.tenantColumn, tenantA);
          const dA = deleteProbeSql(t.schema, t.table);
          const affA = Math.max(await probeWrite(uA.text, uA.values), await probeWrite(dA.text, dA.values));
          writeAffected = Math.max(writeAffected, affA - t.ownA);
        }

        // reverse direction: become tenant B, check reading/writing A's rows
        for (const s of buildBecomeTenant(cfg.becomeTenant, tenantB)) await query(s.text, s.values);
        const crossA = tenantRowCountSql(t.schema, t.table, t.tenantColumn, tenantA);
        crossVisible = Math.max(crossVisible, (await q(crossA.text, crossA.values))[0].n);
        if (probedWrites) {
          const uB = updateProbeSql(t.schema, t.table, t.tenantColumn, tenantB);
          const dB = deleteProbeSql(t.schema, t.table);
          const affB = Math.max(await probeWrite(uB.text, uB.values), await probeWrite(dB.text, dB.values));
          writeAffected = Math.max(writeAffected, affB - t.ownB);
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

      const verdict = classifyTableResult({ rlsEnabled: t.rlsEnabled, policyCount: t.policyCount, ownVisible, crossVisible, writeAffected, tenantCount: t.tenants.length, noAccess, probedWrites });
      const tbl = qualified(t.schema, t.table);
      if (verdict.status === 'leak') {
        for (const leak of verdict.leaks) {
          violations.push({
            where: `${t.schema}.${t.table} (${t.tenantColumn})`,
            kind: leak.kind,
            message: leak.message,
            fix: leak.fix.split('{col}').join(quoteIdent(t.tenantColumn)).split('{tbl}').join(tbl),
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

  const proven = provenCount;
  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length === 0
        ? `${Math.max(proven, 0)}/${scanned} tenant table(s) proven isolated (read + write)` + (notes.length ? `; ${notes.length} not proven (see notes)` : '')
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
