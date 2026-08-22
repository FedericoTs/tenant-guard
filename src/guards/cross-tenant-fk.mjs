/**
 * Guard: foreign keys that reach across tenants.
 *
 * Threat-model §3.11, and the only finding in this tool where one tenant can
 * **destroy** another tenant's data rather than read it.
 *
 * The mechanism is a documented Postgres behaviour that almost nobody accounts
 * for: **referential integrity checks always bypass row-level security.** They
 * have to — a constraint that could be defeated by hiding a row would not be a
 * constraint. So when `tasks.project_id` references `projects(id)` and the
 * foreign key does *not* carry the tenant column:
 *
 *   1. Tenant A points one of their own rows at a project belonging to tenant B.
 *      The FK check happily confirms that project exists even though RLS hides it,
 *      and the child policy's `WITH CHECK` never objects — it governs the tenant
 *      column, not the reference.
 *   2. Tenant B later deletes their own project. `ON DELETE CASCADE` **deletes
 *      tenant A's rows**, with no policy consulted at any point.
 *
 * Verified end to end: tenant A re-pointed its row at a project it could not see,
 * and tenant B's ordinary delete then destroyed it. Neither tenant did anything
 * unusual, and every other guard here reports that database as isolated.
 *
 * With `RESTRICT`/`NO ACTION` the impact inverts rather than disappearing: tenant
 * A's reference **pins** tenant B's row so tenant B can no longer delete their own
 * data.
 *
 * The structural cause is always the same — the FK carries an id but not the
 * tenant. A composite key `(organization_id, project_id) → (organization_id, id)`
 * makes a cross-tenant reference unrepresentable, which is why that is the fix —
 * carrying over whatever ON DELETE/ON UPDATE action the old key had, because
 * dropping it is its own outage.
 *
 * A table that references ITSELF (`parent_id → nodes(id)`) is the same failure:
 * the boundary runs between one table's own rows. Verified there too — org_A
 * re-pointed at a row it could not see, org_B deleted that row, org_A's row was
 * gone.
 */
import {
  quoteIdent, qualified, safeRole, buildBecomeTenant, applyClaimShortcut,
  isPermissionDenied, isRlsCheckViolation, DEFAULTS as PROOF_DEFAULTS,
} from './rls-proof.mjs';

export const meta = {
  id: 'cross-tenant-fk',
  title: 'Foreign keys that reach across tenants',
  why: "Referential integrity checks ALWAYS bypass row-level security — they must, or a constraint could be defeated by hiding a row. So a foreign key that carries an id but not the tenant lets one tenant point their row at another tenant's, which RLS never sees; and then ON DELETE CASCADE means the second tenant deleting their own row DELETES the first tenant's data. It is the one failure here where a tenant destroys another tenant's rows rather than reading them.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: PROOF_DEFAULTS.role,
  becomeTenant: PROOF_DEFAULTS.becomeTenant,
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns,
  allowlist: [], // "schema.table::constraint_name" that spans tenants on purpose
};

/** `confdeltype` / `confupdtype` codes, and what each means for the other tenant. */
export const ACTIONS = {
  a: { name: 'NO ACTION', destructive: false },
  r: { name: 'RESTRICT', destructive: false },
  c: { name: 'CASCADE', destructive: true },
  n: { name: 'SET NULL', destructive: true },
  d: { name: 'SET DEFAULT', destructive: true },
};

export const describeAction = (code) => ACTIONS[code]?.name ?? 'NO ACTION';
export const isDestructive = (code) => ACTIONS[code]?.destructive === true;

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/**
 * Every foreign key whose child and parent both live in the target schemas.
 *
 * Every catalog relation is `pg_catalog.`-qualified. Unqualified, they resolve
 * through the connection's search_path, and a schema listed BEFORE pg_catalog
 * that holds same-named tables silently answers instead. Measured: with
 * `public.pg_class/pg_namespace/pg_attribute/pg_constraint` present and
 * `search_path = public, pg_catalog`, this guard went from reporting the leak to
 * `skipped — no cross-tenant-capable foreign keys`. A qualified read returns
 * exactly what the unqualified one returned whenever it was resolving correctly,
 * so this can only remove the case where the guard goes quiet.
 */
export function foreignKeysSql(schemas) {
  return {
    text: `
      select
        con.conname                                     as name,
        cn.nspname                                      as child_schema,
        cc.relname                                      as child_table,
        pn.nspname                                      as parent_schema,
        pc.relname                                      as parent_table,
        con.confdeltype                                 as on_delete,
        con.confupdtype                                 as on_update,
        (select array_agg(a.attname order by k.ord)
           from unnest(con.conkey) with ordinality k(attnum, ord)
           join pg_catalog.pg_attribute a on a.attrelid = con.conrelid and a.attnum = k.attnum) as child_columns,
        (select array_agg(a.attname order by k.ord)
           from unnest(con.confkey) with ordinality k(attnum, ord)
           join pg_catalog.pg_attribute a on a.attrelid = con.confrelid and a.attnum = k.attnum) as parent_columns
      from pg_catalog.pg_constraint con
      join pg_catalog.pg_class cc     on cc.oid = con.conrelid
      join pg_catalog.pg_namespace cn on cn.oid = cc.relnamespace
      join pg_catalog.pg_class pc     on pc.oid = con.confrelid
      join pg_catalog.pg_namespace pn on pn.oid = pc.relnamespace
      where con.contype = 'f'
        and cn.nspname = any($1)
        and pn.nspname = any($1)
    `,
    values: [schemas],
  };
}

/**
 * Which tables carry a tenant column, and which one.
 *
 * `order by array_position(...)` makes the configured `tenantColumns` order a
 * PRIORITY, which is what every other guard already treats it as
 * (constraint-oracles.tenantColumnSql orders the same way; rls-proof.planTables
 * ranks by `tenantColumns.indexOf`). Without it the rows come back in attnum
 * order and `tenantColumnMap`'s first-wins keeps whichever column was declared
 * first. Measured on a table carrying a legacy nullable `tenant_id` declared
 * before `organization_id`: this guard picked `tenant_id` while
 * constraint-oracles picked `organization_id` on the same database — which made
 * it call the correctly-fixed composite key "without carrying the tenant", and
 * on a genuinely loose FK made `crossTenantRowsSql` compare an all-NULL column
 * against the parent's tenant and report 2 non-existent corrupt rows.
 */
export function tenantColumnsSql(schemas, tenantColumns) {
  return {
    text: `
      select n.nspname as schema, c.relname as table, a.attname as column
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      join pg_catalog.pg_attribute a on a.attrelid = c.oid
      where c.relkind in ('r', 'p')
        and n.nspname = any($1)
        and a.attname = any($2)
        and a.attnum > 0
        and not a.attisdropped
      order by array_position($2::text[], a.attname::text)
    `,
    values: [schemas, tenantColumns],
  };
}

/** Index the tenant-column rows as "schema.table" → column. */
export function tenantColumnMap(rows) {
  const map = new Map();
  for (const r of rows ?? []) {
    if (!map.has(`${r.schema}.${r.table}`)) map.set(`${r.schema}.${r.table}`, r.column);
  }
  return map;
}

/**
 * The foreign keys that can express a cross-tenant reference.
 *
 * Both sides must be tenant tables — a lookup table shared by everyone is not a
 * tenant boundary — and the key must NOT already carry the child's tenant
 * column, because a composite `(tenant, id)` key makes the bad state
 * unrepresentable and is exactly the fix this guard recommends.
 *
 * A SELF-reference is a candidate too. It used to be excluded as "a hierarchy
 * inside one tenant, not a boundary between two", and that is wrong: the tenant
 * boundary in a self-referencing table runs between its own rows. Measured on
 * `nodes(id, organization_id, parent_id references nodes(id) on delete cascade)`
 * with correct RLS on both USING and WITH CHECK — org_A could see 1 row, still
 * ran `update nodes set parent_id = 2 where organization_id='org_A'`
 * successfully, and org_B's ordinary `delete from nodes where id = 2` then left
 * ZERO rows: org_A's row cascade-destroyed, no policy consulted. The guard
 * reported that database `skipped, scanned: 0`. The composite exclusion two
 * lines above already keeps the FIXED self-FK shape
 * `(organization_id, parent_id) → (organization_id, id)` out.
 */
export function candidateFks(fks, tenantCols) {
  const out = [];
  for (const fk of fks ?? []) {
    const childId = `${fk.child_schema}.${fk.child_table}`;
    const parentId = `${fk.parent_schema}.${fk.parent_table}`;
    const childTenant = tenantCols.get(childId);
    const parentTenant = tenantCols.get(parentId);
    if (!childTenant || !parentTenant) continue;

    const childColumns = fk.child_columns ?? [];
    const parentColumns = fk.parent_columns ?? [];
    // Already carries the tenant on both sides → a cross-tenant row cannot exist.
    if (childColumns.includes(childTenant) && parentColumns.includes(parentTenant)) continue;
    // Composite keys that still omit the tenant are real, but the probe below can
    // only re-point a single column, so they are reported structurally.
    out.push({
      ...fk,
      id: `${childId}::${fk.name}`,
      childId,
      parentId,
      childTenant,
      parentTenant,
      childColumn: childColumns.length === 1 ? childColumns[0] : null,
      parentColumn: parentColumns.length === 1 ? parentColumns[0] : null,
      composite: childColumns.length > 1,
    });
  }
  return out;
}

/** Rows that ALREADY reference across tenants — current corruption, not a hypothetical. */
export function crossTenantRowsSql(fk) {
  const child = qualified(fk.child_schema, fk.child_table);
  const parent = qualified(fk.parent_schema, fk.parent_table);
  return {
    text: `
      select count(*)::int as n
      from ${child} c
      join ${parent} p on c.${quoteIdent(fk.childColumn)} = p.${quoteIdent(fk.parentColumn)}
      where c.${quoteIdent(fk.childTenant)} is distinct from p.${quoteIdent(fk.parentTenant)}
    `,
    values: [],
  };
}

/** A parent row belonging to some tenant, read privileged — the target of the probe. */
export function parentTargetSql(fk) {
  return {
    text: `
      select ${quoteIdent(fk.parentTenant)} as tenant, ${quoteIdent(fk.parentColumn)} as key
      from ${qualified(fk.parent_schema, fk.parent_table)}
      where ${quoteIdent(fk.parentColumn)} is not null
        and ${quoteIdent(fk.parentTenant)} is not null
      limit 1
    `,
    values: [],
  };
}

/**
 * A child tenant that is NOT the parent's tenant, so the reference really
 * crosses. Returns a COMPLETE spec: every other `*Sql` helper here can be called
 * as `q(spec.text, spec.values)`, and one that quietly needed its parameters
 * passed separately was a trap for the next caller.
 */
export function otherChildTenantSql(fk, excludeTenant) {
  return {
    text: `
      select distinct ${quoteIdent(fk.childTenant)} as tenant
      from ${qualified(fk.child_schema, fk.child_table)}
      where ${quoteIdent(fk.childTenant)} is not null
        and ${quoteIdent(fk.childTenant)} <> $1
      limit 1
    `,
    values: [excludeTenant],
  };
}

/**
 * The probe: as the owning tenant, re-point their OWN rows at another tenant's
 * parent. No `WHERE` beyond the tenant column, for the same reason the other
 * write probes use none — targeting a row you cannot see hides the leak you are
 * hunting. Always inside a transaction that is rolled back.
 */
export function repointProbeSql(fk, parentKey, childTenant) {
  return {
    text: `update ${qualified(fk.child_schema, fk.child_table)} set ${quoteIdent(fk.childColumn)} = $1 where ${quoteIdent(fk.childTenant)} = $2`,
    values: [parentKey, childTenant],
  };
}

/**
 * The control arm: how many of its OWN rows the impersonated session can see.
 *
 * Run as the tenant, in the same transaction, immediately before the probe. A
 * re-point that changes zero rows has two completely different causes and the
 * guard cannot tell them apart from the row count alone: the database refused
 * it, or the session was never really that tenant and there was nothing there to
 * re-point. Measured on Supabase-shaped policies keyed on
 * `request.jwt.claims->>'org_id'` with the DEFAULT `app.current_tenant`
 * becomeTenant: own rows visible 0, probe matched 0 rows, guard reported
 * `ok: true, 1 cross-tenant-capable foreign key(s) checked` with no notes — while
 * the same database with `claim: 'org_id'` failed with a proven leak. With own
 * rows visible the zero-row reading stays a pass; rls-proof.mjs and
 * view-isolation.mjs already carry the same control arm.
 */
export function ownRowsSql(fk, tenant) {
  return {
    text: `select count(*)::int as n from ${qualified(fk.child_schema, fk.child_table)} where ${quoteIdent(fk.childTenant)} = $1`,
    values: [tenant],
  };
}

/**
 * The referential actions to re-attach to the replacement key.
 *
 * Leaving them off is the trap: `ADD CONSTRAINT ... REFERENCES ...` with no
 * action means NO ACTION, so a migration that closes the cross-tenant hole also
 * takes away the owning tenant's ability to delete their own parent row.
 * Measured on this guard's own fixture — before, org_A's `delete from projects
 * where id = 1` succeeded and cascaded (2 tasks → 0); after applying the three
 * emitted statements verbatim, `confdeltype` flipped 'c' → 'a' and the same
 * delete failed with `update or delete on table "projects" violates foreign key
 * constraint`. The migration is green; the breakage only shows at runtime.
 * Re-attaching costs nothing: with the tenant in the key, a CASCADE can only
 * reach rows inside the same tenant (verified — the owner's delete still
 * cascades, the cross-tenant re-point is still rejected).
 *
 * SET NULL / SET DEFAULT need the column list, because the replacement key is
 * composite. A bare `ON DELETE SET NULL` nulls EVERY key column including the
 * tenant: measured `null value in column "organization_id" of relation "tasks"
 * violates not-null constraint` on the owner's own delete, where
 * `ON DELETE SET NULL (project_id)` left `organization_id` alone. That form is
 * Postgres 15+. ON UPDATE takes no column list at all — Postgres answers
 * "a column list with SET NULL is only supported for ON DELETE actions" — so
 * that case gets a warning rather than syntax that cannot be written correctly.
 *
 * @returns {{ clause: string, warnings: string[] }}
 */
export function referentialActionClause(fk) {
  const del = describeAction(fk.on_delete);
  const upd = describeAction(fk.on_update);
  const nulls = (code) => (code === 'n' ? 'nulls' : 'resets to the column default');
  const warnings = [];

  let onDelete = `ON DELETE ${del}`;
  if (fk.on_delete === 'n' || fk.on_delete === 'd') {
    if (fk.childColumn) {
      onDelete = `ON DELETE ${del} (${fk.childColumn})`;
      warnings.push(
        `      -- The (${fk.childColumn}) column list is load-bearing and needs Postgres 15+: on the\n` +
        `      -- new composite key a bare "ON DELETE ${del}" also ${nulls(fk.on_delete)} ${fk.childTenant}.`,
      );
    } else {
      // Composite child key: the guard does not know which columns are the
      // non-tenant ones, so the column list stays a placeholder — same as the
      // `…` in the FOREIGN KEY line. A bare "ON DELETE SET NULL" here would run
      // and null the tenant column, so leaving something that does NOT run is
      // the safer half of the trade.
      onDelete = `ON DELETE ${del} (…)`;
      warnings.push(
        `      -- Fill in the (…) with the non-tenant key column(s): a bare "ON DELETE ${del}"\n` +
        `      -- also ${nulls(fk.on_delete)} ${fk.childTenant}, which is part of the new key. Postgres 15+.`,
      );
    }
  }

  if (fk.on_update === 'n' || fk.on_update === 'd') {
    warnings.push(
      `      -- "ON UPDATE ${upd}" takes no column list ("a column list with SET NULL is only\n` +
      `      -- supported for ON DELETE actions"), so on the new composite key it also\n` +
      `      -- ${nulls(fk.on_update)} ${fk.childTenant}. Re-scope or change that action by hand.`,
    );
  }

  return { clause: `${onDelete} ON UPDATE ${upd}`, warnings };
}

/**
 * The verdict.
 *
 * Both leak paths are conclusive: rows that already cross tenants are observed
 * corruption, and a probe that lands is an observed capability. A blocked probe
 * is a genuine pass — something (a trigger, a check constraint, a column grant)
 * is stopping it, and the guard says so rather than staying quiet.
 *
 * `probe` is one of:
 *   'landed'   the re-point changed rows                          → leak
 *   'blocked'  the database RAISED on it                          → pass, "refused"
 *   'no-match' it changed nothing, with own rows visible          → pass, no claim of refusal
 *   'unknown'  it could not be run, or ran without impersonation  → note, never a pass
 * 'blocked' and 'no-match' are separate because they used to be the same value,
 * and the merged one printed "attempted and refused" for a session that had
 * simply seen nothing to attempt it on.
 */
export function classifyFk({ fk, existingCrossTenant = 0, probe = 'unknown', probeReason = '' }) {
  const action = describeAction(fk.on_delete);
  const consequence = isDestructive(fk.on_delete)
    ? `\`ON DELETE ${action}\` means the other tenant deleting their own row ${fk.on_delete === 'c' ? 'DELETES' : 'silently rewrites'} these rows — one tenant destroying another tenant's data, with no policy consulted`
    : `\`ON DELETE ${action}\` means the reference PINS the other tenant's row, so they can no longer delete their own data`;

  // The replacement key must carry the SAME referential actions the current one
  // has. Emitting them explicitly (rather than relying on the default) is what
  // stops the remediation from silently downgrading ON DELETE CASCADE to NO
  // ACTION — see referentialActionClause for what that was measured to break.
  const { clause, warnings } = referentialActionClause(fk);
  const fix =
    `Carry the tenant in the key so a cross-tenant row cannot be represented, keeping the referential action it has today:\n` +
    `      ALTER TABLE ${fk.childId} DROP CONSTRAINT ${fk.name};\n` +
    `      ALTER TABLE ${fk.parentId} ADD UNIQUE (${fk.parentTenant}, ${fk.parentColumn ?? 'id'});\n` +
    `      ALTER TABLE ${fk.childId} ADD CONSTRAINT ${fk.name}\n` +
    `        FOREIGN KEY (${fk.childTenant}, ${fk.childColumn ?? '…'}) REFERENCES ${fk.parentId} (${fk.parentTenant}, ${fk.parentColumn ?? 'id'})\n` +
    `        ${clause};\n` +
    (warnings.length ? `${warnings.join('\n')}\n` : '') +
    `      If this reference is meant to span tenants, add "${fk.id}" to crossTenantFk.allowlist[] with a reason.`;

  if (existingCrossTenant > 0) {
    return {
      status: 'leak',
      kind: 'existing-cross-tenant-reference',
      message:
        `${existingCrossTenant} row(s) in ${fk.childId} ALREADY reference a ${fk.parentId} row belonging to a ` +
        `different tenant, through "${fk.name}". This is not a hypothetical — it is in the data now, ` +
        `and ${consequence}.`,
      fix,
    };
  }

  if (probe === 'landed') {
    return {
      status: 'leak',
      kind: 'cross-tenant-reference',
      message:
        `a tenant can point their own ${fk.childId} rows at another tenant's ${fk.parentId} row through ` +
        `"${fk.name}" — proven by doing it in a rolled-back transaction. Referential checks ALWAYS bypass ` +
        `row-level security, so the FK confirms a row the tenant cannot see, and the child policy's ` +
        `WITH CHECK never objects because it governs the tenant column, not the reference. ` +
        `${consequence}.`,
      fix,
    };
  }

  // 'blocked' is reserved for a probe the DATABASE raised on — a policy, a
  // trigger, a missing column grant. That is the only case where "refused" is a
  // true sentence.
  if (probe === 'blocked') {
    return { status: 'ok', message: `${fk.id} — a cross-tenant reference was attempted and refused` };
  }

  // Zero rows changed while the session could see its own rows. Still a pass —
  // the tenant held rows and none of them could be re-pointed — but nothing was
  // raised, so do not claim a refusal that never happened.
  if (probe === 'no-match') {
    return { status: 'ok', message: `${fk.id} — a cross-tenant re-point matched no row it was permitted to change` };
  }

  return {
    status: 'note',
    message:
      `"${fk.name}" links ${fk.childId} to ${fk.parentId} on ${fk.childColumn ?? 'a composite key'} without ` +
      `carrying the tenant, so a cross-tenant reference is representable — but it could not be proven here ` +
      `(${probeReason || 'not probed'}). Referential checks bypass RLS, and ${consequence}.`,
  };
}

// ── the guard ────────────────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = applyClaimShortcut({ ...DEFAULTS, ...config }, config);
  const q = async (text, values) => (await query(text, values)).rows;
  const role = safeRole(cfg.role);
  const allow = new Set(cfg.allowlist);

  const violations = [];
  const notes = [];

  const fkSpec = foreignKeysSql(cfg.schemas);
  const tcSpec = tenantColumnsSql(cfg.schemas, cfg.tenantColumns);
  const fks = await q(fkSpec.text, fkSpec.values);
  const tenantCols = tenantColumnMap(await q(tcSpec.text, tcSpec.values));

  const candidates = candidateFks(fks, tenantCols).filter((fk) => !allow.has(fk.id));
  if (candidates.length === 0) {
    // Say what was EXCLUDED, not that nothing exists. The old wording ("no
    // foreign key links two tenant tables without carrying the tenant column")
    // was also emitted when every such key was allowlisted, or when the parent
    // had no recognised tenant column — a skip whose stated reason is false
    // reads as proof of absence.
    return OK({
      skipped: true,
      reason:
        `of ${fks.length} foreign key(s) in ${cfg.schemas.join(', ')}, none can express a cross-tenant reference: ` +
        `each one already carries the tenant column, is allowlisted, or has an end with no column named in ` +
        `crossTenantFk.tenantColumns (${cfg.tenantColumns.join(', ')})`,
      summary: 'skipped — no cross-tenant-capable foreign keys',
    });
  }

  for (const fk of candidates) {
    // Composite keys that omit the tenant are real but not re-pointable by a
    // single-column update, so they are reported structurally rather than probed.
    if (!fk.childColumn || !fk.parentColumn) {
      notes.push({ where: fk.id, message: classifyFk({ fk, probe: 'unknown', probeReason: 'composite key — not probed' }).message });
      continue;
    }

    // 1. Corruption that already exists. Privileged, read-only, conclusive.
    let existing = 0;
    try {
      const spec = crossTenantRowsSql(fk);
      existing = (await q(spec.text, spec.values))[0]?.n ?? 0;
    } catch (err) {
      notes.push({ where: fk.id, message: `could not check for existing cross-tenant rows: ${err.message.slice(0, 120)}` });
    }

    // 2. Whether one can be created now. Rolled back.
    let probe = 'unknown';
    let probeReason = '';
    if (existing === 0) {
      try {
        const target = (await q(parentTargetSql(fk).text, []))[0];
        if (!target) {
          probeReason = 'no parent rows to point at';
        } else {
          const otherSpec = otherChildTenantSql(fk, target.tenant);
          const other = (await q(otherSpec.text, otherSpec.values))[0];
          if (!other) {
            probeReason = 'no child rows belonging to a second tenant';
          } else {
            await q('begin', []);
            try {
              await q(`set local role ${role}`, []);
              for (const s of buildBecomeTenant(cfg.becomeTenant, other.tenant)) await q(s.text, s.values);

              // Control arm FIRST. A zero-row re-point proves nothing unless the
              // session could see rows to re-point in the first place. Measured:
              // the default `app.current_tenant` becomeTenant against
              // Supabase-shaped `request.jwt.claims` policies saw 0 of its own
              // rows, the UPDATE matched 0 rows, and the guard reported "1
              // cross-tenant-capable foreign key(s) checked" with no notes —
              // while `claim: 'org_id'` on the same database proved the leak.
              //
              // In its own try: a control arm that RAISES (no SELECT grant, say)
              // must not be read as the re-point being refused, because the
              // re-point never ran.
              let ownVisible = null;
              try {
                const ownSpec = ownRowsSql(fk, other.tenant);
                ownVisible = (await q(ownSpec.text, ownSpec.values))[0]?.n ?? 0;
              } catch (err) {
                probe = 'unknown';
                probeReason = `could not read the probing tenant's own rows as role "${role}": ${err.message.slice(0, 120)}`;
              }

              if (ownVisible === 0) {
                probe = 'unknown';
                probeReason =
                  `the impersonated session sees none of its own rows in ${fk.childId} as role "${role}", ` +
                  `so there was nothing to re-point — role/becomeTenant does not match this schema's policies ` +
                  `(for Supabase JWT-claim policies pass crossTenantFk.claim: "<your claim key>")`;
              } else if (ownVisible > 0) {
                const probeSpec = repointProbeSql(fk, target.key, other.tenant);
                const res = await query(probeSpec.text, probeSpec.values);
                const affected = res.rowCount ?? res.affectedRows ?? 0;
                probe = affected > 0 ? 'landed' : 'no-match';
              }
              // ownVisible === null: the control arm itself raised, classified above.
            } catch (err) {
              probe = isRlsCheckViolation(err) || isPermissionDenied(err) ? 'blocked' : 'unknown';
              if (probe === 'unknown') probeReason = err.message.slice(0, 120);
            } finally {
              try { await q('rollback', []); } catch { /* already aborted */ }
            }
          }
        }
      } catch (err) {
        probeReason = err.message.slice(0, 120);
      }
    }

    const verdict = classifyFk({ fk, existingCrossTenant: existing, probe, probeReason });
    if (verdict.status === 'leak') {
      violations.push({ where: fk.id, kind: verdict.kind, message: verdict.message, fix: verdict.fix });
    } else if (verdict.status === 'note') {
      notes.push({ where: fk.id, message: verdict.message });
    }
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned: candidates.length,
    summary:
      violations.length > 0
        ? `${violations.length} foreign key(s) let one tenant reach another tenant's rows`
        : `${candidates.length} cross-tenant-capable foreign key(s) checked` + (notes.length ? `; ${notes.length} note(s)` : ''),
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
