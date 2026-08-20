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
 * makes a cross-tenant reference unrepresentable, which is why that is the fix.
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

/** Every foreign key whose child and parent both live in the target schemas. */
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
           join pg_attribute a on a.attrelid = con.conrelid and a.attnum = k.attnum) as child_columns,
        (select array_agg(a.attname order by k.ord)
           from unnest(con.confkey) with ordinality k(attnum, ord)
           join pg_attribute a on a.attrelid = con.confrelid and a.attnum = k.attnum) as parent_columns
      from pg_constraint con
      join pg_class cc     on cc.oid = con.conrelid
      join pg_namespace cn on cn.oid = cc.relnamespace
      join pg_class pc     on pc.oid = con.confrelid
      join pg_namespace pn on pn.oid = pc.relnamespace
      where con.contype = 'f'
        and cn.nspname = any($1)
        and pn.nspname = any($1)
    `,
    values: [schemas],
  };
}

/** Which tables carry a tenant column, and which one. */
export function tenantColumnsSql(schemas, tenantColumns) {
  return {
    text: `
      select n.nspname as schema, c.relname as table, a.attname as column
      from pg_class c
      join pg_namespace n on n.oid = c.relnamespace
      join pg_attribute a on a.attrelid = c.oid
      where c.relkind in ('r', 'p')
        and n.nspname = any($1)
        and a.attname = any($2)
        and a.attnum > 0
        and not a.attisdropped
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
    // Self-references are a hierarchy within one tenant, not a boundary between two.
    if (childId === parentId) continue;
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

/** A child tenant that is NOT the parent's tenant, so the reference really crosses. */
export function otherChildTenantSql(fk) {
  return {
    text: `
      select distinct ${quoteIdent(fk.childTenant)} as tenant
      from ${qualified(fk.child_schema, fk.child_table)}
      where ${quoteIdent(fk.childTenant)} is not null
        and ${quoteIdent(fk.childTenant)} <> $1
      limit 1
    `,
    values: [],
  };
}

/**
 * The probe: as the owning tenant, re-point their OWN rows at another tenant's
 * parent. No `WHERE` beyond the tenant column, for the same reason the other
 * write probes use none — targeting a row you cannot see hides the leak you are
 * hunting. Always inside a transaction that is rolled back.
 */
export function repointProbeSql(fk) {
  return {
    text: `update ${qualified(fk.child_schema, fk.child_table)} set ${quoteIdent(fk.childColumn)} = $1 where ${quoteIdent(fk.childTenant)} = $2`,
    values: [],
  };
}

/**
 * The verdict.
 *
 * Both leak paths are conclusive: rows that already cross tenants are observed
 * corruption, and a probe that lands is an observed capability. A blocked probe
 * is a genuine pass — something (a trigger, a check constraint, a column grant)
 * is stopping it, and the guard says so rather than staying quiet.
 */
export function classifyFk({ fk, existingCrossTenant = 0, probe = 'unknown', probeReason = '' }) {
  const action = describeAction(fk.on_delete);
  const consequence = isDestructive(fk.on_delete)
    ? `and \`ON DELETE ${action}\` means the other tenant deleting their own row ${fk.on_delete === 'c' ? 'DELETES' : 'silently rewrites'} these rows — one tenant destroying another tenant's data, with no policy consulted`
    : `and \`ON DELETE ${action}\` means the reference PINS the other tenant's row, so they can no longer delete their own data`;

  const fix =
    `Carry the tenant in the key so a cross-tenant row cannot be represented:\n` +
    `      ALTER TABLE ${fk.childId} DROP CONSTRAINT ${fk.name};\n` +
    `      ALTER TABLE ${fk.parentId} ADD UNIQUE (${fk.parentTenant}, ${fk.parentColumn ?? 'id'});\n` +
    `      ALTER TABLE ${fk.childId} ADD CONSTRAINT ${fk.name}\n` +
    `        FOREIGN KEY (${fk.childTenant}, ${fk.childColumn ?? '…'}) REFERENCES ${fk.parentId} (${fk.parentTenant}, ${fk.parentColumn ?? 'id'});\n` +
    `      If this reference is meant to span tenants, add "${fk.id}" to crossTenantFk.allowlist[] with a reason.`;

  if (existingCrossTenant > 0) {
    return {
      status: 'leak',
      kind: 'existing-cross-tenant-reference',
      message:
        `${existingCrossTenant} row(s) in ${fk.childId} ALREADY reference a ${fk.parentId} row belonging to a ` +
        `different tenant, through "${fk.name}". This is not a hypothetical — it is in the data now, ` +
        `${consequence}.`,
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

  if (probe === 'blocked') {
    return { status: 'ok', message: `${fk.id} — a cross-tenant reference was attempted and refused` };
  }

  return {
    status: 'note',
    message:
      `"${fk.name}" links ${fk.childId} to ${fk.parentId} on ${fk.childColumn ?? 'a composite key'} without ` +
      `carrying the tenant, so a cross-tenant reference is representable — but it could not be proven here ` +
      `(${probeReason || 'not probed'}). Referential checks bypass RLS, ${consequence}.`,
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
    return OK({
      skipped: true,
      reason: 'no foreign key links two tenant tables without carrying the tenant column',
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
          const otherSpec = otherChildTenantSql(fk);
          const other = (await q(otherSpec.text, [target.tenant]))[0];
          if (!other) {
            probeReason = 'no child rows belonging to a second tenant';
          } else {
            await q('begin', []);
            try {
              await q(`set local role ${role}`, []);
              for (const s of buildBecomeTenant(cfg.becomeTenant, other.tenant)) await q(s.text, s.values);
              const res = await query(repointProbeSql(fk).text, [target.key, other.tenant]);
              const affected = res.rowCount ?? res.affectedRows ?? 0;
              probe = affected > 0 ? 'landed' : 'blocked';
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
