/**
 * Guard: which sensitive COLUMNS does an anonymous visitor actually read?
 *
 * Row-level isolation is what the other guards prove. This one is about the
 * table nobody meant to protect: a waitlist, a public author directory, an
 * `api_clients` lookup — no tenant column at all, so `anon-reads` and
 * `rls-proof` are silent by design, correctly. Nothing is leaking ACROSS
 * tenants because there are no tenants. It is leaking to the internet.
 *
 * The naive version of this check reads column grants, and it does not work.
 * Measured: a plain table-level `GRANT SELECT` expands to EVERY column in
 * `information_schema.column_privileges`, so on a table whose isolation is
 * verifiably intact a grant-based check reported all seven columns exposed. On
 * a ten-table sample it fired on three tables, one of which — RLS on, no
 * permissive policy — returns nothing at all to anon. Telling someone to
 * tighten a table that is already closed is the advice shape that took a
 * production database down in 0.26.0.
 *
 * So this guard proves the read instead. It fires only when `anon` gets a real
 * non-null value out of a sensitive column. Same sample: two findings, both
 * real, nothing else. The gated table becomes a note.
 *
 * **It never fetches the value.** The probe is `count(col)` over a bounded
 * subquery, so what comes back is a number, not a password. A CI log that
 * quoted the leaked data would be a second copy of the leak.
 */
import { safeRole, DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';

export const meta = {
  id: 'column-exposure',
  title: 'Sensitive columns an anonymous visitor can actually read',
  why: "A table with no tenant column is invisible to every tenancy guard — correctly, since there are no tenants to leak across. That is exactly where a waitlist with an email column, or a lookup table with an api_key, sits reading to the whole internet. Proven by reading: the guard fails only when anon gets a non-null value back, so a table that RLS already closes is never touched.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: 'anon',
  schemas: ['public'],
  tenantColumns: PROOF_DEFAULTS.tenantColumns, // used ONLY to hand off, never to probe
  sampleRows: 500, // bound the count so a huge table is not a full scan
  allowlist: [], // "schema.table" or "schema.table.column" public on purpose
};

// ── which columns are worth asking about ─────────────────────────────

/**
 * Secrets. A value here reaching an anonymous client is never a design choice,
 * so these are reported as their own kind — a leaked key is a rotation task,
 * not a schema discussion.
 */
export const SECRET_PATTERNS = [
  /(^|_)(password|passwd|pwd|password_hash|secret|token|api_?key|apikey|private_?key|access_?key|secret_?key|refresh_?token|session_?token|otp|totp_?secret|recovery_?code|webhook_?secret)($|_)/i,
];

/**
 * Personal data. Publishing it may occasionally be deliberate (a support inbox
 * on a contact page), so the fix names the allowlist — but it is reported,
 * because "we meant to" has to be written down somewhere.
 */
export const PII_PATTERNS = [
  /(^|_)(email|email_address|phone|phone_number|mobile|ssn|social_security|tax_id|vat_number|passport|national_id|date_of_birth|dob|birthdate|address|street|postcode|zip|ip_address|last_ip|credit_card|card_number|iban|bank_account|routing_number)($|_)/i,
];

/**
 * The name of a fact ABOUT a credential is not the credential.
 *
 * Measured on HEAD before this rule: `token_count` on a public pricing table and
 * `password_changed_at` on an author directory both classified as `secret`, and
 * the guard failed the build telling the user to rotate an integer and a
 * timestamp. `address_line_type` ('street' / 'po_box') classified as `pii`.
 * Three hard violations on three correct tables — the exact shape the header
 * comment says this guard exists to avoid.
 *
 * The suppression is deliberately narrow: the sensitive token must be a PREFIX
 * and the whole remainder must be one of these qualifiers. The obvious wider
 * rule — ignore anything ending in `_id` — was tested and rejected: it deletes
 * `tax_id`, `national_id`, `passport_id`, which are named in PII_PATTERNS on
 * purpose. Trading a false positive for a false negative on national ID numbers
 * is the worse bug.
 *
 * Kept sensitive under this rule (checked): api_key, password_hash, secret_key,
 * stripe_secret_key, session_token, refresh_token, recovery_code, otp, email,
 * email_address, phone_number, ip_address, tax_id, national_id, date_of_birth,
 * address_line_1, password_reset_token, api_key_hash.
 */
const METADATA_QUALIFIER =
  /(_at|_on|_count|_version|_verified|_enabled|_required|_attempts|_status|_type|_expiry|_updated|_changed|_rotated)$/i;
const SENSITIVE_PREFIX =
  /^(password|passwd|pwd|secret|token|api_?key|apikey|private_?key|access_?key|secret_?key|refresh_?token|session_?token|otp|totp_?secret|recovery_?code|webhook_?secret|email|phone|mobile|address)_/i;

/** 'secret' | 'pii' | null — null means we do not care about this column. */
export function classifyColumn(name) {
  const n = String(name ?? '');
  if (SENSITIVE_PREFIX.test(n) && METADATA_QUALIFIER.test(n)) return null;
  if (SECRET_PATTERNS.some((re) => re.test(n))) return 'secret';
  if (PII_PATTERNS.some((re) => re.test(n))) return 'pii';
  return null;
}

// ── introspection ────────────────────────────────────────────────────

/**
 * Every column of every readable relation, including views and partitioned
 * parents. Views matter as much as tables here: a view is the usual way a
 * "public profile" ends up carrying the email it was meant to hide.
 */
export function columnsSql(schemas) {
  return {
    text: `
      select n.nspname as schema,
             c.relname as table,
             c.relkind::text as relkind,
             a.attname as column
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      join pg_catalog.pg_attribute a on a.attrelid = c.oid
      where c.relkind in ('r', 'p', 'v', 'm')
        and n.nspname = any($1)
        and a.attnum > 0 and not a.attisdropped
      order by n.nspname, c.relname, a.attnum
    `,
    values: [schemas],
  };
}

/**
 * WHERE the role's SELECT actually comes from, per relation.
 *
 * `REVOKE SELECT ON t FROM anon` closes nothing when the privilege was granted
 * to PUBLIC. Measured: table granted `to public`, `REVOKE SELECT ... FROM anon`
 * succeeded with no error and no notice, anon still counted 1 row out of the
 * api_key column, and the guard re-fired with the identical violation. Only
 * `REVOKE ... FROM PUBLIC` closed it. Same for a grant made to a group role the
 * role is a member of — revoking from the member is a no-op.
 *
 * So the fix has to name the grantee that actually holds the privilege. This
 * returns exactly the ACL entries that give `role` its SELECT: PUBLIC (grantee
 * 0), the role itself, or any role it inherits from. The owner is excluded —
 * revoking from an owner is not a remedy, and an empty list is reported as
 * "this is not a grant you can revoke" rather than as a confident REVOKE.
 *
 * Column-level ACLs are unioned in because a `GRANT SELECT (col)` leaves
 * `relacl` untouched. Verified that the emitted table-level REVOKE does clear a
 * column-level grant: after `revoke select on colgrant from anon`, anon reading
 * the column-granted column got 42501.
 */
export function grantPathsSql(schemas, role) {
  return {
    text: `
      select n.nspname as schema,
             c.relname as table,
             coalesce(array_agg(distinct g.name) filter (where g.name is not null), '{}') as grantees
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      left join lateral (
        select case when a.grantee = 0 then 'PUBLIC' else pg_catalog.pg_get_userbyid(a.grantee) end as name
        from aclexplode(coalesce(c.relacl, pg_catalog.acldefault('r', c.relowner))) a
        where a.privilege_type = 'SELECT'
          and a.grantee <> c.relowner
          and (a.grantee = 0 or pg_catalog.pg_has_role($2, a.grantee, 'USAGE'))
        union
        select case when a2.grantee = 0 then 'PUBLIC' else pg_catalog.pg_get_userbyid(a2.grantee) end
        from pg_catalog.pg_attribute at
        cross join lateral aclexplode(at.attacl) a2
        where at.attrelid = c.oid and at.attnum > 0 and not at.attisdropped and at.attacl is not null
          and a2.privilege_type = 'SELECT'
          and a2.grantee <> c.relowner
          and (a2.grantee = 0 or pg_catalog.pg_has_role($2, a2.grantee, 'USAGE'))
      ) g on true
      where n.nspname = any($1)
        and c.relkind in ('r', 'p', 'v', 'm')
      group by 1, 2
    `,
    values: [schemas, role],
  };
}

/**
 * The grantee list, rendered for a REVOKE. `PUBLIC` is a keyword and must stay
 * unquoted; every other name is a real role out of pg_catalog, so quoting it
 * cannot produce the 42704 that naming a role the database does not have would.
 * `null` means we could not attribute the read to any revocable grant.
 */
export function revokeTarget(grantees) {
  if (!Array.isArray(grantees) || grantees.length === 0) return null;
  const seen = [...new Set(grantees.filter(Boolean).map(String))];
  seen.sort((a, b) => (a === 'PUBLIC' ? -1 : b === 'PUBLIC' ? 1 : a.localeCompare(b)));
  return seen.map((g) => (g === 'PUBLIC' ? 'PUBLIC' : `"${g.replace(/"/g, '""')}"`)).join(', ');
}

/**
 * Group the columns per relation and decide who owns each one.
 *
 * A relation carrying a tenant column is handed off: `anon-reads` proves the
 * row-level question there and this guard would only restate it. That hand-off
 * is what keeps a finding here a NEW fact rather than a louder copy of one.
 */
export function planRelations(rows, { tenantColumns, allowlist = [] } = {}) {
  const tenant = new Set(tenantColumns ?? []);
  const allow = new Set(allowlist);
  const byRel = new Map();

  for (const r of rows ?? []) {
    const id = `${r.schema}.${r.table}`;
    if (!byRel.has(id)) {
      byRel.set(id, { id, schema: r.schema, table: r.table, relkind: r.relkind, columns: [], hasTenantColumn: false, sensitive: [] });
    }
    const rel = byRel.get(id);
    rel.columns.push(r.column);
    if (tenant.has(r.column)) rel.hasTenantColumn = true;
    const kind = classifyColumn(r.column);
    if (kind && !allow.has(id) && !allow.has(`${id}.${r.column}`)) {
      rel.sensitive.push({ column: r.column, kind });
    }
  }

  const plan = [], handedOff = [];
  for (const rel of byRel.values()) {
    if (!rel.sensitive.length) continue;
    if (rel.hasTenantColumn) handedOff.push(rel.id); // anon-reads / rls-proof own it
    else plan.push(rel);
  }
  return { plan, handedOff };
}

/**
 * `count(col)` over a bounded subquery: counts NON-NULL values without
 * selecting a single one of them. Identifiers are quoted rather than
 * parameterised because they are identifiers — they come from pg_catalog, not
 * from user input, and the quoting doubles any embedded quote.
 */
export function probeSql(rel, columns, limit) {
  const q = (s) => `"${String(s).replace(/"/g, '""')}"`;
  // Aliased POSITIONALLY, not by column name. An identifier over 63 bytes is
  // silently truncated by Postgres, so `n_<a 62-character column>` came back
  // under a different key, the lookup missed, and a real exposure read as clean.
  // Verified with a 64-character column name: ok=true, zero violations.
  const counts = columns.map((c, i) => `count(${q(c.column)})::int as c${i}`).join(', ');
  const cols = columns.map((c) => q(c.column)).join(', ');
  return `select ${counts} from (select ${cols} from ${q(rel.schema)}.${q(rel.table)} limit ${Number(limit) || 500}) s`;
}

/** Which of the probed columns actually returned a value. */
export function readableColumns(row, columns) {
  if (!row) return [];
  return columns.filter((c, i) => Number(row[`c${i}`] ?? 0) > 0);
}

// ── verdicts ─────────────────────────────────────────────────────────

export function classifyExposure({ rel, columns, role = 'anon' }) {
  const secrets = columns.filter((c) => c.kind === 'secret').map((c) => c.column);
  const pii = columns.filter((c) => c.kind === 'pii').map((c) => c.column);
  const isSecret = secrets.length > 0;
  const named = (isSecret ? secrets : pii).join(', ');

  // Who to name in the REVOKE. `rel.grantees` is measured from the catalog by
  // check(); when it is absent (a direct call to this function with no ACL
  // facts) fall back to the role and say out loud that a PUBLIC grant would
  // make that line a no-op, rather than printing a confident wrong statement.
  const target = revokeTarget(rel.grantees);
  const unattributed = Array.isArray(rel.grantees) && rel.grantees.length === 0;
  // Quoted, because safeRole() accepts mixed case and an unquoted `MyRole`
  // folds to `myrole` and fails 42704 on a database that has the former.
  const roleSql = `"${String(role).replace(/"/g, '""')}"`;
  const revokeFrom = target ?? roleSql;
  const viaPublic = Array.isArray(rel.grantees) && rel.grantees.includes('PUBLIC');
  const viaOther = Array.isArray(rel.grantees) && rel.grantees.some((g) => g !== 'PUBLIC' && g !== role);

  const revokeNote = unattributed
    ? `      NOTE: ${role}'s SELECT on ${rel.id} does not come from any grant this tool can revoke — ${role} owns the relation, is a member of its owner, or is a superuser. ` +
      `A REVOKE will not close it; change the ownership or the role instead.\n`
    : viaPublic
      ? `      The privilege is held by PUBLIC, not by ${role}: \`REVOKE SELECT ON ${rel.id} FROM ${role};\` succeeds, prints nothing, and changes nothing — verified, the read still worked and this guard re-fired unchanged. ` +
        `Revoking from PUBLIC also removes the read for every OTHER role that was relying on that same grant (authenticated, a service role), so re-grant explicitly wherever it was intended.\n`
      : viaOther
        ? `      The privilege reaches ${role} through ${rel.grantees.filter((g) => g !== role).join(', ')}, which ${role} is a member of — revoking from ${role} alone is a no-op.\n`
        : Array.isArray(rel.grantees)
          ? '' // measured: the grant is held by the role itself, so the line above is the whole fix
          : `      Check who actually holds the grant first — \`select grantee, privilege_type from information_schema.role_table_grants where table_schema = '${rel.schema}' and table_name = '${rel.table}';\`. ` +
            `If it was granted to PUBLIC (an empty grantee in relacl), the line above succeeds and changes nothing; revoke FROM PUBLIC instead, and re-grant explicitly to the roles that were meant to keep the read.\n`;

  return {
    kind: isSecret ? 'anon-readable-secret' : 'anon-readable-pii',
    where: `${rel.id} (${named})`,
    message: isSecret
      ? `the ${role} role reads real values out of ${rel.id}.${named}. This is a credential column readable without authenticating — proven by reading it, not inferred from a grant. ` +
        `${rel.id} has no tenant column, so the tenancy guards are silent on it by design: nothing is leaking ACROSS tenants because there are none. It is leaking to the internet. ` +
        `Treat every value in that column as disclosed and rotate it; closing the read does not un-disclose what has already been served.`
      : `the ${role} role reads real values out of ${rel.id}.${named}. Personal data served to unauthenticated clients — proven by reading it, not inferred from a grant. ` +
        `${rel.id} has no tenant column, so no tenancy guard covers it: this is the table nobody meant to protect. ` +
        `A public waitlist or author directory is the usual shape, and the names are usually meant to be public while the contact details are not.`,
    fix:
      `Either stop granting the read, or publish only the part that is meant to be public.\n` +
      `        REVOKE SELECT ON ${rel.id} FROM ${revokeFrom};\n` +
      revokeNote +
      `      If part of ${rel.table} really is public, keep serving that part and nothing else — this is the whole change, and it needs no view:\n` +
      `        REVOKE SELECT ON ${rel.id} FROM ${revokeFrom};\n` +
      `        GRANT SELECT (<the columns that are meant to be public>) ON ${rel.id} TO ${roleSql};\n` +
      `      A named view is optional, and if you want one it needs BOTH lines above kept, not replaced:\n` +
      `        CREATE VIEW ${rel.schema}.${rel.table}_public\n` +
      `          WITH (security_invoker = true) AS\n` +
      `          SELECT <the same public columns> FROM ${rel.id};\n` +
      `        GRANT SELECT ON ${rel.schema}.${rel.table}_public TO ${roleSql};\n` +
      `      security_invoker re-checks the CALLER's own privileges on the base table, so the column grant is what makes the view readable. Verified in this order: ${role} reads the public column through the view and \`select ${columns[0].column} from ${rel.id}\` still fails 42501. ` +
      `With the REVOKE but no column grant — the pairing this guard used to print — the view itself failed 42501 for ${role}.\n` +
      `      Do NOT drop security_invoker to avoid the base grant: an owner-rights view over a single table is auto-updatable, and measured, ${role} DELETEd a base-table row through exactly that shape. If you ever create one anyway, pair it with \`REVOKE INSERT, UPDATE, DELETE ON ${rel.schema}.${rel.table}_public FROM ${roleSql};\`.\n` +
      (isSecret ? `      Rotate the exposed credentials first — this is a disclosure, not just a misconfiguration.\n` : '') +
      `      If this really is public on purpose, add "${rel.id}.${columns[0].column}" to columnExposure.allowlist[] with the reason.`,
  };
}

// ── the guard ────────────────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = { ...DEFAULTS, ...config };
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;

  // A skip is not a pass. With no such role every `set local role` throws, the
  // per-relation catch turns that into "not reachable", and the guard returned a
  // confident green — "N untenanted relation(s) probed, nothing readable" — on a
  // database where nothing was probed at all. Verified. The two sibling guards
  // already precheck this.
  const roleRows = (await q(`select 1 from pg_catalog.pg_roles where rolname = $1`, [role]));
  if (roleRows.length === 0) {
    return OK({
      skipped: true,
      reason: `role "${role}" does not exist — set columnExposure.role to your unauthenticated role`,
      summary: `skipped — no "${role}" role`,
    });
  }

  const intro = columnsSql(cfg.schemas);
  const { plan, handedOff } = planRelations(await q(intro.text, intro.values), {
    tenantColumns: cfg.tenantColumns,
    allowlist: cfg.allowlist,
  });

  if (!plan.length) {
    return OK({
      scanned: 0,
      notes: handedOff.length
        ? [{ where: '(hand-off)', message: `${handedOff.length} relation(s) with sensitive columns are tenant-scoped — anon-reads and rls-proof cover those; this guard would only restate them.` }]
        : [],
      summary: 'no untenanted relation carries a sensitive column',
    });
  }

  // Where each relation's SELECT comes from, so the printed REVOKE names the
  // grantee that actually holds it. Read as the caller, before any role switch.
  const acl = grantPathsSql(cfg.schemas, role);
  const grantMap = new Map();
  for (const r of await q(acl.text, acl.values)) grantMap.set(`${r.schema}.${r.table}`, r.grantees ?? []);
  for (const rel of plan) rel.grantees = grantMap.get(rel.id);

  const violations = [];
  const notes = [];
  let scanned = 0;

  // ONE transaction, one role switch, a savepoint per probe — the shape
  // anon-reads, view-isolation and trigger-visibility already use. Measured on
  // 60 relations: 241 queries before, 184 after (4.02 -> 3.05 per relation).
  //
  // The savepoints are NOT optional and must not be "simplified" away. Without
  // them, the first relation the role cannot read raises 42501, the whole
  // transaction goes aborted, and every later probe throws "current transaction
  // is aborted" — which this loop's catch reads as "not reachable" and skips.
  // Measured on a fixture with one denied relation ahead of three leaking ones:
  // savepoint-less returned ok=true with zero violations on three proven leaks.
  //
  // `set local role` runs before the first savepoint, so `rollback to savepoint`
  // does not undo it and the role stays applied for the whole loop; the guard
  // issues no privileged query inside the loop (introspection is already done).
  // Read-only throughout, and the outer rollback still holds the promise that
  // every probe leaves the database exactly as it found it.
  await query('begin');
  try {
    try {
      await query(`set local role ${role}`);
    } catch {
      // The role exists (prechecked) but cannot be assumed. A skip, said out loud.
      return OK({
        skipped: true,
        reason: `cannot "set role ${role}" from the connected user — grant it, or set columnExposure.role`,
        summary: `skipped — cannot assume "${role}"`,
      });
    }

    for (const rel of plan) {
      scanned++;
      let row = null;
      let reachable = true;
      await query('savepoint tg_colexp');
      try {
        const res = await query(probeSql(rel, rel.sensitive, cfg.sampleRows));
        row = res.rows?.[0] ?? null;
        await query('release savepoint tg_colexp');
      } catch {
        reachable = false; // 42501, or the role cannot see the relation at all
        try {
          await query('rollback to savepoint tg_colexp');
          await query('release savepoint tg_colexp');
        } catch { /* the outer rollback in `finally` still discards everything */ }
      }

      if (!reachable) continue; // permission denied — nothing to report, and nothing to change

      const readable = readableColumns(row, rel.sensitive);
      if (readable.length) {
        violations.push(classifyExposure({ rel, columns: readable, role }));
      } else {
        // Reachable, but every sampled value came back null or no rows did. Not a
        // finding — it is one permissive policy away from being one, and saying so
        // is worth more than silence.
        notes.push({
          where: rel.id,
          message:
            `${role} can query ${rel.id} but got no value out of ${rel.sensitive.map((c) => c.column).join(', ')} ` +
            `(sampled ${cfg.sampleRows} rows) — RLS or an empty table is holding it. Not a finding; noted because the column is one permissive policy away from being served.`,
        });
      }
    }
  } finally {
    try { await query('rollback'); } catch { /* nothing left to unwind */ }
  }

  if (handedOff.length) {
    notes.push({
      where: '(hand-off)',
      message: `${handedOff.length} tenant-scoped relation(s) with sensitive columns were skipped — anon-reads and rls-proof prove the row-level question there.`,
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
        ? `${violations.length} relation(s) serve sensitive columns to ${role}`
        : `${scanned} untenanted relation(s) probed, nothing readable`,
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
