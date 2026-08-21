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

/** 'secret' | 'pii' | null — null means we do not care about this column. */
export function classifyColumn(name) {
  const n = String(name ?? '');
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
      `Either stop granting the read, or stop exposing the column:\n` +
      `        REVOKE SELECT ON ${rel.id} FROM ${role};\n` +
      `      If part of ${rel.table} really is public, expose that part and nothing else:\n` +
      `        REVOKE SELECT ON ${rel.id} FROM ${role};\n` +
      `        CREATE VIEW ${rel.schema}.${rel.table}_public\n` +
      `          WITH (security_invoker = true) AS\n` +
      `          SELECT <the columns that are meant to be public> FROM ${rel.id};\n` +
      `        GRANT SELECT ON ${rel.schema}.${rel.table}_public TO ${role};\n` +
      `      A column grant works too (GRANT SELECT (col, …)), but it is easy to widen by accident later; a view names the intent.\n` +
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

  const violations = [];
  const notes = [];
  let scanned = 0;

  for (const rel of plan) {
    scanned++;
    let row = null;
    let reachable = true;
    // Read-only, but wrapped and rolled back anyway: every probe in this tool
    // leaves the database exactly as it found it, without exception.
    await query('begin');
    try {
      await query(`set local role ${role}`);
      const res = await query(probeSql(rel, rel.sensitive, cfg.sampleRows));
      row = res.rows?.[0] ?? null;
    } catch {
      reachable = false; // 42501, or the role cannot see the relation at all
    } finally {
      await query('rollback');
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
