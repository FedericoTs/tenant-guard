/**
 * Guard: a view built to expose SAFE columns that is also writable through.
 *
 * Reported from a real production run, where it was strictly worse than the read
 * leak the view had been created to fix: with the public anon key,
 * `DELETE /rest/v1/public_profiles` wiped the users table.
 *
 * Three ordinary facts combine into it, and each one is individually defensible:
 *
 *   1. `security_invoker = false` (the default) means the view executes as its
 *      OWNER, so the base table's RLS is evaluated as the owner and does not
 *      apply to the caller. That is exactly what makes the view useful for
 *      reading a curated column set, so it is not the bug.
 *   2. A view over a single relation with no aggregation is **auto-updatable**:
 *      Postgres passes `INSERT`/`UPDATE`/`DELETE` straight through to the base
 *      table. Nobody writes that down; it is a default.
 *   3. Supabase's `ALTER DEFAULT PRIVILEGES` grants `anon`/`authenticated`
 *      write privileges on every new object in `public`. The author writes
 *      `GRANT SELECT` and reasonably believes they have made it read-only.
 *
 * Nothing in the migration says "writable". The word `DELETE` never appears.
 * And `view-isolation` cannot see it either: that guard proves READ isolation,
 * and this is a write. They are different bugs.
 *
 * Static by design — every ingredient is in the migration text, so this blocks
 * at pull-request time with no database and no install.
 */
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { migrationNumber, stripSqlComments, compareMigrations } from './definer-grants.mjs';
import { definedOnly } from '../config.mjs';

export const meta = {
  id: 'updatable-view-writethrough',
  title: 'A read-only-looking view that writes through to its base table',
  why: "A view over one table with no aggregation is AUTO-UPDATABLE: Postgres passes INSERT/UPDATE/DELETE through to the base table. With the default security_invoker = false those writes run as the view's OWNER, so the base table's RLS never applies to the caller — and on Supabase the default privileges grant anon/authenticated write access to every new object, so `GRANT SELECT` does not make it read-only. Reported in production as DELETE on a public profile view wiping the users table.",
};

export const DEFAULTS = {
  // The roles a browser can reach. On Supabase both ship in the client bundle.
  exposedRoles: ['anon', 'authenticated'],
  // Supabase grants writes on new objects by default, so a view with no explicit
  // REVOKE is writable even when only SELECT was granted. 'auto' looks for the
  // evidence in your migrations rather than assuming a platform.
  assumeDefaultWriteGrants: 'auto', // 'auto' | true | false
  allowlist: [], // view names that are intentionally writable
};

const WRITE_PRIVS = ['insert', 'update', 'delete'];

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

const bare = (name) => String(name ?? '').replace(/"/g, '').split('.').pop().toLowerCase();

/**
 * Every view a migration defines, with the two properties that decide whether a
 * write can pass through it.
 */
export function extractViews(sql) {
  const text = stripSqlComments(sql);
  const re = /create\s+(?:or\s+replace\s+)?(?:(materialized)\s+)?view\s+([a-z0-9_."]+)\s*([\s\S]*?)\bas\b/gi;
  const out = [];
  let m;
  while ((m = re.exec(text)) !== null) {
    const isMaterialized = Boolean(m[1]);
    const name = bare(m[2]);
    const options = m[3] || '';
    const start = m.index + m[0].length;
    const end = text.indexOf(';', start);
    const body = text.slice(start, end === -1 ? text.length : end);

    // `security_invoker = true` makes the view run as the CALLER, so the base
    // table's RLS applies to them and a write-through is checked. Anything else
    // — including the default — runs as the owner.
    const securityInvoker = /security_invoker\s*=\s*(true|on|1)/i.test(options);

    out.push({
      name,
      isMaterialized,
      securityInvoker,
      body: body.trim(),
      ...autoUpdatableShape(body),
    });
  }
  return out;
}

/**
 * Is this SELECT auto-updatable in Postgres' sense?
 *
 * The rule: exactly one relation in FROM, and none of the constructs that make a
 * view read-only. Computed columns do NOT disqualify it — they merely aren't
 * individually updatable, and `DELETE` still passes through, which is the
 * destructive half.
 */
export function autoUpdatableShape(select) {
  const s = stripSqlComments(select).toLowerCase();
  const reasons = [];

  if (/\bdistinct\b/.test(s)) reasons.push('DISTINCT');
  if (/\bgroup\s+by\b/.test(s)) reasons.push('GROUP BY');
  if (/\bhaving\b/.test(s)) reasons.push('HAVING');
  if (/\b(union|intersect|except)\b/.test(s)) reasons.push('a set operation');
  if (/\bwith\b[\s\S]*\bas\s*\(/.test(s)) reasons.push('a CTE');
  if (/\b(limit|offset)\b/.test(s)) reasons.push('LIMIT/OFFSET');
  if (/\bover\s*\(/.test(s)) reasons.push('a window function');
  if (/\b(count|sum|avg|min|max|array_agg|string_agg|jsonb_agg|json_agg|bool_and|bool_or)\s*\(/.test(s)) {
    reasons.push('an aggregate');
  }

  // More than one relation in FROM (an explicit JOIN or a comma list).
  const from = /\bfrom\b([\s\S]*?)(\bwhere\b|\bgroup\s+by\b|\border\s+by\b|\blimit\b|$)/.exec(s);
  const fromClause = from ? from[1] : '';
  if (/\bjoin\b/.test(fromClause)) reasons.push('a JOIN');
  else if (/,/.test(fromClause.replace(/\([^)]*\)/g, ''))) reasons.push('more than one relation');

  const baseTable = (() => {
    const t = /\bfrom\s+([a-z0-9_."]+)/.exec(s);
    return t ? bare(t[1]) : null;
  })();

  return { autoUpdatable: reasons.length === 0, notUpdatableBecause: reasons, baseTable };
}

/**
 * Net write privileges on each object across the whole migration history:
 * a GRANT adds, a REVOKE takes away, in migration order.
 *
 * Two things this has to get right, both of which it used to get wrong.
 *
 * **`ON ALL TABLES IN SCHEMA x` counts, and it covers views.** That statement is
 * the single most common lockdown a Supabase project performs —
 * `REVOKE INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM anon` — and
 * the per-object pattern could not see it, because it looks for an object name
 * followed by TO/FROM. So the guard fired on a migration history that had
 * already closed the hole. A guard that cries wolf on correct code teaches
 * people to ignore it, which is the worst outcome available here.
 *
 * **Order decides it.** A schema-wide REVOKE followed by a per-object GRANT
 * leaves the object writable, and the reverse leaves it closed. So every
 * statement — per-object and schema-wide — is applied in one ordered stream
 * rather than in two passes, which is what made a later re-GRANT invisible.
 *
 * `viewNames` seeds the state so a schema-wide REVOKE reaches views that never
 * had an explicit GRANT of their own — the ones that got their write access from
 * ALTER DEFAULT PRIVILEGES, which is exactly the population this guard is about.
 *
 * @returns {Map<string, {granted:Set<string>, revoked:Set<string>}>} keyed by bare object name
 */
export function netWriteGrants(files, exposedRoles, viewNames = []) {
  const roles = new Set(exposedRoles.map((r) => r.toLowerCase()));
  const state = new Map();
  const touch = (name) => {
    if (!state.has(name)) state.set(name, { granted: new Set(), revoked: new Set() });
    return state.get(name);
  };
  for (const v of viewNames) touch(bare(v));

  const hitsRole = (targets) =>
    [...roles].some((r) => new RegExp(`\\b${r}\\b`).test(targets)) || /\bpublic\b/.test(targets);

  const privsOf = (privs) =>
    /\ball\b/.test(privs) ? WRITE_PRIVS : WRITE_PRIVS.filter((x) => new RegExp(`\\b${x}\\b`).test(privs));

  const apply = (entry, verb, applies) => {
    for (const priv of applies) {
      if (verb === 'grant') { entry.granted.add(priv); entry.revoked.delete(priv); }
      else { entry.revoked.add(priv); entry.granted.delete(priv); }
    }
  };

  for (const { sql } of [...files].sort(compareMigrations)) {
    const text = stripSqlComments(sql);
    const events = [];

    const allRe = /\b(grant|revoke)\s+([\s\S]*?)\s+on\s+all\s+tables\s+in\s+schema\s+([a-z0-9_."]+)\s+(?:to|from)\s+([^;]+)/gi;
    let a;
    while ((a = allRe.exec(text)) !== null) {
      if (!hitsRole(a[4].toLowerCase())) continue;
      const applies = privsOf(a[2].toLowerCase());
      if (applies.length) events.push({ at: a.index, verb: a[1].toLowerCase(), applies, all: true });
    }

    const re = /\b(grant|revoke)\s+([\s\S]*?)\s+on\s+(?:table\s+)?([a-z0-9_."]+)\s+(?:to|from)\s+([^;]+)/gi;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (/^all$/i.test(m[3])) continue; // the schema-wide form, handled above
      if (!hitsRole(m[4].toLowerCase())) continue;
      const applies = privsOf(m[2].toLowerCase());
      if (applies.length) events.push({ at: m.index, verb: m[1].toLowerCase(), applies, obj: bare(m[3]) });
    }

    events.sort((x, y) => x.at - y.at);
    for (const ev of events) {
      if (ev.all) for (const entry of state.values()) apply(entry, ev.verb, ev.applies);
      else apply(touch(ev.obj), ev.verb, ev.applies);
    }
  }
  return state;
}

/**
 * Does this migration history look like a Supabase project — i.e. one where
 * `ALTER DEFAULT PRIVILEGES` hands `anon`/`authenticated` write access to every
 * new object, so a view with no explicit REVOKE is writable?
 */
export function detectDefaultWriteGrants(files, exposedRoles) {
  const all = files.map((f) => stripSqlComments(f.sql)).join('\n').toLowerCase();
  const roleAlt = exposedRoles.map((r) => r.toLowerCase()).join('|');

  // Strongest: the grant is right there in the history.
  if (new RegExp(`alter\\s+default\\s+privileges[\\s\\S]{0,200}?grant[\\s\\S]{0,200}?on\\s+tables[\\s\\S]{0,120}?\\b(${roleAlt})\\b`).test(all)) {
    return { assume: true, evidence: 'an ALTER DEFAULT PRIVILEGES grant on TABLES in these migrations' };
  }
  // Otherwise: does this look like Supabase at all?
  if (new RegExp(`\\b(auth\\.uid\\s*\\(|service_role|\\b${roleAlt}\\b)`).test(all)) {
    return { assume: true, evidence: `this looks like a Supabase project (it references ${exposedRoles.join('/')}), where default privileges grant writes on every new object in public` };
  }
  return { assume: false, evidence: null };
}

/** The verdict for one view. */
export function classifyView({ view, grants, assumeDefaults, evidence, exposedRoles }) {
  const roles = exposedRoles.join(', ');

  if (view.isMaterialized) {
    return { status: 'safe' }; // a matview is never auto-updatable
  }
  if (view.securityInvoker) {
    return { status: 'safe' }; // writes run as the caller, so RLS applies to them
  }
  if (!view.autoUpdatable) {
    return { status: 'safe' }; // Postgres rejects writes through this shape
  }

  const explicitWrites = [...(grants?.granted ?? [])];
  const revokedWrites = [...(grants?.revoked ?? [])];
  const stillWritable = WRITE_PRIVS.filter((p) => !revokedWrites.includes(p));

  const fix =
    `REVOKE INSERT, UPDATE, DELETE ON ${view.name} FROM ${roles};\n` +
    `      A view that exists to expose safe columns should be readable only. If writes ARE intended,\n` +
    `      make them go through checks: CREATE VIEW … WITH (security_invoker = true), or an INSTEAD OF trigger.\n` +
    `      If this view is deliberately writable, add "${view.name}" to updatableViews.allowlist[] with a reason.`;

  if (explicitWrites.length > 0) {
    return {
      status: 'leak',
      kind: 'granted-writethrough',
      message:
        `view "${view.name}" is auto-updatable (one relation, no aggregation) and runs as its OWNER — ` +
        `security_invoker is not set — so writes pass through to "${view.baseTable ?? 'the base table'}" with the base table's ` +
        `RLS evaluated as the owner, not the caller. ${roles} ${explicitWrites.length === 1 ? 'has' : 'have'} ` +
        `${explicitWrites.join('/').toUpperCase()} on it explicitly.`,
      fix,
    };
  }

  if (assumeDefaults && stillWritable.length > 0) {
    return {
      status: 'leak',
      kind: 'default-writethrough',
      message:
        `view "${view.name}" is auto-updatable (one relation, no aggregation) and runs as its OWNER — ` +
        `security_invoker is not set — so INSERT/UPDATE/DELETE pass straight through to ` +
        `"${view.baseTable ?? 'the base table'}", with that table's RLS evaluated as the owner rather than the caller. ` +
        `No REVOKE of ${stillWritable.join('/').toUpperCase()} appears in these migrations, and ${evidence}. ` +
        `Granting only SELECT does not make a view read-only: the write privileges arrive on their own.`,
      fix,
    };
  }

  if (stillWritable.length > 0) {
    return {
      status: 'note',
      message:
        `view "${view.name}" is auto-updatable and runs as its owner, so writes would pass through to ` +
        `"${view.baseTable ?? 'the base table'}" bypassing that table's RLS. Nothing here grants ${roles} write access, ` +
        `so it is probably fine — but if your platform grants writes by default, add an explicit ` +
        `REVOKE INSERT, UPDATE, DELETE ON ${view.name} FROM ${roles}; so it stays that way.`,
    };
  }

  return { status: 'safe' };
}

// ── the guard ────────────────────────────────────────────────────────

export function run(config = {}) {
  // definedOnly: an explicitly-undefined option must not erase its default.
  const cfg = { ...DEFAULTS, ...definedOnly(config) };
  const dir = cfg.dir;
  if (!dir || !existsSync(dir)) {
    return {
      id: meta.id,
      ok: true,
      skipped: true,
      reason: dir ? `migrations dir not found: ${dir}` : 'no migrations dir configured',
      violations: [],
      notes: [],
      scanned: 0,
      summary: 'skipped',
    };
  }

  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.sql'))
    .map((f) => ({ name: f, sql: readFileSync(join(dir, f), 'utf8') }));

  const allow = new Set(cfg.allowlist.map((n) => bare(n)));
  const viewsForGrants = extractViews(files.map((f) => f.sql).join('\n')).map((v) => v.name);
  const grants = netWriteGrants(files, cfg.exposedRoles, viewsForGrants);
  const detected = detectDefaultWriteGrants(files, cfg.exposedRoles);
  const assumeDefaults = cfg.assumeDefaultWriteGrants === 'auto'
    ? detected.assume
    : Boolean(cfg.assumeDefaultWriteGrants);
  const evidence = detected.evidence ?? 'default privileges are assumed to grant writes (updatableViews.assumeDefaultWriteGrants)';

  // The final definition of each view across history wins, as elsewhere.
  const views = new Map();
  for (const { name: file, sql } of [...files].sort(compareMigrations)) {
    for (const v of extractViews(sql)) views.set(v.name, { ...v, file });
  }

  const violations = [];
  const notes = [];
  for (const [name, view] of views) {
    if (allow.has(name)) continue;
    const verdict = classifyView({
      view,
      grants: grants.get(name),
      assumeDefaults,
      evidence,
      exposedRoles: cfg.exposedRoles,
    });
    if (verdict.status === 'leak') {
      violations.push({ where: view.file, kind: verdict.kind, message: verdict.message, fix: verdict.fix });
    } else if (verdict.status === 'note') {
      notes.push({ where: view.file, message: verdict.message });
    }
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned: views.size,
    summary:
      violations.length > 0
        ? `${violations.length} view(s) write through to their base table, bypassing its RLS`
        : `${views.size} view(s) scanned` + (notes.length ? `; ${notes.length} note(s)` : ''),
  };
}
