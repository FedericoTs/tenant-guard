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
 * `schema.name`, defaulting an unqualified name to `public`.
 *
 * Views were keyed by bare name, so `public.profiles` and `reporting.profiles`
 * collapsed into one entry and the later definition overwrote the earlier — a
 * reporting view could silently replace, and hide, a real write-through. The
 * emitted REVOKE was unqualified too, which is ambiguous to paste.
 */
export const qualifiedName = (name) => {
  const parts = String(name ?? '').replace(/"/g, '').toLowerCase().split('.');
  const table = parts.pop() ?? '';
  const schema = parts.pop() || 'public';
  return `${schema}.${table}`;
};

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
    const qualified = qualifiedName(m[2]);
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
      qualified,
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

  // WHAT the FROM clause names decides whether a write can reach a table at all,
  // and none of the shape checks above ask. Measured in PGlite 0.5.5 / PG 18.3
  // with anon holding SELECT+INSERT+UPDATE+DELETE on every view, so nothing
  // failed for want of a privilege — pg_relation_is_updatable(oid, true):
  //     from users            (a table)            -> 28, DELETE affected 2 rows
  //     from (select ...) s   (a subquery)         ->  0
  //     from active_users()   (a set-returning fn) ->  0, DELETE raised 55000
  // So a name followed IMMEDIATELY by `(` is a function call and a leading `(` is
  // a subquery; neither is a write path. `from users u(a,b)` is a table with
  // column aliases — the space before `(` is what separates the two, and that
  // form measured 28, still updatable, so requiring no-space is not merely a
  // convention.
  const head = fromClause.replace(/^\s+/, '');
  const baseIsSubquery = head.startsWith('(');
  const nameMatch = baseIsSubquery ? null : /^([a-z0-9_."]+)(\()?/.exec(head);
  const baseIsCallable = Boolean(nameMatch && nameMatch[2]);
  const baseTable = nameMatch ? bare(nameMatch[1]) : null;
  const baseQualified = nameMatch ? qualifiedName(nameMatch[1]) : null;

  return {
    autoUpdatable: reasons.length === 0,
    notUpdatableBecause: reasons,
    baseTable,
    baseQualified,
    baseIsCallable,
    baseIsSubquery,
  };
}

/**
 * Relations a migration gives an INSTEAD OF trigger or a rule.
 *
 * These are the two ways a shape Postgres would refuse a write on becomes
 * writable again, and they are why the base-relation reasoning below can never
 * conclude "blocked" over one. Measured: a GROUP BY view read
 * pg_relation_is_updatable 0; after `create rule ... as on delete to agg do
 * instead delete from users`, 16 — and `delete from` a thin view stacked on top
 * of it removed 2 rows from the RLS-protected base table as anon.
 *
 * Only creations are collected. A later DROP TRIGGER is not tracked, which
 * leaves the guard reporting a view it could have cleared — the safe direction.
 */
export function extractInsteadWritable(sql) {
  const text = stripSqlComments(sql);
  const out = new Set();
  const trig = /create\s+(?:or\s+replace\s+)?(?:constraint\s+)?trigger\s+[a-z0-9_."]+\s+instead\s+of\b[^;]{0,400}?\bon\s+([a-z0-9_."]+)/gi;
  let m;
  while ((m = trig.exec(text)) !== null) out.add(qualifiedName(m[1]));
  const rule = /create\s+(?:or\s+replace\s+)?rule\s+[a-z0-9_."]+\s+as\s+on\s+(?:insert|update|delete)\s+to\s+([a-z0-9_."]+)/gi;
  while ((m = rule.exec(text)) !== null) out.add(qualifiedName(m[1]));
  return out;
}

/**
 * Can a write actually reach a TABLE through this view's FROM target?
 *
 * The shape checks in autoUpdatableShape() only look at THIS select, so a thin
 * `select a, b from reporting_view` passes every one of them and was reported as
 * a write-through even though Postgres refuses the write outright. On a schema
 * with ordinary reporting views that was three false reports for every true one,
 * and a guard that fires on correct code teaches people to silence it.
 *
 * Returns:
 *   'blocked'  — Postgres refuses the write (SQLSTATE 55000). Proven safe.
 *   'writable' — the chain reaches a table, or a rule/trigger re-opens it.
 *   'unknown'  — the base relation is not defined in these migrations (a table,
 *                or `auth.users`, or another schema entirely). Stays reported:
 *                downgrading unknowns would hide the exact bug this guard was
 *                written for, which was a view over a table it could not see.
 */
export function resolveBaseWritable(view, views, insteadWritable = new Set(), seen = new Set()) {
  if (!view) return 'unknown';
  if (view.baseIsSubquery || view.baseIsCallable) return 'blocked';
  const key = view.baseQualified;
  if (!key || seen.has(key)) return 'unknown'; // cycle: refuse to conclude either way
  seen.add(key);
  const base = views.get(key);
  if (!base) return 'unknown';
  // A matview can carry neither an INSTEAD OF trigger (42809 "relation ... cannot
  // have triggers") nor a rule (0A000 "rules on materialized views are not
  // supported"), both measured, so this leg needs no escape hatch.
  if (base.isMaterialized) return 'blocked';
  if (insteadWritable.has(key)) return 'writable';
  if (!base.autoUpdatable) return 'blocked';
  return resolveBaseWritable(base, views, insteadWritable, seen);
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
 * **The privilege list may not cross a `;`.** It was `[\s\S]*?`, and on the
 * single-file Supabase lockdown — a `GRANT SELECT … TO anon;` immediately
 * followed by `REVOKE INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public FROM
 * anon;` — the lazy group backtracked over the semicolon and matched from the
 * GRANT's verb through the REVOKE's privilege list. The schema-wide REVOKE was
 * therefore recorded as a schema-wide *GRANT* of INSERT/UPDATE/DELETE on every
 * view: not a missed revoke, an inverted one. Splitting the same two statements
 * across two files hid it, which is why it survived the earlier fix.
 *
 * **PUBLIC is a different grantee from `anon`.** `REVOKE … FROM PUBLIC` removes
 * only what was granted to the PUBLIC pseudo-role; it does not touch a grant made
 * directly to `anon`, nor the ALTER DEFAULT PRIVILEGES writes that arrive on
 * `anon` by name. Measured: after `revoke all on all tables in schema public from
 * public`, has_table_privilege('anon', view, 'DELETE') was still true and anon
 * deleted 2 rows through the view. Folding PUBLIC into the role match made that
 * REVOKE read as proof the hole was closed and the guard went green on it. So the
 * two grantees are tracked in separate lanes and only the role lane can prove a
 * privilege gone.
 *
 * @returns {Map<string, {granted:Set<string>, revoked:Set<string>}>} keyed by `schema.name`
 */
export function netWriteGrants(files, exposedRoles, viewNames = []) {
  const roles = new Set(exposedRoles.map((r) => r.toLowerCase()));
  const state = new Map();
  const touch = (name) => {
    if (!state.has(name)) {
      state.set(name, {
        role: { granted: new Set(), revoked: new Set() },
        pub: { granted: new Set(), revoked: new Set() },
      });
    }
    return state.get(name);
  };
  for (const v of viewNames) touch(qualifiedName(v));

  // Which grantee lanes a TO/FROM list touches. Both can be true at once
  // (`REVOKE … FROM anon, PUBLIC`).
  const lanesOf = (targets) => ({
    role: [...roles].some((r) => new RegExp(`\\b${r}\\b`).test(targets)),
    pub: /\bpublic\b/.test(targets),
  });
  const hitsRole = (targets) => {
    const l = lanesOf(targets);
    return l.role || l.pub;
  };

  const privsOf = (privs) =>
    /\ball\b/.test(privs) ? WRITE_PRIVS : WRITE_PRIVS.filter((x) => new RegExp(`\\b${x}\\b`).test(privs));

  const apply = (entry, verb, applies, lanes) => {
    for (const laneName of ['role', 'pub']) {
      if (!lanes[laneName]) continue;
      const lane = entry[laneName];
      for (const priv of applies) {
        if (verb === 'grant') { lane.granted.add(priv); lane.revoked.delete(priv); }
        else { lane.revoked.add(priv); lane.granted.delete(priv); }
      }
    }
  };

  for (const { sql } of [...files].sort(compareMigrations)) {
    const text = stripSqlComments(sql);
    const events = [];

    const allRe = /\b(grant|revoke)\s+([^;]*?)\s+on\s+all\s+tables\s+in\s+schema\s+([a-z0-9_."]+)\s+(?:to|from)\s+([^;]+)/gi;
    let a;
    while ((a = allRe.exec(text)) !== null) {
      const targets = a[4].toLowerCase();
      if (!hitsRole(targets)) continue;
      const applies = privsOf(a[2].toLowerCase());
      if (applies.length) {
        events.push({ at: a.index, verb: a[1].toLowerCase(), applies, lanes: lanesOf(targets), all: true });
      }
    }

    const re = /\b(grant|revoke)\s+([^;]*?)\s+on\s+(?:table\s+)?([a-z0-9_."]+)\s+(?:to|from)\s+([^;]+)/gi;
    let m;
    while ((m = re.exec(text)) !== null) {
      if (/^all$/i.test(m[3])) continue; // the schema-wide form, handled above
      const targets = m[4].toLowerCase();
      if (!hitsRole(targets)) continue;
      const applies = privsOf(m[2].toLowerCase());
      if (applies.length) {
        events.push({ at: m.index, verb: m[1].toLowerCase(), applies, lanes: lanesOf(targets), obj: qualifiedName(m[3]) });
      }
    }

    // DROP VIEW wipes the object's ACL. A recreated view gets FRESH default
    // privileges, so a REVOKE issued before the drop protects nothing — and the
    // guard was carrying that stale revoke forward and reporting the view clean.
    // The shape is completely ordinary: revoke on create, then `drop view` +
    // `create view` in a later migration to add a column.
    const dropRe = /\bdrop\s+(?:materialized\s+)?view\s+(?:if\s+exists\s+)?([a-z0-9_."]+)/gi;
    let d;
    while ((d = dropRe.exec(text)) !== null) events.push({ at: d.index, drop: qualifiedName(d[1]) });

    events.sort((x, y) => x.at - y.at);
    for (const ev of events) {
      if (ev.drop) {
        const entry = state.get(ev.drop);
        if (entry) {
          for (const lane of [entry.role, entry.pub]) { lane.granted.clear(); lane.revoked.clear(); }
        }
      } else if (ev.all) {
        for (const entry of state.values()) apply(entry, ev.verb, ev.applies, ev.lanes);
      } else {
        apply(touch(ev.obj), ev.verb, ev.applies, ev.lanes);
      }
    }
  }

  // Collapse the two lanes into the {granted, revoked} the caller reasons about.
  //   granted — the browser roles hold this privilege, from either grantee.
  //   revoked — PROVEN gone, which also has to clear the ALTER DEFAULT PRIVILEGES
  //             writes classifyView() otherwise assumes. Those arrive on the
  //             named role, so only a revoke on the role lane can prove it; a
  //             revoke from PUBLIC leaves them in place (measured above).
  const out = new Map();
  for (const [name, e] of state) {
    const granted = new Set(WRITE_PRIVS.filter((p) => e.role.granted.has(p) || e.pub.granted.has(p)));
    const revoked = new Set(WRITE_PRIVS.filter((p) => !granted.has(p) && e.role.revoked.has(p)));
    out.set(name, { granted, revoked });
  }
  return out;
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

/**
 * The verdict for one view.
 *
 * `baseWritable` is resolveBaseWritable()'s answer about the FROM target and
 * defaults to 'unknown', which is the behaviour every caller had before it
 * existed. `selfInstead` says this view carries its own INSTEAD OF trigger or
 * rule, which makes it writable no matter what it selects from.
 */
export function classifyView({
  view,
  grants,
  assumeDefaults,
  evidence,
  exposedRoles,
  baseWritable = 'unknown',
  selfInstead = false,
}) {
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
  // The shape is auto-updatable but the FROM target is not a write path: a
  // MATERIALIZED VIEW, a set-returning function, a subquery, or a view Postgres
  // itself refuses writes on. Measured with anon holding all four privileges so
  // nothing failed for want of one — pg_relation_is_updatable was 0 for each and
  // `delete from` raised 55000 ("cannot delete from view …"), as owner too, so it
  // is the relation kind refusing the write and not RLS or grants. Reporting
  // these was three false violations for every true one on a schema that has any
  // reporting views at all. `selfInstead` holds the exception: a rule or INSTEAD
  // OF trigger on THIS view re-opens the write regardless of the base, and one
  // such stack really did delete 2 rows from an RLS-protected table as anon.
  if (baseWritable === 'blocked' && !selfInstead) {
    return { status: 'safe' };
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
  const viewsForGrants = extractViews(files.map((f) => f.sql).join('\n')).map((v) => v.qualified);
  const grants = netWriteGrants(files, cfg.exposedRoles, viewsForGrants);
  const detected = detectDefaultWriteGrants(files, cfg.exposedRoles);
  const assumeDefaults = cfg.assumeDefaultWriteGrants === 'auto'
    ? detected.assume
    : Boolean(cfg.assumeDefaultWriteGrants);
  const evidence = detected.evidence ?? 'default privileges are assumed to grant writes (updatableViews.assumeDefaultWriteGrants)';

  // The final definition of each view across history wins, as elsewhere.
  const views = new Map();
  for (const { name: file, sql } of [...files].sort(compareMigrations)) {
    // Keyed by schema.name: two views of the same name in different schemas are
    // different objects, and collapsing them let a reporting view overwrite —
    // and hide — a real write-through.
    for (const v of extractViews(sql)) views.set(v.qualified, { ...v, file });
  }

  // Rules and INSTEAD OF triggers, over the whole history: the two things that
  // make a shape Postgres would refuse a write on writable again.
  const insteadWritable = extractInsteadWritable(files.map((f) => f.sql).join('\n'));

  const violations = [];
  const notes = [];
  for (const [key, view] of views) {
    // An allowlist entry may be written either way; a bare name still matches,
    // for the configs that were written before views were keyed by schema.
    if (allow.has(key) || allow.has(view.name)) continue;
    const verdict = classifyView({
      view,
      grants: grants.get(key),
      assumeDefaults,
      evidence,
      exposedRoles: cfg.exposedRoles,
      baseWritable: resolveBaseWritable(view, views, insteadWritable),
      selfInstead: insteadWritable.has(key),
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
