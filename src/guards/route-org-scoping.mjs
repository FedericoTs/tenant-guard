/**
 * Guard: API routes that filter by id but not by tenant.
 *
 * The cross-tenant IDOR that AI code generators ship constantly: an
 * authenticated handler loads a row by its primary key alone —
 *   supabase.from('invoices').select().eq('id', params.id)
 * — with no `organization_id` (or whatever your tenant column is) in the
 * filter. Any logged-in user of tenant A can read tenant B's row by guessing
 * or enumerating an id. RLS is the real defence, but (a) plenty of apps ship
 * without it and (b) service-role / admin clients bypass RLS, so the id-only
 * query is a latent leak the moment it runs on a privileged client.
 *
 * This is a heuristic source check, deliberately conservative: it flags a route
 * file only when it BOTH authenticates a user AND filters by a bare id column
 * AND never mentions a tenant column anywhere in the file. That combination is
 * the exact shape of the bug; a file that scopes by tenant, or never
 * authenticates, is not flagged. False positives are handled by an allowlist,
 * not by loosening the check.
 *
 * Zero dependencies. The classifier is a pure function over file text so it is
 * unit-testable without a filesystem.
 */
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';

export const DEFAULTS = {
  routesDir: 'src/app/api',
  routeFilePattern: '(route|handler)\\.(ts|tsx|js|mjs)$',
  // A request is authenticated if any of these appear.
  authSignals: ['withApiAuth', 'requirePermission', 'getUser(', 'auth.getUser', 'getServerSession', 'requireAuth'],
  // A bare-id filter, across the common TS query layers:
  //   Supabase:  .eq('id', …) / .eq("document_id", …)
  //   Prisma:    where: { id: … }
  //   Drizzle:   eq(invoices.id, …) / eq(t.vendor_id, …)
  // Raw SQL (where id = …) is deliberately NOT in the default — too prone to
  // false positives on self-loads; widen idFilterPattern in config if you use it.
  idFilterPattern: `\\.eq\\(\\s*['"\\\`](id|[a-z_]*_id)['"\\\`]|where:\\s*\\{\\s*id\\b|\\beq\\(\\s*[\\w$]+\\.(id|[a-z_]*_id)\\b`,
  // A tenant-scoping mention (any of these makes the file safe).
  tenantSignals: ['organization_id', 'organizationId', 'tenant_id', 'tenantId', 'org_id', 'account_id', 'workspace_id'],
  /**
   * Filter VALUES that come from the verified session rather than the request.
   *
   * `.eq('user_id', user.id)` is a per-user scope, not an IDOR — the value is
   * whoever is logged in, so the row cannot be somebody else's. But `user_id`
   * matches the bare-id pattern, and the pattern stopped at the column name, so
   * every "my notifications" and "my settings" route in the Next.js + Supabase
   * stack these defaults target failed the build. Verified: `.eq('user_id',
   * user.id)`, `.eq('id', user.id)` and the genuine IDOR `.eq('id', params.id)`
   * all classified identically as leak:true.
   *
   * The documented workaround made it worse — putting `user_id` in
   * `tenantSignals` also silences `.eq('user_id', params.userId)`, which IS an
   * IDOR. Verified too. So the VALUE has to be read, not just the column name.
   */
  sessionValueSignals: ['user.id', 'session.user.id', 'session.userId', 'auth.uid()', 'claims.sub', 'currentUser.id'],
  /**
   * Call arguments that are a PROJECTION, not a filter.
   *
   * `.select('id, organization_id, total').eq('id', params.id)` names the tenant
   * column in the column list and nowhere else, and that counted as scoping — so
   * the guard's own canonical service-role IDOR reported clean, with the summary
   * "all tenant-scoped or authless". Verified end to end: that same query
   * returned another tenant's row over a service-role connection.
   */
  projectionCalls: ['select', 'order', 'returns'],
};

/**
 * Classify one route file's text. Pure.
 * @returns {{ authenticated:boolean, filtersById:boolean, mentionsTenant:boolean, leak:boolean }}
 */
/**
 * The statement containing `index`, approximately.
 *
 * Bounded by the surrounding `;` so a whole query builder chain counts as one
 * statement however many lines it spans — which is what "the same query" has to
 * mean for `.from(…).eq(…).eq(…)`, `where: { … }` and `.where(and(…))` alike.
 */
export function enclosingStatement(text, index) {
  const start = Math.max(text.lastIndexOf(';', index) + 1, 0);
  const end = text.indexOf(';', index);
  return text.slice(start, end === -1 ? text.length : end);
}

/**
 * Blank out the ARGUMENTS of projection calls, keeping everything else.
 *
 * A balanced-paren scan rather than a regex, because Drizzle and Prisma pass
 * object literals with nested parens. The call name is left in place so the
 * statement's shape is unchanged; only what is inside the parens goes.
 */
export function stripProjections(stmt, calls = DEFAULTS.projectionCalls) {
  let out = String(stmt ?? '');
  for (const call of calls) {
    const re = new RegExp(`\\.${call}\\s*\\(`, 'gi');
    let m;
    while ((m = re.exec(out)) !== null) {
      let depth = 1;
      let i = m.index + m[0].length;
      const from = i;
      for (; i < out.length && depth > 0; i++) {
        if (out[i] === '(') depth++;
        else if (out[i] === ')') depth--;
      }
      const to = depth === 0 ? i - 1 : out.length;
      out = out.slice(0, from) + ' '.repeat(to - from) + out.slice(to);
      re.lastIndex = m.index + m[0].length;
    }
  }
  return out;
}

/**
 * Is this id-filter's VALUE derived from the verified session?
 *
 * The value span is whatever follows the matched column literal up to the
 * closing paren of the filter call. `.eq('user_id', user.id)` is a per-user
 * scope; `.eq('user_id', params.userId)` is an IDOR, and the only thing that
 * separates them is what comes after the comma.
 */
export function isSessionDerived(text, match, sessionValues = DEFAULTS.sessionValueSignals) {
  const from = match.index + match[0].length;
  const close = text.indexOf(')', from);
  const span = text.slice(from, close === -1 ? Math.min(from + 120, text.length) : close);
  return sessionValues.some((s) => span.includes(s));
}

/**
 * Classify one route file's text. Pure.
 *
 * The tenant signal is looked for in the SAME statement as the bare-id filter,
 * not merely somewhere in the module: a route can call `getUser()` and reference
 * `user.id` for its auth check and still run an unscoped `.eq('id', …)` query
 * underneath, and a file-wide match hides exactly that.
 *
 * Three outcomes rather than two, because "the tenant is mentioned in the file
 * but not in the query" is genuinely ambiguous — it is the IDOR shape, and it is
 * also the ordinary fetch-then-check pattern, and the text cannot tell which. So
 * it is reported, at a severity that does not block the build.
 *
 * @returns {{authenticated, filtersById, mentionsTenant, scopedInQuery, leak, unscopedQuery}}
 */
export function classifyRouteFile(text, opts = {}) {
  const authSignals = opts.authSignals ?? DEFAULTS.authSignals;
  const tenantSignals = opts.tenantSignals ?? DEFAULTS.tenantSignals;
  const pattern = opts.idFilterPattern ?? DEFAULTS.idFilterPattern;
  const sessionValues = opts.sessionValueSignals ?? DEFAULTS.sessionValueSignals;
  const projectionCalls = opts.projectionCalls ?? DEFAULTS.projectionCalls;
  const idFilter = new RegExp(pattern, 'i');

  const authenticated = authSignals.some((s) => text.includes(s));
  const mentionsTenant = tenantSignals.some((s) => text.includes(s));

  // Decided PER MATCH, not once for the file: an id-filter whose value comes
  // from the verified session is a per-user scope, not an IDOR. A file whose
  // only id-filters are session-derived is therefore not a leak, while
  // `.eq('id', params.id)` in that same file still is.
  const matches = [...text.matchAll(new RegExp(pattern, 'gi'))];
  const requestScoped = matches.filter((m) => !isSessionDerived(text, m, sessionValues));
  const filtersById = requestScoped.length > 0;

  // Does at least one bare-id filter sit in a statement that also FILTERS by a
  // tenant? Projections are blanked first — naming the tenant column in a
  // `.select(…)` list is not scoping, and treating it as such made the guard's
  // own canonical IDOR report clean.
  let scopedInQuery = false;
  for (const m of requestScoped) {
    const stmt = stripProjections(enclosingStatement(text, m.index), projectionCalls);
    if (tenantSignals.some((sig) => stmt.includes(sig))) { scopedInQuery = true; break; }
  }

  return {
    authenticated,
    filtersById,
    mentionsTenant,
    scopedInQuery,
    leak: authenticated && filtersById && !mentionsTenant,
    // Authenticated, filters by id, the file knows about tenancy — but the query
    // itself does not carry it.
    unscopedQuery: authenticated && filtersById && mentionsTenant && !scopedInQuery,
  };
}

/** Recursively collect files under `dir` whose basename matches `pattern`. */
export function collectRouteFiles(dir, pattern = DEFAULTS.routeFilePattern) {
  const re = new RegExp(pattern);
  const out = [];
  const walk = (d) => {
    for (const entry of readdirSync(d)) {
      if (entry === 'node_modules' || entry.startsWith('.')) continue;
      const p = join(d, entry);
      const st = statSync(p);
      if (st.isDirectory()) walk(p);
      else if (re.test(entry)) out.push(p);
    }
  };
  walk(dir);
  return out;
}

export const meta = {
  id: 'route-org-scoping',
  title: 'API routes filter by id but not by tenant',
  why: 'An authenticated handler that loads a row by bare id with no tenant filter is a cross-tenant IDOR — trivially exploitable on any RLS-bypassing (service-role/admin) client.',
};

/**
 * @param {object} config { routesDir?, routeFilePattern?, authSignals?, idFilterPattern?, tenantSignals?, allowlist?: string[], cwd? }
 */
export function run(config = {}) {
  const cwd = config.cwd ?? process.cwd();
  const routesDir = join(cwd, config.routesDir ?? DEFAULTS.routesDir);
  if (!existsSync(routesDir)) {
    return {
      id: meta.id,
      ok: true,
      skipped: true,
      reason: `routes dir not found: ${config.routesDir ?? DEFAULTS.routesDir}`,
      violations: [],
      scanned: 0,
      summary: 'skipped',
    };
  }
  const allow = new Set(config.allowlist ?? []);
  const files = collectRouteFiles(routesDir, config.routeFilePattern);
  const violations = [];
  const notes = [];
  for (const abs of files) {
    const rel = relative(cwd, abs).replace(/\\/g, '/');
    if (allow.has(rel)) continue;
    const verdict = classifyRouteFile(readFileSync(abs, 'utf8'), config);
    if (verdict.unscopedQuery) {
      notes.push({
        where: rel,
        message:
          `this route filters by a bare id, and a tenant column appears in the file but NOT in the same query. ` +
          `That is either an IDOR hiding behind an unrelated auth check, or a fetch-then-check — the source cannot tell which. ` +
          `If the row is loaded before it is authorised, put the tenant in the query: .eq('id', id).eq('<tenant column>', …).`,
      });
    }
    if (verdict.leak) {
      violations.push({
        where: rel,
        message: 'authenticated + filters by bare id + never scopes by a tenant column',
        fix:
          `Add the tenant column to every query in this route, e.g. .eq('organization_id', auth.organizationId).\n` +
          `      If this route is genuinely tenant-agnostic, add "${rel}" to routeOrgScoping.allowlist[] with a one-line justification.`,
      });
    }
  }
  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned: files.length,
    summary:
      violations.length === 0
        ? `${files.length} route file(s) scanned; all tenant-scoped or authless`
        : `${violations.length} route(s) can leak across tenants`,
  };
}
