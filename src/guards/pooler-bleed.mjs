/**
 * Guard: the tenant identity outliving the request that set it.
 *
 * Threat-model §6.1, and the only failure mode in this tool that needs BOTH
 * halves of the repository to see. It is also the nastiest one in the set,
 * because every single-request check passes: run one request and isolation is
 * perfect. The leak only exists *between* requests.
 *
 * The mechanism:
 *
 *   1. Your policies authorize from a custom GUC — `current_setting('app.tenant')`.
 *   2. Your app sets it with a **session**-scoped write: `SET app.tenant = …`, or
 *      `set_config('app.tenant', $1, false)`. That third argument is `is_local`,
 *      and `false` means "for the rest of this **connection**", not "for the rest
 *      of this transaction".
 *   3. Connections are pooled. The next request to check that connection out
 *      inherits the previous request's tenant — and reads its data with the
 *      policy working exactly as designed.
 *
 * Supabase's pooler defaults to transaction mode, which is precisely the
 * configuration where a session-scoped SET is left behind on a backend that
 * another client will later be handed.
 *
 * **Why this needs both halves.** The database alone can only say "your policies
 * trust a settable GUC", which is why `identity-trust` reports that as a *note*
 * and never a failure — whether it is exploitable depends on how the app writes
 * it, which SQL cannot see. The source alone can only say "something is set
 * session-wide", which is unremarkable on its own (`app.locale` is nobody's
 * security boundary). Put them together and the finding is conclusive and
 * specific: *this* GUC, authorized by *that* policy, is written session-wide at
 * *this* line. This guard is what upgrades the §2.8 note to a build failure.
 *
 * The runtime probe is a demonstration, not the verdict: it sets a namespaced
 * GUC of its own and reads it back in a later statement. It writes no data,
 * touches no table, and opens no explicit transaction.
 */
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import { classifyIdentitySource } from './identity-trust.mjs';
import { DEFAULTS as PROOF_DEFAULTS } from './rls-proof.mjs';

export const meta = {
  id: 'pooler-bleed',
  title: 'Tenant identity that outlives the request',
  why: "A policy keyed on a custom GUC is only as good as the scope it is set with. `set_config('app.tenant', $1, false)` and a bare `SET` last for the whole CONNECTION, so on a pooled connection the next request inherits the previous tenant's identity and the policy hands over their rows working exactly as designed. Every single-request test passes; the leak only exists between requests.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: PROOF_DEFAULTS.role,
  schemas: ['public'],
  // Where the app sets the GUC. Autodetected; these are the usual roots.
  sourceDirs: ['src', 'app', 'lib', 'server', 'api', 'db', 'supabase/migrations', 'migrations'],
  sourceExtensions: ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.rb', '.go', '.rs', '.java', '.kt', '.php', '.sql', '.ex', '.exs'],
  skipDirs: ['node_modules', '.git', 'dist', 'build', '.next', 'out', 'vendor', 'coverage', '__pycache__', 'target'],
  maxFileBytes: 512 * 1024,
  allowlist: [], // GUC names that are session-scoped on purpose
};

/** Namespaced so it can never collide with an application setting. */
export const PROBE_GUC = 'tenant_guard.bleed_probe';

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Policies in the target schemas, with the expressions they authorize from. */
export function policyGucsSql(schemas) {
  return {
    text: `
      select schemaname as schema, tablename as table, policyname as policy,
             cmd, qual, with_check
      from pg_policies
      where schemaname = any($1)
    `,
    values: [schemas],
  };
}

/**
 * Which custom GUCs the policies authorize from, and which policies use each.
 *
 * The `request.jwt.*` exclusion is inherited from `identity-trust`, deliberately
 * rather than re-implemented: those are set by PostgREST from a verified token,
 * per transaction, and are not the app's to leave lying around.
 */
export function gucsFromPolicies(rows) {
  const byGuc = new Map();
  for (const row of rows ?? []) {
    const gucs = new Set([
      ...classifyIdentitySource(row.qual).settableGucs,
      ...classifyIdentitySource(row.with_check).settableGucs,
    ]);
    for (const guc of gucs) {
      if (!byGuc.has(guc)) byGuc.set(guc, []);
      byGuc.get(guc).push({ id: `${row.schema}.${row.table}`, policy: row.policy, cmd: row.cmd });
    }
  }
  return byGuc;
}

/**
 * Split a call's arguments starting at the index of its opening paren.
 * Quote- and depth-aware, so a value argument containing commas or parens
 * (`set_config('app.t', coalesce(a, b), false)`) doesn't derail the split.
 * @returns {string[]|null} null when the parens never balance
 */
export function splitArgs(text, openIndex) {
  const args = [];
  let depth = 0;
  let quote = null;
  let start = openIndex + 1;
  for (let i = openIndex; i < text.length; i++) {
    const ch = text[i];
    if (quote) {
      if (ch === '\\') { i++; continue; }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') { quote = ch; continue; }
    if (ch === '(') { depth++; continue; }
    if (ch === ')') {
      depth--;
      if (depth === 0) { args.push(text.slice(start, i)); return args; }
      continue;
    }
    if (ch === ',' && depth === 1) { args.push(text.slice(start, i)); start = i + 1; }
  }
  return null;
}

/** The string value of an argument, if it is a plain literal. */
export function literalArg(arg) {
  const m = /^\s*(['"`])((?:[^'"`\\]|\\.)*)\1\s*$/.exec(arg ?? '');
  return m ? m[2] : null;
}

const lineOf = (text, index) => text.slice(0, index).split(/\r?\n/).length;
const snippetAt = (text, index) => {
  const from = text.lastIndexOf('\n', index) + 1;
  const to = text.indexOf('\n', index);
  return text.slice(from, to === -1 ? text.length : to).trim().slice(0, 160);
};

/**
 * Every `set_config(...)` call naming one of `gucs`, classified by scope.
 *
 * `is_local` is the third argument: `true` = this transaction only (safe),
 * `false` = the rest of the connection (the bug). Anything else — a variable, a
 * ternary — is `unknown`, and reported as a note rather than guessed at.
 */
export function setConfigCalls(text, gucs) {
  const wanted = new Set(gucs ?? []);
  const out = [];
  const re = /\bset_config\s*\(/gi;
  let m;
  while ((m = re.exec(text)) !== null) {
    const openIndex = m.index + m[0].length - 1;
    const args = splitArgs(text, openIndex);
    if (!args || args.length < 3) continue;
    const name = literalArg(args[0]);
    if (!name || (wanted.size > 0 && !wanted.has(name))) continue;
    const isLocal = (args[2] ?? '').trim().toLowerCase();
    const scope = isLocal === 'false' ? 'session' : isLocal === 'true' ? 'local' : 'unknown';
    out.push({ guc: name, scope, via: 'set_config', line: lineOf(text, m.index), snippet: snippetAt(text, m.index) });
  }
  return out;
}

/**
 * Every `SET <guc>` statement naming one of `gucs`, classified by scope.
 *
 * Restricted to GUCs the policies actually use, which is what keeps this from
 * matching arbitrary `set x.y =` in application code.
 */
export function setStatements(text, gucs) {
  const out = [];
  for (const guc of gucs ?? []) {
    const escaped = guc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`\\bset\\s+(local\\s+|session\\s+)?${escaped}\\s*(?:=|\\bto\\b)`, 'gi');
    let m;
    while ((m = re.exec(text)) !== null) {
      const modifier = (m[1] ?? '').trim().toLowerCase();
      out.push({
        guc,
        scope: modifier === 'local' ? 'local' : 'session',
        via: modifier === 'local' ? 'SET LOCAL' : modifier === 'session' ? 'SET SESSION' : 'SET',
        line: lineOf(text, m.index),
        snippet: snippetAt(text, m.index),
      });
    }
  }
  return out;
}

/** Both scanners over one file's text. */
export function scanText(text, gucs) {
  return [...setConfigCalls(text, gucs), ...setStatements(text, gucs)];
}

/**
 * Does this source reset connection state on release?
 *
 * `DISCARD ALL` / `RESET ALL` on checkin is the other correct fix, and a
 * codebase that does it has closed the hole a different way. Detected so the
 * finding can be downgraded rather than argued with.
 */
export function resetsConnectionState(text, guc) {
  if (/\b(discard\s+all|reset\s+all)\b/i.test(text)) return true;
  if (!guc) return false;
  const escaped = guc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`\\breset\\s+${escaped}\\b`, 'i').test(text);
}

/**
 * The verdict for one GUC.
 *
 * A session-scoped write to a GUC that policies authorize from is the finding,
 * and it is conclusive: both halves are observed facts, not inferences. Every
 * other outcome is a note, because it turns on something not observed here.
 */
export function classifyGuc({ guc, policies = [], sets = [], resets = false, scannedFiles = 0 }) {
  const where = policies.map((p) => `${p.id} (policy "${p.policy}")`);
  const used = policies.length === 1 ? where[0] : `${policies.length} policies, incl. ${where[0]}`;

  const session = sets.filter((s) => s.scope === 'session');
  const unknown = sets.filter((s) => s.scope === 'unknown');
  const local = sets.filter((s) => s.scope === 'local');

  if (session.length > 0) {
    const at = session.map((s) => `${s.file}:${s.line}`).join(', ');
    if (resets) {
      return {
        status: 'note',
        message:
          `"${guc}" authorizes ${used} and is set for the whole CONNECTION at ${at}, ` +
          `but this codebase also issues DISCARD ALL / RESET — which closes the hole if it runs on every ` +
          `connection release. Confirm that it does; the scope of the write itself is still wrong.`,
      };
    }
    return {
      status: 'leak',
      kind: 'session-scoped-tenant-guc',
      message:
        `"${guc}" authorizes ${used}, and is set for the whole CONNECTION (not the transaction) at ${at}. ` +
        `On a pooled connection the next request inherits the previous request's tenant and reads their rows ` +
        `— the policy works exactly as designed. Every single-request test passes; the leak lives between requests.`,
      fix:
        `Make the write transaction-scoped: set_config('${guc}', $1, true)  — the third argument is is_local — ` +
        `or SET LOCAL ${guc} = $1 inside the request's transaction.\n` +
        `      SET LOCAL only takes effect inside a transaction, so the request must open one.\n` +
        `      Alternatively issue DISCARD ALL when the connection returns to the pool.\n` +
        `      If "${guc}" is session-scoped on purpose, add it to poolerBleed.allowlist[] with a reason.`,
    };
  }

  if (unknown.length > 0) {
    const at = unknown.map((s) => `${s.file}:${s.line}`).join(', ');
    return {
      status: 'note',
      message:
        `"${guc}" authorizes ${used} and is set at ${at} with a non-literal is_local argument, so the scope ` +
        `could not be read. If that value is ever false the setting outlives the request — confirm it is true.`,
    };
  }

  if (local.length > 0) {
    return { status: 'ok', message: `"${guc}" is set transaction-locally (${local.length} site(s))` };
  }

  if (scannedFiles === 0) {
    return {
      status: 'note',
      message:
        `"${guc}" authorizes ${used}, but no source files were scanned, so where it is set is unknown. ` +
        `Set poolerBleed.sourceDirs to the directory that opens your database connections.`,
    };
  }

  return {
    status: 'note',
    message:
      `"${guc}" authorizes ${used}, but no site setting it was found in ${scannedFiles} scanned file(s) — ` +
      `it may be set by an ORM, a connection hook, or a service outside this repository. ` +
      `Confirm it uses SET LOCAL / set_config(…, true), or the value outlives the request on a pooled connection.`,
  };
}

// ── source collection ────────────────────────────────────────────────

/** Recursively collect candidate source files, skipping the usual noise. */
export function collectSourceFiles(cwd, cfg) {
  const files = [];
  const exts = new Set(cfg.sourceExtensions);
  const skip = new Set(cfg.skipDirs);

  const walk = (dir) => {
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name.startsWith('.') && e.name !== '.') continue;
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (skip.has(e.name)) continue;
        walk(full);
      } else if (exts.has(e.name.slice(e.name.lastIndexOf('.')))) {
        files.push(full);
      }
    }
  };

  for (const rel of cfg.sourceDirs) {
    const dir = join(cwd, rel);
    if (existsSync(dir)) {
      try {
        if (statSync(dir).isDirectory()) walk(dir);
      } catch { /* unreadable — nothing to scan */ }
    }
  }
  return [...new Set(files)];
}

/** Scan the tree for writes to any of `gucs`. */
export function scanSources(cwd, gucs, cfg) {
  const files = collectSourceFiles(cwd, cfg);
  const sets = [];
  let resets = false;
  let scanned = 0;

  for (const abs of files) {
    let text;
    try {
      if (statSync(abs).size > cfg.maxFileBytes) continue;
      text = readFileSync(abs, 'utf8');
    } catch {
      continue;
    }
    scanned++;
    const rel = relative(cwd, abs).replace(/\\/g, '/');
    for (const hit of scanText(text, gucs)) sets.push({ ...hit, file: rel });
    if (!resets && resetsConnectionState(text)) resets = true;
  }
  return { sets, resets, scannedFiles: scanned };
}

// ── runtime demonstration ────────────────────────────────────────────

/**
 * Show the mechanism on the live connection: a session-scoped setting survives
 * into a later statement; a transaction-scoped one does not.
 *
 * The second half is the control arm. If a transaction-local value ALSO
 * survived, the probe cannot distinguish the two and its result is reported as
 * inconclusive rather than as evidence.
 *
 * No explicit transaction is opened and no table is touched — each statement is
 * its own implicit transaction, which is exactly what makes the contrast visible.
 */
export async function probePersistence(q) {
  const localGuc = `${PROBE_GUC}_local`;
  await q('select set_config($1, $2, false)', [PROBE_GUC, 'persisted']);
  const survived = (await q('select current_setting($1, true) as v', [PROBE_GUC]))[0]?.v;

  // is_local = true, with no explicit transaction: the implicit one ends at the
  // semicolon, so this must already be gone by the next statement.
  await q('select set_config($1, $2, true)', [localGuc, 'transient']);
  const localSurvived = (await q('select current_setting($1, true) as v', [localGuc]))[0]?.v;

  try { await q('select set_config($1, $2, false)', [PROBE_GUC, '']); } catch { /* cosmetic */ }

  return {
    persists: survived === 'persisted',
    controlHeld: !localSurvived, // the transaction-scoped value correctly vanished
  };
}

// ── the guard ────────────────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {}, cwd = process.cwd() }) {
  const cfg = { ...DEFAULTS, ...config };
  const q = async (text, values) => (await query(text, values)).rows;
  const allow = new Set(cfg.allowlist);

  const violations = [];
  const notes = [];

  const spec = policyGucsSql(cfg.schemas);
  const byGuc = gucsFromPolicies(await q(spec.text, spec.values));

  if (byGuc.size === 0) {
    // The common Supabase case: policies read auth.uid()/auth.jwt(), which
    // PostgREST sets per transaction from a verified token. Nothing to bleed.
    return OK({
      skipped: true,
      reason: 'no policy authorizes from a custom GUC — nothing that can outlive a request',
      summary: 'skipped — no custom-GUC policies',
    });
  }

  const gucs = [...byGuc.keys()];
  const { sets, resets, scannedFiles } = scanSources(cwd, gucs, cfg);

  for (const guc of gucs) {
    if (allow.has(guc)) continue;
    const verdict = classifyGuc({
      guc,
      policies: byGuc.get(guc),
      sets: sets.filter((s) => s.guc === guc),
      resets,
      scannedFiles,
    });
    if (verdict.status === 'leak') {
      violations.push({ where: guc, kind: verdict.kind, message: verdict.message, fix: verdict.fix });
    } else if (verdict.status === 'note') {
      notes.push({ where: guc, message: verdict.message });
    }
  }

  // The demonstration, reported as a fact about this connection. It never
  // decides the verdict — the verdict is the two observed halves above.
  try {
    const { persists, controlHeld } = await probePersistence(q);
    if (!controlHeld) {
      notes.push({ where: '(probe)', message: 'the session-persistence probe was inconclusive: a transaction-scoped setting also survived, so this connection cannot distinguish the two scopes.' });
    } else if (persists) {
      notes.push({ where: '(probe)', message: 'confirmed on this connection: a session-scoped setting survives into later transactions, while a transaction-scoped one does not. That is the mechanism above, demonstrated.' });
    } else {
      notes.push({ where: '(probe)', message: 'a session-scoped setting did NOT survive on this connection — you are probably connected through a transaction-mode pooler. That is not safety: with transaction pooling the value is left on a backend that another client is later handed, which is the bleed itself.' });
    }
  } catch (err) {
    notes.push({ where: '(probe)', message: `could not demonstrate session persistence: ${err.message}` });
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned: gucs.length,
    summary:
      violations.length > 0
        ? `${violations.length} tenant GUC(s) set for the connection, not the transaction`
        : `${gucs.length} custom GUC(s) checked across ${scannedFiles} source file(s)` + (notes.length ? `; ${notes.length} note(s)` : ''),
  };
}

/** CLI/programmatic entry: resolve a connection, import `pg`, run the check. */
export async function run(config = {}, cwd = process.cwd()) {
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
    return await check({ query: (text, values) => client.query(text, values), config: cfg, cwd });
  } finally {
    await client.end();
  }
}
