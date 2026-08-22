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
 * The user functions each policy calls, with their bodies.
 *
 * Measured against pglite: a policy written `using (org = current_tenant())`
 * deparses in `pg_policies.qual` as exactly that — the `current_setting('app.tenant')`
 * inside the helper never appears. Reading only the deparsed expression therefore
 * reported "no policy authorizes from a custom GUC" on a schema where the bleed
 * was live and provable. `pg_depend` records the policy→function edge exactly, so
 * this is a lookup rather than a guess: no parsing of the deparsed expression, and
 * pinned system functions (`current_setting`, casts, operators) are not recorded
 * there at all, so the result is only the user's own helpers.
 */
export function policyFunctionsSql(schemas) {
  return {
    text: `
      select ns.nspname   as schema,
             c.relname    as table,
             p.polname    as policy,
             p.polcmd     as polcmd,
             fnn.nspname  as fn_schema,
             fn.proname   as fn_name,
             l.lanname    as lang,
             fn.prosrc    as body
      from pg_catalog.pg_depend d
      join pg_catalog.pg_policy p     on p.oid = d.objid
      join pg_catalog.pg_class c      on c.oid = p.polrelid
      join pg_catalog.pg_namespace ns on ns.oid = c.relnamespace
      join pg_catalog.pg_proc fn      on fn.oid = d.refobjid
      join pg_catalog.pg_namespace fnn on fnn.oid = fn.pronamespace
      join pg_catalog.pg_language l   on l.oid = fn.prolang
      where d.classid = 'pg_catalog.pg_policy'::regclass
        and d.refclassid = 'pg_catalog.pg_proc'::regclass
        and ns.nspname = any($1)
    `,
    values: [schemas],
  };
}

/**
 * Bodies of functions by bare name, for following one helper into the next.
 *
 * `pg_depend` records the policy→function edge but NOT function→function for
 * plain SQL/plpgsql bodies (verified: a two-level chain produced zero fn→fn rows),
 * so the second hop has to be resolved by name. System schemas are excluded
 * because nothing there is the app's to leave lying around.
 */
export function functionBodiesSql(names) {
  return {
    text: `
      select n.nspname as fn_schema, p.proname as fn_name,
             l.lanname as lang, p.prosrc as body
      from pg_catalog.pg_proc p
      join pg_catalog.pg_namespace n on n.oid = p.pronamespace
      join pg_catalog.pg_language l  on l.oid = p.prolang
      where p.proname = any($1)
        and n.nspname not in ('pg_catalog', 'information_schema')
    `,
    values: [names],
  };
}

/** `pg_policy.polcmd` is a single char; `pg_policies.cmd` is the word. */
const POLCMD = { '*': 'ALL', r: 'SELECT', a: 'INSERT', w: 'UPDATE', d: 'DELETE' };

// Words that appear before `(` in SQL/plpgsql bodies and are never the user's
// own helper. Anything not on this list is looked up in pg_proc, and a name that
// resolves to nothing costs one row in an `= any($1)` query.
const NOT_A_HELPER = new Set([
  'select', 'from', 'where', 'and', 'or', 'not', 'case', 'when', 'then', 'else', 'end',
  'coalesce', 'nullif', 'cast', 'current_setting', 'set_config', 'array', 'row', 'exists',
  'in', 'values', 'if', 'elsif', 'return', 'begin', 'declare', 'using', 'on', 'as', 'is',
  'null', 'true', 'false', 'count', 'min', 'max', 'sum', 'avg', 'trim', 'lower', 'upper',
  'substring', 'concat', 'format', 'any', 'all', 'into', 'language', 'function', 'returns',
]);

/** Bare identifiers called as functions inside a body — the next hop to resolve. */
export function calledFunctionNames(body) {
  const out = new Set();
  for (const m of String(body ?? '').matchAll(/([A-Za-z_][A-Za-z_0-9$]*)\s*\(/g)) {
    const name = m[1].toLowerCase();
    if (!NOT_A_HELPER.has(name)) out.add(name);
  }
  return [...out];
}

/** A body we can actually read. `c` and `internal` store a symbol name, not SQL. */
export function bodyIsReadable(row) {
  const lang = String(row?.lang ?? '').toLowerCase();
  return (lang === 'sql' || lang === 'plpgsql') && typeof row?.body === 'string' && row.body.length > 0;
}

/**
 * Fold GUCs read inside policy-called functions into `byGuc`, in place.
 *
 * Broadening the *input* set cannot broaden the *verdict*: `classifyGuc` only
 * returns 'leak' when a session-scoped write to that same GUC is also found in
 * the source. A codebase using `set_config(…, true)` gets 'ok'; a GUC nothing
 * writes gets a note. The worst case of over-collecting here is an extra note.
 *
 * Returns what was measured, so the caller can report what it could NOT see
 * instead of calling it absence.
 */
export async function resolveGucsThroughFunctions(q, cfg, byGuc, maxDepth = 4) {
  const stats = { resolved: 0, unreadable: [], error: null };
  let rows;
  try {
    const spec = policyFunctionsSql(cfg.schemas);
    rows = await q(spec.text, spec.values);
  } catch (err) {
    stats.error = err.message;
    return stats;
  }
  if (!Array.isArray(rows)) {
    stats.error = 'the policy→function catalog query returned no row set';
    return stats;
  }

  // seed: one entry per (policy, function) edge, carrying the calling policy
  let frontier = [];
  for (const r of rows) {
    if (!r || typeof r.fn_name !== 'string' || typeof r.qual === 'string') continue; // shape guard
    frontier.push({
      policy: { id: `${r.schema}.${r.table}`, policy: r.policy, cmd: POLCMD[r.polcmd] ?? r.polcmd ?? 'ALL' },
      via: `${r.fn_schema}.${r.fn_name}()`,
      row: r,
    });
  }

  const seen = new Set();
  for (let depth = 0; depth < maxDepth && frontier.length > 0; depth++) {
    const next = [];
    const wanted = new Map(); // bare name -> [{policy, via}]
    for (const node of frontier) {
      const key = `${node.row.fn_schema}.${node.row.fn_name}|${node.policy.id}|${node.policy.policy}`;
      if (seen.has(key)) continue;
      seen.add(key);

      if (!bodyIsReadable(node.row)) {
        const label = `${node.row.fn_schema}.${node.row.fn_name} (language ${node.row.lang})`;
        if (!stats.unreadable.includes(label)) stats.unreadable.push(label);
        continue;
      }
      stats.resolved++;

      for (const guc of classifyIdentitySource(node.row.body).settableGucs) {
        if (!byGuc.has(guc)) byGuc.set(guc, []);
        const entry = { ...node.policy, via: node.via };
        const already = byGuc.get(guc).some((p) => p.id === entry.id && p.policy === entry.policy && p.via === entry.via);
        if (!already) byGuc.get(guc).push(entry);
      }

      for (const name of calledFunctionNames(node.row.body)) {
        if (!wanted.has(name)) wanted.set(name, []);
        // The chain so far; the resolved schema-qualified name is appended once
        // the lookup says which function this bare name actually was.
        wanted.get(name).push({ policy: node.policy, viaPrefix: node.via });
      }
    }
    if (wanted.size === 0) break;

    let bodies;
    try {
      const spec = functionBodiesSql([...wanted.keys()]);
      bodies = await q(spec.text, spec.values);
    } catch (err) {
      stats.error = stats.error ?? `nested helper lookup failed: ${err.message}`;
      break;
    }
    if (!Array.isArray(bodies)) break;
    for (const b of bodies) {
      if (!b || typeof b.fn_name !== 'string') continue;
      for (const caller of wanted.get(b.fn_name.toLowerCase()) ?? []) {
        next.push({ policy: caller.policy, via: `${caller.viaPrefix} → ${b.fn_schema}.${b.fn_name}()`, row: b });
      }
    }
    frontier = next;
  }
  return stats;
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

// ── comments and strings ─────────────────────────────────────────────

/**
 * Comment syntax per file extension.
 *
 * Per-language, not one union, because being wrong costs something in both
 * directions. Applying SQL's `--` rule to JavaScript would blank the rest of a
 * line after `i--` and could hide a live `set_config` sitting on it; not
 * applying it to `.sql` is the false positive this table exists to fix —
 * measured: a migration whose only mention of the GUC was the prose
 * `-- Never SET app.tenant = ... session-wide` produced a build-failing
 * violation, and a `client.ts` doing the right thing while documenting the
 * anti-pattern in a `//` comment did the same, with the correct
 * `set_config(…, true)` on the next line masked by it.
 *
 * An extension not in this table masks NOTHING. Guessing the comment syntax of
 * an unknown language would hide real writes, and a false negative here is the
 * one thing worse than the false positive.
 */
const JS_LIKE = { line: ['//'], block: [['/*', '*/']], quotes: ["'", '"', '`'], escape: '\\' };
const C_LIKE = { line: ['//'], block: [['/*', '*/']], quotes: ["'", '"'], escape: '\\' };
const HASH_LIKE = { line: ['#'], block: [], quotes: ["'", '"'], escape: '\\' };
/** Strings only, no comments: what an unknown extension gets. */
const STRINGS_ONLY = { line: [], block: [], quotes: ["'", '"', '`'], escape: '\\' };

export const COMMENT_SYNTAX = {
  // `--` and `/* */`; `''`/`""` double to escape; `$tag$…$tag$` bodies are opaque.
  '.sql': { line: ['--'], block: [['/*', '*/']], quotes: ["'", '"'], escape: null, doubling: true, dollarQuote: true },
  '.ts': JS_LIKE, '.tsx': JS_LIKE, '.js': JS_LIKE, '.jsx': JS_LIKE, '.mjs': JS_LIKE, '.cjs': JS_LIKE,
  '.go': { line: ['//'], block: [['/*', '*/']], quotes: ["'", '"', '`'], escape: '\\' },
  '.rs': C_LIKE, '.java': C_LIKE, '.kt': C_LIKE,
  '.php': { line: ['//', '#'], block: [['/*', '*/']], quotes: ["'", '"', '`'], escape: '\\' },
  '.py': { ...HASH_LIKE, triple: true },
  '.rb': HASH_LIKE, '.ex': HASH_LIKE, '.exs': HASH_LIKE,
};

/**
 * One pass over a file, producing both things the scanners need:
 *   `masked`  — same length as the input, comment bodies replaced by spaces
 *               (newlines kept), so line numbers and offsets still line up with
 *               the original and the reported `line:`/`snippet:` stay right.
 *   `strings` — the spans of string literals, which is where a host language
 *               keeps the SQL it actually executes.
 *
 * Comment starts are only recognised outside string literals, so `"http://…"`
 * is not a comment. Every ambiguity resolves toward *not* masking: an
 * unterminated block comment or an unterminated quote is left as ordinary text
 * rather than swallowing the rest of the file, because under-masking only
 * restores today's behaviour while over-masking hides a real write.
 */
export function tokenize(text, ext) {
  const src = String(text ?? '');
  const syn = COMMENT_SYNTAX[String(ext ?? '').toLowerCase()] ?? STRINGS_ONLY;
  const out = src.split('');
  const strings = [];
  const blank = (from, to) => {
    for (let i = from; i < to && i < out.length; i++) if (out[i] !== '\n' && out[i] !== '\r') out[i] = ' ';
  };

  let i = 0;
  outer: while (i < src.length) {
    for (const [open, close] of syn.block) {
      if (src.startsWith(open, i)) {
        const end = src.indexOf(close, i + open.length);
        if (end === -1) return { masked: out.join(''), strings }; // unterminated: leave it
        blank(i, end + close.length);
        i = end + close.length;
        continue outer;
      }
    }
    for (const open of syn.line) {
      if (src.startsWith(open, i)) {
        let end = src.indexOf('\n', i);
        if (end === -1) end = src.length;
        blank(i, end);
        i = end;
        continue outer;
      }
    }
    if (syn.dollarQuote && src[i] === '$') {
      const m = /^\$(?:[A-Za-z_][A-Za-z_0-9]*)?\$/.exec(src.slice(i));
      if (m) {
        const tag = m[0];
        const end = src.indexOf(tag, i + tag.length);
        if (end !== -1) {
          strings.push({ start: i + tag.length, end, content: src.slice(i + tag.length, end) });
          i = end + tag.length;
          continue;
        }
      }
    }
    const quote = syn.quotes.find((qq) => src.startsWith(qq, i));
    if (quote) {
      const triple = syn.triple && src.startsWith(quote.repeat(3), i) ? quote.repeat(3) : null;
      const open = triple ?? quote;
      let j = i + open.length;
      let closed = -1;
      while (j < src.length) {
        if (syn.escape && src[j] === syn.escape) { j += 2; continue; }
        if (src.startsWith(open, j)) {
          // SQL doubles a quote to escape it: '' inside '…' is one character.
          if (syn.doubling && !triple && src.startsWith(open, j + open.length)) { j += open.length * 2; continue; }
          closed = j;
          break;
        }
        j++;
      }
      if (closed === -1) { i += open.length; continue; } // unterminated: ordinary text
      strings.push({ start: i + open.length, end: closed, content: src.slice(i + open.length, closed) });
      i = closed + open.length;
      continue;
    }
    i++;
  }
  return { masked: out.join(''), strings };
}

/** `tokenize`'s masked half, for callers that only want the comments gone. */
export function maskComments(text, ext) {
  return tokenize(text, ext).masked;
}

/**
 * Every `set_config(...)` call naming one of `gucs`, classified by scope.
 *
 * `is_local` is the third argument: `true` = this transaction only (safe),
 * `false` = the rest of the connection (the bug). Anything else — a variable, a
 * ternary — is `unknown`, and reported as a note rather than guessed at.
 */
export function setConfigCalls(text, gucs, original = text) {
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
    // `original` is the unmasked file: masking preserves offsets, so the index
    // is valid in both, and the snippet stays legible.
    out.push({ guc: name, scope, via: 'set_config', line: lineOf(text, m.index), snippet: snippetAt(original, m.index) });
  }
  return out;
}

/**
 * Every `SET <guc>` statement naming one of `gucs`, classified by scope.
 *
 * Restricted to GUCs the policies actually use, which is what keeps this from
 * matching arbitrary `set x.y =` in application code.
 */
export function setStatements(text, gucs, original = text) {
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
        snippet: snippetAt(original, m.index),
      });
    }
  }
  return out;
}

/**
 * Both scanners over one file's text.
 *
 * Pass `ext` and comments are masked first, so prose about the anti-pattern is
 * not read as the anti-pattern. Without `ext` nothing is masked — a caller that
 * does not know the language gets the raw scan, and a commented-out write still
 * matches. `scanSources` always supplies it.
 */
export function scanText(text, gucs, ext) {
  const scanned = ext === undefined ? text : maskComments(text, ext);
  return [...setConfigCalls(scanned, gucs, text), ...setStatements(scanned, gucs, text)];
}

// A reset that is actually *issued* is the whole of a query string
// (`client.query('DISCARD ALL')`) or the whole of a line in a .sql file. Prose
// that merely mentions it — `"...ask ops whether RESET ALL is configured."` —
// is not, and neither is a comment saying the pooler does NOT issue it.
const RESET_ALL = /^\s*(discard\s+all|reset\s+all)\s*;?\s*$/i;
const resetGucRe = (guc) => new RegExp(`^\\s*reset\\s+${guc.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\s*;?\\s*$`, 'i');

/**
 * Where this file issues `DISCARD ALL` / `RESET ALL` / `RESET <guc>`.
 *
 * `DISCARD ALL` on checkin is the other correct fix, and a codebase that does it
 * has closed the hole a different way — so this downgrades the only build-failing
 * verdict in the guard, and therefore has to be evidence, not a substring.
 *
 * Measured before this was tightened: a single file whose entire content was the
 * comment `// TODO(infra): our pgbouncer config does not currently issue DISCARD
 * ALL on release.` flipped a proven session-scoped tenant-GUC leak from
 * `ok:false, 1 violation` to `ok:true, 0 violations`. A comment stating the
 * opposite of what it was read as suppressed the finding.
 *
 * Returns the sites, not a boolean, so the note can name file:line and the
 * maintainer can check whether the reset really runs on connection release —
 * which is the part no scanner can decide.
 */
export function findConnectionResets(text, gucs, ext) {
  const src = String(text ?? '');
  const { masked, strings } = tokenize(src, ext);
  const found = [];
  const pairs = (gucs ?? []).map((g) => [g, resetGucRe(g)]);
  const push = (guc, index, statement) => found.push({ guc, line: lineOf(src, index), statement: statement.trim().slice(0, 120) });

  let offset = 0;
  for (const rawLine of masked.split('\n')) {
    if (RESET_ALL.test(rawLine)) push('*', offset, rawLine);
    else for (const [g, re] of pairs) if (re.test(rawLine)) push(g, offset, rawLine);
    offset += rawLine.length + 1;
  }
  for (const s of strings) {
    if (RESET_ALL.test(s.content)) push('*', s.start, s.content);
    else for (const [g, re] of pairs) if (re.test(s.content)) push(g, s.start, s.content);
  }
  return found;
}

/** Boolean form of `findConnectionResets`, kept for callers that only ask yes/no. */
export function resetsConnectionState(text, guc, ext) {
  return findConnectionResets(text, guc ? [guc] : [], ext).length > 0;
}

/**
 * The verdict for one GUC.
 *
 * A session-scoped write to a GUC that policies authorize from is the finding,
 * and it is conclusive: both halves are observed facts, not inferences. Every
 * other outcome is a note, because it turns on something not observed here.
 */
export function classifyGuc({ guc, policies = [], sets = [], resets = false, scannedFiles = 0 }) {
  const where = policies.map((p) => `${p.id} (policy "${p.policy}"${p.via ? `, via ${p.via}` : ''})`);
  const used = policies.length === 1 ? where[0] : `${policies.length} policies, incl. ${where[0]}`;

  const session = sets.filter((s) => s.scope === 'session');
  const unknown = sets.filter((s) => s.scope === 'unknown');
  const local = sets.filter((s) => s.scope === 'local');

  // `resets` is a list of sites; `true` is still accepted from older callers.
  const resetSites = Array.isArray(resets) ? resets : resets ? [{}] : [];

  if (session.length > 0) {
    const at = session.map((s) => `${s.file}:${s.line}`).join(', ');
    if (resetSites.length > 0) {
      const resetAt = resetSites.filter((r) => r.file).map((r) => `${r.file}:${r.line} (${r.statement})`).join(', ');
      return {
        status: 'note',
        message:
          `"${guc}" authorizes ${used} and is set for the whole CONNECTION at ${at}, ` +
          `but this codebase also issues DISCARD ALL / RESET${resetAt ? ` at ${resetAt}` : ''} — which closes the hole ` +
          `only if it runs on every connection release. Confirm that it does; the scope of the write itself is still wrong.`,
      };
    }
    return {
      status: 'leak',
      kind: 'session-scoped-tenant-guc',
      message:
        `"${guc}" authorizes ${used}, and is set for the whole CONNECTION (not the transaction) at ${at}. ` +
        `On a pooled connection the next request inherits the previous request's tenant and reads their rows ` +
        `— the policy works exactly as designed. Every single-request test passes; the leak lives between requests.`,
      // Both forms are transaction-scoped, and neither works outside an explicit
      // transaction. Measured on the flagged shape: with `set_config('app.tenant',
      // 'A', false)` as a standalone statement the next query returned 1 row;
      // changing only the third argument to true returned 0 rows and
      // current_setting was "" — the identity was gone before the query ran. The
      // same statement inside BEGIN returned the row. The one-character change is
      // the one a reader will copy, so the caveat has to govern it too.
      fix:
        `Make the write transaction-scoped AND run it in the request's transaction:\n` +
        `        BEGIN;  select set_config('${guc}', $1, true);  -- …the request's queries…  COMMIT;\n` +
        `      or SET LOCAL ${guc} = $1 in that same transaction.\n` +
        `      The third argument to set_config is is_local, and true means "this transaction", exactly as ` +
        `SET LOCAL does — so flipping false to true WITHOUT opening a transaction leaves "${guc}" unset by the ` +
        `time the next statement runs and your policies then match nothing. The implicit transaction ends at the semicolon.\n` +
        `      Alternatively issue DISCARD ALL when the connection returns to the pool. tenant-guard recognises that ` +
        `only when the statement is the whole of a query string (client.query('DISCARD ALL')) or a whole line in a .sql ` +
        `file; if yours is issued some other way it will not have been seen here.\n` +
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

/** The extension of a path, lowercased, or '' when it has none. */
const extOf = (p) => {
  const dot = p.lastIndexOf('.');
  const slash = Math.max(p.lastIndexOf('/'), p.lastIndexOf('\\'));
  return dot > slash ? p.slice(dot).toLowerCase() : '';
};

/**
 * Scan the tree for writes to any of `gucs`, and for resets that undo them.
 *
 * `resets` is a Map keyed by GUC with `'*'` for `DISCARD ALL` / `RESET ALL`,
 * carrying the sites. It used to be one boolean ORed across every file, which
 * meant any file mentioning the words anywhere silenced the finding for every
 * GUC. `RESET <guc>` also only closes the hole for that one GUC, which the
 * single boolean could not express — and the parameter that would have carried
 * it was never passed at the only production call site.
 */
export function scanSources(cwd, gucs, cfg) {
  const files = collectSourceFiles(cwd, cfg);
  const sets = [];
  const resets = new Map();
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
    const ext = extOf(abs);
    for (const hit of scanText(text, gucs, ext)) sets.push({ ...hit, file: rel });
    for (const r of findConnectionResets(text, gucs, ext)) {
      if (!resets.has(r.guc)) resets.set(r.guc, []);
      resets.get(r.guc).push({ file: rel, line: r.line, statement: r.statement });
    }
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
  const policyRows = await q(spec.text, spec.values);
  const byGuc = gucsFromPolicies(policyRows);

  // A policy that reads its GUC through a helper — `org = current_tenant()` —
  // shows nothing in the deparsed qual, so the deparsed expression alone is not
  // evidence of absence. Follow the policy→function edges before deciding.
  const viaFns = await resolveGucsThroughFunctions(q, cfg, byGuc);
  if (viaFns.error) {
    notes.push({
      where: '(functions)',
      message:
        `policies that read their GUC through a helper function could not be resolved (${viaFns.error}), ` +
        `so only the deparsed policy expressions were checked.`,
    });
  }
  if (viaFns.unreadable.length > 0) {
    notes.push({
      where: '(functions)',
      message:
        `${viaFns.unreadable.length} function(s) called by a policy have no readable body — ` +
        `${viaFns.unreadable.join(', ')}. Whether they read a custom GUC was not determined.`,
    });
  }

  if (byGuc.size === 0) {
    // The common Supabase case: policies read auth.uid()/auth.jwt(), which
    // PostgREST sets per transaction from a verified token. Nothing to bleed.
    // Stated as what was measured, not as proof of absence: dynamic SQL inside a
    // plpgsql body, or a body this connection cannot read, would not show here.
    const unread = viaFns.unreadable.length ? `; ${viaFns.unreadable.length} function body(ies) could not be read (${viaFns.unreadable.join(', ')})` : '';
    const failed = viaFns.error ? `; the helper-function walk failed (${viaFns.error})` : '';
    return OK({
      skipped: true,
      reason:
        `no policy authorizes from a custom GUC — checked ${policyRows?.length ?? 0} policy expression(s) and ` +
        `${viaFns.resolved} body(ies) of the functions they call for a current_setting() literal${unread}${failed}`,
      summary: 'skipped — no custom-GUC policies',
      notes,
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
      // DISCARD ALL / RESET ALL closes it for every GUC; RESET <guc> for one.
      resets: [...(resets.get('*') ?? []), ...(resets.get(guc) ?? [])],
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
