/**
 * pooler-bleed pure-logic tests: the source scanners and the verdict.
 *
 * The scanners carry the weight here. This guard fails a build on the strength
 * of a regex over somebody's source, so the interesting cases are the ones it
 * must NOT match — a safe `SET LOCAL`, a `set_config(…, true)`, a GUC no policy
 * uses — as much as the ones it must.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  policyGucsSql,
  gucsFromPolicies,
  splitArgs,
  literalArg,
  setConfigCalls,
  setStatements,
  scanText,
  resetsConnectionState,
  classifyGuc,
} from '../src/guards/pooler-bleed.mjs';

// ── which GUCs matter ────────────────────────────────────────────────

test('policyGucsSql: reads the policy expressions, parameterised by schema', () => {
  const { text, values } = policyGucsSql(['public']);
  assert.match(text, /pg_policies/);
  assert.match(text, /qual/);
  assert.match(text, /with_check/);
  assert.deepEqual(values, [['public']]);
});

test('gucsFromPolicies: collects custom GUCs from qual AND with_check', () => {
  const byGuc = gucsFromPolicies([
    { schema: 'public', table: 'invoices', policy: 'iso', cmd: 'ALL', qual: `(org_id = current_setting('app.tenant'))`, with_check: null },
    { schema: 'public', table: 'notes', policy: 'w', cmd: 'INSERT', qual: null, with_check: `(org_id = current_setting('app.tenant'))` },
  ]);
  assert.deepEqual([...byGuc.keys()], ['app.tenant']);
  assert.equal(byGuc.get('app.tenant').length, 2);
  assert.equal(byGuc.get('app.tenant')[0].id, 'public.invoices');
});

test('gucsFromPolicies: EXCLUDES request.jwt.* — PostgREST sets those per transaction from a verified token', () => {
  const byGuc = gucsFromPolicies([
    { schema: 'public', table: 't', policy: 'p', cmd: 'ALL', qual: `(org_id = (current_setting('request.jwt.claims', true)::json ->> 'org_id'))`, with_check: null },
  ]);
  assert.equal(byGuc.size, 0); // nothing the app leaves lying around
});

// ── argument parsing ─────────────────────────────────────────────────

test('splitArgs: depth- and quote-aware, so a value containing commas survives', () => {
  const s = `set_config('app.t', coalesce(a, b), false)`;
  const args = splitArgs(s, s.indexOf('('));
  assert.equal(args.length, 3);
  assert.equal(args[1].trim(), 'coalesce(a, b)');
  assert.equal(args[2].trim(), 'false');
});

test('splitArgs: a comma or paren INSIDE a string is not a separator', () => {
  const s = `f('a,b(', x, true)`;
  const args = splitArgs(s, s.indexOf('('));
  assert.equal(args.length, 3);
  assert.equal(args[0].trim(), `'a,b('`);
});

test('splitArgs: returns null when the parens never balance', () => {
  assert.equal(splitArgs('f(a, b', 1), null);
});

test('literalArg: only a plain literal, in any of the three quote styles', () => {
  assert.equal(literalArg(`'app.tenant'`), 'app.tenant');
  assert.equal(literalArg(`"app.tenant"`), 'app.tenant');
  assert.equal(literalArg('`app.tenant`'), 'app.tenant');
  assert.equal(literalArg('someVariable'), null); // not a literal — unknowable
});

// ── set_config ───────────────────────────────────────────────────────

const GUCS = ['app.tenant'];

test('set_config(…, false) is SESSION-scoped — the bug', () => {
  const hits = setConfigCalls(`await db.query("select set_config('app.tenant', $1, false)", [orgId]);`, GUCS);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].scope, 'session');
  assert.equal(hits[0].guc, 'app.tenant');
});

test('set_config(…, true) is TRANSACTION-scoped — correct, and must not be flagged', () => {
  const hits = setConfigCalls(`select set_config('app.tenant', $1, true)`, GUCS);
  assert.equal(hits[0].scope, 'local');
});

test('a non-literal is_local is UNKNOWN, not guessed at', () => {
  const hits = setConfigCalls(`select set_config('app.tenant', $1, ${'${isLocal}'})`, GUCS);
  assert.equal(hits[0].scope, 'unknown');
});

test('set_config on a GUC no policy uses is ignored', () => {
  assert.deepEqual(setConfigCalls(`select set_config('app.locale', 'en', false)`, GUCS), []);
});

test('set_config: case and whitespace insensitive, and reports the line', () => {
  const text = `line one\nline two\n  SET_CONFIG (  'app.tenant' , $1 , FALSE )\n`;
  const hits = setConfigCalls(text, GUCS);
  assert.equal(hits.length, 1);
  assert.equal(hits[0].scope, 'session');
  assert.equal(hits[0].line, 3);
});

// ── SET statements ───────────────────────────────────────────────────

test('SET LOCAL is safe; bare SET and SET SESSION are not', () => {
  assert.equal(setStatements(`SET LOCAL app.tenant = 'x'`, GUCS)[0].scope, 'local');
  assert.equal(setStatements(`SET app.tenant = 'x'`, GUCS)[0].scope, 'session');
  assert.equal(setStatements(`SET SESSION app.tenant TO 'x'`, GUCS)[0].scope, 'session');
});

test('SET matching is restricted to GUCs the policies use — that is what keeps it quiet', () => {
  // Application code is full of `set x.y =`. Without the GUC filter this guard
  // would be unusable on any real repository.
  const noise = `state.set config.value = 1;\nSET app.locale = 'en';\nobj.set(a.b, c);`;
  assert.deepEqual(setStatements(noise, GUCS), []);
});

test('scanText: both scanners, over one file', () => {
  const text = `SET app.tenant = 'a';\nselect set_config('app.tenant', $1, true);`;
  const hits = scanText(text, GUCS);
  assert.equal(hits.length, 2);
  assert.deepEqual(hits.map((h) => h.scope).sort(), ['local', 'session']);
});

// ── mitigation ───────────────────────────────────────────────────────

test('resetsConnectionState: DISCARD ALL / RESET ALL / RESET <guc>', () => {
  assert.equal(resetsConnectionState('await c.query("DISCARD ALL")'), true);
  assert.equal(resetsConnectionState('reset all;'), true);
  assert.equal(resetsConnectionState('RESET app.tenant', 'app.tenant'), true);
  assert.equal(resetsConnectionState('nothing here', 'app.tenant'), false);
});

// ── the verdict ──────────────────────────────────────────────────────

const POLICIES = [{ id: 'public.invoices', policy: 'tenant_isolation', cmd: 'ALL' }];

test('LEAK: a policy GUC written session-wide — both halves observed', () => {
  const v = classifyGuc({
    guc: 'app.tenant',
    policies: POLICIES,
    sets: [{ guc: 'app.tenant', scope: 'session', file: 'src/db.ts', line: 42, via: 'set_config' }],
    scannedFiles: 10,
  });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /public\.invoices \(policy "tenant_isolation"\)/);
  assert.match(v.message, /src\/db\.ts:42/);
  assert.match(v.message, /between requests/);
  assert.match(v.fix, /is_local/);
  assert.match(v.fix, /SET LOCAL/);
  assert.match(v.fix, /poolerBleed\.allowlist/);
});

test('OK: the same GUC written transaction-locally is proven safe, not merely unflagged', () => {
  const v = classifyGuc({
    guc: 'app.tenant',
    policies: POLICIES,
    sets: [{ guc: 'app.tenant', scope: 'local', file: 'src/db.ts', line: 42 }],
    scannedFiles: 10,
  });
  assert.equal(v.status, 'ok');
});

test('NOTE not LEAK: DISCARD ALL present — the hole may already be closed the other way', () => {
  const v = classifyGuc({
    guc: 'app.tenant',
    policies: POLICIES,
    sets: [{ guc: 'app.tenant', scope: 'session', file: 'src/db.ts', line: 42 }],
    resets: true,
    scannedFiles: 10,
  });
  assert.equal(v.status, 'note');
  assert.match(v.message, /DISCARD ALL/);
});

test('NOTE: an unreadable is_local argument is reported, never assumed safe', () => {
  const v = classifyGuc({
    guc: 'app.tenant',
    policies: POLICIES,
    sets: [{ guc: 'app.tenant', scope: 'unknown', file: 'src/db.ts', line: 42 }],
    scannedFiles: 10,
  });
  assert.equal(v.status, 'note');
  assert.match(v.message, /could not be read/);
});

test('NOTE: policies depend on the GUC but nothing in the repo sets it', () => {
  const v = classifyGuc({ guc: 'app.tenant', policies: POLICIES, sets: [], scannedFiles: 25 });
  assert.equal(v.status, 'note');
  assert.match(v.message, /25 scanned file/);
  assert.match(v.message, /ORM/);
});

test('NOTE: nothing scanned at all says so, rather than passing', () => {
  const v = classifyGuc({ guc: 'app.tenant', policies: POLICIES, sets: [], scannedFiles: 0 });
  assert.equal(v.status, 'note');
  assert.match(v.message, /no source files were scanned/);
  assert.match(v.message, /sourceDirs/);
});

test('the message names every policy when more than one depends on the GUC', () => {
  const v = classifyGuc({
    guc: 'app.tenant',
    policies: [...POLICIES, { id: 'public.notes', policy: 'p2', cmd: 'ALL' }],
    sets: [{ guc: 'app.tenant', scope: 'session', file: 'a.ts', line: 1 }],
    scannedFiles: 3,
  });
  assert.match(v.message, /2 policies/);
});
