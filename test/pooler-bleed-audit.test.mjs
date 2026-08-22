/**
 * Four audit findings against pooler-bleed, each reproduced against a real
 * database before it was fixed and pinned here.
 *
 *   1. A policy reading its GUC through a helper (`org = current_tenant()`) put
 *      no `current_setting` in the deparsed qual, so the guard returned
 *      `skipped: true` — "no policy authorizes from a custom GUC — nothing that
 *      can outlive a request" — on a schema where the bleed was live and
 *      provable. Measured: request 1 set the GUC session-wide and read row A;
 *      request 2 set nothing and read row A too.
 *   2. Any file mentioning "DISCARD ALL" anywhere — including a comment saying
 *      the pooler does NOT issue it — flipped a proven leak from `ok:false, 1
 *      violation` to `ok:true, 0 violations`.
 *   3. The fix told the reader to change `false` to `true` in set_config, and
 *      attached the "you must open a transaction" caveat only to the SET LOCAL
 *      alternative. Measured: the one-character change alone left the policy
 *      matching 0 rows.
 *   4. The scanners ran over raw file text, so a comment warning developers not
 *      to write `SET app.tenant = …` was itself reported as writing it.
 *
 * Every test here fails against the pre-fix guard.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';

import {
  check,
  maskComments,
  tokenize,
  findConnectionResets,
  bodyIsReadable,
  calledFunctionNames,
  scanText,
} from '../src/guards/pooler-bleed.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('pooler-bleed audit (pglite not installed — skipped)', { skip: true }, () => {});
}

/** A throwaway repo: { 'src/db/client.ts': '…' } */
function repo(files) {
  const dir = mkdtempSync(join(tmpdir(), 'tg-pb-audit-'));
  for (const [rel, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), content);
  }
  return dir;
}
const SESSION_WRITE = `await c.query("select set_config('app.tenant', $1, false)", [t]);\n`;
const LOCAL_WRITE = `await c.query('begin');\nawait c.query("select set_config('app.tenant', $1, true)", [t]);\n`;

async function db(sql) {
  const d = new PGlite();
  await d.exec(sql);
  return { db: d, query: (t, v) => d.query(t, Array.isArray(v) && v.length ? v : undefined) };
}

// ── 4. comments are not code ─────────────────────────────────────────
// These are pure and run without a database.

test('maskComments: per-language, because one union would hide real writes', () => {
  // SQL: `--` is a comment.
  assert.doesNotMatch(maskComments(`-- SET app.tenant = 'x'\nselect 1;`, '.sql'), /app\.tenant/);
  // JavaScript: `--` is decrement. Masking to end of line here would hide the
  // live set_config sitting after it.
  assert.match(maskComments(`for(;;i--) q("select set_config('app.tenant',$1,false)");`, '.ts'), /set_config/);
  // JavaScript: `//` is a comment.
  assert.doesNotMatch(maskComments(`// SET app.tenant = 'x'\nq(1);`, '.ts'), /app\.tenant/);
  // A `//` inside a string is a URL, not a comment start.
  assert.match(maskComments(`const u = "http://x"; q("set_config('app.tenant',$1,false)");`, '.ts'), /set_config/);
  // An extension we do not know masks nothing at all.
  assert.match(maskComments(`-- SET app.tenant = 'x'`, '.unknown'), /app\.tenant/);
});

test('maskComments: same length as the input, so line numbers still line up', () => {
  const src = `line one\n-- SET app.tenant = 'x'\nline three\n`;
  const masked = maskComments(src, '.sql');
  assert.equal(masked.length, src.length);
  assert.equal(masked.split('\n').length, src.split('\n').length);
});

test('maskComments: an unterminated block comment is left alone, not swallowed', () => {
  // Over-masking hides a live write; under-masking only restores the old scan.
  const src = `/* oops\nq("select set_config('app.tenant',$1,false)");`;
  assert.match(maskComments(src, '.ts'), /set_config/);
});

test('scanText: a commented-out write is not a write — both scanners', () => {
  const text = `-- await c.query("select set_config('app.tenant', $1, false)")\n/* old: SET SESSION app.tenant = 'demo'; */`;
  assert.equal(scanText(text, ['app.tenant'], '.sql').length, 0);
  // Without an extension the caller has told us nothing about the language, and
  // the raw scan is what they get — stated, not silently guessed at.
  assert.equal(scanText(text, ['app.tenant']).length, 2);
});

if (PGlite) {
  const GUC_SCHEMA = `
    create table docs (id serial primary key, org text not null);
    alter table docs enable row level security;
    create policy p on docs using (org = current_setting('app.tenant', true));
  `;

  test('FIXTURE A: a .sql migration whose only mention of the GUC is prose does not fail the build', async () => {
    const { query } = await db(GUC_SCHEMA);
    const dir = repo({
      'supabase/migrations/001_rls.sql':
        `-- The application layer must SET LOCAL app.tenant = '<uuid>' at the start of every request transaction.\n` +
        `-- Never SET app.tenant = ... session-wide: on a pooled connection it outlives the request.\n` +
        `alter table public.docs enable row level security;\n`,
    });
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['supabase/migrations'] } });
      assert.equal(res.violations.length, 0, JSON.stringify(res.violations, null, 2));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('FIXTURE B: code that does the right thing while documenting the anti-pattern passes', async () => {
    const { query } = await db(GUC_SCHEMA);
    const dir = repo({
      'src/db/client.ts':
        '// Do NOT use `SET app.tenant = $1` here — that is connection-scoped and bleeds\n' +
        '// across pooled requests. Use the transaction-local form below.\n' +
        LOCAL_WRITE,
    });
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.ok, true, JSON.stringify(res.violations, null, 2));
      assert.equal(res.violations.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a live session-scoped write next to a commented-out one is reported at the LIVE line only', async () => {
    const { query } = await db(GUC_SCHEMA);
    const dir = repo({ 'src/db/client.ts': `// legacy: SET app.tenant = $1\n${SESSION_WRITE}` });
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.violations.length, 1);
      assert.match(res.violations[0].message, /src\/db\/client\.ts:2/);
      assert.doesNotMatch(res.violations[0].message, /client\.ts:1/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // ── 1. the GUC behind a helper function ────────────────────────────

  test('CATCHES a policy that reads its tenant GUC through a helper function', async () => {
    // Verified on this schema: as a non-owner role, request 1 ran
    // set_config('app.tenant','A',false) and read [{id:1,org:'A'}]; request 2 set
    // nothing and read [{id:1,org:'A'}] too. The old guard returned skipped:true.
    const { query } = await db(`
      create table docs (id serial primary key, org text not null);
      create function current_tenant() returns text language sql stable
        as $$ select current_setting('app.tenant', true) $$;
      alter table docs enable row level security;
      create policy tenant_isolation on docs for select using (org = current_tenant());
    `);
    const dir = repo({ 'src/db/client.ts': SESSION_WRITE });
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.skipped, undefined);
      assert.equal(res.ok, false, JSON.stringify(res, null, 2));
      assert.equal(res.violations.length, 1);
      assert.equal(res.violations[0].where, 'app.tenant');
      // the helper is named, so the reader can find the indirection
      assert.match(res.violations[0].message, /via public\.current_tenant\(\)/);
      assert.match(res.violations[0].message, /policy "tenant_isolation"/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('follows a second hop: helper calling helper', async () => {
    const { query } = await db(`
      create table docs (id serial primary key, org text not null);
      create function tenant_inner() returns text language sql stable
        as $$ select current_setting('app.tenant', true) $$;
      create function current_tenant() returns text language sql stable
        as $$ select tenant_inner() $$;
      alter table docs enable row level security;
      create policy tenant_isolation on docs using (org = current_tenant());
    `);
    const dir = repo({ 'src/db/client.ts': SESSION_WRITE });
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.violations.length, 1, JSON.stringify(res, null, 2));
      assert.match(res.violations[0].message, /public\.current_tenant\(\) → public\.tenant_inner\(\)/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('CALIBRATION: the same helper schema with a transaction-scoped write is clean', async () => {
    // Widening what the guard looks at must not widen what it fails on.
    const { query } = await db(`
      create table docs (id serial primary key, org text not null);
      create function current_tenant() returns text language sql stable
        as $$ select current_setting('app.tenant', true) $$;
      alter table docs enable row level security;
      create policy tenant_isolation on docs using (org = current_tenant());
    `);
    const dir = repo({ 'src/db/client.ts': LOCAL_WRITE });
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.ok, true, JSON.stringify(res.violations, null, 2));
      assert.equal(res.violations.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('CALIBRATION: a helper that reads request.jwt.* is still nothing to bleed', async () => {
    // PostgREST sets those per transaction from a verified token. Following the
    // helper must not turn every Supabase project into a finding.
    const { query } = await db(`
      create table docs (id serial primary key, org text not null);
      create function my_org() returns text language sql stable
        as $$ select current_setting('request.jwt.claims', true) $$;
      alter table docs enable row level security;
      create policy p on docs using (org = my_org());
    `);
    const dir = repo({ 'src/db/client.ts': SESSION_WRITE });
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.skipped, true);
      assert.equal(res.violations.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('the skip states what it checked instead of asserting nothing can outlive a request', async () => {
    const { query } = await db(`
      create table docs (id serial primary key, org text not null);
      create function my_org() returns text language sql stable
        as $$ select current_setting('request.jwt.claims', true) $$;
      alter table docs enable row level security;
      create policy p on docs using (org = my_org());
    `);
    const res = await check({ query, cwd: process.cwd() });
    assert.equal(res.skipped, true);
    assert.doesNotMatch(res.reason, /nothing that can outlive a request/);
    assert.match(res.reason, /checked 1 policy expression\(s\) and 1 body\(ies\)/);
  });

  // ── 2. the reset downgrade needs evidence ──────────────────────────

  test('a comment saying the pooler does NOT issue DISCARD ALL no longer silences the finding', async () => {
    const { query } = await db(GUC_SCHEMA);
    const dir = repo({
      'src/db/client.ts': SESSION_WRITE,
      'src/db/notes.ts': `// TODO(infra): our pgbouncer config does not currently issue DISCARD ALL on release.\n`,
      'src/db/help.ts': `export const HELP = "...ask ops whether RESET ALL is configured.";\n`,
    });
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.ok, false, JSON.stringify(res, null, 2));
      assert.equal(res.violations.length, 1);
      assert.equal(res.violations[0].kind, 'session-scoped-tenant-guc');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a reset that is actually ISSUED still downgrades — and the note names the site', async () => {
    const { query } = await db(GUC_SCHEMA);
    const dir = repo({
      'src/db/client.ts': `${SESSION_WRITE}pool.on('release', (c) => c.query('DISCARD ALL'));\n`,
    });
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.violations.length, 0);
      const note = res.notes.find((n) => n.where === 'app.tenant');
      assert.ok(note, JSON.stringify(res.notes, null, 2));
      assert.match(note.message, /DISCARD ALL/);
      assert.match(note.message, /src\/db\/client\.ts:2 \(DISCARD ALL\)/); // the evidence, checkable
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('RESET <guc> is live at the production call site, and is per-GUC', async () => {
    // The guc parameter was only ever passed by a test; scanSources never passed
    // it, so this branch was dead as invoked.
    const { query } = await db(GUC_SCHEMA);
    const hit = repo({ 'src/db/client.ts': `${SESSION_WRITE}await c.query('RESET app.tenant');\n` });
    const miss = repo({ 'src/db/client.ts': `${SESSION_WRITE}await c.query('RESET app.locale');\n` });
    try {
      const a = await check({ query, cwd: hit, config: { sourceDirs: ['src'] } });
      assert.equal(a.violations.length, 0, JSON.stringify(a.violations, null, 2));
      assert.match(a.notes.find((n) => n.where === 'app.tenant').message, /RESET app\.tenant/);

      const b = await check({ query, cwd: miss, config: { sourceDirs: ['src'] } });
      assert.equal(b.violations.length, 1); // resetting a different GUC closes nothing
    } finally {
      rmSync(hit, { recursive: true, force: true });
      rmSync(miss, { recursive: true, force: true });
    }
  });

  // ── 3. the advice has to work when applied literally ───────────────

  test('the fix works when pasted: BEGIN + set_config(…, true) returns rows; without BEGIN it returns none', async () => {
    const { db: d, query } = await db(GUC_SCHEMA);
    const dir = repo({ 'src/db/client.ts': SESSION_WRITE });
    let fix;
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      fix = res.violations[0].fix;
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }

    // The recommended sequence, taken out of the printed advice rather than
    // retyped, so the test breaks if the advice drifts.
    const m = /BEGIN;\s*select set_config\('([^']+)', \$1, true\)/.exec(fix);
    assert.ok(m, `the fix must lead with an explicit transaction, got:\n${fix}`);
    assert.equal(m[1], 'app.tenant');

    await d.exec(`insert into docs (org) values ('A'), ('B');`);
    // A superuser bypasses RLS even with FORCE — measured: 2 rows either way —
    // so the arms below have to run as an ordinary role.
    await d.exec(`create role tester nologin; grant select on docs to tester; set role tester;`);

    // applied as written
    await d.query('begin');
    await d.query(`select set_config('${m[1]}', 'A', true)`);
    const inside = await d.query('select id, org from docs');
    await d.query('commit');
    assert.equal(inside.rows.length, 1, 'the advice, applied as written, must still return the tenant rows');

    // the one-character change on its own — what the old wording invited
    await d.query(`select set_config('${m[1]}', 'A', true)`);
    const outside = await d.query('select id, org from docs');
    assert.equal(outside.rows.length, 0, 'measured: is_local=true outside a transaction is gone by the next statement');

    // and the advice says so, on the set_config branch and not only on SET LOCAL
    assert.match(fix, /flipping false to true WITHOUT opening a transaction/i);
  });
}

// ── pure helpers the fixes introduced ────────────────────────────────

test('findConnectionResets: the statement, not the words', () => {
  const guc = ['app.tenant'];
  // prose and comments are not a reset
  assert.deepEqual(findConnectionResets('// we never DISCARD ALL on release', guc, '.ts'), []);
  assert.deepEqual(findConnectionResets('const H = "ask ops whether RESET ALL is configured";', guc, '.ts'), []);
  assert.deepEqual(findConnectionResets('-- DISCARD ALL is not issued here', guc, '.sql'), []);
  // an issued statement is
  assert.equal(findConnectionResets(`c.query('DISCARD ALL')`, guc, '.ts').length, 1);
  assert.equal(findConnectionResets('discard all;', guc, '.sql').length, 1);
  assert.equal(findConnectionResets(`c.query('RESET app.tenant')`, guc, '.ts')[0].guc, 'app.tenant');
  assert.equal(findConnectionResets(`c.query('DISCARD ALL')`, guc, '.ts')[0].guc, '*');
});

test('tokenize: string spans are where a host language keeps its SQL', () => {
  const { strings } = tokenize(`await c.query("DISCARD ALL");`, '.ts');
  assert.deepEqual(strings.map((s) => s.content), ['DISCARD ALL']);
  // dollar-quoted bodies in .sql are opaque, and their contents survive
  const sql = tokenize(`create function f() returns text as $$ select current_setting('app.tenant') $$ language sql;`, '.sql');
  assert.match(sql.masked, /current_setting/);
});

test('bodyIsReadable: a C or internal function stores a symbol name, not SQL', () => {
  assert.equal(bodyIsReadable({ lang: 'sql', body: 'select 1' }), true);
  assert.equal(bodyIsReadable({ lang: 'plpgsql', body: 'begin end' }), true);
  assert.equal(bodyIsReadable({ lang: 'c', body: 'pg_stat_get_numscans' }), false);
  assert.equal(bodyIsReadable({ lang: 'internal', body: 'x' }), false);
  assert.equal(bodyIsReadable({ lang: 'sql', body: null }), false);
});

test('calledFunctionNames: the next hop, without the SQL keywords', () => {
  const names = calledFunctionNames(`select coalesce(current_setting('app.t', true), my_org())`);
  assert.deepEqual(names, ['my_org']);
});
