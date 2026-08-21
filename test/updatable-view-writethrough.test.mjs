/**
 * The MonkeyTravel critical bug, as a static check.
 *
 * A view created to expose safe profile columns was auto-updatable and running
 * as its owner, and Supabase's default privileges had quietly granted writes on
 * it. With the public anon key: `DELETE /rest/v1/public_profiles` wiped users.
 *
 * The author wrote `GRANT SELECT`. The word DELETE appears nowhere in the
 * migration. Every ingredient is nonetheless in the text, which is why this is a
 * static guard.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import {
  extractViews,
  autoUpdatableShape,
  netWriteGrants,
  detectDefaultWriteGrants,
  classifyView,
  run,
} from '../src/guards/updatable-view-writethrough.mjs';

/** The reported bug, reduced to its migration. */
const REPORTED = `
  CREATE VIEW public.public_profiles WITH (security_invoker = false) AS
    SELECT id, display_name, avatar_url, username FROM public.users;
  GRANT SELECT ON public.public_profiles TO anon, authenticated;
`;

function withMigrations(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'tg-uv-'));
  try {
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

// ── parsing ──────────────────────────────────────────────────────────

test('extractViews: name, security_invoker and shape', () => {
  const [v] = extractViews(REPORTED);
  assert.equal(v.name, 'public_profiles');
  assert.equal(v.securityInvoker, false);
  assert.equal(v.autoUpdatable, true);
  assert.equal(v.baseTable, 'users');
});

test('security_invoker = true is recognised in any spelling', () => {
  for (const opt of ['security_invoker = true', 'security_invoker=on', 'security_invoker = TRUE']) {
    const [v] = extractViews(`CREATE VIEW v WITH (${opt}) AS SELECT a FROM t;`);
    assert.equal(v.securityInvoker, true, opt);
  }
});

test('autoUpdatableShape: the constructs Postgres makes read-only', () => {
  assert.equal(autoUpdatableShape('SELECT a FROM t').autoUpdatable, true);
  assert.equal(autoUpdatableShape('SELECT DISTINCT a FROM t').autoUpdatable, false);
  assert.equal(autoUpdatableShape('SELECT a, count(*) FROM t GROUP BY a').autoUpdatable, false);
  assert.equal(autoUpdatableShape('SELECT a FROM t JOIN u ON t.id = u.id').autoUpdatable, false);
  assert.equal(autoUpdatableShape('SELECT a FROM t, u').autoUpdatable, false);
  assert.equal(autoUpdatableShape('SELECT a FROM t UNION SELECT a FROM u').autoUpdatable, false);
  assert.equal(autoUpdatableShape('SELECT a, row_number() OVER () FROM t').autoUpdatable, false);
  assert.equal(autoUpdatableShape('SELECT a FROM t LIMIT 10').autoUpdatable, false);
});

test('autoUpdatableShape: a computed column does NOT save you — DELETE still passes through', () => {
  const shape = autoUpdatableShape("SELECT id, upper(name) AS name FROM users");
  assert.equal(shape.autoUpdatable, true);
  assert.equal(shape.baseTable, 'users');
});

test('a WHERE clause does not make a view read-only', () => {
  assert.equal(autoUpdatableShape('SELECT a FROM t WHERE is_public').autoUpdatable, true);
});

// ── grants ───────────────────────────────────────────────────────────

test('netWriteGrants: GRANT adds, REVOKE takes away, in migration order', () => {
  const files = [
    { name: '001_a.sql', sql: 'GRANT ALL ON public.v TO anon;' },
    { name: '002_b.sql', sql: 'REVOKE INSERT, UPDATE, DELETE ON public.v FROM anon;' },
  ];
  const state = netWriteGrants(files, ['anon', 'authenticated']);
  assert.deepEqual([...state.get('v').granted], []);
  assert.deepEqual([...state.get('v').revoked].sort(), ['delete', 'insert', 'update']);
});

test('netWriteGrants: SELECT-only grants are not write grants', () => {
  const state = netWriteGrants([{ name: '001.sql', sql: 'GRANT SELECT ON v TO anon;' }], ['anon']);
  assert.equal(state.has('v'), false);
});

test('netWriteGrants: a grant to PUBLIC counts, since the exposed roles inherit it', () => {
  const state = netWriteGrants([{ name: '001.sql', sql: 'GRANT UPDATE ON v TO PUBLIC;' }], ['anon']);
  assert.deepEqual([...state.get('v').granted], ['update']);
});

test('detectDefaultWriteGrants: an explicit ALTER DEFAULT PRIVILEGES is the strongest evidence', () => {
  const d = detectDefaultWriteGrants(
    [{ name: '001.sql', sql: 'ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO anon;' }],
    ['anon', 'authenticated'],
  );
  assert.equal(d.assume, true);
  assert.match(d.evidence, /ALTER DEFAULT PRIVILEGES/);
});

test('detectDefaultWriteGrants: a Supabase-shaped project is presumed, plain Postgres is not', () => {
  assert.equal(detectDefaultWriteGrants([{ name: '1.sql', sql: 'GRANT SELECT ON v TO anon;' }], ['anon']).assume, true);
  assert.equal(detectDefaultWriteGrants([{ name: '1.sql', sql: 'CREATE TABLE t (id int);' }], ['anon']).assume, false);
});

// ── the verdict ──────────────────────────────────────────────────────

const VIEW = { name: 'public_profiles', securityInvoker: false, autoUpdatable: true, baseTable: 'users', isMaterialized: false };
const BASE = { assumeDefaults: true, evidence: 'this looks like a Supabase project', exposedRoles: ['anon', 'authenticated'] };

test('THE REPORTED BUG: only SELECT granted, no REVOKE, Supabase defaults -> LEAK', () => {
  const v = classifyView({ ...BASE, view: VIEW, grants: undefined });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'default-writethrough');
  assert.match(v.message, /pass straight through/);
  assert.match(v.message, /Granting only SELECT does not make a view read-only/);
  assert.match(v.fix, /REVOKE INSERT, UPDATE, DELETE ON public_profiles FROM anon, authenticated/);
});

test('an explicit write GRANT is conclusive, whatever the platform', () => {
  const v = classifyView({ ...BASE, assumeDefaults: false, view: VIEW, grants: { granted: new Set(['delete']), revoked: new Set() } });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'granted-writethrough');
  assert.match(v.message, /DELETE on it explicitly/);
});

test('SAFE: the REVOKE this guard recommends actually clears it', () => {
  const v = classifyView({
    ...BASE, view: VIEW,
    grants: { granted: new Set(), revoked: new Set(['insert', 'update', 'delete']) },
  });
  assert.equal(v.status, 'safe');
});

test('SAFE: security_invoker = true — writes run as the caller, so RLS applies', () => {
  assert.equal(classifyView({ ...BASE, view: { ...VIEW, securityInvoker: true } }).status, 'safe');
});

test('SAFE: a shape Postgres will not write through', () => {
  assert.equal(classifyView({ ...BASE, view: { ...VIEW, autoUpdatable: false } }).status, 'safe');
});

test('SAFE: a materialized view is never auto-updatable', () => {
  assert.equal(classifyView({ ...BASE, view: { ...VIEW, isMaterialized: true } }).status, 'safe');
});

test('NOTE, not failure, when nothing suggests the platform grants writes', () => {
  const v = classifyView({ ...BASE, assumeDefaults: false, view: VIEW, grants: undefined });
  assert.equal(v.status, 'note');
  assert.match(v.message, /probably fine/);
});

// ── end to end ───────────────────────────────────────────────────────

test('run(): the reported migration fails, and names the base table', () => {
  withMigrations({ '200_profiles.sql': REPORTED }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 1);
    assert.match(res.violations[0].message, /public_profiles/);
    assert.match(res.violations[0].message, /"users"/);
  });
});

test('run(): adding the recommended REVOKE in a later migration clears it', () => {
  withMigrations({
    '200_profiles.sql': REPORTED,
    '201_fix.sql': 'REVOKE INSERT, UPDATE, DELETE ON public.public_profiles FROM anon, authenticated;',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });
});

test('run(): rebuilding the view WITH security_invoker clears it too', () => {
  withMigrations({
    '200_profiles.sql': REPORTED,
    '201_fix.sql': 'CREATE OR REPLACE VIEW public.public_profiles WITH (security_invoker = true) AS SELECT id, display_name FROM public.users;',
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });
});

test('run(): an allowlisted view is not reported', () => {
  withMigrations({ '200_profiles.sql': REPORTED }, (dir) => {
    assert.equal(run({ dir, allowlist: ['public_profiles'] }).ok, true);
  });
});

test('run(): an aggregate reporting view is not flagged', () => {
  withMigrations({
    '200_stats.sql': `
      CREATE VIEW public.revenue AS SELECT org_id, sum(amount) AS total FROM invoices GROUP BY org_id;
      GRANT SELECT ON public.revenue TO anon;
    `,
  }, (dir) => {
    const res = run({ dir });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
  });
});

test('run(): skips cleanly with no migrations dir — a skip is not a pass', () => {
  const res = run({ dir: undefined });
  assert.equal(res.skipped, true);
  assert.equal(res.ok, true);
});
