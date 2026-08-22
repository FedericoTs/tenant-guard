/**
 * MFA enforcement — the audit findings, each pinned to a measurement.
 *
 * Three defects were reproduced against PGlite before anything was changed:
 *
 *   1. hasOtherPermissiveGrant compared command but not ROLES, so an aal2 gate
 *      `TO authenticated` was called "enforces nothing" because an unrelated
 *      `TO anon` policy existed. Measured on that schema: authenticated/aal1 read
 *      0 rows and authenticated/aal2 read 3 — the gate enforced. Applying the
 *      printed fix took aal2 from 3 rows to 0.
 *   2. referencesAal used `\baal\b`, and `_` is a word character, so every
 *      helper-named gate (`is_aal2()`, `check_aal()`) was invisible. A permissive
 *      helper gate that measurably leaked was reported ok:true with the note "no
 *      policy ... checks the assurance level".
 *   3. The printed fix hardcoded `FOR ALL TO <cfg.role>` and an invented
 *      auth.jwt() expression instead of using the offending policy's own command,
 *      roles and expression — so it widened SELECT gates to writes and re-targeted
 *      `TO app_user` / `TO public` gates at `authenticated`, leaving the proven
 *      leak open while the guard flipped green.
 *
 * Every test here fails on the pre-fix guard.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  check,
  referencesAal,
  rolesOverlap,
  buildRoleMembers,
  quoteRole,
  classifyPermissiveGate,
} from '../src/guards/mfa-enforcement.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('mfa-enforcement audit (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── pure ─────────────────────────────────────────────────────────────

test('referencesAal sees a gate written through an aal-named helper', () => {
  // All five returned false before the fix; each is a permissive-gate leak the
  // guard would have reported as green.
  for (const expr of ['auth.is_aal2()', 'is_aal2()', 'auth.require_aal2()', 'check_aal()', 'aal_at_least(2)']) {
    assert.equal(referencesAal(expr), true, expr);
  }
});

test('referencesAal does not fire on ordinary columns that merely contain the letters', () => {
  // The obvious widening (/aal[12]?\b/) matches all of these. A tenancy policy
  // misread as an MFA gate is the expensive direction to get wrong: it would be
  // reported as a permissive gate and the printed fix would rewrite it.
  for (const expr of ['totaal > 0', 'zaal_id = 1', 'kraal', 'betaal_status = 1', `organization_id = current_setting('app.tenant')`]) {
    assert.equal(referencesAal(expr), false, expr);
  }
  assert.equal(referencesAal(null), false);
});

test('rolesOverlap: public matches everything, disjoint role sets do not', () => {
  const members = buildRoleMembers([
    { role: 'app_readers', member: 'app_readers' },
    { role: 'app_readers', member: 'authenticated' },
    { role: 'anon', member: 'anon' },
    { role: 'authenticated', member: 'authenticated' },
  ]);
  assert.equal(rolesOverlap(['public'], ['anon'], members), true);
  assert.equal(rolesOverlap(['authenticated'], ['public'], members), true);
  assert.equal(rolesOverlap(['authenticated'], ['authenticated'], members), true);
  // authenticated is a MEMBER of app_readers, so a policy TO app_readers really
  // does apply to an authenticated session. Comparing names alone would miss it.
  assert.equal(rolesOverlap(['authenticated'], ['app_readers'], members), true);
  assert.equal(rolesOverlap(['authenticated'], ['anon'], members), false);
});

test('quoteRole leaves public bare — TO "public" names a role that does not exist', () => {
  assert.equal(quoteRole('public'), 'public');
  assert.equal(quoteRole('authenticated'), '"authenticated"');
  assert.equal(quoteRole('weird role'), '"weird role"');
});

test('the printed fix keeps the policy\'s own command, roles and expression', () => {
  const v = classifyPermissiveGate({
    row: {
      schema: 'public', table: 'notes', policy: 'require_aal2',
      cmd: 'SELECT', roles: ['app_user'],
      qual: `(current_setting('app.aal'::text, true) = 'aal2'::text)`,
      with_check: null,
    },
    role: 'authenticated',
  });
  assert.match(v.fix, /AS RESTRICTIVE FOR SELECT TO "app_user"/);
  assert.doesNotMatch(v.fix, /AS RESTRICTIVE FOR ALL/); // was: FOR ALL, silently gating writes
  assert.doesNotMatch(v.fix, /TO authenticated\b/);   // was: cfg.role, re-targeting the gate
  assert.match(v.fix, /current_setting\('app\.aal'/); // was: an invented auth.jwt() call
  // The command narrowing has to be stated, not left for the reader to notice.
  assert.match(v.fix, /use FOR ALL instead/);
});

test('a {public} gate keeps TO public and says why', () => {
  const v = classifyPermissiveGate({
    row: { schema: 'public', table: 'notes', policy: 'p', cmd: 'ALL', roles: ['public'], qual: `aal = 'aal2'` },
  });
  assert.match(v.fix, /TO public\b/);
  assert.doesNotMatch(v.fix, /TO "public"/);
  assert.match(v.fix, /including anon/);
});

if (PGlite) {
  const boot = async (ddl) => {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create role anon nologin;
      create role app_readers nologin;
      create role app_user nologin;
      grant app_readers to authenticated;
      create schema if not exists auth;
      create table auth.mfa_factors (id int primary key, status text);
      insert into auth.mfa_factors values (1, 'verified');
    `);
    await db.exec(ddl);
    return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
  };

  const readAs = async (db, role, aal, tbl = 'notes') => {
    await db.query('begin');
    await db.query(`select set_config('app.aal', $1, true)`, [aal]);
    await db.query(`select set_config('app.tenant', 'org_A', true)`);
    await db.query(`set local role ${role}`);
    let n;
    try { n = (await db.query(`select * from ${tbl}`)).rows.length; } catch { n = -1; }
    await db.query('rollback');
    return n;
  };

  const table = (name, gateTo, otherTo) => `
    create table ${name} (id int primary key, organization_id text, is_public bool default true);
    insert into ${name} values (1, 'org_A', true);
    grant select on ${name} to authenticated, anon, app_readers, app_user;
    alter table ${name} enable row level security;
    create policy mfa_gate on ${name} for select ${gateTo}
      using (current_setting('app.aal', true) = 'aal2');
    create policy other on ${name} for select ${otherTo} using (is_public);
  `;

  // ── the false positive ─────────────────────────────────────────────
  test('SILENT when the only other permissive policy is for a different role — that gate enforces', async () => {
    const { db, query } = await boot(table('notes', 'to authenticated', 'to anon'));
    // ground truth first: the gate does its job
    assert.equal(await readAs(db, 'authenticated', 'aal1'), 0, 'single-factor session must read nothing');
    assert.equal(await readAs(db, 'authenticated', 'aal2'), 1);
    assert.equal(await readAs(db, 'anon', 'aal1'), 1, 'the anon policy is unrelated to the gate');

    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res.violations, null, 2));
    // and it is reported as a pass, not as "no gate found" — a skip is not a pass
    assert.match(res.summary, /enforcing MFA gate/);
  });

  // ── the true positives that must survive the fix ────────────────────
  test('still FIRES when the other permissive policy covers a role the gate covers', async () => {
    // authenticated is a member of app_readers, so `other TO app_readers` really
    // does OR with the gate. A patch comparing role NAMES would go silent here.
    const { db, query } = await boot(table('notes', 'to authenticated', 'to app_readers'));
    assert.equal(await readAs(db, 'authenticated', 'aal1'), 1, 'the gate really is neutered');
    assert.equal(await readAs(db, 'authenticated', 'aal2'), 1);

    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.match(res.violations[0].where, /mfa_gate/);
  });

  test('still FIRES when the other permissive policy has no TO clause ({public})', async () => {
    const { db, query } = await boot(table('notes', 'to authenticated', ''));
    assert.equal(await readAs(db, 'authenticated', 'aal1'), 1, 'the gate really is neutered');
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
  });

  // ── the false negative ──────────────────────────────────────────────
  test('CATCHES a permissive gate written through a helper named is_aal2()', async () => {
    const { db, query } = await boot(`
      create function is_aal2() returns boolean language sql stable
        as 'select current_setting(''app.aal'', true) = ''aal2''';
      create table notes (id int primary key, organization_id text, body text);
      insert into notes values (1, 'org_A', 's');
      grant select on notes to authenticated;
      grant execute on function is_aal2() to authenticated;
      alter table notes enable row level security;
      create policy own_rows on notes for select to authenticated
        using (organization_id = current_setting('app.tenant', true));
      create policy require_mfa on notes for select to authenticated using (is_aal2());
    `);
    // the leak is real: the second factor buys the session nothing
    assert.equal(await readAs(db, 'authenticated', 'aal2'), 1);
    assert.equal(await readAs(db, 'authenticated', 'aal1'), 1, 'permissive gate — reads everything anyway');

    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.match(res.violations[0].where, /require_mfa/);
    // and the old, wrong note must be gone
    assert.equal(res.notes.find((n) => /no policy in the scanned schemas/.test(n.message)), undefined);
  });

  // ── the advice ──────────────────────────────────────────────────────
  test('the printed fix, applied verbatim, closes the leak and keeps aal2 working', async () => {
    // Scenario C from the audit: both policies written with no TO clause, the
    // default Supabase shape. The old fix emitted `TO authenticated`, which left
    // anon ungated while the guard went green.
    const { db, query } = await boot(`
      create table notes (id int primary key, organization_id text, body text);
      insert into notes values (1, 'org_A', 's');
      grant select on notes to authenticated, anon;
      alter table notes enable row level security;
      create policy own_rows on notes for select using (true);
      create policy require_aal2 on notes for select
        using (current_setting('app.aal', true) = 'aal2');
    `);
    assert.equal(await readAs(db, 'authenticated', 'aal1'), 1);
    assert.equal(await readAs(db, 'anon', 'aal1'), 1);

    const before = await check({ query });
    assert.equal(before.ok, false);

    // take the SQL straight out of the fix text, the way a reader would
    const lines = before.violations[0].fix.split('\n').map((s) => s.trim()).filter(Boolean);
    const start = lines.findIndex((s) => s.startsWith('DROP POLICY'));
    assert.ok(start >= 0, before.violations[0].fix);
    const sql = [];
    for (let i = start; i < lines.length; i++) {
      sql.push(lines[i]);
      if (lines[i].endsWith(';') && sql.join(' ').includes('CREATE POLICY')) break;
    }
    await db.exec(sql.join('\n')); // must simply run

    assert.equal(await readAs(db, 'authenticated', 'aal2'), 1, 'MFA sessions must still work');
    assert.equal(await readAs(db, 'authenticated', 'aal1'), 0, 'leak closed');
    assert.equal(await readAs(db, 'anon', 'aal1'), 0, 'and closed for anon too — the gate was TO public');
    assert.equal((await check({ query })).ok, true);
  });
}
