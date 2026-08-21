/**
 * MFA enforcement, against a real database.
 *
 * The first test is the reason the guard exists: it does not check that the
 * guard fires, it shows that a PERMISSIVE `aal2` policy lets a single-factor
 * session read every row — so the policy reads exactly right and enforces
 * nothing. Postgres ORs permissive policies and ANDs restrictive ones.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check, referencesAal, isPermissive, classifyAalPolicies, classifyPermissiveGate } from '../src/guards/mfa-enforcement.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('mfa-enforcement integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const schema = (mode) => `
  create role authenticated nologin;
  create schema if not exists auth;
  create table auth.mfa_factors (id int primary key, status text);
  insert into auth.mfa_factors values (1, 'verified');

  create table notes (id int primary key, organization_id text, body text);
  insert into notes values (1, 'org_A', 'secret');
  grant select on notes to authenticated;
  alter table notes enable row level security;

  create policy own_rows on notes for select to authenticated
    using (organization_id = current_setting('app.tenant', true));

  ${mode === 'none' ? '' : `
  create policy require_aal2 on notes as ${mode} for select to authenticated
    using (current_setting('app.aal', true) = 'aal2');`}
`;

async function fresh(mode) {
  const db = new PGlite();
  await db.exec(schema(mode));
  return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
}

async function readAs(db, aal) {
  await db.query('begin');
  await db.query(`select set_config('app.tenant', 'org_A', true)`);
  await db.query(`select set_config('app.aal', $1, true)`, [aal]);
  await db.query('set local role authenticated');
  const r = await db.query('select * from notes');
  await db.query('rollback');
  return r.rows.length;
}

// ── pure ─────────────────────────────────────────────────────────────

test('referencesAal matches the spellings the claim is read with', () => {
  assert.equal(referencesAal(`(auth.jwt()->>'aal') = 'aal2'`), true);
  assert.equal(referencesAal(`current_setting('request.jwt.claims')::json->>'aal' = 'aal2'`), true);
  assert.equal(referencesAal(`organization_id = current_setting('app.tenant')`), false);
  assert.equal(referencesAal(null), false);
});

test('isPermissive defaults to permissive — that is what Postgres does', () => {
  assert.equal(isPermissive({ permissive: 'PERMISSIVE' }), true);
  assert.equal(isPermissive({ permissive: 'RESTRICTIVE' }), false);
  assert.equal(isPermissive({}), true); // an unspecified policy IS permissive
});

test('classifyAalPolicies splits the gates by whether they can enforce', () => {
  const rows = [
    { schema: 'public', table: 't', policy: 'a', permissive: 'PERMISSIVE', qual: `aal = 'aal2'` },
    { schema: 'public', table: 't', policy: 'b', permissive: 'RESTRICTIVE', qual: `aal = 'aal2'` },
    { schema: 'public', table: 't', policy: 'c', permissive: 'PERMISSIVE', qual: `org = x` },
  ];
  const g = classifyAalPolicies(rows);
  assert.deepEqual(g.permissive.map((r) => r.policy), ['a']);
  assert.deepEqual(g.restrictive.map((r) => r.policy), ['b']);
});

test('the fix names AS RESTRICTIVE, because that is the whole difference', () => {
  const v = classifyPermissiveGate({ row: { schema: 'public', table: 'notes', policy: 'require_aal2' } });
  assert.equal(v.status, 'leak');
  assert.match(v.fix, /AS RESTRICTIVE/);
  assert.match(v.message, /can only ever ADD access/);
});

if (PGlite) {
  // ── the point ──────────────────────────────────────────────────────
  test('DEMONSTRATES it: a PERMISSIVE aal2 gate lets a single-factor session read everything', async () => {
    const { db } = await fresh('permissive');
    assert.equal(await readAs(db, 'aal2'), 1);
    assert.equal(await readAs(db, 'aal1'), 1, 'the gate did nothing — permissive policies OR');
  });

  test('…and AS RESTRICTIVE actually enforces it', async () => {
    const { db } = await fresh('restrictive');
    assert.equal(await readAs(db, 'aal2'), 1);
    assert.equal(await readAs(db, 'aal1'), 0, 'restrictive policies AND');
  });

  // ── the guard ──────────────────────────────────────────────────────
  test('CATCHES the permissive gate', async () => {
    const { query } = await fresh('permissive');
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations[0].kind, 'permissive-mfa-gate');
    assert.match(res.violations[0].where, /require_aal2/);
  });

  test('PASSES on a restrictive gate', async () => {
    const { query } = await fresh('restrictive');
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('factors enrolled but NO gate anywhere is a note, not silence', async () => {
    const { query } = await fresh('none');
    const res = await check({ query });
    assert.equal(res.ok, true);
    const note = res.notes.find((n) => /verified MFA factor/.test(n.message));
    assert.ok(note, JSON.stringify(res.notes, null, 2));
    assert.match(note.message, /gating your login screen, not your data/);
  });

  test('partial coverage is named — the protected table is the one they thought of', async () => {
    const { db, query } = await fresh('restrictive');
    await db.exec(`
      create table invoices (id int primary key, organization_id text);
      alter table invoices enable row level security;
      create policy own on invoices for select to authenticated using (true);
    `);
    const res = await check({ query });
    const note = res.notes.find((n) => /no such gate/.test(n.message));
    assert.ok(note, JSON.stringify(res.notes, null, 2));
    assert.match(note.message, /invoices/);
  });

  test('an allowlisted policy is not reported', async () => {
    const { query } = await fresh('permissive');
    const res = await check({ query, config: { allowlist: ['public.notes.require_aal2'] } });
    assert.equal(res.ok, true);
  });

    test('does NOT report a LONE permissive aal2 gate — that one does restrict', async () => {
    // The precondition the guard was missing. With no other permissive policy the
    // gate IS the grant, so an aal1 session reads nothing. Verified:
    //   aal2 gate + tenancy policy  ->  aal2 sees 1, aal1 sees 1  (enforces nothing)
    //   aal2 gate alone             ->  aal2 sees 1, aal1 sees 0  (enforces)
    // Reporting the second is telling someone to fix working code.
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create schema if not exists auth;
      create table auth.mfa_factors (id int primary key, status text);
      insert into auth.mfa_factors values (1, 'verified');
      create table notes (id int primary key, organization_id text, body text);
      insert into notes values (1, 'org_A', 'secret');
      grant select on notes to authenticated;
      alter table notes enable row level security;
      create policy require_aal2 on notes for select to authenticated
        using (current_setting('app.aal', true) = 'aal2');
    `);
    const q = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

    // prove it actually restricts before asserting the guard stays quiet
    const read = async (aal) => {
      await db.query('begin');
      await db.query(`select set_config('app.aal', $1, true)`, [aal]);
      await db.query('set local role authenticated');
      const r = await db.query('select * from notes');
      await db.query('rollback');
      return r.rows.length;
    };
    assert.equal(await read('aal2'), 1);
    assert.equal(await read('aal1'), 0, 'a lone permissive gate IS the grant');

    const res = await check({ query: q });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('a project with no MFA at all skips cleanly — a skip is not a pass', async () => {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table t (id int, organization_id text);
      alter table t enable row level security;
      create policy p on t for select using (true);
    `);
    const res = await check({ query: (q, v) => db.query(q, Array.isArray(v) && v.length ? v : undefined) });
    assert.equal(res.skipped, true);
    assert.match(res.reason, /nothing here uses MFA/);
  });
}
