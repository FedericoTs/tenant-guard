/**
 * The positive control: isolation has two failure modes and this tool named one.
 *
 * `rls-proof` proves "A cannot see B". A policy that is too TIGHT never leaks
 * anything and still breaks the product — the reported symptoms were a referral
 * page rendering "A friend" and a balances screen showing blank names, both from
 * an application writing rows it could not then read.
 *
 * The control is conclusive because the database accepted the row: the WITH
 * CHECK passed, so it is unambiguously the acting tenant's. If a table the
 * session CAN read does not show it, the SELECT policy is strictly narrower
 * than the INSERT policy.
 *
 * The calibration tests matter as much as the catch. An append-only table
 * legitimately accepts writes it cannot read back, and it is told apart by
 * having no readable rows at all; a NOT NULL column or a unique constraint stops
 * the insert for reasons that say nothing about policy and must stay silent.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { classifyTableResult, insertOwnProbeSql, prove } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('positive control (pglite not installed — skipped)', { skip: true }, () => {});
}

const BASE = { rlsEnabled: true, policyCount: 2, tenantCount: 2, crossVisible: 0, probedWrites: true };

// ── the classifier ───────────────────────────────────────────────────

test('a row written and not readable back is its own verdict, not a leak', () => {
  const v = classifyTableResult({ ...BASE, ownVisible: 3, ownInsertInvisible: true });
  assert.equal(v.status, 'write-read-asymmetry');
  assert.match(v.message, /could not read it back/);
  assert.match(v.message, /Not a leak; still a bug/);
});

test('a LEAK always outranks it — the quiet bug never hides the loud one', () => {
  const v = classifyTableResult({ ...BASE, ownVisible: 3, crossVisible: 5, ownInsertInvisible: true });
  assert.equal(v.status, 'leak');
});

test('an append-only table is NOT reported — it has no readable rows to begin with', () => {
  // ownVisible 0 is the append-only / audit-sink shape, and it is caught by the
  // over-restrictive branch that already existed rather than by this one.
  const v = classifyTableResult({ ...BASE, ownVisible: 0, ownInsertInvisible: true });
  assert.equal(v.status, 'over-restrictive');
});

test('an insert refused outright stays a pass, with the caveat spelled out', () => {
  const v = classifyTableResult({ ...BASE, ownVisible: 3, ownInsertRejected: true });
  assert.equal(v.status, 'isolated');
  assert.match(v.message, /could not INSERT a row of its own/);
});

test('the ordinary isolated case is unchanged', () => {
  assert.equal(classifyTableResult({ ...BASE, ownVisible: 3 }).status, 'isolated');
});

test('insertOwnProbeSql binds the tenant id rather than interpolating it', () => {
  const { text, values } = insertOwnProbeSql('public', 'notes', 'organization_id', "o'rg");
  assert.match(text, /values \(\$1\)/);
  assert.deepEqual(values, ["o'rg"]);
});

if (PGlite) {
  async function fresh(policies) {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table notes (id serial primary key, organization_id text, status text default 'draft', body text);
      insert into notes (organization_id, status) values ('org_A','published'), ('org_B','published');
      grant select, insert, update, delete on notes to authenticated;
      grant usage on sequence notes_id_seq to authenticated;
      alter table notes enable row level security;
      ${policies}
    `);
    return {
      db,
      query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined),
      config: {
        role: 'authenticated',
        becomeTenant: [`select set_config('app.tenant', $1, true)`],
        tenantColumns: ['organization_id'],
      },
    };
  }

  const SYMMETRIC = `
    create policy all_ on notes for all to authenticated
      using (organization_id = current_setting('app.tenant', true))
      with check (organization_id = current_setting('app.tenant', true));`;

  // The bug shape: the SELECT policy filters on a column the INSERT leaves at
  // its DEFAULT, so every new row is created outside the policy's own window.
  const ASYMMETRIC = `
    create policy sel on notes for select to authenticated
      using (organization_id = current_setting('app.tenant', true) and status = 'published');
    create policy ins on notes for insert to authenticated
      with check (organization_id = current_setting('app.tenant', true));`;

  test('DEMONSTRATES it: the row is accepted and then invisible', async () => {
    const { db } = await fresh(ASYMMETRIC);
    await db.query('begin');
    await db.query(`select set_config('app.tenant', 'org_A', true)`);
    await db.query('set local role authenticated');
    const before = (await db.query(`select count(*)::int as n from notes`)).rows[0].n;
    await db.query(`insert into notes (organization_id) values ('org_A')`); // accepted
    const after = (await db.query(`select count(*)::int as n from notes`)).rows[0].n;
    await db.query('rollback');
    assert.equal(after, before, 'the database took the row and the session cannot see it');
  });

  test('CATCHES it end to end', async () => {
    const { query, config } = await fresh(ASYMMETRIC);
    const res = await prove({ query, config });
    const notes = res.notes ?? [];
    const found = [...res.violations, ...notes].some((x) =>
      /write-read-asymmetry|could not read it back/.test(JSON.stringify(x)));
    assert.ok(found, JSON.stringify(res, null, 2));
  });

  test('says NOTHING extra when the policies agree', async () => {
    const { query, config } = await fresh(SYMMETRIC);
    const res = await prove({ query, config });
    assert.equal(
      /could not read it back/.test(JSON.stringify(res)), false,
      JSON.stringify(res, null, 2),
    );
  });

  test('a NOT NULL column makes the control inconclusive, never a finding', async () => {
    // The insert fails for a reason that says nothing about policy. Reporting
    // that would make the control worthless on any real schema.
    const { db, query, config } = await fresh(SYMMETRIC);
    // Backfill via a default, then drop it: existing rows are valid, and a new
    // INSERT that omits the column fails with 23502 — which is the real-schema
    // situation the probe has to stay quiet about.
    await db.exec(`alter table notes add column title text not null default 'x';
                   alter table notes alter column title drop default;`);
    const res = await prove({ query, config });
    assert.equal(/could not read it back/.test(JSON.stringify(res)), false, JSON.stringify(res, null, 2));
  });
}
