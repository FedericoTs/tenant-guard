/**
 * pooler-bleed against a real database and a real source tree.
 *
 * The first test is the important one: it does not check that the guard fires,
 * it **demonstrates the leak** — one connection, a session-scoped tenant GUC,
 * and a later request that sets nothing reading the previous tenant's rows
 * through a policy that is working exactly as written. Every other test in this
 * project would pass against that database.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { check, probePersistence } from '../src/guards/pooler-bleed.mjs';
import { prove } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('pooler-bleed integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const SCHEMA = `
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select on invoices to authenticated;
  insert into invoices (organization_id, amount) values ('org_A', 100), ('org_B', 999);
  alter table invoices enable row level security;
  create policy tenant_iso on invoices
    using (organization_id = current_setting('app.current_tenant', true));
`;

async function freshDb(setup = SCHEMA) {
  const db = new PGlite();
  await db.exec('create role authenticated nologin;');
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

/** A throwaway repo whose db layer sets the tenant GUC with the given scope. */
function fakeRepo(isLocal, guc = 'app.current_tenant') {
  const dir = mkdtempSync(join(tmpdir(), 'tg-pooler-'));
  mkdirSync(join(dir, 'src'), { recursive: true });
  writeFileSync(
    join(dir, 'src', 'db.ts'),
    [
      "import { pool } from './pool';",
      'export async function withTenant(orgId: string, fn: () => Promise<void>) {',
      '  const client = await pool.connect();',
      `  await client.query("select set_config('${guc}', $1, ${isLocal})", [orgId]);`,
      '  try { await fn(); } finally { client.release(); }',
      '}',
    ].join('\n'),
  );
  return dir;
}

if (PGlite) {
  // ── the leak itself ────────────────────────────────────────────────
  test('DEMONSTRATES the bleed: a later request with no tenant set reads the previous one\'s rows', async () => {
    const { db } = await freshDb();
    await db.exec('set role authenticated');

    // Request 1 — sets the tenant SESSION-wide (is_local = false). The bug.
    await db.query("select set_config('app.current_tenant', 'org_A', false)");
    const mine = await db.query('select * from invoices');
    assert.equal(mine.rows.length, 1);
    assert.equal(mine.rows[0].organization_id, 'org_A');

    // Request 2 — a later statement on the SAME connection that sets nothing.
    // In a pool this is a different user's request holding a recycled client.
    const inherited = await db.query('select organization_id from invoices');
    assert.equal(inherited.rows.length, 1);
    assert.equal(
      inherited.rows[0].organization_id,
      'org_A',
      'the connection is still authorized as the previous tenant',
    );

    // The control: with a transaction-scoped write the identity does NOT
    // survive, so the same later request sees nothing at all.
    const { db: db2 } = await freshDb();
    await db2.exec('set role authenticated');
    await db2.query('begin');
    await db2.query("select set_config('app.current_tenant', 'org_A', true)");
    await db2.query('commit');
    const after = await db2.query('select organization_id from invoices');
    assert.equal(after.rows.length, 0, 'SET LOCAL must not outlive its transaction');
  });

  test('rls-proof reports that same database as fully isolated — this guard exists for the gap', async () => {
    const { query } = await freshDb();
    const res = await prove({ query });
    assert.equal(res.ok, true);
    assert.equal(res.violations.length, 0); // per-request isolation is perfect
  });

  // ── the guard ──────────────────────────────────────────────────────
  test('CATCHES it: policy GUC + a session-scoped write in the source', async () => {
    const { query } = await freshDb();
    const dir = fakeRepo('false');
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.ok, false, JSON.stringify(res, null, 2));
      assert.equal(res.violations.length, 1);
      const v = res.violations[0];
      assert.equal(v.where, 'app.current_tenant');
      assert.match(v.message, /public\.invoices/);
      assert.match(v.message, /src\/db\.ts:4/);      // the exact line
      assert.match(v.message, /whole CONNECTION/);
      assert.match(v.fix, /is_local/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('PASSES when the same code sets it transaction-locally', async () => {
    const { query } = await freshDb();
    const dir = fakeRepo('true');
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.ok, true, JSON.stringify(res, null, 2));
      assert.equal(res.violations.length, 0);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a session-scoped write to an UNRELATED GUC is not flagged', async () => {
    const { query } = await freshDb();
    const dir = fakeRepo('false', 'app.locale'); // no policy authorizes from this
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.ok, true);
      // …and the real GUC is reported as unset-in-repo rather than passed over.
      assert.ok(res.notes.some((n) => n.where === 'app.current_tenant'));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test('SKIPS cleanly on a JWT-only database — nothing there can outlive a request', async () => {
    const { query } = await freshDb(`
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      alter table invoices enable row level security;
      create policy p on invoices
        using (organization_id = (current_setting('request.jwt.claims', true)::json ->> 'org_id'));
    `);
    const res = await check({ query, cwd: process.cwd() });
    assert.equal(res.skipped, true);
    assert.match(res.reason, /no policy authorizes from a custom GUC/);
  });

  test('an allowlisted GUC is not flagged', async () => {
    const { query } = await freshDb();
    const dir = fakeRepo('false');
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'], allowlist: ['app.current_tenant'] } });
      assert.equal(res.ok, true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  // ── the runtime demonstration ──────────────────────────────────────
  test('probePersistence: session survives, transaction-local does not — and says so', async () => {
    const { query } = await freshDb();
    const q = async (t, v) => (await query(t, v)).rows;
    const { persists, controlHeld } = await probePersistence(q);
    assert.equal(persists, true, 'a session-scoped setting must survive into a later statement');
    assert.equal(controlHeld, true, 'a transaction-scoped setting must not — this is the control arm');
  });

  test('the probe result is reported as a note and never decides the verdict', async () => {
    const { query } = await freshDb();
    const dir = fakeRepo('true'); // safe source ⇒ no violation…
    try {
      const res = await check({ query, cwd: dir, config: { sourceDirs: ['src'] } });
      assert.equal(res.ok, true); // …even though the probe confirms persistence
      const probe = res.notes.find((n) => n.where === '(probe)');
      assert.ok(probe, 'the demonstration should be reported');
      assert.match(probe.message, /confirmed on this connection/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}
