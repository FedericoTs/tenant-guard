/**
 * rls-drift end-to-end, against a REAL Postgres catalog (embedded via pglite).
 *
 * The scenario that motivated this guard: a policy applied by hand (here,
 * created directly in the database) that no migration declares. We assert the
 * guard reads pg_policies and flags exactly that — and stays silent when the
 * database matches the migrations.
 *
 * pglite is a dev-only dependency; if it isn't installed the whole file skips.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { drift } from '../src/guards/rls-drift.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('rls-drift integration (pglite not installed — skipped)', { skip: true }, () => {});
}

/** Fresh embedded Postgres; `dbSetup` is the ACTUAL state, `files` the migrations. */
async function fresh(dbSetup) {
  const db = new PGlite();
  await db.exec(dbSetup);
  const query = (text, values) => db.query(text, Array.isArray(values) && values.length ? values : undefined);
  return { db, query };
}

if (PGlite) {
  test('CATCHES a hand-applied policy: in the database, in no migration', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text);
      alter table invoices enable row level security;
      create policy tenant_iso on invoices using (organization_id = current_setting('app.t', true));
      create policy hand_edited_public_write on invoices for all using (true) with check (true);
    `);
    // migrations declare ONLY the good policy + the enable
    const files = [{ name: '001_rls.sql', sql: `alter table invoices enable row level security;\ncreate policy tenant_iso on invoices using (organization_id = current_setting('app.t', true));` }];

    const res = await drift({ query, files });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 1);
    assert.match(res.violations[0].where, /public\.invoices/);
    assert.match(res.violations[0].message, /hand_edited_public_write.*in NO migration/);
    assert.match(res.violations[0].fix, /Capture it in a migration/);
  });

  test('PASSES when the database matches the migrations exactly', async () => {
    const setup = `
      create table invoices (id serial primary key, organization_id text);
      alter table invoices enable row level security;
      create policy tenant_iso on invoices using (organization_id = current_setting('app.t', true));
    `;
    const { query } = await fresh(setup);
    const files = [{ name: '001_rls.sql', sql: setup }];
    const res = await drift({ query, files });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    assert.match(res.summary, /all declared in migrations/);
  });

  test('CATCHES RLS enabled in the database but declared in no migration', async () => {
    const { query } = await fresh(`
      create table audit (id serial primary key, tenant_id text);
      alter table audit enable row level security;  -- turned on by hand, no policy, no migration
    `);
    const res = await drift({ query, files: [] }); // no migrations at all
    assert.equal(res.ok, false);
    assert.ok(res.violations.some((v) => /ROW LEVEL SECURITY is enabled/.test(v.message) && /public\.audit/.test(v.where)));
  });

  test('allowlist silences a policy intentionally managed outside migrations', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key);
      alter table invoices enable row level security;
      create policy supabase_managed on invoices using (true);
    `);
    const files = [{ name: '001.sql', sql: `alter table invoices enable row level security;` }];
    const res = await drift({ query, files, config: { allowlist: ['public.invoices::supabase_managed'] } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('declared-but-absent is a note, not a build failure', async () => {
    const { query } = await fresh(`create table invoices (id serial primary key);`); // RLS never enabled here
    const files = [{ name: '001.sql', sql: `alter table invoices enable row level security;\ncreate policy p on invoices using (true);` }];
    const res = await drift({ query, files });
    assert.equal(res.ok, true); // migrations may just be unapplied on this DB
    assert.equal(res.violations.length, 0);
    assert.ok(res.notes.some((n) => /unapplied/.test(n.message)));
  });
}
