/**
 * schema-per-tenant — the other multi-tenant architecture, and a verified blind
 * spot before this guard: point `rls-proof` at a database with `tenant_a.docs`
 * and `tenant_b.docs` both granted to the app role and it reports
 * "1/1 proven isolated", having found the one table in `public` and never
 * noticed the app role can read both tenants.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/schema-tenancy.mjs';
import { prove } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('schema-tenancy integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role app_user nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

const TWO_TENANTS = `
  create schema tenant_a;
  create schema tenant_b;
  create table tenant_a.docs (id int, body text);
  create table tenant_b.docs (id int, body text);
  insert into tenant_a.docs values (1,'A');
  insert into tenant_b.docs values (1,'B-SECRET');
`;

if (PGlite) {
  test('CATCHES one role reaching every tenant schema — and rls-proof is blind to it', async () => {
    const { query } = await fresh(`
      ${TWO_TENANTS}
      grant usage on schema tenant_a, tenant_b to app_user;
      grant select on tenant_a.docs, tenant_b.docs to app_user;
    `);
    // The column-based proof finds nothing to complain about.
    const rls = await prove({ query, config: { role: 'app_user', schemas: ['public', 'tenant_a', 'tenant_b'] } });
    assert.equal(rls.ok, true, 'rls-proof has no tenant column to key on');

    const res = await check({ query, config: { role: 'app_user' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'schema-reach');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.deepEqual(v.reachable.sort(), ['tenant_a', 'tenant_b']);
    assert.match(v.message, /GRANTs are the entire boundary/);
    assert.match(v.message, /proven by reading from/);      // reachability is read, not inferred
    assert.match(v.message, /search_path is not a substitute/);
    assert.match(v.fix, /GRANT USAGE ON SCHEMA tenant_a/);
  });

  test('PROVES a correct per-tenant role reaches only its own schema', async () => {
    const { query } = await fresh(`
      ${TWO_TENANTS}
      create role tenant_a_app nologin;
      grant usage on schema tenant_a to tenant_a_app;
      grant select on tenant_a.docs to tenant_a_app;
    `);
    const res = await check({ query, config: { role: 'tenant_a_app' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /proven scoped to one tenant/);
  });

  test('reachability is PROBED, not inferred — schema USAGE without a table grant is not access', async () => {
    const { query } = await fresh(`
      ${TWO_TENANTS}
      grant usage on schema tenant_a, tenant_b to app_user;   -- can enter both...
      grant select on tenant_a.docs to app_user;              -- ...but read only one
    `);
    const res = await check({ query, config: { role: 'app_user' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('does NOT false-flag an ordinary multi-schema database (different tables, not tenants)', async () => {
    const { query } = await fresh(`
      create schema analytics;
      create schema audit;
      create table analytics.rollups (id int, metric text);
      create table audit.events (id int, what text);
      grant usage on schema analytics, audit to app_user;
      grant select on analytics.rollups, audit.events to app_user;
    `);
    const res = await check({ query, config: { role: 'app_user' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.skipped, true);
    assert.match(res.summary, /not a schema-per-tenant database/);
  });

  test('schemaPattern overrides inference for a less regular layout', async () => {
    const { query } = await fresh(`
      create schema org_123;
      create schema org_456;
      create table org_123.docs (id int, body text);
      create table org_456.docs (id int, note text);   -- different columns: shape inference alone would miss it
      grant usage on schema org_123, org_456 to app_user;
      grant select on org_123.docs, org_456.docs to app_user;
    `);
    const res = await check({ query, config: { role: 'app_user', schemaPattern: '^org_' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.deepEqual(res.violations[0].reachable.sort(), ['org_123', 'org_456']);
  });

  test('a role with no access anywhere is a note, not a leak', async () => {
    const { query } = await fresh(TWO_TENANTS); // no grants at all
    const res = await check({ query, config: { role: 'app_user' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.ok(res.notes.some((n) => /cannot reach any/.test(n.message)), JSON.stringify(res.notes, null, 2));
  });

  test('allowlist exempts a schema that is shared on purpose', async () => {
    const setup = `
      ${TWO_TENANTS}
      create schema tenant_shared;
      create table tenant_shared.docs (id int, body text);
      grant usage on schema tenant_a, tenant_b, tenant_shared to app_user;
      grant select on tenant_a.docs, tenant_b.docs, tenant_shared.docs to app_user;
    `;
    const flagged = await check({ query: (await fresh(setup)).query, config: { role: 'app_user' } });
    assert.equal(flagged.ok, false);
    // Exempting the shared one still leaves two real tenants reachable — still a leak.
    const still = await check({ query: (await fresh(setup)).query, config: { role: 'app_user', allowlist: ['tenant_shared'] } });
    assert.equal(still.ok, false);
    assert.equal(still.violations[0].reachable.includes('tenant_shared'), false);
  });

  test('skips cleanly on a single-schema (column-tenancy) database', async () => {
    const { query } = await fresh(`
      create table invoices (id int, organization_id text);
      grant select on invoices to app_user;
    `);
    const res = await check({ query, config: { role: 'app_user' } });
    assert.equal(res.ok, true);
    assert.equal(res.skipped, true);
  });
}
