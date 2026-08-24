/**
 * Audit regression: `security_invoker` does not propagate to nested views.
 *
 * Before this, any leaking view that set security_invoker was told the cause was
 * "the UNDERLYING TABLE's policy" and referred to `tenant-guard prove`. Measured
 * false in pglite (server_version_num 180003): with `internal.v_inner` a plain
 * definer view between the invoker view and a correctly-RLS'd `orders`, tenant A
 * read tenant B's rows through the view while `prove` returned ok=true on the
 * base table — the referral terminated with nothing to act on. The statement
 * that actually closed it, ALTER VIEW internal.v_inner SET (security_invoker =
 * true), was never emitted.
 *
 * The verdict was always right (it comes from the probe); only the diagnosis and
 * the remediation were wrong, so every test here is about message content and
 * about NOT changing the cases that were already correct.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  check,
  classifyViewResult,
  fixForView,
  nestedViewDepsSql,
  nestedDefinerRelations,
} from '../src/guards/view-isolation.mjs';
import { prove } from '../src/guards/rls-proof.mjs';

// ── pure helpers ─────────────────────────────────────────────────────

test('nestedDefinerRelations keeps definer views and ALL matviews, drops invoker views', () => {
  const out = nestedDefinerRelations([
    { schema: 'internal', view: 'v_definer', kind: 'v', owner_role: 'postgres', reloptions: '' },
    { schema: 'internal', view: 'v_invoker', kind: 'v', owner_role: 'postgres', reloptions: 'security_invoker=true' },
    // RLS never applies to a matview, so it is a culprit whatever its reloptions say.
    { schema: 'public', view: 'mv', kind: 'm', owner_role: 'postgres', reloptions: 'security_invoker=true' },
  ]);
  assert.deepEqual(out.map((r) => r.id), ['internal.v_definer', 'public.mv']);
  assert.deepEqual(out.map((r) => r.kind), ['view', 'matview']);
});

test('classifyViewResult names the nested view instead of blaming the base table', () => {
  const nested = [{ schema: 'internal', view: 'v_inner', id: 'internal.v_inner', kind: 'view', ownerRole: 'postgres', securityInvoker: false }];
  const r = classifyViewResult({
    kind: 'view', securityInvoker: true, ownerRole: 'postgres',
    ownVisible: 2, crossVisible: 1, tenantCount: 2,
    schema: 'public', view: 'v_outer', role: 'authenticated', nested,
  });
  assert.equal(r.status, 'leak');
  assert.match(r.message, /internal\.v_inner/);
  assert.match(r.message, /NOT inherited/);
  // The old, wrong assertion must be gone from this branch.
  assert.doesNotMatch(r.message, /the leak is in the underlying table's policy/);
  assert.match(r.fix, /ALTER VIEW "internal"\."v_inner" SET \(security_invoker = true\)/);
  assert.doesNotMatch(r.fix, /the leak is in the UNDERLYING TABLE's policy/);
});

test('a nested MATVIEW gets a REVOKE naming the real grantee, never a security_invoker ALTER', () => {
  const nested = [{ schema: 'internal', view: 'mv', id: 'internal.mv', kind: 'matview', ownerRole: 'postgres', securityInvoker: false }];
  const fix = fixForView({ kind: 'view', schema: 'public', view: 'v_outer', securityInvoker: true, role: 'authenticated', nested });
  assert.match(fix, /REVOKE SELECT ON "internal"\."mv" FROM authenticated;/);
  assert.doesNotMatch(fix, /ALTER VIEW "internal"\."mv"/);
  // Applying it blind breaks the outer view; that consequence has to be stated.
  assert.match(fix, /42501/);
});

test('with nothing nested the base-table diagnosis is KEPT — but stated as conditional', () => {
  const r = classifyViewResult({
    kind: 'view', securityInvoker: true, ownerRole: 'postgres',
    ownVisible: 2, crossVisible: 1, tenantCount: 2,
    schema: 'public', view: 'v', role: 'authenticated', nested: [],
  });
  assert.match(r.message, /every relation it reads is a table or another security_invoker view/);
  assert.match(r.fix, /tenant-guard prove/);
});

test('a skip is never a pass: if the dependency walk failed, say so instead of blaming the table', () => {
  const r = classifyViewResult({
    kind: 'view', securityInvoker: true, ownerRole: 'postgres',
    ownVisible: 2, crossVisible: 1, tenantCount: 2,
    schema: 'public', view: 'v', role: 'authenticated', nested: [], nestedError: 'permission denied for table pg_rewrite',
  });
  assert.match(r.message, /could not be listed/);
  assert.match(r.message, /cannot tell the base table's policy apart/);
  assert.match(r.fix, /could NOT be listed/);
});

test('the definer-view recipe warns when security_invoker alone will not reach a nested relation', () => {
  const nested = [{ schema: 'internal', view: 'v_inner', id: 'internal.v_inner', kind: 'view', ownerRole: 'postgres', securityInvoker: false }];
  const withNested = fixForView({ kind: 'view', schema: 'public', view: 'v_outer', securityInvoker: false, role: 'authenticated', nested, pgVersionNum: 180003 });
  assert.match(withNested, /NOT sufficient on their own/);
  assert.match(withNested, /ALTER VIEW "internal"\."v_inner" SET \(security_invoker = true\)/);
  // Unchanged when there is nothing below it — no new noise on the common case.
  const plain = fixForView({ kind: 'view', schema: 'public', view: 'v_outer', securityInvoker: false, role: 'authenticated', nested: [], pgVersionNum: 180003 });
  assert.doesNotMatch(plain, /NOT sufficient on their own/);
});

// ── against a real Postgres ──────────────────────────────────────────

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('view-isolation audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const SECURE_TABLE = `
  create table orders (id serial primary key, org_id text not null, amount int);
  grant select on orders to authenticated;
  insert into orders (org_id, amount) values ('A',1),('A',2),('B',3);
  alter table orders enable row level security;
  create policy tenant_iso on orders using (org_id = current_setting('app.current_tenant', true));
`;

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
}
const CFG = { tenantColumns: ['org_id'] };

if (PGlite) {
  // The layout that made this a real-world problem rather than a curiosity: the
  // nested view lives in a schema the scan does not cover (Supabase's standard
  // "private schema behind a public view"), so the outer view is the ONLY output
  // and there is no second violation to accidentally rescue the diagnosis.
  const NESTED_OUT_OF_SCHEMA = `
    create schema internal;
    ${SECURE_TABLE}
    create view internal.v_inner as select id, org_id, amount from orders;
    grant usage on schema internal to authenticated;
    grant select on internal.v_inner to authenticated;
    create view public.v_outer with (security_invoker = true) as select id, org_id, amount from internal.v_inner;
    grant select on public.v_outer to authenticated;
  `;

  test('NAMES the nested definer view in another schema — and does not send the user to the base table', async () => {
    const { query } = await fresh(NESTED_OUT_OF_SCHEMA);
    const res = await check({ query, config: CFG });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 1, JSON.stringify(res.violations, null, 2));
    const v = res.violations[0];
    assert.equal(v.where, 'public.v_outer (org_id)');
    assert.match(v.message, /internal\.v_inner/);
    assert.match(v.fix, /ALTER VIEW "internal"\."v_inner" SET \(security_invoker = true\)/);
    // The dead end this replaces.
    assert.doesNotMatch(v.fix, /the leak is in the UNDERLYING TABLE's policy/);

    // ...and the referral really was a dead end: the base table is correct.
    const p = await prove({ query, config: CFG });
    assert.equal(p.ok, true, JSON.stringify(p, null, 2));
  });

  test("the guard's own emitted statement closes the leak", async () => {
    const { db, query } = await fresh(NESTED_OUT_OF_SCHEMA);
    const before = await check({ query, config: CFG });
    // Take the ALTER straight out of the fix text and run it verbatim.
    const stmt = before.violations[0].fix.match(/ALTER VIEW [^\n;]+;/)[0];
    await db.exec(stmt);
    const after = await check({ query, config: CFG });
    assert.equal(after.ok, true, JSON.stringify(after, null, 2));
    assert.match(after.summary, /1\/1 tenant view\(s\) proven isolated/);
  });

  test('CORRECT code stays silent: an all-invoker chain over a correct table is not flagged', async () => {
    const { query } = await fresh(`
      create schema internal;
      ${SECURE_TABLE}
      create view internal.v_inner with (security_invoker = true) as select id, org_id, amount from orders;
      grant usage on schema internal to authenticated;
      grant select on internal.v_inner to authenticated;
      create view public.v_outer with (security_invoker = true) as select id, org_id, amount from internal.v_inner;
      grant select on public.v_outer to authenticated;
    `);
    const res = await check({ query, config: CFG });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
  });

  test('when the base policy really IS the cause, the base-table diagnosis is still given', async () => {
    const { query } = await fresh(`
      create schema internal;
      create table orders (id serial primary key, org_id text not null, amount int);
      grant select on orders to authenticated;
      insert into orders (org_id, amount) values ('A',1),('A',2),('B',3);
      alter table orders enable row level security;
      create policy wide_open on orders using (true);
      create view internal.v_inner with (security_invoker = true) as select id, org_id, amount from orders;
      grant usage on schema internal to authenticated;
      grant select on internal.v_inner to authenticated;
      create view public.v_outer with (security_invoker = true) as select id, org_id, amount from internal.v_inner;
      grant select on public.v_outer to authenticated;
    `);
    const res = await check({ query, config: CFG });
    assert.equal(res.ok, false);
    const v = res.violations.find((x) => x.where.startsWith('public.v_outer'));
    assert.match(v.fix, /UNDERLYING TABLE's policy/);
    assert.match(v.fix, /tenant-guard prove/);
  });

  test('a nested MATERIALIZED VIEW under an invoker view is named, with the REVOKE not an ALTER', async () => {
    const { query } = await fresh(`
      create schema internal;
      ${SECURE_TABLE}
      create materialized view internal.mv_inner as select id, org_id, amount from orders;
      grant usage on schema internal to authenticated;
      grant select on internal.mv_inner to authenticated;
      create view public.v_outer with (security_invoker = true) as select id, org_id, amount from internal.mv_inner;
      grant select on public.v_outer to authenticated;
    `);
    const res = await check({ query, config: CFG });
    const v = res.violations.find((x) => x.where.startsWith('public.v_outer'));
    assert.ok(v, JSON.stringify(res, null, 2));
    assert.match(v.message, /stored snapshot that RLS never applies to/);
    assert.match(v.fix, /REVOKE SELECT ON "internal"\."mv_inner" FROM authenticated;/);
  });

  test('the dependency walk survives a mixed-case, reserved-word view name', async () => {
    const { query } = await fresh(`
      create schema "Internal";
      ${SECURE_TABLE}
      create view "Internal"."select" as select id, org_id, amount from orders;
      grant usage on schema "Internal" to authenticated;
      grant select on "Internal"."select" to authenticated;
      create view public."Order View" with (security_invoker = true) as select id, org_id, amount from "Internal"."select";
      grant select on public."Order View" to authenticated;
    `);
    const res = await check({ query, config: CFG });
    const v = res.violations.find((x) => x.where.startsWith('public.Order View'));
    assert.ok(v, JSON.stringify(res, null, 2));
    assert.match(v.message, /Internal\.select/);
    assert.match(v.fix, /ALTER VIEW "Internal"\."select" SET \(security_invoker = true\)/);
    // No note claiming the walk failed.
    assert.deepEqual(res.notes, []);
  });

  test('the dependency SQL itself is what finds the nested relation', async () => {
    const { query } = await fresh(NESTED_OUT_OF_SCHEMA);
    const d = nestedViewDepsSql('public', 'v_outer');
    const rows = (await query(d.text, d.values)).rows;
    assert.deepEqual(nestedDefinerRelations(rows).map((r) => r.id), ['internal.v_inner']);
    // The starting view must not report itself as its own nested dependency.
    assert.ok(!rows.some((r) => r.view === 'v_outer'));
  });

  test('a failing dependency walk degrades to the honest message, not to a leak-free run', async () => {
    const { db } = await fresh(NESTED_OUT_OF_SCHEMA);
    // Fail only the dependency walk; every other statement passes through.
    const query = (t, v) => {
      if (/with recursive refs/.test(t)) return Promise.reject(new Error('simulated catalog failure'));
      return db.query(t, Array.isArray(v) && v.length ? v : undefined);
    };
    const res = await check({ query, config: CFG });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where.startsWith('public.v_outer'));
    assert.match(v.message, /simulated catalog failure/);
    assert.match(v.message, /cannot tell the base table's policy apart/);
  });
}
