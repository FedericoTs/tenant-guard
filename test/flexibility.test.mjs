/**
 * Flexibility proofs: does `prove` work beyond the toy `current_setting` policy,
 * and does `route-org-scoping` work beyond Supabase's `.eq('id')`?
 *
 * These are the claims that must be PROVEN, not asserted. Each test stands up
 * the real shape (real Postgres via pglite for RLS; real source text for the
 * route classifier) and checks the guard actually holds.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { prove } from '../src/guards/rls-proof.mjs';
import { classifyRouteFile, DEFAULTS as ROUTE_DEFAULTS } from '../src/guards/route-org-scoping.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('flexibility (pglite not installed — DB proofs skipped)', { skip: true }, () => {});
}

async function freshDb(setupSql) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setupSql);
  const query = (text, values) =>
    db.query(text, Array.isArray(values) && values.length ? values : undefined);
  return { db, query };
}

// ── PROOF 1: real Supabase JWT-claim policy shape ─────────────────────
// Supabase's most common pattern: RLS reads the org straight out of the JWT.
//   USING (organization_id = (auth.jwt() ->> 'org_id'))
// which is exactly current_setting('request.jwt.claims')::json ->> 'org_id'.
const SUPABASE_JWT_CLAIM = {
  role: 'authenticated',
  // $1::text is required — json_build_object can't infer the placeholder's type.
  becomeTenant: ["select set_config('request.jwt.claims', json_build_object('org_id', $1::text)::text, true)"],
};

if (PGlite) {
  test('PROOF: prove() isolates a Supabase JWT-claim RLS policy', async () => {
    const { query } = await freshDb(`
      create table invoices (id serial primary key, organization_id text not null, amount int);
      grant select on invoices to authenticated;
      insert into invoices (organization_id, amount) values ('org_A',100),('org_A',150),('org_B',200);
      alter table invoices enable row level security;
      create policy tenant_iso on invoices
        using (organization_id = (current_setting('request.jwt.claims', true)::json ->> 'org_id'));
    `);
    const res = await prove({ query, config: SUPABASE_JWT_CLAIM });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /1\/1 tenant table\(s\) proven isolated/);
  });

  test('PROOF: prove() CATCHES a broken Supabase JWT-claim policy', async () => {
    const { query } = await freshDb(`
      create table invoices (id serial primary key, organization_id text not null, amount int);
      grant select on invoices to authenticated;
      insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200);
      alter table invoices enable row level security;
      -- BUG: compares to a literal, not the caller's claim -> everyone sees org_A's world? no: leaks all
      create policy oops on invoices using (true);
    `);
    const res = await prove({ query, config: SUPABASE_JWT_CLAIM });
    assert.equal(res.ok, false);
    assert.equal(res.violations.length, 1);
  });

  test('ROBUSTNESS: a becomeTenant config error becomes a clear note, not a crash', async () => {
    const { query } = await freshDb(`
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A'),('org_B');
      alter table invoices enable row level security;
      create policy p on invoices using (organization_id = (current_setting('request.jwt.claims', true)::json ->> 'org_id'));
    `);
    // Intentionally missing the ::text cast -> Postgres 42P18. Must NOT crash the proof.
    const res = await prove({
      query,
      config: {
        role: 'authenticated',
        becomeTenant: ["select set_config('request.jwt.claims', json_build_object('org_id', $1)::text, true)"],
      },
    });
    assert.equal(res.ok, true); // not a proven leak, and no unhandled throw
    assert.equal(res.violations.length, 0);
    assert.ok(res.notes.some((n) => /could not probe/.test(n.message) && /\$1::text/.test(n.message)), JSON.stringify(res.notes));
  });

  // ── PROOF 2: non-Supabase plain-Postgres app (Rails/Django/Go style) ──
  // The canonical multi-tenant Postgres pattern: a session GUC set by app
  // middleware, no Supabase roles or JWT at all.
  test('PROOF: prove() works on a non-Supabase plain-Postgres app (session GUC)', async () => {
    const { query } = await freshDb(`
      create table orders (id serial primary key, account_id int not null, total int);
      grant select on orders to authenticated;
      insert into orders (account_id, total) values (1, 50), (1, 75), (2, 999);
      alter table orders enable row level security;
      create policy acct_iso on orders
        using (account_id = current_setting('app.current_account', true)::int);
    `);
    const res = await prove({
      query,
      config: {
        role: 'authenticated',
        tenantColumns: ['account_id'],
        becomeTenant: ["select set_config('app.current_account', $1, true)"],
      },
    });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /1\/1 tenant table\(s\) proven isolated/);
  });
}

// ── PROOF 3: route classifier across stacks (pure source text) ────────
test('PROOF: route-org-scoping flags a Prisma bare-id read (NextAuth session)', () => {
  const leaky = `
    export async function GET(req) {
      const session = await getServerSession();
      const invoice = await prisma.invoice.findUnique({ where: { id: req.query.id } });
      return Response.json(invoice);
    }`;
  assert.equal(classifyRouteFile(leaky).leak, true);
});

test('PROOF: route-org-scoping clears the Prisma read once it scopes by tenant', () => {
  const safe = `
    export async function GET(req) {
      const session = await getServerSession();
      const invoice = await prisma.invoice.findFirst({ where: { id: req.query.id, organizationId: session.orgId } });
      return Response.json(invoice);
    }`;
  assert.equal(classifyRouteFile(safe).leak, false);
});

test('PROOF: route-org-scoping honours a custom tenant column (account_id) via config', () => {
  const safe = `
    export async function GET(req) {
      const auth = await withApiAuth(req);
      const row = await supabase.from('t').select().eq('id', req.query.id).eq('account_id', auth.accountId);
      return Response.json(row);
    }`;
  // With the default tenant signals it would still be safe (account_id is in defaults),
  // but prove it's configurable to a non-default column too.
  const custom = safe.replace('account_id', 'workspace').replace('accountId', 'workspace');
  assert.equal(classifyRouteFile(custom, { tenantSignals: ['workspace'] }).leak, false);
});

test('PROOF: route-org-scoping flags a Drizzle bare-id read', () => {
  const drizzle = `
    export async function GET(req) {
      const auth = await withApiAuth(req);
      return Response.json(await db.select().from(invoices).where(eq(invoices.id, req.query.id)));
    }`;
  assert.equal(classifyRouteFile(drizzle).leak, true);
});

test('PROOF: route-org-scoping clears a Drizzle read scoped by tenant', () => {
  const safe = `
    export async function GET(req) {
      const auth = await withApiAuth(req);
      return Response.json(await db.select().from(invoices)
        .where(and(eq(invoices.id, req.query.id), eq(invoices.organization_id, auth.orgId))));
    }`;
  assert.equal(classifyRouteFile(safe).leak, false);
});

// ── The honest, remaining boundary: raw SQL is not in the default ─────
test('BOUNDARY: default idFilter does NOT catch raw SQL "where id =" (configurable, documented)', () => {
  const rawSql = `
    export async function GET(req) {
      const auth = await withApiAuth(req);
      return Response.json(await db.query('select * from invoices where id = $1', [req.query.id]));
    }`;
  assert.equal(classifyRouteFile(rawSql).filtersById, false);
  // …but you can opt into it with a one-line config widening:
  const withRawSql = classifyRouteFile(rawSql, {
    idFilterPattern: `\\bwhere\\s+id\\s*=`,
  });
  assert.equal(withRawSql.leak, true);
});
