/**
 * Supabase Storage isolation (threat-model 5.1) against a real Postgres.
 *
 * Storage is the one surface with no tenant COLUMN: tenancy lives in the object
 * path (`org_A/invoices/q1.pdf`), so the tenant is an expression over `name`.
 * Two things follow, and both are tested here:
 *
 *   • the client chooses the path on UPLOAD, so a perfect read policy still lets
 *     a user write into someone else's folder (the path-hop);
 *   • a PUBLIC bucket is served with no auth and no RLS at all, so "the path is
 *     unguessable" is not a boundary.
 *
 * The schema below mirrors Supabase's `storage.objects` / `storage.buckets`
 * closely enough to exercise the real policies people write.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/storage-isolation.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('storage integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const SCHEMA = `
  create schema storage;
  create table storage.buckets (id text primary key, name text, public boolean not null default false);
  create table storage.objects (
    id uuid primary key default gen_random_uuid(),
    bucket_id text not null references storage.buckets(id),
    name text not null,
    owner uuid,
    created_at timestamptz default now()
  );
  grant usage on schema storage to authenticated;
  grant select, insert, update, delete on storage.objects to authenticated;
  grant select on storage.buckets to authenticated;
`;

const SEED = `
  insert into storage.buckets (id, name, public) values ('docs','docs',false);
  insert into storage.objects (bucket_id, name) values
    ('docs','org_A/invoice-1.pdf'),
    ('docs','org_B/invoice-2.pdf'),
    ('docs','org_B/invoice-3.pdf');
`;

// A read policy that correctly pins the tenant path segment.
const READ_SCOPED = `
  create policy tenant_read on storage.objects for select
    using (split_part(name, '/', 1) = current_setting('app.current_tenant', true));
`;

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  test('CATCHES the upload PATH-HOP: reads are scoped, but a user can write into another tenant\'s folder', async () => {
    const { query } = await fresh(`
      ${SCHEMA} ${SEED}
      alter table storage.objects enable row level security;
      ${READ_SCOPED}
      -- the bug: the client supplies the object name on upload and nothing pins it
      create policy tenant_write on storage.objects for insert with check (true);
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'write');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /UPLOADED an object into ANOTHER tenant's folder/);
    assert.match(v.message, /client chooses the object path/);
    assert.match(v.fix, /FOR INSERT/);
    assert.equal(res.violations.some((x) => x.kind === 'read'), false); // reads are clean
  });

  test('CATCHES a cross-tenant READ when the policy does not pin the path segment', async () => {
    const { query } = await fresh(`
      ${SCHEMA} ${SEED}
      alter table storage.objects enable row level security;
      create policy any_read on storage.objects for select using (true);
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'read');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /listed \d+ object\(s\) inside ANOTHER tenant's folder/);
  });

  test('FLAGS a PUBLIC bucket holding more than one tenant\'s objects', async () => {
    const { query } = await fresh(`
      ${SCHEMA}
      insert into storage.buckets (id, name, public) values ('files','files',true);
      insert into storage.objects (bucket_id, name) values ('files','org_A/a.pdf'),('files','org_B/b.pdf');
      alter table storage.objects enable row level security;
      ${READ_SCOPED}
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'public-bucket');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /NO auth and NO row-level security/);
    assert.match(v.message, /catalog fact rather than a probe result/); // stays honest about what was observed
    assert.match(v.fix, /createSignedUrl/);
  });

  test('PROVES isolation when BOTH read and write pin the tenant path segment', async () => {
    const { query } = await fresh(`
      ${SCHEMA} ${SEED}
      alter table storage.objects enable row level security;
      ${READ_SCOPED}
      create policy tenant_write on storage.objects for insert
        with check (split_part(name, '/', 1) = current_setting('app.current_tenant', true));
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /1\/1 storage bucket\(s\) proven isolated/);
  });

  test('FLAGS storage.objects with RLS disabled outright', async () => {
    const { query } = await fresh(`${SCHEMA} ${SEED}`);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.ok(res.violations.some((v) => v.where === 'storage.objects' && /ROW LEVEL SECURITY is not enabled/.test(v.message)), JSON.stringify(res.violations, null, 2));
  });

  test('allowlist: a genuinely public asset bucket can be exempted', async () => {
    const setup = `
      ${SCHEMA}
      insert into storage.buckets (id, name, public) values ('assets','assets',true);
      insert into storage.objects (bucket_id, name) values ('assets','brand/logo.svg'),('assets','icons/x.svg');
      alter table storage.objects enable row level security;
      ${READ_SCOPED}
    `;
    const flagged = await check({ query: (await fresh(setup)).query });
    assert.equal(flagged.ok, false);
    const okd = await check({ query: (await fresh(setup)).query, config: { allowlist: ['assets'] } });
    assert.equal(okd.ok, true, JSON.stringify(okd, null, 2));
  });

  test('skips cleanly on a NON-Supabase database (no storage schema)', async () => {
    const { query } = await fresh(`create table invoices (id serial primary key, organization_id text);`);
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.equal(res.skipped, true);
    assert.match(res.summary, /no storage schema/);
  });

  test('does not claim isolation from a single-tenant bucket (never a silent pass)', async () => {
    const { query } = await fresh(`
      ${SCHEMA}
      insert into storage.buckets (id, name, public) values ('docs','docs',false);
      insert into storage.objects (bucket_id, name) values ('docs','org_A/only.pdf');
      alter table storage.objects enable row level security;
      create policy any_read on storage.objects for select using (true);   -- wide open, but one tenant
    `);
    const res = await check({ query });
    assert.ok(res.notes.some((n) => /cannot prove cross-tenant isolation/.test(n.message)), JSON.stringify(res.notes, null, 2));
  });
}
