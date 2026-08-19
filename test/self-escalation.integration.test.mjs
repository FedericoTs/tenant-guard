/**
 * Threat-model 3.8 — self-row escalation.
 *
 * `CREATE POLICY self ON profiles FOR UPDATE
 *    USING (id = auth.uid()) WITH CHECK (id = auth.uid());`
 *
 * is exactly right, and exactly the bug. **RLS is ROW-level**: it decides *which
 * rows* you may touch and says nothing about *which columns*. So a policy that
 * correctly confines you to your own row still lets you rewrite every field of
 * it — including the `role` another policy reads to grant admin access, or the
 * `organization_id` that decides which tenant you belong to.
 *
 * The only thing that actually stops it is a column-level GRANT, so that is what
 * this check reads (`has_column_privilege`), and that is what the fix says.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/identity-trust.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('self-escalation integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

// invoices' access is decided by profiles.role — the classic admin-flag shape.
const ADMIN_GATED = `
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select on invoices to authenticated;
  insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200);
  alter table invoices enable row level security;
  create policy admin_all on invoices for select using (
    exists (select 1 from profiles p
             where p.id = (current_setting('app.uid', true))::uuid and p.role = 'admin')
  );
`;

if (PGlite) {
  test('FLAGS a self-update policy that lets a user set their own profiles.role', async () => {
    const { query } = await fresh(`
      create table profiles (id uuid primary key, display_name text, role text not null default 'member');
      grant select, update on profiles to authenticated;   -- table-wide UPDATE: every column
      alter table profiles enable row level security;
      -- Textbook-correct, and still the bug: it pins the ROW, not the COLUMNS.
      create policy self on profiles for update
        using (id = (current_setting('app.uid', true))::uuid)
        with check (id = (current_setting('app.uid', true))::uuid);
      ${ADMIN_GATED}
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'self-escalation');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.equal(v.where, 'public.profiles');
    assert.match(v.message, /may UPDATE "role"/);
    assert.match(v.message, /RLS is ROW-level/);
    assert.match(v.message, /read by a policy to decide access/);
    assert.match(v.fix, /GRANT UPDATE \(/);       // the fix is a column grant...
    assert.doesNotMatch(v.fix, /CREATE POLICY/);  // ...not a policy change
  });

  test('does NOT flag when column-level GRANTs keep the authorization column unwritable', async () => {
    const { query } = await fresh(`
      create table profiles (id uuid primary key, display_name text, role text not null default 'member');
      grant select on profiles to authenticated;
      grant update (display_name) on profiles to authenticated;   -- the actual fix
      alter table profiles enable row level security;
      create policy self on profiles for update
        using (id = (current_setting('app.uid', true))::uuid)
        with check (id = (current_setting('app.uid', true))::uuid);
      ${ADMIN_GATED}
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((x) => x.kind === 'self-escalation'), false, JSON.stringify(res.violations, null, 2));
  });

  test('FLAGS re-parenting: a user can UPDATE their own organization_id into another tenant', async () => {
    const { query } = await fresh(`
      create table profiles (id uuid primary key, organization_id text not null, display_name text);
      grant select, update on profiles to authenticated;
      alter table profiles enable row level security;
      create policy self on profiles for update
        using (id = (current_setting('app.uid', true))::uuid)
        with check (id = (current_setting('app.uid', true))::uuid);
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A'),('org_B');
      alter table invoices enable row level security;
      create policy tenant on invoices for select using (
        organization_id in (select p.organization_id from profiles p
                             where p.id = (current_setting('app.uid', true))::uuid)
      );
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => x.kind === 'self-escalation');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /may UPDATE "organization_id"/);
    assert.match(v.message, /re-parents the row into another tenant/);
  });

  test('does NOT flag when there is no UPDATE policy at all (updates are denied)', async () => {
    const { query } = await fresh(`
      create table profiles (id uuid primary key, display_name text, role text not null default 'member');
      grant select, update on profiles to authenticated;
      alter table profiles enable row level security;
      create policy read_self on profiles for select
        using (id = (current_setting('app.uid', true))::uuid);   -- reads only
      ${ADMIN_GATED}
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((x) => x.kind === 'self-escalation'), false, JSON.stringify(res.violations, null, 2));
  });

  test('does NOT flag a writable column that no policy reads (not every column is authority)', async () => {
    const { query } = await fresh(`
      -- 'plan' is in the authorization-column list, but nothing authorizes from
      -- it here, so writing it escalates nothing.
      create table profiles (id uuid primary key, display_name text, plan text default 'free');
      grant select, update on profiles to authenticated;
      alter table profiles enable row level security;
      create policy self on profiles for update
        using (id = (current_setting('app.uid', true))::uuid)
        with check (id = (current_setting('app.uid', true))::uuid);
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A');
      alter table invoices enable row level security;
      create policy any_profile on invoices for select using (
        exists (select 1 from profiles p where p.id = (current_setting('app.uid', true))::uuid)
      );
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((x) => x.kind === 'self-escalation'), false, JSON.stringify(res.violations, null, 2));
  });
}
