/**
 * identity-trust — the five audit findings, each pinned by a test that fails
 * without the fix.
 *
 * Four of the five were the guard reporting a build-breaking violation on code
 * that the database itself refuses to escalate through, or on code that has no
 * write path at all. That is the most expensive failure mode this project has:
 * a developer who cannot silence a finding by writing correct code eventually
 * silences it by writing incorrect code. Every "does NOT fire" test below is
 * paired with a control that still DOES fire, so narrowing can never be
 * mistaken for the check going quiet.
 *
 * The fifth is the mirror image — an INSERT self-grant that the guard could not
 * see because the grant was per-column — and the sixth thing fixed here is
 * advice that did not compile when pasted.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  check,
  writePoliciesSql,
  allPoliciesSql,
  authorityDetailSql,
  classifyAuthority,
  classifySelfEscalation,
  policyTextForMatching,
  policyAppliesToRole,
  isRestrictivePolicy,
  userMetadataFix,
} from '../src/guards/identity-trust.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('identity-trust audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(`create role service_role nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

// ── pure: what a policy row means ────────────────────────────────────

test('writePoliciesSql asks for permissive AND role applicability, and takes the role', () => {
  const { text, values } = writePoliciesSql(['public.memberships'], 'authenticated');
  assert.match(text, /p\.permissive/);
  assert.match(text, /pg_has_role/);
  // 'public' in pg_policies.roles means "every role" and is not a real role —
  // handing it to pg_has_role raises "role public does not exist".
  assert.match(text, /r <> 'public'/);
  assert.deepEqual(values, [['public.memberships'], 'authenticated']);
});

test('allPoliciesSql carries the same two dimensions (3.8 reads it too)', () => {
  const { text, values } = allPoliciesSql(['public'], 'authenticated');
  assert.match(text, /p\.permissive/);
  assert.match(text, /pg_has_role/);
  assert.deepEqual(values, [['public'], 'authenticated']);
});

test('policyAppliesToRole / isRestrictivePolicy default to the permissive, applicable reading', () => {
  assert.equal(policyAppliesToRole({}), true);          // absent => assume it applies
  assert.equal(policyAppliesToRole({ applies_to_role: false }), false);
  assert.equal(policyAppliesToRole({ applies_to_role: 't' }), true);
  assert.equal(isRestrictivePolicy({}), false);
  assert.equal(isRestrictivePolicy({ permissive: 'RESTRICTIVE' }), true);
  assert.equal(isRestrictivePolicy({ permissive: 'PERMISSIVE' }), false);
});

test('classifyAuthority: a RESTRICTIVE policy is never the grant', () => {
  // Measured: adding this restrictive policy next to a permissive one that
  // already pins organization_id left the self-grant BLOCKED at the database and
  // flipped the guard from ok:true to ok:false, naming the restrictive policy.
  const v = classifyAuthority({
    schema: 'public', table: 'memberships', tenantColumn: 'organization_id',
    rlsEnabled: true, canInsert: true,
    writePolicies: [
      { policy: 'own_org_only', cmd: 'INSERT', permissive: 'PERMISSIVE', applies_to_role: true, with_check: `(organization_id = current_setting('app.tenant'))` },
      { policy: 'self_rows_only', cmd: 'INSERT', permissive: 'RESTRICTIVE', applies_to_role: true, with_check: '(user_id = auth.uid())' },
    ],
  });
  assert.equal(v.status, 'safe');
});

test('classifyAuthority: a RESTRICTIVE policy that DOES pin the tenant makes it safe', () => {
  const v = classifyAuthority({
    schema: 'public', table: 'memberships', tenantColumn: 'organization_id',
    rlsEnabled: true, canInsert: true,
    writePolicies: [
      { policy: 'anyone', cmd: 'INSERT', permissive: 'PERMISSIVE', applies_to_role: true, with_check: '(user_id = auth.uid())' },
      { policy: 'own_org', cmd: 'INSERT', permissive: 'RESTRICTIVE', applies_to_role: true, with_check: `(organization_id = current_setting('app.tenant'))` },
    ],
  });
  assert.equal(v.status, 'safe'); // restrictive is ANDed: it narrows which tenants are reachable
});

test('classifyAuthority: a write policy scoped to another role is not this role\'s write path', () => {
  const v = classifyAuthority({
    schema: 'public', table: 'memberships', tenantColumn: 'organization_id',
    rlsEnabled: true, canInsert: true, canUpdate: true, role: 'authenticated',
    writePolicies: [
      { policy: 'backend_writes', cmd: 'ALL', permissive: 'PERMISSIVE', applies_to_role: false, qual: 'true', with_check: 'true' },
    ],
  });
  assert.equal(v.status, 'safe');
});

test('classifyAuthority: the real near-miss still leaks (the narrowing did not go quiet)', () => {
  const v = classifyAuthority({
    schema: 'public', table: 'memberships', tenantColumn: 'organization_id',
    rlsEnabled: true, canInsert: true,
    writePolicies: [
      { policy: 'self', cmd: 'INSERT', permissive: 'PERMISSIVE', applies_to_role: true, with_check: '(user_id = auth.uid())' },
    ],
  });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /never constrains "organization_id"/);
});

test('classifyAuthority: the role OWNING the table bypasses RLS unless it is FORCED', () => {
  // Without this, "no policy applies to my role => denied" is wrong for exactly
  // one role: the owner. Verified in PGlite — table owned by the app role, RLS
  // enabled, ZERO policies, insert ALLOWED.
  const owned = {
    schema: 'public', table: 'memberships', tenantColumn: 'organization_id',
    rlsEnabled: true, canInsert: true, role: 'authenticated', ownerRole: 'authenticated',
    writePolicies: [],
  };
  assert.equal(classifyAuthority(owned).status, 'leak');
  assert.match(classifyAuthority(owned).message, /OWNS public\.memberships/);
  assert.equal(classifyAuthority({ ...owned, rlsForced: true }).status, 'safe');
  assert.equal(classifyAuthority({ ...owned, ownerRole: 'postgres' }).status, 'safe');
});

test('authorityDetailSql scopes the write test to the TENANT COLUMN, not to any column', () => {
  const { text } = authorityDetailSql(['public.memberships'], ['organization_id'], 'authenticated');
  assert.match(text, /has_column_privilege\(\$3::text, c\.oid, tc\.attnum, 'INSERT'\)/);
  // any-column is the no-tenant-column fallback ONLY: `grant insert (user_id)`
  // with the tenant column deliberately ungrantable is the hardened shape this
  // guard recommends, and any-column would fail the build on it.
  assert.match(text, /tc\.attnum is null and pg_catalog\.has_any_column_privilege/);
  assert.match(text, /c\.relowner::regrole::text as owner_role/);
});

// ── pure: which policy text can possibly read a column ───────────────

test('policyTextForMatching removes auth.<fn> so auth.role() is not read as a "role" column', () => {
  const stripped = policyTextForMatching(`((auth.role() = 'authenticated'::text) AND (organization_id = current_setting('app.t'::text, true)))`);
  assert.equal(/\brole\b/i.test(stripped), false);
  assert.match(stripped, /organization_id/);
  // real column references survive, including one that merely contains "role"
  assert.match(policyTextForMatching(`(role = 'admin'::text)`), /\brole\b/);
  assert.match(policyTextForMatching(`(user_role = 'admin')`), /user_role/);
  assert.equal(/\buid\b/i.test(policyTextForMatching(`(id = auth.uid())`)), false);
});

// ── pure: self-escalation and the WITH CHECK it never read ───────────

test('classifySelfEscalation: a tenant column pinned by the UPDATE check is not escalatable', () => {
  const v = classifySelfEscalation({
    schema: 'public', table: 'documents',
    columns: [{ name: 'organization_id', canUpdate: true, isTenant: true }],
    updatePolicies: [{ policy: 'd_upd', cmd: 'UPDATE', qual: '(organization_id in (select current_org_ids()))', with_check: '(organization_id in (select current_org_ids()))' }],
    referencedColumns: [],
  });
  assert.equal(v.status, 'safe');
});

test('classifySelfEscalation: ANY unconstrained applicable policy is enough (permissive checks are OR-ed)', () => {
  // Measured: two permissive UPDATE policies, one pinning organization_id and
  // one not — `UPDATE documents SET organization_id='org_B'` SUCCEEDED.
  const v = classifySelfEscalation({
    schema: 'public', table: 'documents',
    columns: [{ name: 'organization_id', canUpdate: true, isTenant: true }],
    updatePolicies: [
      { policy: 'd_upd', cmd: 'UPDATE', with_check: '(organization_id in (select current_org_ids()))' },
      { policy: 'd_upd2', cmd: 'UPDATE', with_check: '(owner = auth.uid())' },
    ],
    referencedColumns: [],
  });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /re-parents the row into another tenant/);
});

test('classifySelfEscalation: permissive/restrictive read the same way as classifyAuthority', () => {
  const base = {
    schema: 'public', table: 'documents',
    columns: [{ name: 'organization_id', canUpdate: true, isTenant: true }],
    referencedColumns: [],
  };
  // A RESTRICTIVE policy is ANDed on, so one that pins the tenant column blocks
  // the hop no matter what the permissive policy allows.
  assert.equal(classifySelfEscalation({
    ...base,
    updatePolicies: [
      { policy: 'anyone', cmd: 'UPDATE', permissive: 'PERMISSIVE', with_check: '(id > 0)' },
      { policy: 'own_org', cmd: 'UPDATE', permissive: 'RESTRICTIVE', with_check: '(organization_id in (select current_org_ids()))' },
    ],
  }).status, 'safe');
  // …and a RESTRICTIVE policy on its own is not an update path at all.
  assert.equal(classifySelfEscalation({
    ...base,
    updatePolicies: [{ policy: 'own_org', cmd: 'UPDATE', permissive: 'RESTRICTIVE', with_check: '(id > 0)' }],
  }).status, 'safe');
  // control: permissive-only and unconstrained is still a leak
  assert.equal(classifySelfEscalation({
    ...base,
    updatePolicies: [{ policy: 'anyone', cmd: 'UPDATE', permissive: 'PERMISSIVE', with_check: '(id > 0)' }],
  }).status, 'leak');
});

test('classifySelfEscalation: a NON-tenant authorization column keeps firing under id = auth.uid()', () => {
  // The gate is deliberately tenant-only: `WITH CHECK (id = auth.uid())` says
  // nothing whatever about `role`, which is the bug 3.8 exists for.
  const v = classifySelfEscalation({
    schema: 'public', table: 'profiles',
    columns: [{ name: 'role', canUpdate: true, isTenant: false }],
    updatePolicies: [{ policy: 'self', cmd: 'UPDATE', qual: '(id = auth.uid())', with_check: '(id = auth.uid())' }],
    referencedColumns: ['role'],
  });
  assert.equal(v.status, 'leak');
});

// ── pure: advice that has to compile ─────────────────────────────────

test('userMetadataFix types the comparison and keeps column and claim key separate', () => {
  // uuid = text is 42883 "operator does not exist" — the commonest tenant type.
  assert.match(userMetadataFix('org_id', 'uuid', 'org_id'), /"org_id" = \(auth\.jwt\(\) -> 'app_metadata' ->> 'org_id'\)::uuid/);
  assert.match(userMetadataFix('org_id', 'text', 'org_id'), /"org_id" = \(auth\.jwt\(\) -> 'app_metadata' ->> 'org_id'\)\)/);
  assert.match(userMetadataFix('org_id', 'bigint', 'org_id'), /"org_id"::text = /);
  assert.match(userMetadataFix('org_id', null, 'org_id'), /"org_id" = /);
  // column and claim are different things: `claim: 'tenant'` on an
  // organization_id table used to print `USING (tenant = … ->> 'tenant')`.
  const mixed = userMetadataFix('organization_id', 'text', 'tenant');
  assert.match(mixed, /"organization_id" = \(auth\.jwt\(\) -> 'app_metadata' ->> 'tenant'\)/);
  assert.doesNotMatch(mixed, /\(tenant =/);
});

// ── integration ──────────────────────────────────────────────────────

if (PGlite) {
  test('a defence-in-depth RESTRICTIVE policy and a service_role-only write policy are not leaks', async () => {
    // Three authority tables in one database, all reached through pg_depend.
    // mem_leaky is the control: if the narrowing had gone too far, it would go
    // quiet too and this test would not be able to tell.
    const { query } = await fresh(`
      create table mem_restrictive (user_id uuid not null, organization_id text not null);
      grant select, insert on mem_restrictive to authenticated;
      alter table mem_restrictive enable row level security;
      create policy r_ins on mem_restrictive for insert to authenticated
        with check (organization_id = current_setting('app.current_tenant', true));
      create policy r_self on mem_restrictive as restrictive for insert to authenticated
        with check (user_id = (current_setting('app.uid', true))::uuid);

      create table mem_backend (user_id uuid not null, organization_id text not null);
      grant select, insert, update on mem_backend to authenticated;
      grant all on mem_backend to service_role;
      alter table mem_backend enable row level security;
      create policy b_read on mem_backend for select to authenticated
        using (user_id = (current_setting('app.uid', true))::uuid);
      create policy b_write on mem_backend for all to service_role using (true) with check (true);

      create table mem_leaky (user_id uuid not null, organization_id text not null);
      grant select, insert on mem_leaky to authenticated;
      alter table mem_leaky enable row level security;
      create policy l_ins on mem_leaky for insert to authenticated
        with check (user_id = (current_setting('app.uid', true))::uuid);

      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A'),('org_B');
      alter table invoices enable row level security;
      create policy i1 on invoices for select using (
        organization_id in (select m.organization_id from mem_restrictive m where m.user_id = (current_setting('app.uid', true))::uuid));
      create policy i2 on invoices for select using (
        organization_id in (select m.organization_id from mem_backend m where m.user_id = (current_setting('app.uid', true))::uuid));
      create policy i3 on invoices for select using (
        organization_id in (select m.organization_id from mem_leaky m where m.user_id = (current_setting('app.uid', true))::uuid));
    `);
    const res = await check({ query });
    const where = res.violations.map((v) => v.where);
    assert.equal(where.includes('public.mem_restrictive'), false, JSON.stringify(res.violations, null, 2));
    assert.equal(where.includes('public.mem_backend'), false, JSON.stringify(res.violations, null, 2));
    assert.ok(where.includes('public.mem_leaky'), 'the control must still fire: ' + JSON.stringify(res.violations, null, 2));
    // 3.8 reads the same two dimensions: a service_role-only write policy is not
    // an UPDATE path for `authenticated` either.
    assert.equal(res.violations.some((v) => v.kind === 'self-escalation' && v.where === 'public.mem_backend'), false,
      JSON.stringify(res.violations, null, 2));
  });

  test('a per-COLUMN INSERT grant covering the tenant column is a self-grant the guard must see', async () => {
    // Verified against the database: with these grants, as `authenticated`,
    // `insert into <t> values (u1,'org_B')` succeeds on mem_open and takes
    // invoices from 1 visible row to 2; on mem_locked it fails with
    // "permission denied for table mem_locked".
    const { query } = await fresh(`
      create table mem_open (user_id uuid not null, organization_id text not null, primary key (user_id, organization_id));
      grant select on mem_open to authenticated;
      grant insert (user_id, organization_id) on mem_open to authenticated;
      alter table mem_open enable row level security;
      create policy o_sel on mem_open for select to authenticated using (user_id = (current_setting('app.uid', true))::uuid);
      create policy o_ins on mem_open for insert to authenticated with check (user_id = (current_setting('app.uid', true))::uuid);

      create table mem_locked (user_id uuid not null, organization_id text not null, primary key (user_id, organization_id));
      grant select on mem_locked to authenticated;
      grant insert (user_id) on mem_locked to authenticated;   -- tenant column NOT grantable: the hardened shape
      alter table mem_locked enable row level security;
      create policy k_sel on mem_locked for select to authenticated using (user_id = (current_setting('app.uid', true))::uuid);
      create policy k_ins on mem_locked for insert to authenticated with check (user_id = (current_setting('app.uid', true))::uuid);

      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A'),('org_B');
      alter table invoices enable row level security;
      create policy i1 on invoices for select using (
        organization_id in (select m.organization_id from mem_open m where m.user_id = (current_setting('app.uid', true))::uuid));
      create policy i2 on invoices for select using (
        organization_id in (select m.organization_id from mem_locked m where m.user_id = (current_setting('app.uid', true))::uuid));
    `);
    const res = await check({ query });
    const open = res.violations.find((v) => v.kind === 'writable-authority' && v.where === 'public.mem_open');
    assert.ok(open, JSON.stringify(res, null, 2));
    assert.equal(res.violations.some((v) => v.where === 'public.mem_locked'), false,
      'the hardened per-column grant must stay silent: ' + JSON.stringify(res.violations, null, 2));
  });

  test('auth.role() on an unrelated table does not promote profiles.role from note to violation', async () => {
    const { query } = await fresh(`
      create schema auth;
      create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('app.uid', true),'')::uuid $$;
      create function auth.role() returns text language sql stable as $$ select 'authenticated'::text $$;

      create table profiles (id uuid primary key, display_name text, role text default 'member');
      grant select, update on profiles to authenticated;
      alter table profiles enable row level security;
      create policy self_update on profiles for update to authenticated
        using (id = auth.uid()) with check (id = auth.uid());

      create table docs (id serial primary key, organization_id text not null);
      grant select on docs to authenticated;
      alter table docs enable row level security;
      -- the stock Supabase idiom. Nothing here reads profiles.role.
      create policy t on docs for select to authenticated
        using (auth.role() = 'authenticated' and organization_id = current_setting('app.current_tenant', true));
    `);
    const res = await check({ query });
    assert.equal(res.violations.some((v) => v.kind === 'self-escalation'), false, JSON.stringify(res.violations, null, 2));
    // still surfaced, at the honest confidence level: no policy authorizes from it
    assert.ok(res.notes.some((n) => n.where === 'public.profiles' && /No policy authorizes from it/.test(n.message)),
      JSON.stringify(res.notes, null, 2));
  });

  test('the canonical Supabase tenant table — WITH CHECK pins the tenant — is not a self-escalation', async () => {
    // Verified as `authenticated` inside a transaction: `update documents set
    // organization_id='org_B'` is REFUSED 42501, while updating `title` on the
    // same rows succeeds. The guard used to fail the build on this.
    const { query } = await fresh(`
      create schema auth;
      create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('app.uid', true),'')::uuid $$;

      create table memberships (user_id uuid not null, organization_id text not null);
      grant select on memberships to authenticated;   -- read-only: no self-grant
      alter table memberships enable row level security;
      create policy m_self on memberships for select to authenticated using (user_id = auth.uid());

      create function current_org_ids() returns setof text
        language sql security definer set search_path = public, pg_temp stable as
        $$ select organization_id from memberships where user_id = auth.uid() $$;
      grant execute on function current_org_ids() to authenticated;

      create table documents (id serial primary key, organization_id text not null, title text);
      grant select, insert, update, delete on documents to authenticated;
      alter table documents enable row level security;
      create policy d_sel on documents for select to authenticated using (organization_id in (select current_org_ids()));
      create policy d_ins on documents for insert to authenticated with check (organization_id in (select current_org_ids()));
      create policy d_upd on documents for update to authenticated
        using (organization_id in (select current_org_ids()))
        with check (organization_id in (select current_org_ids()));
      insert into documents (organization_id, title) values ('org_A','a'),('org_B','b');
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('an UPDATE policy that leaves the tenant open still fails the build (control for the above)', async () => {
    const { query } = await fresh(`
      create schema auth;
      create function auth.uid() returns uuid language sql stable as $$ select nullif(current_setting('app.uid', true),'')::uuid $$;
      create table documents (id serial primary key, organization_id text not null, title text);
      grant select, update on documents to authenticated;
      alter table documents enable row level security;
      create policy d_sel on documents for select to authenticated using (organization_id = current_setting('app.current_tenant', true));
      create policy d_upd on documents for update to authenticated
        using (id > 0) with check (id > 0);   -- pins nothing about the tenant
      insert into documents (organization_id, title) values ('org_A','a'),('org_B','b');
    `);
    const res = await check({ query });
    const v = res.violations.find((x) => x.kind === 'self-escalation');
    assert.ok(v, JSON.stringify(res, null, 2));
    assert.match(v.message, /re-parents the row into another tenant/);
  });

  test('the user_metadata fix compiles when pasted — uuid column, claim key that differs from it', async () => {
    const { db, query } = await fresh(`
      create schema auth;
      create function auth.jwt() returns jsonb language sql stable as
        $$ select coalesce(nullif(current_setting('request.jwt.claims', true),''),'{}')::jsonb $$;
      create table notes (id serial primary key, org_id uuid not null, body text);
      grant select on notes to authenticated;
      alter table notes enable row level security;
      create policy tenant on notes for select to authenticated
        using (org_id::text = (auth.jwt() -> 'user_metadata' ->> 'tenant'));
      insert into notes (org_id, body) values
        ('11111111-1111-1111-1111-111111111111','a'),
        ('22222222-2222-2222-2222-222222222222','b');
    `);
    const res = await check({ query, config: { claim: 'tenant' } });
    const v = res.violations.find((x) => x.kind === 'user-metadata');
    assert.ok(v, JSON.stringify(res, null, 2));
    const m = v.fix.match(/USING \((.*)\)\s+--/);
    assert.ok(m, v.fix);
    // The whole point: run the advice. It used to raise
    // `operator does not exist: uuid = text`, or name a column that is not there.
    await db.exec(`create policy pasted on notes for select to authenticated using (${m[1]})`);
  });
}
