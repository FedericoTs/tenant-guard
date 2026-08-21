/**
 * identity-trust end-to-end against a REAL Postgres (embedded via pglite).
 *
 * The load-bearing test is the FORGERY PROOF: a policy that authorizes from
 * `user_metadata` is defeated by setting `user_metadata.org_id` to the victim's
 * id — which any user can do to themselves through the Supabase client. The
 * control arm (forging a tenant that cannot exist) is what keeps it falsifiable:
 * a table that is simply open to everyone must NOT be blamed on user_metadata.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/identity-trust.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('identity-trust integration (pglite not installed — skipped)', { skip: true }, () => {});
}

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

const SEED = `
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select on invoices to authenticated;
  insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200),('org_B',300);
  alter table invoices enable row level security;
`;

if (PGlite) {
  // ── 3.8, the commonest shape: an admin flag on the table whose OWN policy
  //    reads it. No cross-table dependency exists, so the dependency-driven
  //    lookup never examined this table at all.
  test('CATCHES a self-settable admin flag when the policy is on the same table', async () => {
    const { query } = await fresh(`
      create table profiles (
        id uuid primary key default gen_random_uuid(),
        organization_id text not null,
        is_admin boolean not null default false
      );
      grant select, update on profiles to authenticated;
      alter table profiles enable row level security;
      create policy self_update on profiles for update
        using (id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid)
        with check (id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid);
      create policy admin_reads_all on profiles for select
        using (is_admin or organization_id = current_setting('app.current_tenant', true));
      insert into profiles (organization_id) values ('org_A'), ('org_B');
    `);
    const res = await check({ query, config: { claim: 'org_id' } });
    const v = res.violations.find((x) => x.kind === 'self-escalation');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /is_admin/);
    assert.match(v.message, /RLS is ROW-level/);
    assert.match(v.fix, /GRANT UPDATE \(/);
  });

  test('a column-level GRANT is recognised as the fix — no finding once applied', async () => {
    const { query } = await fresh(`
      create table profiles (
        id uuid primary key default gen_random_uuid(),
        organization_id text not null,
        is_admin boolean not null default false,
        display_name text
      );
      grant select on profiles to authenticated;
      grant update (display_name) on profiles to authenticated;   -- the fix
      alter table profiles enable row level security;
      create policy self_update on profiles for update
        using (id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid)
        with check (id = (current_setting('request.jwt.claims', true)::json ->> 'sub')::uuid);
      create policy admin_reads_all on profiles for select
        using (is_admin or organization_id = current_setting('app.current_tenant', true));
      insert into profiles (organization_id) values ('org_A'), ('org_B');
    `);
    const res = await check({ query, config: { claim: 'org_id' } });
    assert.equal(res.violations.filter((v) => v.kind === 'self-escalation').length, 0);
  });

  test('PROVES the user_metadata leak: forging the claim reads another tenant', async () => {
    const { query } = await fresh(`
      ${SEED}
      -- The bug: authorizing from user_metadata, which the USER can rewrite.
      create policy tenant on invoices for select to authenticated
        using (organization_id = (current_setting('request.jwt.claims', true)::json -> 'user_metadata' ->> 'org_id'));
    `);
    const res = await check({ query, config: { claim: 'org_id' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'user-metadata');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /PROVEN by forgery/);
    assert.match(v.message, /granted [1-9][0-9]* row\(s\)/); // count depends on which tenant the sampler picks first
    assert.match(v.fix, /app_metadata/);
  });

  test('does NOT blame user_metadata for a table that is simply open to everyone (control arm)', async () => {
    const { query } = await fresh(`
      ${SEED}
      -- Reads user_metadata, but the OR true makes it open regardless — forging
      -- the claim grants nothing that was not already granted. rls-proof is the
      -- guard that should flag this table, not a forgery finding.
      create policy tenant on invoices for select to authenticated
        using (true or organization_id = (current_setting('request.jwt.claims', true)::json -> 'user_metadata' ->> 'org_id'));
    `);
    const res = await check({ query, config: { claim: 'org_id' } });
    const proven = res.violations.filter((x) => /PROVEN by forgery/.test(x.message));
    assert.equal(proven.length, 0, JSON.stringify(res.violations, null, 2));
  });

  test('still FLAGS user_metadata from the policy text when the probe cannot run (one tenant only)', async () => {
    const { query } = await fresh(`
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A');   -- a single tenant: nothing to forge into
      alter table invoices enable row level security;
      create policy tenant on invoices for select to authenticated
        using (organization_id = (current_setting('request.jwt.claims', true)::json -> 'user_metadata' ->> 'org_id'));
    `);
    const res = await check({ query, config: { claim: 'org_id' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'user-metadata');
    assert.ok(v);
    assert.match(v.message, /writable BY THE USER/);
    assert.doesNotMatch(v.message, /PROVEN/); // never claims more than it proved
  });

  test('does NOT flag app_metadata (server-controlled — the correct source)', async () => {
    const { query } = await fresh(`
      ${SEED}
      create policy tenant on invoices for select to authenticated
        using (organization_id = (current_setting('request.jwt.claims', true)::json -> 'app_metadata' ->> 'org_id'));
    `);
    const res = await check({ query, config: { claim: 'org_id' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
  });

  test('FLAGS a callable SECURITY DEFINER function that sets the trusted GUC from its ARGUMENT', async () => {
    const { query } = await fresh(`
      ${SEED}
      create policy tenant on invoices for select to authenticated
        using (organization_id = current_setting('app.current_tenant', true));
      -- A "become any tenant" primitive: the caller picks the tenant.
      create function set_tenant(target text) returns void
        language plpgsql security definer as $$
        begin
          perform set_config('app.current_tenant', target, true);
        end $$;
      grant execute on function set_tenant(text) to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'forgeable-guc');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.where, /set_tenant/);
    assert.match(v.message, /become any tenant/i);
    assert.match(v.fix, /REVOKE EXECUTE/);
  });

  test('does NOT flag a definer function that derives the tenant from the SESSION, not an argument', async () => {
    const { query } = await fresh(`
      ${SEED}
      create policy tenant on invoices for select to authenticated
        using (organization_id = current_setting('app.current_tenant', true));
      create function sync_tenant() returns void
        language plpgsql security definer as $$
        begin
          perform set_config('app.current_tenant', (current_setting('request.jwt.claims', true)::json ->> 'org_id'), true);
        end $$;
      grant execute on function sync_tenant() to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    // it is still surfaced as a note to review, just not a build failure
    assert.ok(res.notes.some((n) => /sync_tenant/.test(n.where)), JSON.stringify(res.notes, null, 2));
  });

  test('does NOT fail the build merely for authorizing from a settable GUC — advisory only', async () => {
    const { query } = await fresh(`
      ${SEED}
      create policy tenant on invoices for select to authenticated
        using (organization_id = current_setting('app.current_tenant', true));
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    const note = res.notes.find((n) => /app\.current_tenant/.test(n.where));
    assert.ok(note, JSON.stringify(res.notes, null, 2));
    assert.match(note.message, /client-settable/);
    assert.match(note.message, /signature-verified token/);
  });

  test('skips cleanly when no tenant policies exist (a skip is never a pass)', async () => {
    const { query } = await fresh(`create table notes (id serial primary key, body text);`);
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.equal(res.skipped, true);
    assert.match(res.summary, /no tenant policies/);
  });
}
