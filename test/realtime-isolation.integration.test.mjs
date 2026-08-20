/**
 * Supabase Realtime isolation (threat-model 5.4) against a real Postgres.
 *
 * Broadcast and Presence authorize channel access through RLS on
 * `realtime.messages`, and the tenant lives in the **topic**, not a column. Two
 * consequences, both tested here:
 *
 *   • with no RLS (or a permissive policy) any client subscribes to any tenant's
 *     channel and reads the payloads flowing through it;
 *   • joining is a WRITE, so an unpinned INSERT policy lets a user *publish* into
 *     another tenant's live channel — fabricated events straight into their
 *     running app. A correct read policy does not prevent that.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check } from '../src/guards/realtime-isolation.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('realtime integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const SCHEMA = `
  create schema realtime;
  create table realtime.messages (
    id uuid primary key default gen_random_uuid(),
    topic text not null,
    extension text not null default 'broadcast',
    event text,
    payload jsonb,
    private boolean default true,
    inserted_at timestamptz default now()
  );
  grant usage on schema realtime to authenticated;
  grant select, insert on realtime.messages to authenticated;
`;

const SEED = `
  insert into realtime.messages (topic, event) values
    ('org_A:notifications','ping'),
    ('org_B:notifications','ping'),
    ('org_B:presence','join');
`;

const READ_SCOPED = `
  create policy tenant_channels on realtime.messages for select
    using (split_part(topic, ':', 1) = current_setting('app.current_tenant', true));
`;

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  test('FLAGS realtime.messages with RLS off — any client joins any tenant\'s channel', async () => {
    const { query } = await fresh(`${SCHEMA} ${SEED}`);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where === 'realtime.messages');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /ROW LEVEL SECURITY is not enabled/);
    assert.match(v.message, /publish into it/);
    assert.match(v.fix, /tenant_publish/);
  });

  test('CATCHES a cross-tenant channel READ when the policy does not pin the topic', async () => {
    const { query } = await fresh(`
      ${SCHEMA} ${SEED}
      alter table realtime.messages enable row level security;
      create policy any_channel on realtime.messages for select using (true);
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'read');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /read \d+ message\(s\) on ANOTHER tenant's channel/);
  });

  test('CATCHES publishing INTO another tenant\'s channel, with reads correctly scoped', async () => {
    const { query } = await fresh(`
      ${SCHEMA} ${SEED}
      alter table realtime.messages enable row level security;
      ${READ_SCOPED}
      -- the bug: the client picks the topic when it joins, and nothing pins it
      create policy any_publish on realtime.messages for insert with check (true);
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'write');
    assert.ok(v, JSON.stringify(res.violations, null, 2));
    assert.match(v.message, /PUBLISHED into ANOTHER tenant's channel/);
    assert.match(v.message, /fabricated updates/);
    assert.equal(res.violations.some((x) => x.kind === 'read'), false); // reads are clean
  });

  test('PROVES isolation when both subscribe and publish pin the topic tenant', async () => {
    const { query } = await fresh(`
      ${SCHEMA} ${SEED}
      alter table realtime.messages enable row level security;
      ${READ_SCOPED}
      create policy tenant_publish on realtime.messages for insert
        with check (split_part(topic, ':', 1) = current_setting('app.current_tenant', true));
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /proven isolated/);
  });

  test('RLS on with NO policy is a note, not a leak — broadcast is denied, not secured', async () => {
    const { query } = await fresh(`
      ${SCHEMA} ${SEED}
      alter table realtime.messages enable row level security;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.ok(res.notes.some((n) => /NO policy/.test(n.message) && /denied, not secured|switched off/.test(n.message)), JSON.stringify(res.notes, null, 2));
  });

  test('reports which tenant tables stream via postgres_changes (informational, not a re-check)', async () => {
    const { query } = await fresh(`
      ${SCHEMA} ${SEED}
      alter table realtime.messages enable row level security;
      ${READ_SCOPED}
      create policy tenant_publish on realtime.messages for insert
        with check (split_part(topic, ':', 1) = current_setting('app.current_tenant', true));
      create table invoices (id serial primary key, organization_id text not null);
      create publication supabase_realtime for table invoices;
    `);
    const res = await check({ query });
    const n = res.notes.find((x) => x.where === 'supabase_realtime publication');
    assert.ok(n, JSON.stringify(res.notes, null, 2));
    assert.match(n.message, /public\.invoices/);
    assert.match(n.message, /RLS OFF/);          // invoices has no RLS: called out
    assert.match(n.message, /tenant-guard prove/); // points at the guard that owns that check
  });

  test('skips cleanly when there is no realtime schema (non-Supabase, or older Supabase)', async () => {
    const { query } = await fresh(`create table invoices (id serial primary key, organization_id text);`);
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.equal(res.skipped, true);
    assert.match(res.summary, /no realtime schema/);
  });

  test('does not claim isolation from a single tenant\'s channel traffic', async () => {
    const { query } = await fresh(`
      ${SCHEMA}
      insert into realtime.messages (topic, event) values ('org_A:notifications','ping');
      alter table realtime.messages enable row level security;
      create policy any_channel on realtime.messages for select using (true);   -- open, but one tenant
    `);
    const res = await check({ query });
    assert.ok(res.notes.some((n) => /cannot prove cross-tenant isolation/.test(n.message)), JSON.stringify(res.notes, null, 2));
  });
}
