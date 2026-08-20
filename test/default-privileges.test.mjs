/**
 * default-privileges pure-logic tests.
 *
 * The calibration is the load-bearing part here. This condition is latent, and
 * for `anon`/`authenticated` in `public` it is the stock configuration of a
 * Supabase project — so the tests below pin *what fails the build* as tightly
 * as what is merely reported.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  defaultAclSql,
  probeCreateSql,
  probeAclSql,
  eventTriggersSql,
  forcesRls,
  groupGrants,
  classifyInherited,
} from '../src/guards/default-privileges.mjs';

// ── SQL ──────────────────────────────────────────────────────────────

test('defaultAclSql: reads pg_default_acl, parameterised, and keeps the all-schemas rows', () => {
  const { text, values } = defaultAclSql(['public']);
  assert.match(text, /pg_default_acl/);
  assert.match(text, /aclexplode/);
  assert.match(text, /nspname is null/); // defaclnamespace = 0 means every schema
  assert.deepEqual(values, [['public']]);
});

test('probeCreateSql: identifiers are validated, never interpolated blind', () => {
  assert.match(probeCreateSql('public', 'tg_probe'), /create table public\.tg_probe/);
  assert.throws(() => probeCreateSql('public"; drop table users; --', 'p'));
  assert.throws(() => probeCreateSql('public', 'p; drop table users'));
});

test('probeAclSql: asks for the owner and the RLS flag alongside the grants', () => {
  const { text, values } = probeAclSql('public', 'tg_probe');
  assert.match(text, /relowner/);
  assert.match(text, /relrowsecurity/);
  assert.match(text, /left join lateral aclexplode/); // a NULL acl must still return the row
  assert.deepEqual(values, ['public', 'tg_probe']);
});

test('eventTriggersSql: reads the body, because plpgsql records no dependency for what it runs', () => {
  const { text } = eventTriggersSql();
  assert.match(text, /pg_event_trigger/);
  assert.match(text, /prosrc/);
  assert.match(text, /ddl_command_end/);
});

// ── mitigation ───────────────────────────────────────────────────────

test('forcesRls: an enabled trigger that enables RLS counts', () => {
  assert.equal(forcesRls([{ enabled: 'O', body: 'execute format($$alter table %s enable row level security$$, t)' }]), true);
});

test('forcesRls: a DISABLED trigger mitigates nothing', () => {
  assert.equal(forcesRls([{ enabled: 'D', body: 'alter table x enable row level security' }]), false);
});

test('forcesRls: an unrelated trigger does not count, and no triggers is not a mitigation', () => {
  assert.equal(forcesRls([{ enabled: 'O', body: 'insert into ddl_audit values (now())' }]), false);
  assert.equal(forcesRls([]), false);
  assert.equal(forcesRls(null), false);
});

// ── grant grouping ───────────────────────────────────────────────────

const ROWS = [
  { grantee: 'postgres', privilege: 'SELECT', owner: 'postgres', rls_enabled: false },
  { grantee: 'postgres', privilege: 'DELETE', owner: 'postgres', rls_enabled: false },
  { grantee: 'anon', privilege: 'SELECT', owner: 'postgres', rls_enabled: false },
  { grantee: 'authenticated', privilege: 'SELECT', owner: 'postgres', rls_enabled: false },
  { grantee: 'authenticated', privilege: 'INSERT', owner: 'postgres', rls_enabled: false },
];

test('groupGrants: drops the OWNER — it always holds everything, which is not a finding', () => {
  const g = groupGrants(ROWS);
  assert.deepEqual(g.map((x) => x.grantee), ['anon', 'authenticated']);
});

test('groupGrants: collapses privileges per grantee and flags write access', () => {
  const g = groupGrants(ROWS);
  assert.deepEqual(g[0], { grantee: 'anon', privileges: ['SELECT'], writes: false });
  assert.deepEqual(g[1].privileges, ['INSERT', 'SELECT']);
  assert.equal(g[1].writes, true);
});

test('groupGrants: ignores non-data privileges like TRIGGER and REFERENCES', () => {
  const g = groupGrants([
    { grantee: 'anon', privilege: 'TRIGGER', owner: 'postgres' },
    { grantee: 'anon', privilege: 'REFERENCES', owner: 'postgres' },
  ]);
  assert.deepEqual(g, []); // neither reads nor writes rows
});

test('groupGrants: a table with no ACL at all yields nothing', () => {
  assert.deepEqual(groupGrants([{ grantee: null, privilege: null, owner: 'postgres', rls_enabled: false }]), []);
});

// ── the verdict ──────────────────────────────────────────────────────

test('OK: a new table that inherits nothing beyond its owner', () => {
  const v = classifyInherited({ schema: 'public', grants: [] });
  assert.equal(v.status, 'ok');
});

test('LEAK: PUBLIC — every role that exists or ever will', () => {
  const v = classifyInherited({
    schema: 'public',
    grants: [{ grantee: 'PUBLIC', privileges: ['SELECT'], writes: false }],
  });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /rolled-back transaction/);
  assert.match(v.message, /ever will/);
  assert.match(v.fix, /REVOKE ALL ON TABLES FROM PUBLIC/);
  assert.match(v.fix, /ON ALL TABLES IN SCHEMA public/); // existing tables need their own fix
});

test('NOTE not LEAK: the stock Supabase shape must not fail every user of the platform', () => {
  const v = classifyInherited({
    schema: 'public',
    grants: [
      { grantee: 'anon', privileges: ['SELECT'], writes: false },
      { grantee: 'authenticated', privileges: ['INSERT', 'SELECT'], writes: true },
    ],
  });
  assert.equal(v.status, 'note');
  assert.match(v.message, /UNAUTHENTICATED role \(anon\)/);
  assert.match(v.message, /says nothing about the table somebody adds next week/);
  assert.match(v.message, /failRoles/); // and it names the knob to escalate
});

test('failRoles escalates the same finding to a build failure', () => {
  const grants = [{ grantee: 'anon', privileges: ['SELECT'], writes: false }];
  assert.equal(classifyInherited({ schema: 'public', grants }).status, 'note');
  assert.equal(classifyInherited({ schema: 'public', grants, config: { failRoles: ['PUBLIC', 'anon'] } }).status, 'leak');
});

test('the note leads with WRITE access when no unauthenticated role is involved', () => {
  const v = classifyInherited({
    schema: 'public',
    grants: [{ grantee: 'reporting', privileges: ['INSERT', 'SELECT'], writes: true }],
  });
  assert.equal(v.status, 'note');
  assert.match(v.message, /reporting can WRITE to it/);
});

test('an RLS-forcing event trigger downgrades even the PUBLIC case', () => {
  const v = classifyInherited({
    schema: 'public',
    grants: [{ grantee: 'PUBLIC', privileges: ['SELECT'], writes: false }],
    mitigated: true,
  });
  assert.equal(v.status, 'note');
  assert.match(v.message, /event trigger/);
  assert.match(v.message, /every path that creates a table/); // still asks them to check
});
