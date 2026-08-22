/**
 * create-grants pure-logic tests.
 *
 * The calibration is what these pin down. `CREATE` is an escalation *primitive*,
 * not a leak, so who holds it decides everything: PUBLIC and `anon` fail, the app
 * role is a note. And the messages must link to §4.4 rather than re-report it —
 * `definer-rpc` already fails on the exploitable combination from the other side.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  schemaCreateGrantsSql,
  databaseCreateGrantsSql,
  definerSearchPathSql,
  serverVersionSql,
  unpinnedDefiners,
  classifyCreateGrant,
} from '../src/guards/create-grants.mjs';

// ── SQL ──────────────────────────────────────────────────────────────

test('schemaCreateGrantsSql: effective privilege, plus HOW it is held', () => {
  const { text, values } = schemaCreateGrantsSql(['anon', 'authenticated'], ['public']);
  assert.match(text, /has_schema_privilege/);      // the effective answer
  assert.match(text, /grantee = 0/);               // …via PUBLIC
  assert.match(text, /grantee = r\.oid/);          // …or via a direct grant
  assert.match(text, /nspname = any\(\$2\)/);       // scoped in SQL, not filtered after
  assert.deepEqual(values, [['anon', 'authenticated'], ['public']]);
});

test('the effective and direct privileges are distinct columns — they have different fixes', () => {
  const { text } = schemaCreateGrantsSql(['anon'], ['public']);
  assert.match(text, /as can_create/);
  assert.match(text, /as public_can_create/);
  assert.match(text, /as direct_can_create/);
});

test('databaseCreateGrantsSql: CREATE on the database is the right to make SCHEMAS', () => {
  const { text } = databaseCreateGrantsSql(['anon']);
  assert.match(text, /has_database_privilege/);
  assert.match(text, /current_database\(\)/);
  assert.match(text, /grantee = 0/);
});

test('the role list is parameterised, so a role that does not exist simply drops out', () => {
  // has_schema_privilege('nosuchrole', …) would ERROR; joining pg_roles avoids it.
  assert.match(schemaCreateGrantsSql(['ghost'], ['public']).text, /pg_roles/);
  assert.match(schemaCreateGrantsSql(['ghost'], ['public']).text, /rolname = any\(\$1\)/);
});

test('definerSearchPathSql and serverVersionSql are shaped as expected', () => {
  assert.match(definerSearchPathSql(['public']).text, /prosecdef/);
  assert.match(definerSearchPathSql(['public']).text, /proconfig/);
  assert.match(serverVersionSql().text, /server_version_num/);
});

// ── which definer functions a grant would arm ────────────────────────

test('unpinnedDefiners: only the ones without SET search_path', () => {
  const rows = [
    { schema: 'public', name: 'safe', config: ['search_path=pg_catalog, public'] },
    { schema: 'public', name: 'risky', config: null },
    { schema: 'public', name: 'other_setting', config: ['work_mem=64MB'] },
  ];
  assert.deepEqual(unpinnedDefiners(rows), ['public.risky', 'public.other_setting']);
  assert.deepEqual(unpinnedDefiners([]), []);
  assert.deepEqual(unpinnedDefiners(null), []);
});

// ── calibration ──────────────────────────────────────────────────────

const base = { scope: 'schema', where: 'public', unauthenticatedRoles: ['anon'], appRole: 'authenticated' };

test('LEAK: PUBLIC — every role, including ones that do not exist yet', () => {
  const v = classifyCreateGrant({ ...base, role: 'PUBLIC', viaPublic: true });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'public-create');
  assert.match(v.message, /do not exist yet/);
  assert.match(v.fix, /REVOKE CREATE ON SCHEMA public FROM PUBLIC/);
});

test('LEAK: an unauthenticated role holding CREATE is never legitimate', () => {
  const v = classifyCreateGrant({ ...base, role: 'anon' });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'anon-create');
  assert.match(v.message, /not a legitimate configuration/);
  assert.match(v.fix, /FROM anon/);
});

test('NOTE: the app role — running migrations as it is legitimate, and SQL cannot tell', () => {
  const v = classifyCreateGrant({ ...base, role: 'authenticated' });
  assert.equal(v.status, 'note');
  assert.match(v.message, /SQL cannot tell which/);
});

test('the pre-PG15 default is named as such, so the finding is context not pedantry', () => {
  const old = classifyCreateGrant({ ...base, role: 'PUBLIC', viaPublic: true, serverVersion: 140009 });
  assert.match(old.message, /pre-Postgres-15 default/);
  const modern = classifyCreateGrant({ ...base, role: 'PUBLIC', viaPublic: true, serverVersion: 160002 });
  assert.doesNotMatch(modern.message, /pre-Postgres-15 default/); // deliberate on 15+, not inherited
});

// ── the §4.4 relationship ────────────────────────────────────────────

test('with unpinned definers present it says EXPLOITABLE NOW and points at the other guard', () => {
  const v = classifyCreateGrant({ ...base, role: 'anon', unpinned: ['public.risky'] });
  assert.match(v.message, /exploitable NOW/);
  assert.match(v.message, /tenant-guard rpc/);
  assert.match(v.message, /from the function side/); // complementary, not duplicate
});

test('with none present it is stated as a LATENT precondition, not a false alarm', () => {
  const v = classifyCreateGrant({ ...base, role: 'anon', unpinned: [] });
  // This used to assert "nothing is exploitable today", which was a claim about
  // exploitability decided by a check that only tested whether a `SET` clause
  // existed. The claim is now scoped to what was actually looked at.
  assert.match(v.message, /nothing there is hijackable through this grant today/);
  assert.doesNotMatch(v.message, /nothing is exploitable today/);
  assert.match(v.message, /arms the next one/);
  assert.match(v.message, /no diff will show a security change/);
});

// ── the database scope ───────────────────────────────────────────────

test('CREATE on the database is described as the right to create SCHEMAS', () => {
  const v = classifyCreateGrant({ ...base, scope: 'database', where: undefined, role: 'anon' });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /create new SCHEMAS/);
  assert.match(v.fix, /REVOKE CREATE ON DATABASE/);
});

test('every finding names its exact allowlist entry', () => {
  assert.match(classifyCreateGrant({ ...base, role: 'anon' }).fix, /"public:anon"/);
  assert.match(classifyCreateGrant({ ...base, role: 'PUBLIC', viaPublic: true }).fix, /"public:PUBLIC"/);
  assert.match(classifyCreateGrant({ ...base, scope: 'database', role: 'anon' }).fix, /"database:anon"/);
});
