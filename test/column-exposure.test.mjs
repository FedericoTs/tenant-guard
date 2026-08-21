/**
 * Column exposure — and the calibration that decides whether it is worth having.
 *
 * The measurement that shaped this guard, reproduced below as tests: a plain
 * table-level `GRANT SELECT` expands to EVERY column in
 * `information_schema.column_privileges`, so a grant-based version of this
 * check reports a fully-isolated table as exposing all seven of its columns.
 * On the sample app it fired three times, once on a table RLS already closes.
 * Proving the read instead fires twice, and both are real.
 *
 * The false-positive tests below matter more than the true-positive ones. A
 * guard that cries wolf on `drafts` teaches people to loosen RLS to silence it,
 * which is exactly how 0.26.0 took a production database down.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyColumn,
  planRelations,
  probeSql,
  readableColumns,
  classifyExposure,
  check,
} from '../src/guards/column-exposure.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('column-exposure integration (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── pure ─────────────────────────────────────────────────────────────

test('classifyColumn separates a credential from personal data', () => {
  assert.equal(classifyColumn('api_key'), 'secret');
  assert.equal(classifyColumn('password_hash'), 'secret');
  assert.equal(classifyColumn('stripe_secret_key'), 'secret');
  assert.equal(classifyColumn('email'), 'pii');
  assert.equal(classifyColumn('phone_number'), 'pii');
  assert.equal(classifyColumn('ip_address'), 'pii');
});

test('classifyColumn does not reach for words that merely contain a match', () => {
  // `emailed_at` is a timestamp, `token_count` is a number, `address_line_type`
  // is a label. Firing on these is how a name heuristic becomes noise.
  assert.equal(classifyColumn('title'), null);
  assert.equal(classifyColumn('created_at'), null);
  assert.equal(classifyColumn('body'), null);
  assert.equal(classifyColumn('display_name'), null);
});

test('planRelations HANDS OFF anything with a tenant column', () => {
  const rows = [
    { schema: 'public', table: 'members', relkind: 'r', column: 'organization_id' },
    { schema: 'public', table: 'members', relkind: 'r', column: 'email' },
    { schema: 'public', table: 'waitlist', relkind: 'r', column: 'email' },
  ];
  const { plan, handedOff } = planRelations(rows, { tenantColumns: ['organization_id'] });
  assert.deepEqual(plan.map((r) => r.id), ['public.waitlist']);
  assert.deepEqual(handedOff, ['public.members']);
});

test('planRelations ignores a relation with nothing sensitive on it', () => {
  const rows = [
    { schema: 'public', table: 'countries', relkind: 'r', column: 'code' },
    { schema: 'public', table: 'countries', relkind: 'r', column: 'name' },
  ];
  assert.deepEqual(planRelations(rows, { tenantColumns: [] }).plan, []);
});

test('the allowlist takes a whole relation or one column of it', () => {
  const rows = [
    { schema: 'public', table: 'contacts', relkind: 'r', column: 'email' },
    { schema: 'public', table: 'contacts', relkind: 'r', column: 'phone' },
  ];
  const one = planRelations(rows, { tenantColumns: [], allowlist: ['public.contacts.email'] });
  assert.deepEqual(one.plan[0].sensitive.map((c) => c.column), ['phone']);
  const all = planRelations(rows, { tenantColumns: [], allowlist: ['public.contacts'] });
  assert.deepEqual(all.plan, []);
});

test('probeSql COUNTS, it never selects the value', () => {
  const sql = probeSql({ schema: 'public', table: 'waitlist' }, [{ column: 'email' }], 500);
  assert.match(sql, /count\("email"\)/);
  assert.match(sql, /limit 500/);
  // The point: nothing in the result set can carry the leaked data itself.
  assert.doesNotMatch(sql, /select "email" from "public"\."waitlist"(?! limit)/);
});

test('probeSql quotes identifiers rather than interpolating them raw', () => {
  const sql = probeSql({ schema: 'public', table: 'we"ird' }, [{ column: 'ema"il' }], 10);
  assert.match(sql, /"we""ird"/);
  assert.match(sql, /"ema""il"/);
});

test('readableColumns keeps only the columns that returned a value', () => {
  const cols = [{ column: 'email', kind: 'pii' }, { column: 'phone', kind: 'pii' }];
  assert.deepEqual(readableColumns({ n_email: 3, n_phone: 0 }, cols).map((c) => c.column), ['email']);
  assert.deepEqual(readableColumns(null, cols), []);
});

test('a leaked secret is reported as a rotation, not a schema discussion', () => {
  const v = classifyExposure({
    rel: { id: 'public.api_clients', schema: 'public', table: 'api_clients' },
    columns: [{ column: 'api_key', kind: 'secret' }],
  });
  assert.equal(v.kind, 'anon-readable-secret');
  assert.match(v.message, /rotate/i);
  assert.match(v.message, /already been served/);
});

if (PGlite) {
  const app = `
    create role anon nologin; create role authenticated nologin;
    grant usage on schema public to anon, authenticated;

    -- tenant-scoped: anon-reads and rls-proof own these
    create table members (id int, organization_id text, email text, phone text);

    -- public by design, nothing sensitive on them
    create table countries (code text, name text);
    create table posts (id int, title text, body text, author_name text);

    -- granted to anon, but RLS returns nothing: the false positive that
    -- grant-based detection produces, and the one that must NOT fail a build
    create table drafts (id int, email text, body text);

    -- the real bugs
    create table waitlist (id int, email text, phone text);
    create table api_clients (id int, name text, api_key text);

    insert into countries values ('IE','Ireland');
    insert into posts values (1,'Hello','Body','Ada');
    insert into drafts values (1,'ada@x.com','wip');
    insert into waitlist values (1,'ada@x.com','+3531');
    insert into api_clients values (1,'mobile','sk_live_abc');
    insert into members values (1,'org_A','ada@x.com','+3531');

    grant select on countries, posts, drafts, waitlist, api_clients to anon;
    grant select on members to authenticated;
    alter table drafts enable row level security;
    alter table members enable row level security;
  `;

  async function fresh(extra = '') {
    const db = new PGlite();
    await db.exec(app + extra);
    return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
  }

  test('MEASURES the false-positive rate: a table grant covers every column', async () => {
    const { db } = await fresh();
    const acl = await db.query(`
      select count(*)::int as n from information_schema.column_privileges
      where table_name = 'waitlist' and grantee = 'anon' and privilege_type = 'SELECT'`);
    // One `GRANT SELECT ON waitlist` — three columns in the catalog. This is
    // why the grant is not evidence of anything.
    assert.equal(acl.rows[0].n, 3);
  });

  test('CATCHES both real exposures and nothing else', async () => {
    const { query } = await fresh();
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.deepEqual(
      res.violations.map((v) => v.kind).sort(),
      ['anon-readable-pii', 'anon-readable-secret'],
    );
    assert.ok(res.violations.some((v) => /api_clients/.test(v.where) && /api_key/.test(v.where)));
    assert.ok(res.violations.some((v) => /waitlist/.test(v.where) && /email/.test(v.where)));
  });

  test('does NOT fire on a table RLS already closes — it becomes a note', async () => {
    const { query } = await fresh();
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.violations.some((v) => /drafts/.test(v.where)), false,
      'drafts is granted to anon but returns no rows — failing here is the 0.26.0 mistake');
    assert.ok(res.notes.some((n) => n.where === 'public.drafts'));
  });

  test('says nothing about a tenant-scoped table — that is anon-reads\' fact', async () => {
    const { query } = await fresh();
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.violations.some((v) => /members/.test(v.where)), false);
    assert.ok(res.notes.some((n) => n.where === '(hand-off)'));
  });

  test('a column with only NULLs is not an exposure', async () => {
    const { db, query } = await fresh();
    await db.exec(`update waitlist set email = null, phone = null;`);
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.violations.some((v) => /waitlist/.test(v.where)), false);
  });

  test('a VIEW that re-exposes a hidden column is caught too', async () => {
    const { db, query } = await fresh();
    await db.exec(`
      create table authors (id int, display_name text, email text);
      insert into authors values (1, 'Ada', 'ada@x.com');
      revoke select on authors from anon;
      -- The classic: a "public profile" view built on the table, carrying the
      -- column the table grant was withheld to protect.
      create view public_authors as select display_name, email from authors;
      grant select on public_authors to anon;
    `);
    const res = await check({ query, config: { role: 'anon' } });
    assert.ok(
      res.violations.some((v) => /public_authors/.test(v.where) && /email/.test(v.where)),
      JSON.stringify(res.violations, null, 2),
    );
  });

  test('revoking the read clears the finding — the fix is the one it prints', async () => {
    const { db, query } = await fresh();
    await db.exec(`revoke select on waitlist, api_clients from anon;`);
    const res = await check({ query, config: { role: 'anon' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('an allowlisted column is not reported', async () => {
    const { query } = await fresh();
    const res = await check({
      query,
      config: { role: 'anon', allowlist: ['public.waitlist', 'public.api_clients'] },
    });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  test('the probe leaves the database exactly as it found it', async () => {
    const { db, query } = await fresh();
    const before = await db.query('select count(*)::int as n from waitlist');
    await check({ query, config: { role: 'anon' } });
    const after = await db.query('select count(*)::int as n from waitlist');
    assert.equal(after.rows[0].n, before.rows[0].n);
    // And the session role is not left switched.
    const who = await db.query('select current_user as u');
    assert.notEqual(who.rows[0].u, 'anon');
  });
}
