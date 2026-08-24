/**
 * Audit findings closed on updatable-view-writethrough.
 *
 * Two of them, and both are cases where the guard's answer disagreed with what
 * Postgres actually does. Every expectation below was measured first in PGlite
 * 0.5.5 / PG 18.3 (the measurements are quoted at each test) and the static
 * assertion was written to match, rather than the other way round.
 *
 *   1. uvw-fp-views-over-non-updatable-relations — a thin view over a matview,
 *      an aggregate view, a set-returning function or a subquery was reported as
 *      a write-through. Postgres refuses every write through those with SQLSTATE
 *      55000, so all of them were false CI failures.
 *   2. uvw-fp-schema-wide-revoke-not-parsed — the single-file form of the
 *      standard Supabase lockdown was not merely unparsed, it was parsed
 *      backwards into a schema-wide GRANT. And the earlier ALL TABLES handler
 *      counted `REVOKE … FROM PUBLIC` as proof anon's writes were gone, which
 *      turned a proven leak green.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  run,
  netWriteGrants,
  autoUpdatableShape,
  extractInsteadWritable,
  resolveBaseWritable,
  extractViews,
} from '../src/guards/updatable-view-writethrough.mjs';

/** Run the guard over a throwaway migrations dir. */
function guard(files, config = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'uvw-audit-'));
  try {
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return run({ dir, ...config });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const kinds = (r) => r.violations.map((v) => v.kind);
const named = (r, name) => r.violations.filter((v) => v.message.includes(`"${name}"`));

// ── 1. views over relations Postgres will not write through ──────────

/**
 * The reported schema, all four shapes side by side.
 *
 * Ground truth, anon granted SELECT+INSERT+UPDATE+DELETE on all four so nothing
 * could fail for want of a privilege — pg_relation_is_updatable(oid, true):
 *     revenue_public   (over a GROUP BY view)          0   DELETE -> 55000
 *     user_search_v    (over a MATERIALIZED VIEW)      0   DELETE -> 55000
 *     active_users_v   (over a set-returning function) 0   DELETE -> 55000
 *     public_profiles  (over the table)               28   DELETE -> 2 rows gone
 * The three refusals hold as owner too, so it is the relation kind refusing the
 * write, not RLS and not grants. Before the fix the guard failed CI on all four.
 */
test('a thin view over a matview / aggregate view / function / subquery is not a write path', () => {
  const r = guard({
    '001_base.sql': `
      create table users (id int primary key, organization_id uuid, email text);
      alter table users enable row level security;
      create materialized view user_search as select id, email from users;
      create view revenue as select organization_id, count(*) as n from users group by organization_id;
      create function active_users() returns setof users as $$ select * from users $$ language sql;
      grant select on users to anon;
    `,
    '002_thin.sql': `
      create view revenue_public as select organization_id, n from revenue;
      create view user_search_v as select id, email from user_search;
      create view active_users_v as select id, email from active_users();
      create view sub_v as select id, email from (select * from users) s;
      create view public_profiles as select id, email from users;
      grant select on revenue_public, user_search_v, active_users_v, sub_v, public_profiles to anon;
    `,
  });

  // The one real leak still fails the build — the guard has not gone quiet.
  assert.equal(r.ok, false);
  assert.equal(named(r, 'public_profiles').length, 1, 'the view over the TABLE must still be reported');
  assert.equal(kinds(r).length, 1, `expected only public_profiles, got ${JSON.stringify(kinds(r))}`);
  for (const quiet of ['revenue_public', 'user_search_v', 'active_users_v', 'sub_v']) {
    assert.equal(named(r, quiet).length, 0, `${quiet}: Postgres refuses this write with 55000`);
    assert.equal(r.notes.filter((n) => n.message.includes(`"${quiet}"`)).length, 0, `${quiet}: silent when proven safe`);
  }
});

/**
 * The escape hatch, and the reason "base is non-updatable" can never be taken on
 * its own. Measured: a GROUP BY view read pg_relation_is_updatable 0; after
 * `create rule … as on delete to agg do instead delete from users` it read 16,
 * and as anon `delete from` a thin view stacked on it removed 2 rows from the
 * RLS-protected users table. An INSTEAD OF trigger does the same — user_counts
 * and user_counts_v both read 16 and the delete emptied users.
 */
test('a rule or INSTEAD OF trigger on the base view keeps the write path open', () => {
  const withTrigger = guard({
    '001.sql': `
      create table users (id int primary key, organization_id uuid);
      alter table users enable row level security;
      create view user_counts as select organization_id, count(*) as n from users group by organization_id;
      create function del_uc() returns trigger security definer as $$ begin
        delete from users where organization_id = old.organization_id; return old; end $$ language plpgsql;
      create trigger t_del instead of delete on user_counts for each row execute function del_uc();
      create view user_counts_v as select organization_id, n from user_counts;
      grant select on user_counts, user_counts_v to anon;
    `,
  });
  assert.equal(named(withTrigger, 'user_counts_v').length, 1, 'INSTEAD OF trigger on the base re-opens the write');

  const withRule = guard({
    '001.sql': `
      create table users (id int primary key, email text);
      alter table users enable row level security;
      create view agg as select email, count(*) as n from users group by email;
      create rule r_del as on delete to agg do instead delete from users where email = old.email;
      create view agg_v as select email, n from agg;
      grant select on agg, agg_v to anon;
    `,
  });
  assert.equal(named(withRule, 'agg_v').length, 1, 'DO INSTEAD rule on the base re-opens the write');
});

/**
 * The same hatch one level up: the view under test carries the trigger itself, so
 * what it selects from is irrelevant. Without this the matview leg would have
 * silenced a genuinely writable view.
 */
test('an INSTEAD OF trigger on the view itself is not silenced by a blocked base', () => {
  const r = guard({
    '001.sql': `
      create table users (id int primary key, email text);
      alter table users enable row level security;
      create materialized view user_mv as select id, email from users;
      create view mv_writer as select id, email from user_mv;
      create function del_mv() returns trigger security definer as $$ begin
        delete from users where id = old.id; return old; end $$ language plpgsql;
      create trigger t instead of delete on mv_writer for each row execute function del_mv();
      grant select on mv_writer to anon;
    `,
  });
  assert.equal(named(r, 'mv_writer').length, 1, 'the trigger makes this writable whatever the base is');
});

/**
 * The finding proposed also downgrading views whose base is not defined in the
 * migrations. That is refused on purpose: the production bug this guard exists
 * for was a view over a table the migration set did not create.
 */
test('a base relation defined outside the migrations stays reported, not downgraded', () => {
  const r = guard({
    '001.sql': `
      create view public_profiles as select id, email from auth.users;
      grant select on public_profiles to anon;
    `,
  });
  assert.equal(r.ok, false);
  assert.equal(named(r, 'public_profiles').length, 1);
});

test('resolveBaseWritable / autoUpdatableShape agree with the measurements', () => {
  const shape = (sql) => autoUpdatableShape(sql);
  assert.equal(shape('select id from users').baseIsCallable, false);
  assert.equal(shape('select id from users').baseQualified, 'public.users');
  assert.equal(shape('select id from active_users()').baseIsCallable, true);
  // `from users u(a,b)` measured 28 — still a table, still updatable. The space
  // before the paren is the whole difference from a function call.
  assert.equal(shape('select a from users u(a,b)').baseIsCallable, false);
  assert.equal(shape('select id from (select * from users) s').baseIsSubquery, true);

  const views = new Map(
    extractViews(`
      create materialized view mv as select id from users;
      create view agg as select id, count(*) n from users group by id;
      create view thin_mv as select id from mv;
      create view thin_agg as select id from agg;
      create view thin_tbl as select id from users;
    `).map((v) => [v.qualified, v]),
  );
  const at = (n) => resolveBaseWritable(views.get(`public.${n}`), views, new Set());
  assert.equal(at('thin_mv'), 'blocked');
  assert.equal(at('thin_agg'), 'blocked');
  assert.equal(at('thin_tbl'), 'unknown', 'a base outside the view catalog is not concluded on');
  // With a rule on the aggregate view, the same chain is writable again.
  assert.equal(
    resolveBaseWritable(views.get('public.thin_agg'), views, new Set(['public.agg'])),
    'writable',
  );
});

test('extractInsteadWritable finds both triggers and rules, keyed by schema', () => {
  const s = extractInsteadWritable(`
    create trigger t instead of insert or update or delete on public.v1 for each row execute function f();
    create rule r as on delete to reporting.v2 do instead nothing;
    create trigger normal after insert on some_table for each row execute function f();
  `);
  assert.deepEqual([...s].sort(), ['public.v1', 'reporting.v2']);
});

// ── 2. the schema-wide REVOKE, and who it actually revokes from ──────

/**
 * The standard Supabase lockdown written in ONE file, which is how it is
 * normally written.
 *
 * Before the fix the privilege group was `[\s\S]*?` and backtracked over the
 * semicolon: it matched from the GRANT's verb through the REVOKE's privilege
 * list, so the schema-wide REVOKE was recorded as a schema-wide GRANT of
 * INSERT/UPDATE/DELETE. Splitting the two statements across files parsed fine,
 * which is why the earlier fix looked complete.
 *
 * Ground truth: before the revoke, has_table_privilege('anon', view, 'DELETE')
 * was true and anon deleted 2 rows through the view; after it, false.
 */
test('the schema-wide REVOKE closes the hole even when it follows a GRANT in the same file', () => {
  const files = {
    '001.sql': `
      create table users (id int primary key, email text);
      alter table users enable row level security;
      create view public_profiles as select id, email from users;
      grant select on public_profiles to anon, authenticated;
      revoke insert, update, delete on all tables in schema public from anon, authenticated;
    `,
  };
  const r = guard(files);
  assert.equal(r.ok, true, `expected clean, got ${JSON.stringify(kinds(r))}`);
  assert.equal(r.notes.length, 0);

  // And directly: the REVOKE must not be recorded as a GRANT.
  const g = netWriteGrants([{ name: '001.sql', sql: files['001.sql'] }], ['anon', 'authenticated'], [
    'public.public_profiles',
  ]);
  const e = g.get('public.public_profiles');
  assert.deepEqual([...e.granted].sort(), [], 'the REVOKE was being read as a GRANT');
  assert.deepEqual([...e.revoked].sort(), ['delete', 'insert', 'update']);
});

/**
 * `REVOKE … FROM PUBLIC` is not `REVOKE … FROM anon`.
 *
 * Measured: `alter default privileges in schema public grant all on tables to
 * anon, authenticated` then `revoke all on all tables in schema public from
 * public` left has_table_privilege('anon', 'public.public_profiles', 'DELETE')
 * TRUE, and anon deleted 2 rows through the view. Only
 * `revoke … from anon, authenticated` flipped it to false.
 *
 * Folding PUBLIC into the role match made that statement read as proof the hole
 * was closed, so the guard reported GREEN on a live leak.
 */
test('REVOKE FROM PUBLIC does not clear the default-privilege writes anon holds by name', () => {
  const r = guard({
    '001.sql': `
      alter default privileges in schema public grant all on tables to anon, authenticated;
      create table users (id int primary key, email text);
      alter table users enable row level security;
      create view public_profiles as select id, email from users;
      grant select on public_profiles to anon;
    `,
    '002.sql': `revoke all on all tables in schema public from public;`,
  });
  assert.equal(r.ok, false, 'anon keeps its default-privilege writes after a revoke from PUBLIC');
  assert.equal(named(r, 'public_profiles').length, 1);
});

test('REVOKE FROM PUBLIC does not clear a grant made directly to anon', () => {
  const r = guard({
    '001.sql': `
      create table users (id int primary key, email text);
      alter table users enable row level security;
      create view public_profiles as select id, email from users;
      grant select, insert, update, delete on public_profiles to anon;
    `,
    '002.sql': `revoke all on all tables in schema public from public;`,
  });
  assert.equal(r.ok, false);
  assert.equal(kinds(r)[0], 'granted-writethrough');
});

/**
 * The other direction of the same lane split: a GRANT to PUBLIC really does
 * reach anon, so it still counts as an explicit write grant, and a later revoke
 * from PUBLIC really does take it back.
 */
test('a GRANT to PUBLIC counts, and a REVOKE from PUBLIC takes back what PUBLIC was given', () => {
  const granted = netWriteGrants(
    [{ name: '001.sql', sql: 'grant insert, update, delete on public_profiles to public;' }],
    ['anon', 'authenticated'],
    ['public.public_profiles'],
  ).get('public.public_profiles');
  assert.deepEqual([...granted.granted].sort(), ['delete', 'insert', 'update']);

  const takenBack = netWriteGrants(
    [
      { name: '001.sql', sql: 'grant insert, update, delete on public_profiles to public;' },
      { name: '002.sql', sql: 'revoke insert, update, delete on public_profiles from public;' },
    ],
    ['anon', 'authenticated'],
    ['public.public_profiles'],
  ).get('public.public_profiles');
  assert.deepEqual([...takenBack.granted].sort(), []);
  // Not "revoked": the platform default privileges arrive on anon by name and a
  // revoke from PUBLIC cannot prove those gone. The guard must still speak up.
  assert.deepEqual([...takenBack.revoked].sort(), []);
});
