/**
 * definer-rpc — the audit fixes, each pinned to the measurement that forced it.
 *
 * Four defects, all of them in what the guard SAYS rather than in whether it can
 * see the hole:
 *
 *  1. `format()` — a `%s` anywhere in the string was reported as injection
 *     through whichever parameter happened to appear in the statement, even when
 *     that parameter was bound by `%L` and the `%s` consumed a constant. A false
 *     accusation naming a correctly-escaped argument, and a build failure.
 *  2. The unpinned-search_path note claimed "Not exploitable here" on a
 *     configuration that is exploitable with a plain `create temp table`, and
 *     recommended a pin WITHOUT `pg_temp` — which the same guard fails on, so
 *     following the tool's own advice turned a green run red.
 *  3. The emitted `ALTER FUNCTION … SET search_path` named the schema the
 *     FUNCTION lives in. A body reading an unqualified table in another schema
 *     broke with 42P01 the moment the fix was applied.
 *  4. The module header claimed Postgres "guarantees" a STABLE function cannot
 *     modify anything. It does not: the flag is not inherited, and a sequence
 *     consumed inside one survives the rollback.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  check,
  dynamicSqlInjection,
  parameterSignature,
  canCarrySql,
  splitCallArgs,
  formatSpecifierMap,
  unqualifiedRelationRefs,
  relationsSql,
  tempCreateSql,
} from '../src/guards/definer-rpc.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('definer-rpc audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const SECURED = `
  create table invoices (id serial primary key, organization_id text not null, amount int, note text);
  grant select on invoices to authenticated;
  insert into invoices (organization_id, amount, note) values ('org_A',100,'a'),('org_B',200,'b'),('org_B',300,'c');
  alter table invoices enable row level security;
  create policy tenant on invoices
    using (organization_id = current_setting('app.current_tenant', true));
`;

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setup);
  return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
}

/** The one executable statement out of a fix/note blob — what a user would paste. */
const alterFrom = (text) => (String(text).match(/ALTER FUNCTION [^\n;]+;/) || [])[0];

// ── 1. format(): the specifier that consumes the parameter, not any %s ──────

test('format(): a parameter bound by %L is not injection because a CONSTANT uses %s', () => {
  // Measured: this exact function was the sole violation on a build, naming
  // p_owner — which %L escapes. Payloads "' or true --" / "%' or true --" /
  // "x%' union select …" each returned zero rows as the pinned role.
  assert.equal(
    dynamicSqlInjection(
      `begin return query execute format('select * from public.notes where owner = %L limit %s', p_owner, 50); end`,
      ['p_owner'],
    ),
    null,
  );
});

test('format(): a nested call in the argument list does not shift the mapping', () => {
  // Naive comma-splitting turns "coalesce(p_o, 'x'), 50" into three pieces and
  // lines %s up with 'x'. splitCallArgs tracks paren depth so it does not.
  assert.equal(
    dynamicSqlInjection(
      `execute format('select * from t where o = %L limit %s', coalesce(p_o, 'x'), 50);`,
      ['p_o'],
    ),
    null,
  );
});

test('format(): explicit %n$ positions are read, not counted', () => {
  // Mixed sequential and explicit, confirmed against PG 18.3:
  //   format('select %s from t where o = %2$L', 'count(*)', 'bob')
  //     -> select count(*) from t where o = 'bob'
  // The sequential %s takes argument 1, the explicit %2$L takes the parameter.
  assert.equal(
    dynamicSqlInjection(`execute format('select %s from t where o = %2$L', 'count(*)', p_owner);`, ['p_owner']),
    null,
  );
  // ...and the mirror image is still caught.
  assert.equal(
    dynamicSqlInjection(`execute format('select %1$L from t where o = %2$s', 'x', p_owner);`, ['p_owner']).via,
    'format-%s',
  );
});

test('format(): %s on a type that cannot carry SQL is not a finding; on text it still is', () => {
  const sig = parameterSignature('p_query text, p_limit integer');
  assert.deepEqual(sig, [{ name: 'p_query', type: 'text' }, { name: 'p_limit', type: 'integer' }]);
  // an integer rendered by %s is digits — there is no payload it can carry
  assert.equal(
    dynamicSqlInjection(`execute format('select * from t where o = %L limit %s', p_query, p_limit);`, sig),
    null,
  );
  // the same shape with the TEXT parameter on the %s is the real thing
  assert.equal(
    dynamicSqlInjection(`execute format('select * from t where o = %s limit %s', p_query, p_limit);`, sig).param,
    'p_query',
  );
});

test('format(): an unreadable mapping reports unproven, never a named accusation', () => {
  // %*s takes its width from an argument, so sequential positions shift by one.
  // Guessing here is how a correctly-escaped parameter gets accused.
  const r = dynamicSqlInjection(`execute format('select * from t where o = %L limit %*s', p_owner, 4, 50);`, ['p_owner']);
  assert.equal(r.via, 'format-unproven');
});

test('canCarrySql: unknown and text-shaped types assume the worst', () => {
  assert.equal(canCarrySql('text'), true);
  assert.equal(canCarrySql('character varying'), true);
  assert.equal(canCarrySql('jsonb'), true);
  assert.equal(canCarrySql('text[]'), true);
  assert.equal(canCarrySql(null), true);           // unparsed => flagged, not waved through
  assert.equal(canCarrySql('integer'), false);
  assert.equal(canCarrySql('uuid'), false);
  assert.equal(canCarrySql('numeric(10,2)'), false);
});

test('splitCallArgs / formatSpecifierMap: the pieces the mapping rests on', () => {
  const s = `format('a %L b %s', coalesce(p, 'x,y'), 50)`;
  const split = splitCallArgs(s, s.indexOf('('));
  assert.equal(split.args.length, 3);
  assert.equal(split.args[1].trim(), `coalesce(p, 'x,y')`);

  const map = formatSpecifierMap(`a %L b %s`, 2);
  assert.deepEqual([...map.get(1)], ['L']);
  assert.deepEqual([...map.get(2)], ['s']);
  assert.equal(formatSpecifierMap(`%%s only a literal percent`, 0).size, 0);
  assert.equal(formatSpecifierMap(`%s %s`, 1), null);       // more specifiers than arguments
  assert.equal(formatSpecifierMap(`limit %*s`, 2), null);   // width from an argument
});

// ── 2/3. where the body's names actually resolve ────────────────────────────

test('unqualifiedRelationRefs: resolves real relations, skips qualified names and CTEs', () => {
  const rels = [{ schema: 'app', name: 'invoices' }, { schema: 'public', name: 'notes' }];
  assert.deepEqual(unqualifiedRelationRefs('select * from invoices', rels), [{ name: 'invoices', schemas: ['app'] }]);
  assert.deepEqual(unqualifiedRelationRefs('select * from app.invoices', rels), []);
  assert.deepEqual(unqualifiedRelationRefs('with invoices as (select 1) select * from invoices', rels), []);
  assert.deepEqual(unqualifiedRelationRefs('select * from unrelated_thing', rels), []);
  assert.deepEqual(unqualifiedRelationRefs('select 1', rels), []);
});

test('relationsSql / tempCreateSql: the two catalog reads the advice now depends on', () => {
  const r = relationsSql(['public', 'app']);
  assert.match(r.text, /relkind in \('r','p','v','m','f'\)/);
  assert.deepEqual(r.values, [['public', 'app']]);
  const t = tempCreateSql('authenticated');
  assert.match(t.text, /has_database_privilege\(\$1::text, current_database\(\), 'TEMP'\)/);
  assert.deepEqual(t.values, ['authenticated']);
});

// ── 4. the volatility claim ─────────────────────────────────────────────────

if (PGlite) {
  test('a STABLE definer function consumes a sequence THROUGH check(), past its rollback', async () => {
    const { db, query } = await fresh(`
      ${SECURED}
      create sequence setof_seq;
      create function all_invoices_audited() returns setof invoices
        language sql security definer stable as $$ select * from invoices where nextval('setof_seq') > 0 $$;
      grant execute on function all_invoices_audited() to authenticated;
    `);
    const before = (await db.query('select last_value, is_called from setof_seq')).rows[0];
    await check({ query });
    const after = (await db.query('select last_value, is_called from setof_seq')).rows[0];
    assert.equal(before.is_called, false);
    assert.equal(after.is_called, true, 'the rollback did not contain it');
    assert.ok(Number(after.last_value) > Number(before.last_value), JSON.stringify({ before, after }));

    // ...so the module must not claim the engine guarantees otherwise. This is a
    // documentation assertion on purpose: the claim never reached CLI output, it
    // only ever misled whoever read the file and trusted the gate.
    const src = readFileSync(fileURLToPath(new URL('../src/guards/definer-rpc.mjs', import.meta.url)), 'utf8');
    assert.doesNotMatch(src, /guarantees they cannot modify anything/);
    assert.doesNotMatch(src, /which Postgres guarantees cannot write/);
    assert.match(src, /is \*\*not\*\* inherited/);
  });

  // ── 2. the unpinned note ─────────────────────────────────────────────────

  test('the unpinned note does not claim safety, and its own DDL keeps the next run green', async () => {
    const { db, query } = await fresh(`
      ${SECURED}
      revoke create on schema public from public;
      create function my_invoices() returns setof invoices
        language sql security definer stable as $$
          select * from invoices where organization_id = current_setting('app.current_tenant', true) $$;
      grant execute on function my_invoices() to authenticated;
    `);

    // The precondition the old note asserted: CREATE nowhere. It holds here.
    const priv = (await db.query(`select
      (select count(*)::int from pg_namespace n
         where n.nspname not like 'pg\\_%' and n.nspname <> 'information_schema'
           and has_schema_privilege('authenticated', n.oid, 'CREATE')) as create_schemas,
      has_database_privilege('authenticated', current_database(), 'TEMP') as temp`)).rows[0];
    assert.equal(priv.create_schemas, 0);
    assert.equal(priv.temp, true, 'TEMP to PUBLIC is the default this turns on');

    // And the hijack works anyway, with nothing but a temp table. Same session,
    // same role, one statement between the honest answer and the planted one.
    await db.exec('begin');
    await db.exec('set local role authenticated');
    await db.exec(`select set_config('app.current_tenant','org_A',true)`);
    const real = (await db.query('select note from public.my_invoices()')).rows;
    await db.exec(`create temp table invoices (id int, organization_id text, amount int, note text)`);
    await db.exec(`insert into pg_temp.invoices values (99,'org_A',0,'PWNED')`);
    const hijacked = (await db.query('select note from public.my_invoices()')).rows;
    await db.exec('rollback');
    assert.deepEqual(real, [{ note: 'a' }]);
    assert.deepEqual(hijacked, [{ note: 'PWNED' }], 'no CREATE anywhere and the shadow still lands');

    const run1 = await check({ query });
    assert.equal(run1.ok, true, JSON.stringify(run1, null, 2));
    const note = run1.notes.find((n) => /my_invoices/.test(n.where));
    assert.ok(note, JSON.stringify(run1.notes, null, 2));
    assert.doesNotMatch(note.message, /Not exploitable here/);
    assert.doesNotMatch(note.message, /nowhere to plant a shadowing object/);
    assert.match(note.message, /pg_temp is searched BEFORE/);

    // The DDL it recommends must name pg_temp — the old one did not, so applying
    // it added a 'search-path' violation on the very next run of this guard.
    const ddl = alterFrom(note.message);
    assert.match(ddl, /pg_temp;$/);
    await db.exec(ddl);
    assert.equal((await db.query('select count(*)::int n from my_invoices()')).rows[0].n, 0, 'still runs after the pin');
    const run2 = await check({ query });
    assert.equal(run2.violations.filter((v) => v.kind === 'search-path').length, 0, JSON.stringify(run2.violations, null, 2));
    assert.equal(run2.ok, true, JSON.stringify(run2, null, 2));
  });

  // ── 3. the emitted ALTER ─────────────────────────────────────────────────

  test('the emitted search_path pin names the BODY\'s schema, so the function still runs', async () => {
    const { db, query } = await fresh(`
      create schema app;
      create table app.invoices (id serial primary key, organization_id text not null, amount int);
      insert into app.invoices (organization_id, amount) values ('org_A',1),('org_B',2);
      grant usage on schema app to authenticated;
      grant select on app.invoices to authenticated;
      alter table app.invoices enable row level security;
      create policy tenant on app.invoices using (organization_id = current_setting('app.current_tenant', true));
      grant create on schema public to authenticated;   -- puts it in the failing population
      create function public.helper() returns setof app.invoices
        language plpgsql security definer stable as $fn$ begin return query select * from invoices; end $fn$;
      grant execute on function public.helper() to authenticated;
    `);
    const res = await check({ query, config: { schemas: ['public', 'app'] } });
    const sp = res.violations.find((v) => v.kind === 'search-path');
    assert.ok(sp, JSON.stringify(res.violations, null, 2));

    const ddl = alterFrom(sp.fix);
    assert.match(ddl, /search_path = pg_catalog, app, public, pg_temp;$/, ddl);
    assert.match(sp.fix, /CALL the function once/);

    await db.exec('set search_path = public, app');
    const before = (await db.query('select count(*)::int n from public.helper()')).rows[0].n;
    await db.exec(ddl);                                  // paste the fix verbatim
    const after = (await db.query('select count(*)::int n from public.helper()')).rows[0].n;
    assert.equal(after, before, 'the guard\'s own fix must not break the function');

    // the writable schema it had to keep in the path is called out, not silently kept
    assert.match(sp.fix, /REVOKE CREATE ON SCHEMA public FROM authenticated/);
  });

  test('a pin that is only missing pg_temp keeps its own schema list', async () => {
    // The pin already resolves — `app` is where the body's table lives. The fix
    // must add pg_temp and change nothing else; emitting `pg_catalog, public,
    // pg_temp` here (the function's own schema) took the function down with
    // 42P01, which is what it used to do.
    const db = new PGlite();
    await db.exec('create role authenticated nologin;');
    await db.exec(`
      create schema app;
      create table app.invoices (id serial primary key, organization_id text not null, amount int);
      insert into app.invoices (organization_id, amount) values ('org_A',1),('org_B',2);
      grant usage on schema app to authenticated;
      grant select on app.invoices to authenticated;
      alter table app.invoices enable row level security;
      create policy tenant on app.invoices using (organization_id = current_setting('app.current_tenant', true));
      create function public.helper() returns setof app.invoices
        language plpgsql security definer stable
        set search_path = pg_catalog, app
        as $fn$ begin return query select * from invoices; end $fn$;
      grant execute on function public.helper() to authenticated;
    `);
    const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
    const res = await check({ query, config: { schemas: ['public', 'app'] } });
    const sp = res.violations.find((v) => v.kind === 'search-path');
    assert.ok(sp, JSON.stringify(res.violations, null, 2));
    const ddl = alterFrom(sp.fix);
    assert.match(ddl, /search_path = pg_catalog, app, pg_temp;$/, ddl);

    const before = (await db.query('select count(*)::int n from public.helper()')).rows[0].n;
    await db.exec(ddl);
    const after = (await db.query('select count(*)::int n from public.helper()')).rows[0].n;
    assert.equal(after, before);
    const rerun = await check({ query, config: { schemas: ['public', 'app'] } });
    assert.equal(rerun.violations.filter((v) => v.kind === 'search-path').length, 0, JSON.stringify(rerun.violations, null, 2));
  });

  // ── 1, end to end ────────────────────────────────────────────────────────

  test('a correct format() function passes the build; the genuinely unsafe twin still fails it', async () => {
    const { query } = await fresh(`
      ${SECURED}
      create function search_notes(p_query text, p_limit int) returns setof invoices
        language plpgsql security definer stable set search_path = pg_catalog, public, pg_temp
      as $fn$ begin
        return query execute format('select * from public.invoices where organization_id = %L and note like %L limit %s',
          current_setting('app.current_tenant', true), p_query, p_limit);
      end $fn$;
      create function bad_notes(p_owner text) returns setof invoices
        language plpgsql security definer stable set search_path = pg_catalog, public, pg_temp
      as $fn$ begin
        return query execute format('select * from public.invoices where organization_id = %s', p_owner);
      end $fn$;
      grant execute on function search_notes(text,int), bad_notes(text) to authenticated;
    `);
    const res = await check({ query });
    const inj = res.violations.filter((v) => v.kind === 'sql-injection');
    assert.equal(inj.length, 1, JSON.stringify(inj, null, 2));
    assert.match(inj[0].where, /bad_notes/);
    assert.doesNotMatch(inj[0].where, /search_notes/);
  });
}
