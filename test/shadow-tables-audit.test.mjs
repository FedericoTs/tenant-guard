/**
 * shadow-tables — the six audit findings, each pinned by a test that fails
 * against the pre-fix guard.
 *
 * Three of them were wrong ADVICE (the printed remediation did not run, or ran
 * and broke the protected source table), two were detection holes (an aliased
 * UPDATE, and RLS-enabled-but-decorative), one was a false positive (a table
 * named only inside a comment). The advice cases are checked by APPLYING the
 * emitted DDL to a real database, not by matching on its text: the whole class
 * of bug here is advice that reads fine and does not execute.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  destinationSql,
  blankSqlComments,
  writeTargets,
  classifyDestination,
  check,
} from '../src/guards/shadow-tables.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('shadow-tables audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── the false positive: a table named only in a comment ──────────────

test('blankSqlComments blanks -- and /* */ but keeps string literals', () => {
  assert.equal(blankSqlComments(`a -- b\nc`), `a     \nc`);
  assert.equal(blankSqlComments(`a /* b */ c`).replace(/\s+/g, ' '), `a c`);
  // nested block comments, the way Postgres nests them
  assert.doesNotMatch(blankSqlComments(`x /* a /* b */ c */ y`), /a|b|c/);
  // literals survive: a dynamic write is still visible to the scan
  assert.match(blankSqlComments(`execute 'insert into audit_log values (1)'`), /insert into audit_log/);
});

test('writeTargets: a table named only inside a comment is NOT a write target', () => {
  // Pre-fix this returned ["public.app_settings"] and failed the build with a
  // message asserting the table "receives rows derived from tenant data".
  assert.deepEqual(
    writeTargets(`begin\n  -- 2023: we used to "insert into app_settings" here; removed, it leaked\n  return NEW;\nend`),
    [],
  );
  assert.deepEqual(writeTargets(`begin /* old: insert into audit_log(a) values (1); */ return NEW; end`), []);
  assert.deepEqual(writeTargets(`raise exception 'do not insert into archive_log directly'`), ['public.archive_log']);
});

test('writeTargets: a -- inside a string literal does not swallow the real write after it', () => {
  // The naive `body.replace(/--[^\n]*/g,'')` fix loses this one entirely.
  assert.deepEqual(
    writeTargets(`begin raise notice 'skipped -- see ticket'; insert into audit_log(a) values (1); end`),
    ['public.audit_log'],
  );
  // and a dollar-quoted span is skipped whole, not mis-lexed
  assert.deepEqual(writeTargets(`begin execute $q$ insert into audit_log(a) values (1) $q$; end`), ['public.audit_log']);
});

// ── the false negative: UPDATE with an alias / ONLY / MERGE ──────────

test('writeTargets: an aliased, ONLY or schema-qualified UPDATE is still a write', () => {
  // Pre-fix each of these returned [] — the verdict flipped on the alias alone,
  // while both databases leaked identically.
  assert.deepEqual(writeTargets(`update audit_log a set seen = true where a.id = 1`), ['public.audit_log']);
  assert.deepEqual(writeTargets(`update audit_log as a set seen = true`), ['public.audit_log']);
  assert.deepEqual(writeTargets(`update only audit_log set seen = true`), ['public.audit_log']);
  assert.deepEqual(writeTargets(`update public.audit_log a set seen = true`), ['public.audit_log']);
  assert.deepEqual(writeTargets(`merge into audit_log t using s on true when matched then update set a = 1`), ['public.audit_log']);
});

test('writeTargets: the looser UPDATE pattern adds no false targets', () => {
  assert.deepEqual(writeTargets(`insert into t (a) values (1) on conflict (id) do update set n = excluded.n`), ['public.t']);
  assert.deepEqual(writeTargets(`perform 1 from q for update skip locked; update rollup set n = n + 1`), ['public.rollup']);
  assert.deepEqual(writeTargets(`begin execute 'update ' || tbl || ' set x = 1'; end`), []);
  assert.deepEqual(writeTargets(`update cache set n = 1 where id = 2`), ['public.cache']); // unchanged
});

// ── the wrong advice: the emitted policy has to compile, and has to
//    not break the source table's writes ────────────────────────────

test('the emitted policy casts to the destination column type', () => {
  const uuid = classifyDestination({
    schema: 'public', table: 'audit_log', rlsEnabled: false, canSelect: true,
    tenantColumn: 'organization_id', tenantColumnType: 'uuid', sources: ['public.invoices'],
  });
  // pre-fix: `USING ("organization_id" = current_setting('app.current_tenant'))`,
  // which Postgres rejects with 42883 `operator does not exist: uuid = text`.
  assert.match(uuid.fix, /::uuid/);
  const bigint = classifyDestination({
    schema: 'public', table: 'audit_log', rlsEnabled: false, canSelect: true,
    tenantColumn: 'org_id', tenantColumnType: 'bigint', sources: ['public.invoices'],
  });
  assert.match(bigint.fix, /"org_id"::text = current_setting/);
});

test('the emitted policy uses the two-argument current_setting so a GUC-less session fails closed', () => {
  const v = classifyDestination({
    schema: 'public', table: 'audit_log', rlsEnabled: false, canSelect: true,
    tenantColumn: null, sources: ['public.invoices'],
  });
  // pre-fix the one-arg form raised 42704 on every read from a session that had
  // not set the GUC — an error, not zero rows.
  assert.match(v.fix, /current_setting\('app\.current_tenant', true\)/);
  assert.doesNotMatch(v.fix, /current_setting\('app\.current_tenant'\)/);
});

test('the emitted fix names the write side: WITH CHECK, the trigger change, and the backfill', () => {
  const v = classifyDestination({
    schema: 'public', table: 'audit_log', rlsEnabled: false, canSelect: true,
    tenantColumn: null, sources: ['public.invoices'], sourceTenantColumn: 'organization_id',
  });
  assert.match(v.fix, /WITH CHECK/);
  assert.match(v.fix, /NEW\."organization_id"/);        // the trigger must carry the tenant
  assert.match(v.fix, /IS NULL/);                        // the backfill
  assert.match(v.fix, /every INSERT INTO public\.invoices fails with 42501/);
  assert.doesNotMatch(v.fix, /WITH CHECK \(true\)/);     // that trades the break for a write leak
});

// ── the false negative: RLS on but decorative ────────────────────────

test('destinationSql asks the catalog what the role\'s SELECT policies actually do', () => {
  const { text } = destinationSql(['public.audit_log'], ['organization_id'], 'authenticated');
  assert.match(text, /pg_has_role/);
  assert.match(text, /polpermissive/);
  assert.match(text, /format_type/);
});

test('classify: RLS on, no tenant column, a constant-true policy for the role -> leak', () => {
  const v = classifyDestination({
    schema: 'public', table: 'audit_log', rlsEnabled: true, canSelect: true, tenantColumn: null,
    permissiveCount: 1, restrictiveCount: 0, allRowsPolicies: ['wide'], sources: ['public.invoices'],
  });
  assert.equal(v.status, 'leak');            // pre-fix: 'safe'
  assert.match(v.message, /PERMISSIVE with a constant-true qual/);
  assert.match(v.fix, /DROP POLICY "wide"/);
});

test('classify: the shapes that look decorative but are not must NOT be a leak', () => {
  // `using (true)` granted TO another role only; the app role has a scoped one.
  // Measured on pglite: authenticated sees 1 of 2 rows. all_rows_policies is
  // empty because the true-qual policy does not apply to this role.
  const roleTargeted = classifyDestination({
    schema: 'public', table: 'audit_log', rlsEnabled: true, canSelect: true, tenantColumn: null,
    permissiveCount: 1, restrictiveCount: 0, allRowsPolicies: [], sources: ['public.invoices'],
  });
  assert.notEqual(roleTargeted.status, 'leak');
  // `using (true)` neutralised by an AS RESTRICTIVE tenant policy. Measured:
  // authenticated sees 1 of 2 rows.
  const restricted = classifyDestination({
    schema: 'public', table: 'audit_log', rlsEnabled: true, canSelect: true, tenantColumn: null,
    permissiveCount: 1, restrictiveCount: 1, allRowsPolicies: ['wide'], sources: ['public.invoices'],
  });
  assert.notEqual(restricted.status, 'leak');
});

test('classify: RLS on with no applicable policy denies every row — silent, not a note', () => {
  const v = classifyDestination({
    schema: 'public', table: 'audit_log', rlsEnabled: true, canSelect: true, tenantColumn: null,
    permissiveCount: 0, restrictiveCount: 0, allRowsPolicies: [], sources: ['public.invoices'],
  });
  assert.equal(v.status, 'safe');
});

test('classify: RLS on WITH a tenant column stays safe — rls-proof plans exactly that table', () => {
  const v = classifyDestination({
    schema: 'public', table: 'audit_log', rlsEnabled: true, canSelect: true, tenantColumn: 'organization_id',
    permissiveCount: 1, restrictiveCount: 0, allRowsPolicies: ['wide'], sources: ['public.invoices'],
  });
  assert.equal(v.status, 'safe');
});

// ── integration: the advice has to run, and the guard has to see it ──

const SOURCE = `
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select, insert on invoices to authenticated;
  grant usage on all sequences in schema public to authenticated;
  alter table invoices enable row level security;
  create policy tenant on invoices for all
    using (organization_id = current_setting('app.current_tenant', true))
    with check (organization_id = current_setting('app.current_tenant', true));
`;

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin; create role reporter nologin;`);
  await db.exec(setup);
  return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
}

/** The runnable statements out of a printed fix — comment and prose lines dropped. */
function ddlOf(fix) {
  return fix
    .split('\n')
    .filter((l) => /^ {8,}\S/.test(l) && !/^\s*--/.test(l))
    .join('\n')
    .split(/;\s*(?:\n|$)/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => s + ';');
}

/** Read `sql` as the app role in tenant `org`, inside a rolled-back transaction. */
async function asTenant(db, org, sql) {
  await db.query('begin');
  try {
    await db.query('set local role authenticated');
    await db.query(`select set_config('app.current_tenant', '${org}', true)`);
    return (await db.query(sql)).rows;
  } finally {
    await db.query('rollback');
  }
}

if (PGlite) {
  test('the printed fix RUNS on a uuid destination (pre-fix: 42883, policy never created)', async () => {
    const { db, query } = await fresh(`
      create table invoices (id serial primary key, organization_id uuid not null, amount int);
      grant select, insert on invoices to authenticated;
      alter table invoices enable row level security;
      create policy tenant on invoices for all
        using (organization_id = current_setting('app.current_tenant', true)::uuid)
        with check (organization_id = current_setting('app.current_tenant', true)::uuid);
      create table audit_log (id serial primary key, organization_id uuid, detail text);
      grant select on audit_log to authenticated;
      create function log_invoice() returns trigger language plpgsql as $fn$
        begin insert into audit_log (organization_id, detail) values (new.organization_id, 'x'); return new; end $fn$;
      create trigger t_log after insert on invoices for each row execute function log_invoice();
    `);
    const res = await check({ query });
    assert.equal(res.ok, false);
    for (const stmt of ddlOf(res.violations[0].fix)) await db.exec(stmt);
    // and a session that never set the GUC gets zero rows, not an error
    const rows = await asTenant(db, '00000000-0000-0000-0000-000000000001', 'select count(*)::int n from audit_log');
    assert.equal(rows[0].n, 0);
  });

  test('following the printed fix leaves the SOURCE table writable (pre-fix: 42501 on every insert)', async () => {
    const { db, query } = await fresh(`
      ${SOURCE}
      create table audit_log (id serial primary key, actor text, detail text);
      grant select, insert on audit_log to authenticated;
      grant usage on sequence audit_log_id_seq to authenticated;
      create function log_invoice() returns trigger language plpgsql as $fn$
        begin insert into audit_log (actor, detail) values (current_user, 'inv'); return new; end $fn$;
      create trigger t_log after insert on invoices for each row execute function log_invoice();
    `);
    const res = await check({ query });
    assert.equal(res.ok, false);
    const fix = res.violations[0].fix;
    // Step 2 of the printed recipe, which the pre-fix advice never mentioned.
    assert.match(fix, /make the trigger carry the tenant across/);
    await db.exec(`create or replace function log_invoice() returns trigger language plpgsql as $fn$
      begin insert into audit_log (organization_id, actor, detail)
            values (new.organization_id, current_user, 'inv'); return new; end $fn$;`);
    for (const stmt of ddlOf(fix)) await db.exec(stmt);
    const rows = await asTenant(db, 'org_A', `insert into invoices (organization_id, amount) values ('org_A', 1) returning id`);
    assert.equal(rows.length, 1, 'the source table still accepts writes after the fix');
  });

  test('CATCHES a decorative RLS destination — using(true), no tenant column', async () => {
    const { db, query } = await fresh(`
      ${SOURCE}
      create table audit_log (id serial primary key, detail text, org text);
      alter table audit_log enable row level security;
      create policy wide on audit_log for select using (true);
      grant select on audit_log to authenticated;
      create function log_invoice() returns trigger language plpgsql security definer as $fn$
        begin insert into audit_log (detail, org) values ('x', new.organization_id); return new; end $fn$;
      create trigger t_log after insert on invoices for each row execute function log_invoice();
      insert into invoices (organization_id, amount) values ('org_A',100),('org_B',999);
    `);
    // prove the leak first, so this can't pass on a rotted premise
    assert.equal((await asTenant(db, 'org_A', 'select count(*)::int n from invoices'))[0].n, 1);
    assert.equal((await asTenant(db, 'org_A', 'select count(*)::int n from audit_log'))[0].n, 2);

    const res = await check({ query });          // pre-fix: ok=true, "all protected or unreadable"
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.where === 'public.audit_log');
    assert.ok(v);
    assert.match(v.message, /constant-true qual/);

    // and the printed fix, applied literally (plus its two commented steps), scopes it
    for (const stmt of ddlOf(v.fix)) await db.exec(stmt);
    await db.exec(`update audit_log set organization_id = org where organization_id is null;`);
    await db.exec(`create or replace function log_invoice() returns trigger language plpgsql security definer as $fn$
      begin insert into audit_log (detail, org, organization_id)
            values ('x', new.organization_id, new.organization_id); return new; end $fn$;`);
    assert.equal((await asTenant(db, 'org_A', 'select count(*)::int n from audit_log'))[0].n, 1);
    assert.equal((await check({ query })).ok, true);
  });

  test('does NOT fail the build on a using(true) policy granted to a different role', async () => {
    const { db, query } = await fresh(`
      ${SOURCE}
      create table audit_log (id serial primary key, detail text, org text);
      alter table audit_log enable row level security;
      create policy wide on audit_log for select to reporter using (true);
      create policy scoped on audit_log for select to authenticated
        using (org = current_setting('app.current_tenant', true));
      grant select on audit_log to authenticated, reporter;
      create function log_invoice() returns trigger language plpgsql security definer as $fn$
        begin insert into audit_log (detail, org) values ('x', new.organization_id); return new; end $fn$;
      create trigger t_log after insert on invoices for each row execute function log_invoice();
      insert into invoices (organization_id, amount) values ('org_A',100),('org_B',999);
    `);
    assert.equal((await asTenant(db, 'org_A', 'select count(*)::int n from audit_log'))[0].n, 1);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    // but it does not claim to have judged it, either
    assert.equal(res.notes.length, 1);
    assert.match(res.summary, /could not be judged/);
  });

  test('CATCHES an aliased UPDATE into an unprotected rollup (pre-fix: green)', async () => {
    const { db, query } = await fresh(`
      ${SOURCE}
      create table tenant_rollup (id int primary key, n int default 0, detail text default '');
      grant select on tenant_rollup to authenticated;
      insert into tenant_rollup (id, n) values (1, 0);
      create function bump() returns trigger language plpgsql security definer as $fn$
        begin update tenant_rollup r set n = r.n + 1, detail = r.detail || ' org ' || new.organization_id
               where r.id = 1; return new; end $fn$;
      create trigger t_b after insert on invoices for each row execute function bump();
      insert into invoices (organization_id, amount) values ('org_A',100),('org_B',999);
    `);
    assert.match((await asTenant(db, 'org_A', 'select detail from tenant_rollup'))[0].detail, /org_B/);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.ok(res.violations.find((x) => x.where === 'public.tenant_rollup'));
  });

  test('does NOT flag a shared config table mentioned only in a comment', async () => {
    const { query } = await fresh(`
      ${SOURCE}
      create table app_settings (k text primary key, v text);
      grant select on app_settings to authenticated;
      create function t_note() returns trigger language plpgsql as $fn$
        begin
          -- 2023: we used to "insert into app_settings" here; removed, it leaked
          return NEW;
        end $fn$;
      create trigger t_n after insert on invoices for each row execute function t_note();
    `);
    const res = await check({ query });   // pre-fix: ok=false on public.app_settings
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });
}
