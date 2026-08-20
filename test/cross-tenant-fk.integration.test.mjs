/**
 * cross-tenant-fk against a real database.
 *
 * The first test is the one that matters, and it is the only place in this
 * project where a tenant **destroys** another tenant's data rather than reading
 * it: tenant A points its row at tenant B's project, tenant B deletes that
 * project, and tenant A's row is gone. Both tenants did something entirely
 * ordinary, and `rls-proof` calls the same database isolated.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check } from '../src/guards/cross-tenant-fk.mjs';
import { prove } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('cross-tenant-fk integration (pglite not installed — skipped)', { skip: true }, () => {});
}

const POLICIES = `
  alter table projects enable row level security;
  alter table tasks    enable row level security;
  create policy p on projects
    using (organization_id = current_setting('app.current_tenant', true))
    with check (organization_id = current_setting('app.current_tenant', true));
  create policy t on tasks
    using (organization_id = current_setting('app.current_tenant', true))
    with check (organization_id = current_setting('app.current_tenant', true));
`;

/** The vulnerable shape: the FK carries an id, but not the tenant. */
const LOOSE_FK = (onDelete = 'cascade') => `
  create table projects (id int primary key, organization_id text not null, name text);
  create table tasks (
    id int primary key,
    organization_id text not null,
    project_id int references projects(id) on delete ${onDelete}
  );
  insert into projects values (1,'org_A','A project'), (2,'org_B','B project');
  insert into tasks values (10,'org_A',1), (20,'org_B',2);
  grant select, insert, update, delete on projects, tasks to authenticated;
  ${POLICIES}
`;

/** The fix: the tenant is part of the key, so a cross-tenant row cannot exist. */
const TIGHT_FK = `
  create table projects (id int primary key, organization_id text not null, name text);
  alter table projects add unique (organization_id, id);
  create table tasks (
    id int primary key,
    organization_id text not null,
    project_id int,
    foreign key (organization_id, project_id) references projects (organization_id, id) on delete cascade
  );
  insert into projects values (1,'org_A','A project'), (2,'org_B','B project');
  insert into tasks values (10,'org_A',1), (20,'org_B',2);
  grant select, insert, update, delete on projects, tasks to authenticated;
  ${POLICIES}
`;

async function freshDb(setup) {
  const db = new PGlite();
  await db.exec('create role authenticated nologin;');
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

if (PGlite) {
  // ── the leak, end to end ───────────────────────────────────────────
  test('DEMONSTRATES it: tenant B deleting their own row destroys tenant A\'s data', async () => {
    const { db } = await freshDb(LOOSE_FK());

    const asTenant = async (tenant, sql) => {
      await db.query('begin');
      await db.query(`select set_config('app.current_tenant', $1, true)`, [tenant]);
      await db.query('set local role authenticated');
      const r = await db.query(sql);
      await db.query('commit');
      return r;
    };

    // org_A cannot even SEE org_B's project…
    const visible = await asTenant('org_A', 'select * from projects');
    assert.equal(visible.rows.length, 1, 'RLS is working for reads');

    // …but can point its own task at it. The FK check bypasses RLS, and the
    // WITH CHECK governs the tenant column, not the reference.
    await asTenant('org_A', 'update tasks set project_id = 2 where id = 10');
    const repointed = await db.query('select project_id from tasks where id = 10');
    assert.equal(repointed.rows[0].project_id, 2, 'a cross-tenant reference was created');

    // org_B now deletes their own project. Nothing unusual about that.
    await asTenant('org_B', 'delete from projects where id = 2');

    // org_A's task is gone. No policy was consulted at any point.
    const survivors = await db.query(`select count(*)::int as n from tasks where id = 10`);
    assert.equal(survivors.rows[0].n, 0, "org_B's ordinary delete destroyed org_A's row");
  });

  test('rls-proof reports that same database as isolated — this guard exists for the gap', async () => {
    const { query } = await freshDb(LOOSE_FK());
    const res = await prove({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });

  // ── the guard ──────────────────────────────────────────────────────
  test('CATCHES it: the probe re-points a row and the guard fails', async () => {
    const { query } = await freshDb(LOOSE_FK());
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 1);
    const v = res.violations[0];
    assert.equal(v.where, 'public.tasks::tasks_project_id_fkey');
    assert.equal(v.kind, 'cross-tenant-reference');
    assert.match(v.message, /DELETES these rows/);
    assert.match(v.fix, /FOREIGN KEY \(organization_id, project_id\)/);
  });

  test('the probe is rolled back — no row is left re-pointed', async () => {
    const { db, query } = await freshDb(LOOSE_FK());
    await check({ query });
    const rows = await db.query('select id, project_id from tasks order by id');
    assert.deepEqual(rows.rows.map((r) => r.project_id), [1, 2], 'the original references are intact');
  });

  test('PASSES when the key carries the tenant — the bad row is unrepresentable', async () => {
    const { query } = await freshDb(TIGHT_FK);
    const res = await check({ query });
    assert.equal(res.skipped, true, JSON.stringify(res, null, 2));
    assert.match(res.reason, /without carrying the tenant column/);
  });

  test('CATCHES existing corruption without probing anything', async () => {
    // A cross-tenant reference already in the data — a bad migration, a bug
    // fixed later, an import. Conclusive, and no probe is needed to say so.
    const { db, query } = await freshDb(LOOSE_FK());
    await db.exec('update tasks set project_id = 2 where id = 10'); // privileged, no RLS
    const res = await check({ query });
    assert.equal(res.ok, false);
    assert.equal(res.violations[0].kind, 'existing-cross-tenant-reference');
    assert.match(res.violations[0].message, /1 row\(s\)/);
    assert.match(res.violations[0].message, /not a hypothetical/);
  });

  test('RESTRICT is still a finding — one tenant pins another tenant\'s row', async () => {
    const { query } = await freshDb(LOOSE_FK('restrict'));
    const res = await check({ query });
    assert.equal(res.ok, false);
    assert.match(res.violations[0].message, /PINS the other tenant's row/);
  });

  test('a reference to a shared lookup table is not flagged', async () => {
    const { query } = await freshDb(`
      create table countries (code text primary key, name text);
      create table projects (id int primary key, organization_id text not null, country_code text references countries(code));
      insert into countries values ('IE','Ireland');
      insert into projects values (1,'org_A','IE'), (2,'org_B','IE');
      grant select, update on projects, countries to authenticated;
      alter table projects enable row level security;
      create policy p on projects using (organization_id = current_setting('app.current_tenant', true));
    `);
    const res = await check({ query });
    assert.equal(res.skipped, true); // countries has no tenant column — not a boundary
  });

  test('an allowlisted constraint is skipped', async () => {
    const { query } = await freshDb(LOOSE_FK());
    const res = await check({ query, config: { allowlist: ['public.tasks::tasks_project_id_fkey'] } });
    assert.equal(res.skipped, true);
  });

  test('with only one tenant present the finding is a note, never a pass', async () => {
    const { query } = await freshDb(`
      create table projects (id int primary key, organization_id text not null);
      create table tasks (id int primary key, organization_id text not null, project_id int references projects(id) on delete cascade);
      insert into projects values (1,'org_A');
      insert into tasks values (10,'org_A',1);
      grant select, update on projects, tasks to authenticated;
      ${POLICIES}
    `);
    const res = await check({ query });
    assert.equal(res.ok, true);
    assert.equal(res.violations.length, 0);
    assert.match(res.notes[0].message, /no child rows belonging to a second tenant/);
  });
}
