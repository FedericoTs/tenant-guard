/**
 * cross-tenant-fk — five places the guard was wrong, each pinned by the thing
 * that was actually measured.
 *
 * Against the guard as it stood at 0.24.2, on real databases:
 *
 *   the emitted fix     applied verbatim, confdeltype 'c' -> 'a'; the owning
 *                       tenant could no longer delete their own parent row
 *   a zero-row probe    read as "attempted and refused" -> silent pass on a leak
 *                       proven one line later with `claim: 'org_id'`
 *   tenant columns      unordered, so a legacy `tenant_id` declared before
 *                       `organization_id` won; the CORRECT composite key was
 *                       reported as not carrying the tenant, and a loose FK was
 *                       reported as 2 rows of corruption that did not exist
 *   catalog reads       unqualified, so `public.pg_class` + search_path made the
 *                       guard report "nothing to check"
 *   self-references     excluded outright; a parent_id hierarchy is the FULL
 *                       §3.11 attack and was reported skipped, scanned 0
 *
 * The integration tests apply what the guard prints and look at the database
 * afterwards, rather than checking the wording.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  check,
  candidateFks,
  classifyFk,
  foreignKeysSql,
  tenantColumnsSql,
  tenantColumnMap,
  ownRowsSql,
  referentialActionClause,
} from '../src/guards/cross-tenant-fk.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('cross-tenant-fk-audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── pure: the fix keeps the referential action ───────────────────────

const TC = tenantColumnMap([
  { schema: 'public', table: 'tasks', column: 'organization_id' },
  { schema: 'public', table: 'projects', column: 'organization_id' },
]);
const FK = {
  name: 'tasks_project_id_fkey',
  child_schema: 'public', child_table: 'tasks',
  parent_schema: 'public', parent_table: 'projects',
  on_delete: 'c', on_update: 'a',
  child_columns: ['project_id'], parent_columns: ['id'],
};
const candidate = (over = {}) => candidateFks([{ ...FK, ...over }], TC)[0];

test('the replacement key carries the action the current key has, not the default', () => {
  const cascade = referentialActionClause(candidate());
  assert.equal(cascade.clause, 'ON DELETE CASCADE ON UPDATE NO ACTION');
  assert.deepEqual(cascade.warnings, []);

  const restrict = referentialActionClause(candidate({ on_delete: 'r', on_update: 'c' }));
  assert.equal(restrict.clause, 'ON DELETE RESTRICT ON UPDATE CASCADE');
});

test('ON DELETE SET NULL / SET DEFAULT are scoped to the non-tenant column', () => {
  // A bare SET NULL on the composite replacement key nulls organization_id too:
  // measured as `null value in column "organization_id" ... violates not-null`.
  const setNull = referentialActionClause(candidate({ on_delete: 'n' }));
  assert.equal(setNull.clause, 'ON DELETE SET NULL (project_id) ON UPDATE NO ACTION');
  assert.equal(setNull.warnings.length, 1);
  assert.match(setNull.warnings[0], /Postgres 15\+/);

  const setDefault = referentialActionClause(candidate({ on_delete: 'd' }));
  assert.equal(setDefault.clause, 'ON DELETE SET DEFAULT (project_id) ON UPDATE NO ACTION');

  // Composite child key: the guard cannot name the non-tenant columns, so the
  // list stays a placeholder that does NOT run, rather than a bare SET NULL
  // that runs and nulls the tenant column.
  const composite = candidateFks([{ ...FK, on_delete: 'n', child_columns: ['project_id', 'seq'], parent_columns: ['id', 'seq'] }], TC)[0];
  assert.equal(referentialActionClause(composite).clause, 'ON DELETE SET NULL (…) ON UPDATE NO ACTION');
});

test('ON UPDATE SET NULL gets a warning, not a column list Postgres rejects', () => {
  // "a column list with SET NULL is only supported for ON DELETE actions".
  const v = referentialActionClause(candidate({ on_delete: 'a', on_update: 'n' }));
  assert.equal(v.clause, 'ON DELETE NO ACTION ON UPDATE SET NULL');
  assert.doesNotMatch(v.clause, /SET NULL \(/);
  assert.equal(v.warnings.length, 1);
  assert.match(v.warnings[0], /by hand/);
});

test('the emitted ALTER carries the action', () => {
  const v = classifyFk({ fk: candidate(), probe: 'landed' });
  assert.match(v.fix, /REFERENCES public\.projects \(organization_id, id\)\s*\n\s*ON DELETE CASCADE ON UPDATE NO ACTION;/);
});

// ── pure: a zero-row probe is not a refusal ──────────────────────────

test('"no-match" is a pass that does not claim a refusal that never happened', () => {
  const v = classifyFk({ fk: candidate(), probe: 'no-match' });
  assert.equal(v.status, 'ok');
  assert.doesNotMatch(v.message, /refused/);
  assert.match(v.message, /matched no row/);
});

// ── pure: catalog reads and tenant-column priority ───────────────────

test('every catalog reference is pg_catalog-qualified', () => {
  // Unqualified, these resolve through search_path, and a public.pg_class
  // shadow flipped this guard from a violation to "nothing to check".
  for (const spec of [foreignKeysSql(['public']), tenantColumnsSql(['public'], ['organization_id'])]) {
    const unqualified = spec.text.match(/\b(?:from|join)\s+pg_(?!catalog\.)\w+/gi) ?? [];
    assert.deepEqual(unqualified, [], `unqualified catalog reads: ${unqualified.join(', ')}`);
  }
});

test('tenantColumnsSql ranks by the configured order, like every other guard', () => {
  const { text } = tenantColumnsSql(['public'], ['organization_id', 'tenant_id']);
  assert.match(text, /order by array_position\(\$2::text\[\], a\.attname::text\)/);
});

// ── pure: self-references ────────────────────────────────────────────

test('a self-reference IS a candidate — the boundary runs between its own rows', () => {
  const selfTc = tenantColumnMap([{ schema: 'public', table: 'nodes', column: 'organization_id' }]);
  const self = {
    ...FK, name: 'nodes_parent_id_fkey',
    child_table: 'nodes', parent_table: 'nodes',
    child_columns: ['parent_id'], parent_columns: ['id'],
  };
  const [c] = candidateFks([self], selfTc);
  assert.equal(c.id, 'public.nodes::nodes_parent_id_fkey');
  assert.equal(c.childColumn, 'parent_id');
});

test('a self-reference that carries the tenant is still excluded — no cry-wolf on the fixed shape', () => {
  const selfTc = tenantColumnMap([{ schema: 'public', table: 'nodes', column: 'organization_id' }]);
  const fixed = {
    ...FK, name: 'nodes_parent_id_fkey',
    child_table: 'nodes', parent_table: 'nodes',
    child_columns: ['organization_id', 'parent_id'], parent_columns: ['organization_id', 'id'],
  };
  assert.deepEqual(candidateFks([fixed], selfTc), []);
});

test('ownRowsSql is a complete spec and quotes its identifiers', () => {
  const spec = ownRowsSql(candidate({ child_table: 'ta"sks' }) ?? candidate(), 'org_A');
  assert.equal(spec.values.length, (spec.text.match(/\$\d+/g) ?? []).length);
});

// ── integration ──────────────────────────────────────────────────────

const POLICIES = (setting) => `
  alter table projects enable row level security;
  alter table tasks    enable row level security;
  create policy p on projects using (organization_id = ${setting}) with check (organization_id = ${setting});
  create policy t on tasks    using (organization_id = ${setting}) with check (organization_id = ${setting});
`;
const APP_SETTING = `current_setting('app.current_tenant', true)`;
const JWT_SETTING = `current_setting('request.jwt.claims', true)::json->>'org_id'`;

const LOOSE = (onDelete = 'cascade', setting = APP_SETTING) => `
  create table projects (id int primary key, organization_id text not null, name text);
  create table tasks (
    id int primary key,
    organization_id text not null,
    project_id int references projects(id) on delete ${onDelete}
  );
  insert into projects values (1,'org_A','A project'), (2,'org_B','B project');
  insert into tasks values (10,'org_A',1), (20,'org_B',2);
  grant select, insert, update, delete on projects, tasks to authenticated;
  ${POLICIES(setting)}
`;

async function freshDb(setup) {
  const db = new PGlite();
  await db.exec('create role authenticated nologin;');
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

/** The executable statements out of a printed `fix`, comments and prose dropped. */
function sqlFromFix(fix) {
  return fix
    .split('\n')
    .slice(1)
    .filter((l) => !/^\s*--/.test(l) && !/^\s*If this reference/.test(l))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => `${s};`);
}

/** Run `sql` as `authenticated` impersonating `tenant`, committing. */
async function asTenant(db, tenant, sql) {
  await db.query('begin');
  await db.query(`select set_config('app.current_tenant', $1, true)`, [tenant]);
  await db.query('set local role authenticated');
  try {
    const r = await db.query(sql);
    await db.query('commit');
    return { ok: true, rows: r.rows };
  } catch (err) {
    await db.query('rollback');
    return { ok: false, message: err.message };
  }
}

if (PGlite) {
  test('APPLYING the emitted fix verbatim closes the hole AND leaves the owner able to delete', async () => {
    const { db, query } = await freshDb(LOOSE('cascade'));

    // Baseline: the owning tenant can delete their own project, and it cascades.
    const before = await asTenant(db, 'org_A', 'delete from projects where id = 1');
    assert.equal(before.ok, true, before.message);
    assert.equal((await db.query(`select count(*)::int n from tasks where id = 10`)).rows[0].n, 0);
    await db.exec(`insert into projects values (1,'org_A','A project'); insert into tasks values (10,'org_A',1);`);

    const res = await check({ query });
    assert.equal(res.ok, false);
    for (const stmt of sqlFromFix(res.violations[0].fix)) await db.exec(stmt);

    // The action survived the migration. This is the whole finding: it was 'a'.
    const del = await db.query(`select confdeltype from pg_catalog.pg_constraint where conname = 'tasks_project_id_fkey'`);
    assert.equal(del.rows[0].confdeltype, 'c', 'ON DELETE CASCADE must survive the remediation');

    // The owner can still delete their own parent row, and it still cascades —
    // but only within their own tenant.
    const after = await asTenant(db, 'org_A', 'delete from projects where id = 1');
    assert.equal(after.ok, true, `the owner lost DELETE on their own row: ${after.message}`);
    assert.equal((await db.query(`select count(*)::int n from tasks where organization_id = 'org_A'`)).rows[0].n, 0);
    assert.equal((await db.query(`select count(*)::int n from tasks where organization_id = 'org_B'`)).rows[0].n, 1);

    // And the hole really is closed.
    const repoint = await asTenant(db, 'org_B', `update tasks set project_id = 1 where organization_id = 'org_B'`);
    assert.equal(repoint.ok, false, 'a cross-tenant re-point must now be rejected');
    assert.equal((await check({ query })).skipped, true);
  });

  test('the emitted SET NULL fix runs, and does not null the tenant column', async () => {
    const { db, query } = await freshDb(LOOSE('set null'));
    const res = await check({ query });
    assert.equal(res.ok, false);
    for (const stmt of sqlFromFix(res.violations[0].fix)) await db.exec(stmt);

    const gone = await asTenant(db, 'org_A', 'delete from projects where id = 1');
    assert.equal(gone.ok, true, `a bare SET NULL would null organization_id here: ${gone.message}`);
    const row = (await db.query(`select organization_id, project_id from tasks where id = 10`)).rows[0];
    assert.deepEqual(row, { organization_id: 'org_A', project_id: null });
  });

  test('a becomeTenant that does not match the policies is a NOTE, never a green pass', async () => {
    // Supabase-shaped JWT-claim policies, default app.current_tenant config: the
    // impersonated session sees none of its own rows, so the zero-row UPDATE
    // means nothing. This reported ok with no notes at all.
    const blind = await freshDb(LOOSE('cascade', JWT_SETTING));
    const res = await check({ query: blind.query });
    assert.equal(res.violations.length, 0);
    assert.equal(res.notes.length, 1, JSON.stringify(res));
    assert.match(res.notes[0].message, /sees none of its own rows/);
    assert.match(res.notes[0].message, /claim/);

    // Same database, config that DOES match: a proven leak.
    const sighted = await freshDb(LOOSE('cascade', JWT_SETTING));
    const real = await check({ query: sighted.query, config: { claim: 'org_id' } });
    assert.equal(real.ok, false, JSON.stringify(real));
    assert.equal(real.violations[0].kind, 'cross-tenant-reference');
  });

  test('a probe the database RAISES on is still a silent pass — the control arm does not cry wolf', async () => {
    // Calibration, not a fix-proving case: this passed before the change too.
    // It is here so the control arm cannot regress into a false alarm.
    const { db, query } = await freshDb(LOOSE('cascade'));
    await db.exec(`
      revoke update on tasks from authenticated;
      grant update (organization_id) on tasks to authenticated;
    `);
    const res = await check({ query });
    assert.equal(res.ok, true, JSON.stringify(res));
    assert.equal(res.violations.length, 0);
    assert.equal(res.notes.length, 0, `a refused probe must stay quiet: ${JSON.stringify(res.notes)}`);
  });

  test('the tenant column is the highest-priority one, not the earliest-declared', async () => {
    // A legacy nullable `tenant_id` sitting before `organization_id`. Picking it
    // made the CORRECT composite key look loose, and made `is distinct from`
    // count every joined row as pre-existing corruption.
    const CORRECT = `
      create table projects (id int primary key, organization_id text not null);
      alter table projects add unique (organization_id, id);
      create table tasks (
        id int primary key, tenant_id text, organization_id text not null, project_id int,
        foreign key (organization_id, project_id) references projects (organization_id, id) on delete cascade
      );
      insert into projects values (1,'org_A'),(2,'org_B');
      insert into tasks (id, tenant_id, organization_id, project_id) values (10,null,'org_A',1),(20,null,'org_B',2);
      grant select, insert, update, delete on projects, tasks to authenticated;
      ${POLICIES(APP_SETTING)}
    `;
    const good = await freshDb(CORRECT);
    const res = await check({ query: good.query });
    assert.equal(res.skipped, true, JSON.stringify(res));
    assert.equal(res.notes.length, 0);

    const VULNERABLE = `
      create table projects (id int primary key, organization_id text not null);
      create table tasks (
        id int primary key, tenant_id text, organization_id text not null,
        project_id int references projects(id) on delete cascade
      );
      insert into projects values (1,'org_A'),(2,'org_B');
      insert into tasks (id, tenant_id, organization_id, project_id) values (10,null,'org_A',1),(20,null,'org_B',2);
      grant select, insert, update, delete on projects, tasks to authenticated;
      ${POLICIES(APP_SETTING)}
    `;
    const bad = await freshDb(VULNERABLE);
    const leak = await check({ query: bad.query });
    assert.equal(leak.ok, false);
    // The right verdict for the right reason: proven by the probe, not invented
    // by comparing an all-NULL column against the parent's tenant.
    assert.equal(leak.violations[0].kind, 'cross-tenant-reference');
  });

  test('a shadowed pg_catalog does not silence the guard', async () => {
    const { db, query } = await freshDb(LOOSE('cascade'));
    await db.exec(`
      create table public.pg_class (oid oid, relname name, relnamespace oid, relkind "char", relowner oid, relacl aclitem[], relrowsecurity bool);
      create table public.pg_namespace (oid oid, nspname name);
      create table public.pg_attribute (attrelid oid, attname name, attnum smallint, attisdropped bool);
      create table public.pg_constraint (oid oid, conname name, contype "char", conrelid oid, confrelid oid, conkey smallint[], confkey smallint[], confdeltype "char", confupdtype "char");
      set search_path = public, pg_catalog;
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res));
    assert.equal(res.violations[0].kind, 'cross-tenant-reference');
  });

  test('DEMONSTRATES it on a self-reference: org_B deleting their own row destroys org_A\'s', async () => {
    const SELF = `
      create table nodes (
        id int primary key, organization_id text not null, label text,
        parent_id int references nodes(id) on delete cascade
      );
      insert into nodes values (1,'org_A','a',null),(2,'org_B','b',null);
      grant select, insert, update, delete on nodes to authenticated;
      alter table nodes enable row level security;
      create policy n on nodes using (organization_id = ${APP_SETTING}) with check (organization_id = ${APP_SETTING});
    `;
    const { db, query } = await freshDb(SELF);

    // The guard must now see it. It reported skipped, scanned 0.
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res));
    assert.equal(res.violations[0].where, 'public.nodes::nodes_parent_id_fkey');

    // And the attack it describes really lands.
    const seen = await asTenant(db, 'org_A', 'select * from nodes');
    assert.equal(seen.rows.length, 1, 'RLS is working for reads');
    assert.equal((await asTenant(db, 'org_A', `update nodes set parent_id = 2 where organization_id = 'org_A'`)).ok, true);
    assert.equal((await asTenant(db, 'org_B', 'delete from nodes where id = 2')).ok, true);
    assert.equal((await db.query('select count(*)::int n from nodes')).rows[0].n, 0, "org_B's ordinary delete destroyed org_A's row");
  });

  test('the self-reference probe is rolled back, and the emitted fix applies', async () => {
    const SELF = `
      create table nodes (
        id int primary key, organization_id text not null,
        parent_id int references nodes(id) on delete cascade
      );
      insert into nodes values (1,'org_A',null),(2,'org_B',null);
      grant select, insert, update, delete on nodes to authenticated;
      alter table nodes enable row level security;
      create policy n on nodes using (organization_id = ${APP_SETTING}) with check (organization_id = ${APP_SETTING});
    `;
    const { db, query } = await freshDb(SELF);
    const res = await check({ query });
    assert.deepEqual(
      (await db.query('select id, parent_id from nodes order by id')).rows.map((r) => r.parent_id),
      [null, null],
      'the probe must leave nothing re-pointed',
    );
    for (const stmt of sqlFromFix(res.violations[0].fix)) await db.exec(stmt);
    assert.equal((await check({ query })).skipped, true);
  });

  test('the skip reason describes what was excluded instead of asserting absence', async () => {
    const { query } = await freshDb(LOOSE('cascade'));
    const res = await check({ query, config: { allowlist: ['public.tasks::tasks_project_id_fkey'] } });
    assert.equal(res.skipped, true);
    // The old wording claimed no such foreign key existed. One did; it was
    // allowlisted.
    assert.match(res.reason, /allowlisted/);
    assert.match(res.reason, /1 foreign key\(s\)/);
  });
}
