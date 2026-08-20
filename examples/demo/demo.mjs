/**
 * The README demo, and something you can actually run:
 *
 *   npm i @electric-sql/pglite     # embedded Postgres — no Docker, no server
 *   npm run demo
 *
 * It stands up a throwaway database shaped like a small multi-tenant SaaS that
 * was built quickly — the RLS on the main table is genuinely correct, and then
 * six other things around it are not — and runs the REAL guards against it,
 * through the real reporter. Nothing here is mocked or hand-written: every line
 * of output below is produced by the same code `tenant-guard all` runs.
 *
 * The point it makes is the point of the whole tool: the policy on `projects` is
 * fine. Every leak here is somewhere else.
 */
import { prove } from '../../src/guards/rls-proof.mjs';
import { check as checkViews } from '../../src/guards/view-isolation.mjs';
import { check as checkAnonReads } from '../../src/guards/anon-reads.mjs';
import { check as checkFks } from '../../src/guards/cross-tenant-fk.mjs';
import { check as checkCreateGrants } from '../../src/guards/create-grants.mjs';
import { check as checkDefaults } from '../../src/guards/default-privileges.mjs';
import { report, bold, dim } from '../../src/runner.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  console.error('This demo needs pglite (embedded Postgres):\n\n  npm i @electric-sql/pglite\n');
  process.exit(1);
}

/**
 * A plausible little app. One table is done right; the rest is the sort of
 * thing that accumulates when you are moving fast.
 */
const SCHEMA = `
  create role anon nologin;
  create role authenticated nologin;
  grant usage on schema public to anon, authenticated;

  -- The tenant table, and its RLS is CORRECT. This is the part everybody checks.
  create table projects (id int primary key, organization_id text not null, name text);
  insert into projects values (1, 'org_acme', 'Website'), (2, 'org_globex', 'Migration');
  grant select, insert, update, delete on projects to authenticated;
  alter table projects enable row level security;
  create policy tenant_isolation on projects
    using      (organization_id = current_setting('app.current_tenant', true))
    with check (organization_id = current_setting('app.current_tenant', true));

  -- 1. A table somebody added later and forgot to protect.
  create table invoices (id int primary key, organization_id text not null, amount int);
  insert into invoices values (10, 'org_acme', 4200), (20, 'org_globex', 99000);
  grant select on invoices to authenticated, anon;

  -- 2. A dashboard matview. RLS never applies to one of these, at all.
  create materialized view revenue_by_org as
    select organization_id, sum(amount) as total from invoices group by 1;
  grant select on revenue_by_org to authenticated;

  -- 3. A foreign key that carries an id but not the tenant.
  create table tasks (
    id int primary key,
    organization_id text not null,
    project_id int references projects(id) on delete cascade
  );
  insert into tasks values (100, 'org_acme', 1), (200, 'org_globex', 2);
  grant select, update on tasks to authenticated;
  alter table tasks enable row level security;
  create policy tasks_isolation on tasks
    using      (organization_id = current_setting('app.current_tenant', true))
    with check (organization_id = current_setting('app.current_tenant', true));

  -- 4. Left over from a tutorial.
  grant create on schema public to public;

  -- 5. So the next table "just works" — and arrives readable by anyone.
  alter default privileges in schema public grant select on tables to anon;
`;

const db = new PGlite();
await db.exec(SCHEMA);
const query = (text, values) => db.query(text, Array.isArray(values) && values.length ? values : undefined);

console.log(bold('\ntenant-guard') + dim('  — a small SaaS, built quickly\n'));
console.log(dim('  projects: RLS enabled, policy scopes by organization_id — correct.'));
console.log(dim('  Everything below is somewhere else.\n'));

const results = [];
results.push(await prove({ query }));
results.push(await checkAnonReads({ query }));
results.push(await checkViews({ query }));
results.push(await checkFks({ query }));
results.push(await checkDefaults({ query }));
results.push(await checkCreateGrants({ query }));

const code = report(results, { title: false, emptyHint: false });
process.exit(code);
