/**
 * Runtime RLS proof — a self-contained demo you can actually run.
 *
 *   npm i @electric-sql/pglite      # embedded Postgres, no Docker, no server
 *   node examples/rls-proof/demo.mjs
 *
 * It stands up throwaway Postgres databases in-process and runs the exact same
 * proof `tenant-guard prove` runs — dropping to a non-superuser role, assuming a
 * tenant's identity, and measuring whether that session can READ or WRITE the
 * OTHER tenant's rows. Watch it pass a correct policy, fail an obvious read
 * leak, and — the subtle one — fail a table whose reads look perfectly isolated
 * but whose UPDATE path is wide open.
 */
import { prove } from '../../src/guards/rls-proof.mjs';
import { report, bold, dim } from '../../src/runner.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  console.error('This demo needs pglite (embedded Postgres):\n\n  npm i @electric-sql/pglite\n');
  process.exit(1);
}

async function db(setupSql) {
  const pg = new PGlite();
  await pg.exec(`create role authenticated nologin;`);
  await pg.exec(setupSql);
  return (text, values) => pg.query(text, Array.isArray(values) && values.length ? values : undefined);
}

const seed = `
  insert into invoices (organization_id, amount) values ('org_acme', 100), ('org_acme', 250), ('org_globex', 900);
  grant select on invoices to authenticated;
  alter table invoices enable row level security;
`;

console.log('\n' + bold('1) A correctly scoped tenant policy — the proof should PASS'));
const good = await db(`
  create table invoices (id serial primary key, organization_id text not null, amount int);
  ${seed}
  create policy tenant_isolation on invoices
    using (organization_id = current_setting('app.current_tenant', true));
`);
report([await prove({ query: good })], { emptyHint: false });

console.log(bold('2) The same schema, but the policy forgot the tenant predicate — the proof should FAIL'));
const bad = await db(`
  create table invoices (id serial primary key, organization_id text not null, amount int);
  ${seed}
  create policy oops_all_rows on invoices using (true);
`);
const code2 = report([await prove({ query: bad })], { emptyHint: false });

console.log(bold("3) The subtle one — reads are correctly scoped, but UPDATE is wide open"));
const writeLeak = await db(`
  create table invoices (id serial primary key, organization_id text not null, amount int);
  insert into invoices (organization_id, amount) values ('org_acme', 100), ('org_acme', 250), ('org_globex', 900);
  grant select, update, delete on invoices to authenticated;
  alter table invoices enable row level security;
  create policy reads_ok on invoices for select
    using (organization_id = current_setting('app.current_tenant', true));           -- reads: correct
  create policy writes_open on invoices for update using (true) with check (true);   -- writes: BUG
`);
const code3 = report([await prove({ query: writeLeak })], { emptyHint: false });

console.log(
  dim(
    'Scenario 3 is the one a read-only check — and every SELECT-based test — misses: the read\n' +
      'policy is correct, so nothing *looks* wrong, yet one tenant can UPDATE/DELETE another\n' +
      "tenant's rows because Postgres RLS is per-command. A scanner reads policy text; only a\n" +
      'runtime proof exercises the write path. Wire `tenant-guard prove` into CI against a seeded\n' +
      'test database and it runs on every commit.',
  ) + '\n',
);

process.exit(code2 || code3); // non-zero — exactly what CI would see on a leak
