/**
 * Runtime RLS proof — a self-contained demo you can actually run.
 *
 *   npm i @electric-sql/pglite      # embedded Postgres, no Docker, no server
 *   node examples/rls-proof/demo.mjs
 *
 * It stands up two throwaway Postgres databases in-process: one with a correct
 * tenant policy, one with a policy that leaks. Then it runs the exact same proof
 * `tenant-guard prove` runs — dropping to a non-superuser role, assuming a
 * tenant's identity, and measuring whether that session can read the OTHER
 * tenant's rows. Watch it pass the first and fail the second.
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
const code = report([await prove({ query: bad })], { emptyHint: false });

console.log(
  dim(
    'That second failure is the whole point: a scanner can read the policy text, but only a\n' +
      "runtime proof can tell you the session actually saw another tenant's rows. Wire\n" +
      '`tenant-guard prove` into CI against a seeded test database and it runs on every commit.',
  ) + '\n',
);

process.exit(code); // non-zero — exactly what CI would see on the leak
