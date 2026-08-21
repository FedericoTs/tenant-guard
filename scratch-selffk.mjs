import { PGlite } from '@electric-sql/pglite';
import { check } from './src/guards/cross-tenant-fk.mjs';
import { prove } from './src/guards/rls-proof.mjs';
import { check as oracles } from './src/guards/constraint-oracles.mjs';

const SETUP = `
  create table nodes (
    id int primary key,
    organization_id text not null,
    label text,
    parent_id int references nodes(id) on delete cascade
  );
  insert into nodes values (1,'org_A','A root',null), (2,'org_B','B root',null);
  grant select, insert, update, delete on nodes to authenticated;
  alter table nodes enable row level security;
  create policy p on nodes
    using (organization_id = current_setting('app.current_tenant', true))
    with check (organization_id = current_setting('app.current_tenant', true));
`;

const db = new PGlite();
await db.exec('create role authenticated nologin;');
await db.exec(SETUP);
const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

const asTenant = async (tenant, sql) => {
  await db.query('begin');
  await db.query(`select set_config('app.current_tenant', $1, true)`, [tenant]);
  await db.query('set local role authenticated');
  const r = await db.query(sql);
  await db.query('commit');
  return r;
};

// 1. Manual exploit
const vis = await asTenant('org_A', 'select * from nodes');
console.log('org_A sees rows:', vis.rows.length);
await asTenant('org_A', "update nodes set parent_id = 2 where organization_id = 'org_A'");
console.log('after repoint:', (await db.query('select id, parent_id from nodes order by id')).rows);
await asTenant('org_B', 'delete from nodes where id = 2');
console.log('survivors:', (await db.query('select id, organization_id from nodes order by id')).rows);

// 2. Fresh DB — what the guards say
const db2 = new PGlite();
await db2.exec('create role authenticated nologin;');
await db2.exec(SETUP);
const q2 = (t, v) => db2.query(t, Array.isArray(v) && v.length ? v : undefined);
console.log('\ncross-tenant-fk:', JSON.stringify(await check({ query: q2 }), null, 2));
console.log('\nrls-proof.ok:', (await prove({ query: q2 })).ok);
const o = await oracles({ query: q2 });
console.log('\nconstraint-oracles:', JSON.stringify({ ok: o.ok, summary: o.summary, violations: o.violations, notes: o.notes }, null, 2));
