import { PGlite } from '@electric-sql/pglite';
import { check } from './src/guards/definer-rpc.mjs';

const db = new PGlite();
await db.exec(`create role authenticated nologin;`);
await db.exec(`
  create table invoices (id serial primary key, organization_id text not null, amount int);
  grant select on invoices to authenticated;
  insert into invoices (organization_id, amount) values ('org_A',100),('org_B',200);
  alter table invoices enable row level security;
  create policy tenant on invoices using (organization_id = current_setting('app.current_tenant', true));
  create function helper() returns setof invoices
    language sql security definer stable
    as $$ select * from invoices where organization_id = current_setting('app.current_tenant', true) $$;
  grant execute on function helper() to authenticated;
  revoke create on schema public from public;
`);
const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

const r1 = await check({ query });
console.log('RUN 1 ok=', r1.ok);
console.log('  violations:', r1.violations.map(v=>v.kind));
for (const n of r1.notes) if (/search_path/.test(n.message)) console.log('  NOTE:', n.where, '::', n.message);

// apply the advice VERBATIM as printed in the note
await db.exec(`alter function public.helper() set search_path = pg_catalog, public`);

const r2 = await check({ query });
console.log('RUN 2 ok=', r2.ok);
for (const v of r2.violations) console.log('  VIOLATION', v.kind, '::', v.message.slice(0,160));
