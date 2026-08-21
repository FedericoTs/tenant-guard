import { PGlite } from '@electric-sql/pglite';
import { check } from './src/guards/constraint-oracles.mjs';

const db = new PGlite();
const q = (text, values) => db.query(text, values);

await q(`create role anon; create role authenticated;`);
await q(`create table plans(id serial primary key, organization_id text not null, code text unique)`);
await q(`alter table plans enable row level security`);
await q(`create policy p on plans for select to authenticated using (organization_id = current_setting('request.jwt.claim.org', true))`);
await q(`revoke all on plans from public`);
await q(`grant select on plans to anon, authenticated`);

const priv = await q(`select has_table_privilege('anon','plans','INSERT') a, has_table_privilege('authenticated','plans','INSERT') b, has_table_privilege('anon','plans','SELECT') c`);
console.log('privs', priv.rows[0]);

const res = await check({ query: q, config: {} });
console.log(JSON.stringify({ ok: res.ok, scanned: res.scanned, summary: res.summary, v: res.violations.map(v=>({where:v.where,kind:v.kind})) }, null, 2));
await db.close();
