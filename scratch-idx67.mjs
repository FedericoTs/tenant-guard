import { PGlite } from '@electric-sql/pglite';
import { check as checkCreate } from './src/guards/create-grants.mjs';
import { check as checkRpc } from './src/guards/definer-rpc.mjs';

async function fresh(setup) {
  const db = new PGlite();
  await db.exec(`
    create role anon nologin;
    create role authenticated nologin;
    grant usage on schema public to anon, authenticated;
    revoke create on schema public from public;
  `);
  await db.exec(setup);
  const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
  return { db, query };
}

async function scenario(name, setup) {
  const { db, query } = await fresh(setup);
  const rpc = await checkRpc({ query });
  const cg = await checkCreate({ query });
  console.log('=== ' + name);
  console.log(' definer-rpc ok=' + rpc.ok, JSON.stringify(rpc.violations.map(v => ({k:v.kind, w:v.where, m:(v.message||'').slice(0,180)})), null, 1));
  console.log(' create-grants ok=' + cg.ok);
  for (const v of cg.violations) console.log('  VIOL', v.where, '::', v.message.slice(-260));
  for (const n of cg.notes) console.log('  NOTE', n.where, '::', n.message.slice(-260));
  await db.close();
}

// Case A: pin names a WRITABLE schema first -> definer-rpc (0.37) says the pin is worthless
await scenario('A: pin = public, pg_catalog  + CREATE on public to anon', `
  create schema app;
  create table public.t(id int);
  grant create on schema public to anon;
  create function public.helper() returns int language sql security definer
    set search_path = public, pg_catalog, pg_temp as $$ select count(*)::int from t $$;
  grant execute on function public.helper() to anon, authenticated;
`);

// Case B: candidate's stated repro: pin missing pg_temp
await scenario('B: pin = pg_catalog, public (no pg_temp) + CREATE to authenticated', `
  create table public.t(id int);
  grant create on schema public to authenticated;
  create function public.helper() returns int language sql security definer
    set search_path = pg_catalog, public as $$ select count(*)::int from t $$;
  grant execute on function public.helper() to anon, authenticated;
`);
