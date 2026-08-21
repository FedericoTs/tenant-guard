import { PGlite } from '@electric-sql/pglite';
import { check as ceCheck } from './src/guards/column-exposure.mjs';
import { check as arCheck } from './src/guards/anon-reads.mjs';

async function mk(sql) {
  const db = new PGlite();
  await db.exec(sql);
  return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
}

// SCENARIO A: no anon role at all, real leaky table
{
  const { query } = await mk(`
    create table waitlist (id int, email text, api_key text);
    insert into waitlist values (1, 'ada@x.com', 'sk_live_abc');
  `);
  const ce = await ceCheck({ query, config: { role: 'anon' } });
  console.log('A column-exposure:', JSON.stringify({ ok: ce.ok, skipped: ce.skipped, scanned: ce.scanned, notes: ce.notes, summary: ce.summary, v: ce.violations.length }, null, 2));
  const ar = await arCheck({ query, config: { role: 'anon' } });
  console.log('A anon-reads:', JSON.stringify({ ok: ar.ok, skipped: ar.skipped, reason: ar.reason, summary: ar.summary }));
}

// SCENARIO B: anon exists -> guard fires (control)
{
  const { query } = await mk(`
    create role anon nologin; grant usage on schema public to anon;
    create table waitlist (id int, email text, api_key text);
    insert into waitlist values (1, 'ada@x.com', 'sk_live_abc');
    grant select on waitlist to anon;
  `);
  const ce = await ceCheck({ query, config: { role: 'anon' } });
  console.log('B column-exposure:', JSON.stringify({ ok: ce.ok, scanned: ce.scanned, where: ce.violations.map(v=>v.where), summary: ce.summary }));
}

// SCENARIO C: anon exists but no grant (genuinely closed) -> silent pass, correct
{
  const { query } = await mk(`
    create role anon nologin; grant usage on schema public to anon;
    create table waitlist (id int, email text, api_key text);
    insert into waitlist values (1, 'ada@x.com', 'sk_live_abc');
  `);
  const ce = await ceCheck({ query, config: { role: 'anon' } });
  console.log('C column-exposure:', JSON.stringify({ ok: ce.ok, scanned: ce.scanned, notes: ce.notes, summary: ce.summary }));
}
