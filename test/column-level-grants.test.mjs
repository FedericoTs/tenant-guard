/**
 * Column-level grants were invisible to the whole anon surface.
 *
 * `has_table_privilege` answers about the TABLE ACL only. `GRANT SELECT (id,
 * body) ON notes TO anon` does not appear in it, so both `anon-reads` and
 * `anon-writes` skipped the relation entirely — on a table with RLS OFF, where
 * anon genuinely was reading and writing every tenant's rows.
 *
 * Measured before the fix, on the fixture below:
 *
 *     reality                       anon read 2 rows across 2 tenants; UPDATE affected 2
 *     has_table_privilege SELECT    false      <- what the guards asked
 *     has_any_column_privilege      true       <- what they should have asked
 *     anon-reads                    ok
 *     anon-writes                   ok
 *
 * A column grant is not exotic: it is what you are told to use instead of a
 * table grant when you want to expose part of a table, so the tool was blind
 * precisely where someone had been careful.
 *
 * Note DELETE has no column-level form — `GRANT DELETE (col)` is not valid SQL —
 * so the table-level answer remains the whole answer for it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check as anonReads } from '../src/guards/anon-reads.mjs';
import { check as anonWrites } from '../src/guards/anon-writes.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('column-level grants (pglite not installed — skipped)', { skip: true }, () => {});
}

if (PGlite) {
  async function fixture(grants) {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin;
      grant usage on schema public to anon;
      create table notes (id int, organization_id text, body text, secret text);
      insert into notes values (1,'org_A','a','s1'), (2,'org_B','b','s2');
      ${grants}
    `);
    return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
  }

  const COLUMN_GRANTS = `
    grant select (id, organization_id, body) on notes to anon;
    grant update (body) on notes to anon;`;

  test('DEMONSTRATES it: a column grant with RLS off is a real cross-tenant surface', async () => {
    const { db } = await fixture(COLUMN_GRANTS);
    await db.query('begin');
    await db.query('set local role anon');
    const read = await db.query('select id, organization_id from notes');
    const upd = await db.query(`update notes set body = 'x'`);
    await db.query('rollback');
    assert.equal(read.rows.length, 2, 'anon reads both tenants');
    assert.equal(upd.rowCount ?? upd.affectedRows, 2, 'anon writes both tenants');
  });

  test('…and has_table_privilege is what made it invisible', async () => {
    const { db } = await fixture(COLUMN_GRANTS);
    const t = await db.query(`select has_table_privilege('anon','notes','SELECT') as b`);
    const c = await db.query(`select has_any_column_privilege('anon','notes','SELECT') as b`);
    assert.equal(t.rows[0].b, false);
    assert.equal(c.rows[0].b, true);
  });

  test('anon-reads CATCHES a column-level SELECT grant', async () => {
    const { query } = await fixture(COLUMN_GRANTS);
    const res = await anonReads({ query, config: { role: 'anon' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.ok(res.violations.some((v) => /notes/.test(v.where)));
  });

  test('anon-writes CATCHES a column-level UPDATE grant', async () => {
    const { query } = await fixture(COLUMN_GRANTS);
    const res = await anonWrites({ query, config: { role: 'anon' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.ok(res.violations.some((v) => /notes/.test(v.where)));
  });

  test('neither fires when anon holds no grant at all', async () => {
    const { query } = await fixture('');
    assert.equal((await anonReads({ query, config: { role: 'anon' } })).ok, true);
    assert.equal((await anonWrites({ query, config: { role: 'anon' } })).ok, true);
  });

  test('a column grant on an RLS-protected table is still governed by the policy', async () => {
    // The guards must not treat "column grant exists" as the finding — RLS still
    // applies, so this one is proven by probing, not by reading the ACL.
    const { query } = await fixture(`
      alter table notes enable row level security;
      create policy own on notes for all to anon
        using (organization_id = current_setting('app.tenant', true));
      ${COLUMN_GRANTS}
    `);
    const res = await anonWrites({ query, config: { role: 'anon' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
  });
}
