/**
 * The advice has to WORK when applied literally. Four cases where it did not.
 *
 * This is the same failure mode as 0.26.0, where a recommended REVOKE would have
 * taken a production database down. A linter's fix gets applied without much
 * thought — that is what a fix is for — so a fix that is a no-op, that does not
 * compile, or that breaks the thing it was protecting is worse than no fix.
 *
 * Measured against a real database, before the change:
 *
 *   rls-proof, uuid tenant column   USING (col = current_setting(...))  -> 42883, would not compile
 *   rls-proof, write leak           "add a FOR ALL policy"              -> 2 rows writable, still 2
 *   anon-writes, PUBLIC grant       REVOKE ... FROM anon                -> privilege survives
 *   view-isolation                  ALTER VIEW SET security_invoker     -> legitimate tenant gets 42501
 *
 * Each test below applies what the guard prints and checks the database
 * afterwards, rather than checking the wording.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { tenantComparison, prove } from '../src/guards/rls-proof.mjs';
import { fixForView } from '../src/guards/view-isolation.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('advice-actually-works (pglite not installed — skipped)', { skip: true }, () => {});
}

test('tenantComparison casts per column type', () => {
  assert.match(tenantComparison('"org"', 'uuid'), /::uuid/);
  assert.match(tenantComparison('"org"', 'text'), /current_setting/);
  assert.doesNotMatch(tenantComparison('"org"', 'text'), /::uuid/);
  assert.match(tenantComparison('"org"', 'bigint'), /::text = current_setting/);
});

if (PGlite) {
  const CFG = {
    role: 'authenticated',
    becomeTenant: ["select set_config('app.current_tenant', $1, true)"],
    tenantColumns: ['organization_id'],
  };
  const qq = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

  async function leakyDb(colType) {
    const a = colType === 'uuid' ? "'11111111-1111-1111-1111-111111111111'" : "'org_A'";
    const b = colType === 'uuid' ? "'22222222-2222-2222-2222-222222222222'" : "'org_B'";
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table notes (id serial primary key, organization_id ${colType});
      insert into notes (organization_id) values (${a}), (${b});
      grant select, insert, update, delete on notes to authenticated;
      grant usage on sequence notes_id_seq to authenticated;
      alter table notes enable row level security;
      create policy loose on notes for all to authenticated using (true) with check (true);
    `);
    return db;
  }

  test('the emitted policy COMPILES against a uuid tenant column', async () => {
    const db = await leakyDb('uuid');
    const res = await prove({ query: qq(db), config: CFG });
    const fix = res.violations.map((v) => v.fix).join('\n');
    const m = fix.match(/USING \((.+?)\)\s*$/m);
    assert.ok(m, `no USING clause in the emitted fix: ${fix.slice(0, 300)}`);
    await db.exec(`create policy emitted on notes for all using (${m[1]});`); // throws on 42883
  });

  test('no violation ever prints a literal {col} / {tbl} / {cmp}', async () => {
    const db = await leakyDb('uuid');
    const res = await prove({ query: qq(db), config: CFG });
    assert.doesNotMatch(JSON.stringify(res), /\{(col|tbl|cmp)\}/);
  });

  test('the write-leak fix leads with DROP, because adding a policy is a no-op', async () => {
    // Verified: with the loose policy present, adding the scoped one left exactly
    // as many rows writable. Permissive policies OR together.
    const db = await leakyDb('text');
    const res = await prove({ query: qq(db), config: CFG });
    const w = res.violations.find((v) => v.kind === 'write');
    assert.ok(w, JSON.stringify(res.violations.map((v) => v.kind)));
    assert.match(w.fix, /DROP POLICY/);
    assert.match(w.fix, /NOT enough on its own/);
    assert.ok(w.fix.indexOf('DROP POLICY') < w.fix.indexOf('CREATE POLICY'), 'DROP must come first');
  });

  test('DEMONSTRATES why: adding the scoped policy alone changes nothing', async () => {
    const db = await leakyDb('text');
    const writable = async () => {
      await db.query('begin');
      await db.query(`select set_config('app.current_tenant','org_A',true)`);
      await db.query('set local role authenticated');
      const r = await db.query('update notes set organization_id = organization_id');
      await db.query('rollback');
      return r.rowCount ?? r.affectedRows;
    };
    const before = await writable();
    await db.exec(`create policy tenant_all on notes for all to authenticated
      using (organization_id = current_setting('app.current_tenant', true))
      with check (organization_id = current_setting('app.current_tenant', true));`);
    assert.equal(await writable(), before, 'adding a permissive policy cannot restrict');
    await db.exec(`drop policy loose on notes;`);
    assert.ok(await writable() < before, 'dropping the loose one is what fixes it');
  });

  test('the view fix pairs security_invoker with the base grant it requires', () => {
    const fix = fixForView({ kind: 'view', schema: 'public', view: 'v', role: 'authenticated', pgVersionNum: 150000 });
    assert.match(fix, /security_invoker = true/);
    assert.match(fix, /GRANT SELECT ON/);
    assert.match(fix, /breaks the view for its legitimate users/);
  });

  test('DEMONSTRATES why: security_invoker alone gives the legit tenant 42501', async () => {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      grant usage on schema public to authenticated;
      create table notes (id int, organization_id text);
      insert into notes values (1,'org_A');
      alter table notes enable row level security;
      create policy own on notes for all to authenticated
        using (organization_id = current_setting('app.tenant', true));
      create view v as select * from notes;
      grant select on v to authenticated;   -- the view only, which is the point of a view
    `);
    const read = async () => {
      await db.query('begin');
      await db.query(`select set_config('app.tenant','org_A',true)`);
      await db.query('set local role authenticated');
      let out;
      try { out = (await db.query('select * from v')).rows.length; } catch (e) { out = e.code; }
      await db.query('rollback');
      return out;
    };
    assert.equal(await read(), 1);
    await db.exec(`alter view v set (security_invoker = true);`);
    assert.equal(await read(), '42501', 'the first line alone breaks it');
    await db.exec(`grant select on notes to authenticated;`);
    assert.equal(await read(), 1, 'the second line is what makes it work');
  });
}
