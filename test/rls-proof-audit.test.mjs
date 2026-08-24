/**
 * rls-proof — regressions found by auditing the guard against a real database.
 *
 * Each test here corresponds to a measured defect, not a hypothetical one:
 *
 *  1. The omitted-tenant ("orphan") probe inferred the leak from the acting
 *     session's TOTAL visible row count. A `BEFORE INSERT` trigger that stamps
 *     the tenant server-side — the hardened shape, and the one this repo's own
 *     trigger-visibility test calls "the trigger every schema has" — grows that
 *     same count, because the row it just wrote became the acting tenant's OWN
 *     row. So a correct table was failed with an orphan leak that could not
 *     exist (privileged ground truth: zero NULL-tenant rows), and the advice
 *     printed with it ("make the column NOT NULL") did not clear it either.
 *     The probe now counts `where <tenant col> is null`.
 *
 *  2. The orphan fix text wrapped `{col}` in literal double quotes while the
 *     substituted value is quoteIdent output, already quoted — so operators read
 *     `""organization_id"`.
 *
 * pglite is a dev-only dependency; without it the whole file skips.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { prove, tenantNullVisibleSql } from '../src/guards/rls-proof.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('rls-proof audit (pglite not installed — skipped)', { skip: true }, () => {});
}

/** Fresh embedded Postgres + a node-postgres-shaped query adapter. */
async function freshDb(setupSql) {
  const db = new PGlite();
  await db.exec(`create role authenticated nologin;`);
  await db.exec(setupSql);
  const query = (text, values) =>
    db.query(text, Array.isArray(values) && values.length ? values : undefined);
  return { db, query };
}

const CMP = `organization_id = current_setting('app.current_tenant', true)`;

/** Tenant table the app role can actually write, so the INSERT probes run. */
const WRITABLE = `
  create table invoices (id serial primary key, organization_id text, amount int);
  grant select, insert, update, delete on invoices to authenticated;
  grant usage on sequence invoices_id_seq to authenticated;
  insert into invoices (organization_id, amount) values ('org_A', 100), ('org_A', 150), ('org_B', 200);
  alter table invoices enable row level security;
  alter table invoices force row level security;
`;

/** The ordinary server-side tenant stamp. `mode` picks the two common spellings. */
const stampTrigger = (mode) => `
  create function stamp() returns trigger language plpgsql as $$
    begin
      new.organization_id := ${
        mode === 'coalesce'
          ? `coalesce(new.organization_id, current_setting('app.current_tenant', true))`
          : `current_setting('app.current_tenant', true)`
      };
      return new;
    end $$;
  create trigger stamp_t before insert on invoices for each row execute function stamp();
`;

const orphanViolations = (res) =>
  res.violations.filter((v) => /NO tenant|owned by nobody/.test(v.message));

if (PGlite) {
  // ── 1. the false positive ─────────────────────────────────────────────
  for (const mode of ['coalesce', 'unconditional']) {
    test(`orphan probe stays QUIET on a correct table with a ${mode} tenant-stamping BEFORE INSERT trigger`, async () => {
      const { db, query } = await freshDb(`
        ${WRITABLE}
        create policy tenant_all on invoices for all using (${CMP}) with check (${CMP});
        ${stampTrigger(mode)}
      `);
      const res = await prove({ query });
      // Ground truth the violation would be claiming: there are no orphans.
      const orphans = (await db.query(`select count(*)::int as n from invoices where organization_id is null`)).rows[0].n;
      assert.equal(orphans, 0);
      assert.deepEqual(orphanViolations(res), [], JSON.stringify(res.violations, null, 2));
      assert.equal(res.ok, true, JSON.stringify(res, null, 2));
      await db.close();
    });
  }

  test('orphan probe stays QUIET when a stamping trigger makes orphans impossible even under a NULL-permissive policy', async () => {
    // The policy alone WOULD leak (it treats NULL as global) but the trigger
    // means a client can never actually create a NULL-tenant row. Nothing to
    // report: the guard fails only when it has measured a real leak.
    const { db, query } = await freshDb(`
      ${WRITABLE}
      create policy tenant_all on invoices for all
        using (${CMP} or organization_id is null)
        with check (${CMP} or organization_id is null);
      ${stampTrigger('coalesce')}
    `);
    const res = await prove({ query });
    assert.deepEqual(orphanViolations(res), [], JSON.stringify(res.violations, null, 2));
    await db.close();
  });

  // ── the other direction: detection must be intact ─────────────────────
  test('orphan probe STILL FIRES on a genuine NULL-is-global read policy', async () => {
    const { db, query } = await freshDb(`
      ${WRITABLE}
      create policy tenant_all on invoices for all
        using (${CMP} or organization_id is null)
        with check (${CMP} or organization_id is null);
    `);
    const res = await prove({ query });
    assert.equal(res.ok, false);
    const orphan = orphanViolations(res);
    assert.equal(orphan.length, 1, JSON.stringify(res.violations, null, 2));
    assert.equal(orphan[0].kind, 'write');
    await db.close();
  });

  test('a plain correct table (nullable tenant column, no trigger) still passes', async () => {
    const { db, query } = await freshDb(`
      ${WRITABLE}
      create policy tenant_all on invoices for all using (${CMP}) with check (${CMP});
    `);
    const res = await prove({ query });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    await db.close();
  });

  // ── 2. the advice text ────────────────────────────────────────────────
  test('orphan fix text quotes the column exactly once', async () => {
    const { db, query } = await freshDb(`
      ${WRITABLE}
      create policy tenant_all on invoices for all
        using (${CMP} or organization_id is null)
        with check (${CMP} or organization_id is null);
    `);
    const res = await prove({ query });
    const [orphan] = orphanViolations(res);
    assert.ok(orphan, 'expected the orphan violation');
    for (const text of [orphan.message, orphan.fix]) {
      assert.ok(!/\{(col|tbl|cmp)\}/.test(text), `unsubstituted placeholder: ${text}`);
      assert.ok(!/""organization_id/.test(text), `doubled quotes: ${text}`);
      assert.match(text, /"organization_id"/);
    }
    await db.close();
  });
}

// ── pure helper (runs with or without pglite) ───────────────────────────
test('tenantNullVisibleSql counts only rows whose tenant column IS NULL', () => {
  const s = tenantNullVisibleSql('public', 'invoices', 'organization_id');
  assert.equal(s.text, 'select count(*)::int as n from "public"."invoices" where "organization_id" is null');
  assert.deepEqual(s.values, []);
});
