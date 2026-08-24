/**
 * anon-reads — audit regressions.
 *
 * Finding "anon-reads-full-count-for-an-emptiness-test" (reproduced at v0.42.0):
 * the guard ran an unbounded `count(*)` over every tenant relation, and a second
 * unbounded `count(*)` as anon on every granted one, when the only things consumed
 * were "is it non-empty" and "is it > 0". Measured under PGlite on a 300k-row
 * table: `count(*)` = Aggregate over Seq Scan, 3704 shared buffers, 306 ms;
 * `exists(select 1 ...)` = InitPlan stopping at row 1, 2 buffers, 0.05 ms; the
 * bounded probe = 14 buffers, 1.7 ms. The privileged count was taken even for
 * relations anon holds no grant on, where classifyRead returns 'safe' before ever
 * reading it.
 *
 * These tests fail against the pre-fix guard. The verdict tests here are the other
 * half: making the scan cheap must not change a single verdict, and must not make
 * the guard fire on correct code.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  readSurfaceSql,
  nonEmptySql,
  anonSelectCountSql,
  classifyRead,
  check,
  ANON_PROBE_CAP,
} from '../src/guards/anon-reads.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('anon-reads audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── the SQL no longer scans a relation to answer a boolean ───────────

test('readSurfaceSql does not read the relation at all — catalog only', () => {
  const s = readSurfaceSql('public', 'invoices', 'anon');
  assert.doesNotMatch(s.text, /count\(\*\)/, 'a full count to answer "is it empty" is the defect');
  assert.doesNotMatch(s.text, /from "public"\."invoices"/, 'the grant question needs no heap access');
  assert.match(s.text, /has_table_privilege/);
});

test('nonEmptySql asks existence, not a total', () => {
  const s = nonEmptySql('public', 'invoices');
  assert.match(s.text, /^select exists\(select 1 from "public"\."invoices"\) as nonempty$/);
  assert.deepEqual(s.values, []);
});

test('the anon probe is bounded, and the bound is a real integer literal', () => {
  const c = anonSelectCountSql('public', 'invoices');
  assert.match(c.text, new RegExp(`limit ${ANON_PROBE_CAP + 1}\\) s$`));
  // A caller-supplied cap is sanitised — it is interpolated, not bound.
  assert.match(anonSelectCountSql('public', 'i', 5).text, /limit 6\) s$/);
  for (const bad of ['1; drop table users', 1.5, -3, 0, NaN, null, undefined]) {
    assert.match(anonSelectCountSql('public', 'i', bad).text, new RegExp(`limit ${ANON_PROBE_CAP + 1}\\) s$`), `cap ${bad}`);
  }
});

// ── the verdict is unchanged by the cheaper measurement ──────────────

test('classifyRead: nonempty=false is the old total=0 — not-proven, never a silent pass', () => {
  const v = classifyRead({ rlsEnabled: true, canSelect: true, nonempty: false, anonVisible: 0 });
  assert.equal(v.status, 'not-proven');
  assert.match(v.message, /empty/);
});

test('classifyRead: nonempty=true + anon sees nothing -> safe (policy restricts)', () => {
  assert.equal(classifyRead({ rlsEnabled: true, canSelect: true, nonempty: true, anonVisible: 0 }).status, 'safe');
});

test('classifyRead: emptiness never asked -> not-proven, not "safe"', () => {
  // A skip is not a pass. check() asks under exactly the condition that reaches
  // this line, so this is defence against a future caller that forgets.
  const v = classifyRead({ rlsEnabled: true, canSelect: true, anonVisible: 0 });
  assert.equal(v.status, 'not-proven');
  assert.match(v.message, /could not determine/);
});

test('classifyRead: the pre-0.43 `total` key still classifies identically', () => {
  // The helper is a package export; switching key names must not silently
  // re-classify an external caller.
  assert.equal(classifyRead({ rlsEnabled: true, canSelect: true, total: 0, anonVisible: 0 }).status, 'not-proven');
  assert.equal(classifyRead({ rlsEnabled: true, canSelect: true, total: 9, anonVisible: 0 }).status, 'safe');
});

test('classifyRead: verdicts are identical for every (total, nonempty) pair, all kinds', () => {
  // Exhaustive equivalence — the whole point of the change is that it is a
  // measurement change, not a behaviour change.
  for (const kind of ['table', 'view', 'matview']) {
    for (const rlsEnabled of [true, false]) {
      for (const canSelect of [true, false]) {
        for (const anonVisible of [0, 3]) {
          for (const [total, nonempty] of [[0, false], [7, true]]) {
            const a = classifyRead({ kind, rlsEnabled, canSelect, total, anonVisible });
            const b = classifyRead({ kind, rlsEnabled, canSelect, nonempty, anonVisible });
            assert.deepEqual(b, a, `${kind}/${rlsEnabled}/${canSelect}/${anonVisible}/${total}`);
          }
        }
      }
    }
  }
});

test('classifyRead: a saturated probe reports "1000+", not a wrong exact count', () => {
  const v = classifyRead({ rlsEnabled: true, canSelect: true, nonempty: true, anonVisible: ANON_PROBE_CAP, anonVisibleCapped: true });
  assert.equal(v.status, 'leak');
  assert.match(v.message, new RegExp(`${ANON_PROBE_CAP}\\+ row\\(s\\)`));
  // …and an unsaturated one still reports the exact number, with no "+".
  const w = classifyRead({ rlsEnabled: true, canSelect: true, nonempty: true, anonVisible: 4 });
  assert.match(w.message, /\b4 row\(s\)/);
  assert.doesNotMatch(w.message, /\+ row/);
});

// ── end to end: the expensive statement is gone, verdicts intact ─────

if (PGlite) {
  /** Runs check() against a fresh database, returning the result AND every statement issued. */
  async function traced(setup, config = {}) {
    const db = new PGlite();
    await db.exec(`create role anon nologin; create role authenticated nologin; grant usage on schema public to anon;`);
    await db.exec(setup);
    const statements = [];
    const query = (t, v) => {
      statements.push(String(t).replace(/\s+/g, ' '));
      return db.query(t, Array.isArray(v) && v.length ? v : undefined);
    };
    const res = await check({ query, config });
    return { res, statements };
  }

  const MIXED = `
    -- (a) big, tenant-scoped, anon has NO grant: the old pre-pass counted it anyway
    create table big (id serial primary key, organization_id text not null, body text);
    grant select on big to authenticated;
    insert into big (organization_id, body) select 'org_'||(i%7), 'x' from generate_series(1,5000) i;
    alter table big enable row level security;
    create policy p on big for select to authenticated using (true);

    -- (b) a real leak: anon-readable under a permissive policy
    create table leaky (id serial primary key, organization_id text not null);
    grant select on leaky to anon;
    insert into leaky (organization_id) select 'org_'||(i%3) from generate_series(1,20) i;
    alter table leaky enable row level security;
    create policy pub on leaky for select to anon using (true);

    -- (c) empty + granted: the case emptiness exists to report as not-proven
    create table emptyt (id serial primary key, organization_id text not null);
    grant select on emptyt to anon;
    alter table emptyt enable row level security;
    create policy pub2 on emptyt for select to anon using (true);
  `;

  test('no unbounded count is issued against a scanned tenant relation', async () => {
    // Scoped to the relations under test — the catalog counts over pg_policy and
    // the two-row negative-control canary are bounded by construction, not by a
    // LIMIT, and are not what this finding is about.
    const { statements } = await traced(MIXED);
    const overTenantRel = statements.filter((s) => /count\(\*\)|exists\(/.test(s) && /"public"\."(big|leaky|emptyt)"/.test(s));
    assert.ok(overTenantRel.length > 0, 'sanity: the guard did read the granted relations');
    const unbounded = overTenantRel.filter((s) => /count\(\*\)/.test(s) && !/\blimit \d+\) s$/.test(s));
    assert.deepEqual(unbounded, [], 'every count over a tenant relation must be bounded by the probe LIMIT');
  });

  test('a relation anon cannot select is never read at all', async () => {
    const { statements } = await traced(MIXED);
    // "big" has no anon grant, so neither the emptiness question nor the probe
    // can change its verdict. Pre-fix, the privileged count scanned it every run.
    assert.equal(statements.some((s) => /from "public"\."big"/.test(s)), false,
      statements.filter((s) => /big/.test(s)).join('\n'));
    // …while the granted ones ARE examined.
    assert.ok(statements.some((s) => /exists\(select 1 from "public"\."leaky"\)/.test(s)));
    assert.ok(statements.some((s) => /exists\(select 1 from "public"\."emptyt"\)/.test(s)));
  });

  test('the verdicts are exactly what they were: leak on leaky, not-proven on empty, silent on big', async () => {
    const { res } = await traced(MIXED);
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.deepEqual(res.violations.map((v) => v.where), ['public.leaky']);
    assert.match(res.violations[0].message, /a policy permits it/);
    assert.ok(res.notes.some((n) => n.where === 'public.emptyt' && /empty/.test(n.message)),
      JSON.stringify(res.notes, null, 2));
    assert.equal(res.notes.some((n) => n.where === 'public.big'), false, 'big is conclusively safe, so silent');
  });

  test('a correctly-scoped database is still completely silent', async () => {
    const { res } = await traced(`
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to authenticated;
      insert into invoices (organization_id) values ('org_A'),('org_B');
      alter table invoices enable row level security;
      create policy tenant on invoices for select to authenticated using (true);
    `);
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    assert.equal(res.notes.length, 0, JSON.stringify(res.notes, null, 2));
  });

  test('the TO public idiom that evaluates false for anon is still NOT flagged', async () => {
    // The false positive the probe exists to avoid. Emptiness is measured with
    // exists() here; the verdict must be unchanged.
    const { res } = await traced(`
      create table invoices (id serial primary key, organization_id text not null);
      grant select on invoices to anon;
      insert into invoices (organization_id) values ('org_A'),('org_B');
      alter table invoices enable row level security;
      create policy tenant on invoices for select to public
        using (organization_id = current_setting('app.current_tenant', true));
    `);
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    assert.equal(res.notes.length, 0, 'the table is non-empty, so nothing is "not proven"');
  });

  test('an unpopulated matview anon CAN select is still reported as not examined', async () => {
    // exists() raises 55000 on an unpopulated matview exactly as count(*) did, so
    // the "isolation is NOT proven here" note must survive the switch.
    const { res } = await traced(`
      create table orders (id int, organization_id text);
      insert into orders values (1,'org_A'),(2,'org_B');
      grant select on orders to anon;                       -- a real leak: RLS off
      create materialized view order_rollup as
        select organization_id, count(*) n from orders group by 1 with no data;
      grant select on order_rollup to anon;
    `);
    assert.equal(res.ok, false);
    assert.ok(res.violations.some((v) => /orders/.test(v.where)), 'the real leak must still be reported');
    assert.ok(res.notes.some((n) => n.where === 'public.order_rollup' && /not examined/.test(n.message)),
      JSON.stringify(res.notes, null, 2));
  });

  test('an unpopulated matview anon CANNOT select is silent, not a "not examined" note', async () => {
    // New: the grant question alone settles this conclusively (no grant ⇒ safe),
    // so we no longer touch the relation and no longer emit a note about a
    // relation that cannot leak. Pre-fix this produced a spurious note, because
    // the privileged count(*) raised 55000 before the grant was consulted.
    const { res } = await traced(`
      create table orders (id int, organization_id text);
      insert into orders values (1,'org_A');
      grant select on orders to authenticated;
      alter table orders enable row level security;
      create policy p on orders for select to authenticated using (true);
      create materialized view order_rollup as
        select organization_id, count(*) n from orders group by 1 with no data;
      grant select on order_rollup to authenticated;        -- anon has nothing
    `);
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.notes.length, 0, JSON.stringify(res.notes, null, 2));
  });

  test('a leak wider than the cap is reported as 1000+, and still as a leak', async () => {
    const { res, statements } = await traced(`
      create table wide (id serial primary key, organization_id text not null);
      grant select on wide to anon;
      insert into wide (organization_id) select 'org_'||(i%3) from generate_series(1,${ANON_PROBE_CAP + 500}) i;
      alter table wide enable row level security;
      create policy pub on wide for select to anon using (true);
    `);
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 1);
    assert.ok(statements.some((s) => new RegExp(`from "public"\\."wide" limit ${ANON_PROBE_CAP + 1}\\)`).test(s)));
  });
}
