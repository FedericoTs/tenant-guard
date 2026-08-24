/**
 * The negative control: prove every guard CAN fail.
 *
 * Suggested by u/Guidondor on r/Supabase, from his own experience — his RLS
 * smoke test sat green for weeks and the green meant nothing, because Postgres
 * was raising a type error on the line that built the failure message. The
 * assertion could never be reached. In his words: *a suite that can't fail looks
 * exactly like a suite that passes, and you can't tell them apart from the
 * outside.*
 *
 * That is the same class as the five "false assurance" bugs the 0.40.0 audit
 * found here — guards reporting a confident green about a probe that never ran —
 * except his version is more general and catches it from one level up. Every
 * other test in this repo asks "does the guard behave correctly". This one asks
 * the prior question: **is this guard capable of reporting a failure at all?**
 *
 * So: build a database deliberately broken in exactly the way each guard exists
 * to detect, run the guard, and require it to fail. A guard that returns ok on
 * its own worst case is not a guard, however green its other tests are.
 *
 * Each entry also carries the CORRECT version of the same schema, because a
 * check that fails on everything is just as useless as one that fails on
 * nothing — and that direction is what teaches people to switch the tool off.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { prove } from '../src/guards/rls-proof.mjs';
import { check as anonReads } from '../src/guards/anon-reads.mjs';
import { check as anonWrites } from '../src/guards/anon-writes.mjs';
import { check as columnExposure } from '../src/guards/column-exposure.mjs';
import { check as viewIsolation } from '../src/guards/view-isolation.mjs';
import { check as constraintOracles } from '../src/guards/constraint-oracles.mjs';
import { check as crossTenantFk } from '../src/guards/cross-tenant-fk.mjs';
import { check as triggerVisibility } from '../src/guards/trigger-visibility.mjs';
import { check as mfaEnforcement } from '../src/guards/mfa-enforcement.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('negative control (pglite not installed — skipped)', { skip: true }, () => {});
}

const q = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

const TENANT_CFG = {
  role: 'authenticated',
  becomeTenant: ["select set_config('app.current_tenant', $1, true)"],
  tenantColumns: ['organization_id'],
};

/** Two tenants, RLS on, a correct FOR ALL policy. The baseline everything builds on. */
const CORRECT = `
  create role anon nologin;
  create role authenticated nologin;
  grant usage on schema public to anon, authenticated;
  create table notes (id serial primary key, organization_id text not null, body text, email text);
  insert into notes (organization_id, body, email) values
    ('org_A','a','a@x.com'), ('org_B','b','b@x.com');
  alter table notes enable row level security;
  create policy own on notes for all to authenticated
    using (organization_id = current_setting('app.current_tenant', true))
    with check (organization_id = current_setting('app.current_tenant', true));
  grant select, insert, update, delete on notes to authenticated;
`;

/**
 * Each guard, with a schema broken in the exact way it exists to detect and the
 * corrected version of that same schema.
 */
const CASES = [
  {
    guard: 'rls-proof',
    run: (db) => prove({ query: q(db), config: TENANT_CFG }),
    broken: CORRECT.replace(
      `using (organization_id = current_setting('app.current_tenant', true))\n    with check (organization_id = current_setting('app.current_tenant', true));`,
      `using (true) with check (true);`,
    ),
    correct: CORRECT,
  },
  {
    guard: 'anon-reads',
    run: (db) => anonReads({ query: q(db), config: { role: 'anon' } }),
    broken: CORRECT + `alter table notes disable row level security; grant select on notes to anon;`,
    correct: CORRECT,
  },
  {
    guard: 'anon-writes',
    run: (db) => anonWrites({ query: q(db), config: { role: 'anon' } }),
    broken: CORRECT + `alter table notes disable row level security; grant update on notes to anon;`,
    correct: CORRECT,
  },
  {
    guard: 'column-exposure',
    run: (db) => columnExposure({ query: q(db), config: { role: 'anon' } }),
    // No tenant column at all — the population this guard owns.
    broken: `create role anon nologin; grant usage on schema public to anon;
             create table waitlist (id int, email text, phone text);
             insert into waitlist values (1,'ada@x.com','+3531');
             grant select on waitlist to anon;`,
    correct: `create role anon nologin; grant usage on schema public to anon;
              create table waitlist (id int, email text, phone text);
              insert into waitlist values (1,'ada@x.com','+3531');`,
  },
  {
    guard: 'view-isolation',
    run: (db) => viewIsolation({ query: q(db), config: TENANT_CFG }),
    broken: CORRECT + `create view all_notes as select * from notes;
                       grant select on all_notes to authenticated;`,
    correct: CORRECT + `create view all_notes with (security_invoker = true) as select * from notes;
                        grant select on all_notes to authenticated;
                        grant select on notes to authenticated;`,
  },
  {
    guard: 'constraint-oracles',
    run: (db) => constraintOracles({ query: q(db), config: TENANT_CFG }),
    broken: CORRECT + `alter table notes add constraint u unique (email);`,
    correct: CORRECT + `alter table notes add constraint u unique (organization_id, email);`,
  },
  {
    guard: 'cross-tenant-fk',
    run: (db) => crossTenantFk({ query: q(db), config: TENANT_CFG }),
    broken: CORRECT + `
      create table comments (id serial primary key, organization_id text not null,
        note_id int references notes(id) on delete cascade);
      -- Rows in BOTH tenants. Without them the guard has nothing to move and
      -- correctly emits a note rather than claiming proof — which is right, and
      -- which the first draft of this fixture got wrong. A negative control has
      -- to actually be broken, not just look broken.
      insert into comments (organization_id, note_id) values ('org_A', 1), ('org_B', 2);
      alter table comments enable row level security;
      create policy c on comments for all to authenticated
        using (organization_id = current_setting('app.current_tenant', true))
        with check (organization_id = current_setting('app.current_tenant', true));
      grant select, insert, update, delete on comments to authenticated;`,
    correct: CORRECT + `
      alter table notes add constraint nu unique (organization_id, id);
      create table comments (id serial primary key, organization_id text not null, note_id int,
        foreign key (organization_id, note_id) references notes(organization_id, id) on delete cascade);
      alter table comments enable row level security;
      create policy c on comments for all to authenticated
        using (organization_id = current_setting('app.current_tenant', true))
        with check (organization_id = current_setting('app.current_tenant', true));
      grant select, insert, update, delete on comments to authenticated;`,
  },
  {
    guard: 'trigger-visibility',
    run: (db) => triggerVisibility({ query: q(db), config: { role: 'authenticated' } }),
    broken: CORRECT + `
      create function chk() returns trigger language plpgsql as $fn$ begin
        if exists (select 1 from notes where body = new.body) then
          raise exception 'taken'; end if; return new; end; $fn$;
      create trigger t before insert on notes for each row execute function chk();`,
    // A trigger that RECORDS rather than enforces is not a finding.
    correct: CORRECT + `
      create function stamp() returns trigger language plpgsql as $fn$ begin
        new.body = coalesce(new.body, ''); return new; end; $fn$;
      create trigger t before insert on notes for each row execute function stamp();`,
  },
  {
    guard: 'mfa-enforcement',
    run: (db) => mfaEnforcement({ query: q(db), config: { role: 'authenticated' } }),
    broken: CORRECT + `
      create policy require_aal2 on notes for select to authenticated
        using (current_setting('app.aal', true) = 'aal2');`,
    correct: CORRECT + `
      create policy require_aal2 on notes as restrictive for select to authenticated
        using (current_setting('app.aal', true) = 'aal2');`,
  },
];

if (PGlite) {
  for (const c of CASES) {
    test(`${c.guard}: FAILS on a database broken the way it exists to detect`, async () => {
      const db = new PGlite();
      await db.exec(c.broken);
      const res = await c.run(db);
      assert.equal(
        res.ok, false,
        `${c.guard} reported ok on its own worst case — it cannot fail, so its green means nothing.\n`
        + JSON.stringify({ summary: res.summary, skipped: res.skipped, reason: res.reason }, null, 2),
      );
      assert.ok(res.violations.length > 0, `${c.guard} said not-ok but produced no violation`);
    });

    test(`${c.guard}: PASSES on the corrected version of that same schema`, async () => {
      const db = new PGlite();
      await db.exec(c.correct);
      const res = await c.run(db);
      assert.equal(
        res.ok, true,
        `${c.guard} fires on correct code, which is how a tool gets switched off.\n`
        + JSON.stringify(res.violations, null, 2),
      );
    });
  }

  test('a SKIP is never counted as a pass', async () => {
    // The other half of the same idea. A guard that cannot run must say so,
    // because "skipped" and "clean" are indistinguishable to a CI badge — which
    // is exactly how five of the 0.40.0 findings hid.
    const db = new PGlite();
    await db.exec(`create table t (id int);`); // no anon role at all
    const res = await columnExposure({ query: q(db), config: { role: 'anon' } });
    assert.equal(res.skipped, true, 'a guard with no usable role must report skipped, not ok');
    assert.ok(res.reason, 'a skip must carry a reason');
  });
}
