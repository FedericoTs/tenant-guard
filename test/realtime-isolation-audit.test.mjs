/**
 * realtime-isolation: audit regressions.
 *
 * Both findings closed here are about ADVICE, not detection. The guard found the
 * leaks correctly the whole time; what it printed underneath them did not close
 * them. That is the worse half of the failure, because a developer who applies the
 * advice, re-runs the guard, and still sees red concludes the guard is broken —
 * and the next thing they reach for is loosening something to make it shut up.
 *
 * So these tests do not stop at asserting strings. Where it is possible they
 * EXECUTE the SQL the guard printed and re-run check() on the result, which is the
 * only assertion that actually distinguishes advice that works from advice that
 * merely reads well.
 *
 *   1. additive-create-policy-fix-does-not-close-the-leak
 *      The remediation was `CREATE POLICY ...` alone. Postgres OR-combines
 *      permissive policies, so on the loose policy that caused the leak it added
 *      nothing and removed nothing: byte-identical violation afterwards.
 *
 *   2. fix-text-ignores-configured-topicSeparator
 *      Detection honoured `topicSeparator`; the fix text hardcoded ':'. On
 *      `{ topicSeparator: '-' }` the printed policy pins the whole topic string
 *      instead of its first segment, so applied literally it hides the tenant's OWN
 *      rows — an "isolating" policy that blanks the table.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { check, classifyRealtime } from '../src/guards/realtime-isolation.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('realtime-isolation audit (pglite not installed — skipped)', { skip: true }, () => {});
}

/** Same shape as the Supabase table, parameterised by the topic separator. */
const SCHEMA = (sep) => `
  create schema realtime;
  create table realtime.messages (
    id uuid primary key default gen_random_uuid(),
    topic text not null,
    extension text not null default 'broadcast',
    event text,
    payload jsonb,
    private boolean default true,
    inserted_at timestamptz default now()
  );
  grant usage on schema realtime to authenticated;
  grant select, insert on realtime.messages to authenticated;
  insert into realtime.messages (topic, event) values
    ('org_A${sep}notifications','ping'),
    ('org_B${sep}notifications','ping'),
    ('org_B${sep}presence','join');
`;

async function fresh(setup) {
  const db = new PGlite();
  await db.exec('create role authenticated nologin;');
  await db.exec(setup);
  return { db, query: (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined) };
}

/**
 * Pull the CREATE POLICY the guard printed out of its fix text and turn it into a
 * statement that will actually run: the only placeholder is the tenant source, which
 * the guard cannot know (GUC vs JWT claim), so we bind it to the same GUC the probe
 * uses. Everything else — command, clause, predicate — is the guard's own words.
 */
function emittedPolicy(fix, name) {
  const re = new RegExp(
    `CREATE POLICY ${name} ON realtime\\.messages FOR (SELECT|INSERT)\\s*\\n\\s*(USING|WITH CHECK) \\((.+?) = <the caller's tenant>\\);`,
  );
  const m = fix.match(re);
  assert.ok(m, `fix text did not contain a parseable CREATE POLICY ${name}:\n${fix}`);
  const [, cmd, clause, expr] = m;
  return {
    expr,
    sql: `create policy ${name} on realtime.messages for ${cmd} ${clause} (${expr} = current_setting('app.current_tenant', true));`,
  };
}

/**
 * Do what the fix text's steps 1 and 2 tell a reader to do, using the fix text's own
 * SQL: run the printed enumeration query, keep the policies its printed condition
 * describes, and drop each one through the printed DROP template. Nothing here is
 * hand-written SQL, so the test fails outright if the guard stops printing those steps
 * — which is the whole point of the finding.
 */
async function applyRemovalSteps(db, fix, { cmds, topicExpr }) {
  const enumSql = fix.match(/SELECT polname[\s\S]*?::regclass;/);
  assert.ok(enumSql, `fix text printed no way to enumerate the existing policies:\n${fix}`);
  const dropTpl = fix.match(/DROP POLICY "<name>" ON realtime\.messages;/);
  assert.ok(dropTpl, `fix text never says to remove anything:\n${fix}`);

  const { rows } = await db.query(enumSql[0]);
  // polcmd: 'r' SELECT, 'a' INSERT, '*' ALL. `polpermissive` is what makes a policy
  // OR-combine; a restrictive one cannot widen access and must not be dropped.
  const head = topicExpr.slice(0, topicExpr.indexOf(','));   // "split_part(topic"
  const loose = rows.filter(
    (r) => r.polpermissive && cmds.includes(r.polcmd) &&
      !`${r.using_expr ?? ''}${r.check_expr ?? ''}`.includes(head),
  );
  assert.ok(loose.length > 0, `step 1 surfaced nothing to drop: ${JSON.stringify(rows)}`);
  for (const r of loose) await db.exec(dropTpl[0].replace('<name>', r.polname));
  return loose.map((r) => r.polname);
}

/** What one tenant can see under the policies currently on the table. */
async function visibleAs(db, tenant, sep) {
  await db.exec('begin');
  try {
    await db.exec(`set local role authenticated`);
    await db.query(`select set_config('app.current_tenant', $1, true)`, [tenant]);
    const own = await db.query(
      `select count(*)::int as n from realtime.messages where split_part(topic, $1, 1) = $2`,
      [sep, tenant],
    );
    const other = await db.query(
      `select count(*)::int as n from realtime.messages where split_part(topic, $1, 1) <> $2`,
      [sep, tenant],
    );
    return { own: own.rows[0].n, other: other.rows[0].n };
  } finally {
    await db.exec('rollback');
  }
}

if (PGlite) {
  // ── finding 1: the fix has to say DROP, because CREATE alone cannot subtract ──

  test('READ fix names the loose policy as the thing to remove, not just a policy to add', async () => {
    const { query } = await fresh(`${SCHEMA(':')}
      alter table realtime.messages enable row level security;
      alter table realtime.messages force row level security;
      create policy p_all on realtime.messages for select using (true);
      create policy p_ins on realtime.messages for insert
        with check (split_part(topic, ':', 1) = current_setting('app.current_tenant', true));
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations.find((x) => x.kind === 'read');
    assert.ok(v, JSON.stringify(res.violations, null, 2));

    // The three things that make the advice applicable rather than decorative.
    assert.match(v.fix, /OR-combines permissive policies/);
    assert.match(v.fix, /FROM pg_policy WHERE polrelid = 'realtime\.messages'::regclass;/);
    assert.match(v.fix, /DROP POLICY "<name>" ON realtime\.messages;/);
    // A restrictive policy grants nothing, so offering it as the whole remedy locks
    // the app out. If it is mentioned at all it has to be as a warning.
    assert.match(v.fix, /restrictive policy only subtracts/);
  });

  test('following the READ fix end to end actually turns the guard green (CREATE alone does not)', async () => {
    const { db, query } = await fresh(`${SCHEMA(':')}
      alter table realtime.messages enable row level security;
      alter table realtime.messages force row level security;
      create policy p_all on realtime.messages for select using (true);
      create policy p_ins on realtime.messages for insert
        with check (split_part(topic, ':', 1) = current_setting('app.current_tenant', true));
    `);
    const before = await check({ query });
    const fix = before.violations.find((x) => x.kind === 'read').fix;
    const emitted = emittedPolicy(fix, 'tenant_channels');

    // Step 3 on its own — what the guard used to print, and all of it.
    await db.exec(emitted.sql);
    const additiveOnly = await check({ query });
    assert.equal(additiveOnly.ok, false, 'adding a permissive policy must not be able to close a leak');
    assert.equal(additiveOnly.violations[0].message, before.violations[0].message); // identical, not merely similar

    // Steps 1 and 2, executed from the fix text itself. `p_all` is what the printed
    // enumeration surfaces as permissive-SELECT-not-pinning-the-topic.
    const dropped = await applyRemovalSteps(db, fix, { cmds: ['r', '*'], topicExpr: emitted.expr });
    assert.deepEqual(dropped, ['p_all']);
    const after = await check({ query });
    assert.equal(after.ok, true, JSON.stringify(after, null, 2));
    assert.match(after.summary, /proven isolated/);

    // Positive control: the remedy scoped the table, it did not blank it.
    assert.deepEqual(await visibleAs(db, 'org_A', ':'), { own: 1, other: 0 });
  });

  test('WRITE fix says the same thing about WITH CHECK, and works end to end', async () => {
    const { db, query } = await fresh(`${SCHEMA(':')}
      alter table realtime.messages enable row level security;
      alter table realtime.messages force row level security;
      create policy tenant_channels on realtime.messages for select
        using (split_part(topic, ':', 1) = current_setting('app.current_tenant', true));
      create policy p_ins_all on realtime.messages for insert with check (true);
    `);
    const before = await check({ query });
    const v = before.violations.find((x) => x.kind === 'write');
    assert.ok(v, JSON.stringify(before, null, 2));
    assert.match(v.fix, /OR-combines permissive policies/);
    assert.match(v.fix, /whose WITH CHECK does not pin/);
    assert.match(v.fix, /DROP POLICY "<name>" ON realtime\.messages;/);

    const emitted = emittedPolicy(v.fix, 'tenant_publish');
    await db.exec(emitted.sql);
    const additiveOnly = await check({ query });
    assert.equal(additiveOnly.ok, false, 'a permissive WITH CHECK (true) survives anything added beside it');

    const dropped = await applyRemovalSteps(db, v.fix, { cmds: ['a', '*'], topicExpr: emitted.expr });
    assert.deepEqual(dropped, ['p_ins_all']);
    const after = await check({ query });
    assert.equal(after.ok, true, JSON.stringify(after, null, 2));
    assert.match(after.summary, /proven isolated/);
  });

  test('RLS-off fix warns that pre-existing policies go live the moment RLS is enabled', async () => {
    // A table can carry policies while RLS is off; ENABLE switches them all on at
    // once. Advice that stops at ENABLE + CREATE walks straight into the OR-combine.
    const { query } = await fresh(`${SCHEMA(':')}
      create policy p_all on realtime.messages for select using (true);
    `);
    const res = await check({ query });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
    const v = res.violations[0];
    assert.match(v.fix, /ENABLE ROW LEVEL SECURITY/);
    assert.match(v.fix, /go live the moment you enable it/);
    assert.match(v.fix, /FROM pg_policy WHERE polrelid = 'realtime\.messages'::regclass;/);
  });

  // ── finding 2: the printed predicate must use the CONFIGURED separator ──

  test('fix text uses the configured topicSeparator, and the emitted policy scopes rather than blanks', async () => {
    const { db, query } = await fresh(`${SCHEMA('-')}
      alter table realtime.messages enable row level security;
      alter table realtime.messages force row level security;
      create policy p_all on realtime.messages for select using (true);
      create policy p_ins_all on realtime.messages for insert with check (true);
    `);
    const before = await check({ query, config: { topicSeparator: '-' } });
    assert.equal(before.ok, false, JSON.stringify(before, null, 2));
    const v = before.violations.find((x) => x.kind === 'read');
    assert.ok(v, JSON.stringify(before.violations, null, 2));

    const emitted = emittedPolicy(v.fix, 'tenant_channels');
    assert.equal(emitted.expr, "split_part(topic, '-', 1)");
    assert.equal(/split_part\(topic, ':', 1\)/.test(v.fix), false, 'must not print the default separator on a non-default config');

    // The measurement that matters: `split_part('org_A-notifications', ':', 1)`
    // returns the whole string, so the old advice matched nothing at all. Apply the
    // new advice for real and confirm org_A keeps its own row and loses org_B's.
    await db.exec(emitted.sql);
    await db.exec('drop policy p_all on realtime.messages;');
    assert.deepEqual(await visibleAs(db, 'org_A', '-'), { own: 1, other: 0 });

    // Reads are scoped now, so the guard surfaces the write arm. Apply its advice
    // the same way and the whole surface goes green on a non-default separator.
    const mid = await check({ query, config: { topicSeparator: '-' } });
    const w = mid.violations.find((x) => x.kind === 'write');
    assert.ok(w, JSON.stringify(mid, null, 2));
    assert.equal(emittedPolicy(w.fix, 'tenant_publish').expr, "split_part(topic, '-', 1)");
    await db.exec(emittedPolicy(w.fix, 'tenant_publish').sql);
    await db.exec('drop policy p_ins_all on realtime.messages;');
    const after = await check({ query, config: { topicSeparator: '-' } });
    assert.equal(after.ok, true, JSON.stringify(after, null, 2));
  });

  test('the RLS-off fix also honours the configured separator (both policies it prints)', async () => {
    const { query } = await fresh(SCHEMA('/'));
    const res = await check({ query, config: { topicSeparator: '/' } });
    assert.equal(res.ok, false);
    const fix = res.violations[0].fix;
    assert.equal(emittedPolicy(fix, 'tenant_channels').expr, "split_part(topic, '/', 1)");
    assert.equal(emittedPolicy(fix, 'tenant_publish').expr, "split_part(topic, '/', 1)");
    assert.equal(/split_part\(topic, ':', 1\)/.test(fix), false);
  });

  test('a correctly scoped non-default-separator project still gets a silent pass', async () => {
    // Calibration guard: none of the advice rewrites may cost the guard its quiet.
    const { query } = await fresh(`${SCHEMA('-')}
      alter table realtime.messages enable row level security;
      alter table realtime.messages force row level security;
      create policy tenant_channels on realtime.messages for select
        using (split_part(topic, '-', 1) = current_setting('app.current_tenant', true));
      create policy tenant_publish on realtime.messages for insert
        with check (split_part(topic, '-', 1) = current_setting('app.current_tenant', true));
    `);
    const res = await check({ query, config: { topicSeparator: '-' } });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.match(res.summary, /proven isolated/);
  });
}

// ── pure-logic arms (run with or without pglite) ──────────────────────

test('classifyRealtime threads the separator into every fix it prints', () => {
  for (const sep of [':', '-', '/', '.']) {
    const expected = `split_part(topic, '${sep}', 1)`;
    const off = classifyRealtime({ rlsEnabled: false, separator: sep });
    const read = classifyRealtime({ rlsEnabled: true, policyCount: 1, tenantCount: 2, crossVisible: 2, separator: sep });
    const write = classifyRealtime({ rlsEnabled: true, policyCount: 2, tenantCount: 2, crossVisible: 0, broadcastIntoOther: true, ownBroadcastWorked: true, separator: sep });
    for (const v of [off, read, write]) {
      assert.ok(v.fix.includes(expected), `${sep}: fix did not use the configured separator:\n${v.fix}`);
      if (sep !== ':') assert.equal(v.fix.includes("split_part(topic, ':', 1)"), false, `${sep}: fix still hardcodes ':'`);
    }
  }
});

test('classifyRealtime defaults to the documented separator when none is passed', () => {
  // Keeps the existing unit tests and any external caller on the same expression.
  const v = classifyRealtime({ rlsEnabled: false });
  assert.match(v.fix, /split_part\(topic, ':', 1\)/);
});

test('classifyRealtime rejects an unsafe separator instead of interpolating it into advice', () => {
  // The advice string is SQL a human will paste. It gets the same validation the
  // probe expression gets — a quote or backslash must never reach either.
  assert.throws(() => classifyRealtime({ rlsEnabled: false, separator: "'" }));
  assert.throws(() => classifyRealtime({ rlsEnabled: false, separator: '::' }));
});

test('both leak arms lead with removal, and neither offers RESTRICTIVE as the whole answer', () => {
  const read = classifyRealtime({ rlsEnabled: true, policyCount: 1, tenantCount: 2, crossVisible: 1 });
  const write = classifyRealtime({ rlsEnabled: true, policyCount: 2, tenantCount: 2, crossVisible: 0, broadcastIntoOther: true, ownBroadcastWorked: true });
  for (const v of [read, write]) {
    assert.match(v.fix, /Adding a policy is NOT enough on its own/);
    assert.match(v.fix, /DROP POLICY/);
    assert.match(v.fix, /pg_policy/);
    assert.match(v.fix, /restrictive policy only subtracts/);
    // DROP has to come before the CREATE, or the reader applies step 3 and stops.
    assert.ok(v.fix.indexOf('DROP POLICY') < v.fix.indexOf('CREATE POLICY'), v.fix);
  }
});

test('non-leak verdicts stay short — no remediation is attached to a note', () => {
  // A "we could not test this" note that carries DROP POLICY advice reads as an
  // instruction to change a database the guard never proved anything about.
  for (const v of [
    classifyRealtime({ rlsEnabled: true, policyCount: 0 }),
    classifyRealtime({ rlsEnabled: true, policyCount: 1, tenantCount: 1 }),
    classifyRealtime({ rlsEnabled: true, policyCount: 1, tenantCount: 2, noAccess: true }),
  ]) {
    assert.notEqual(v.status, 'leak');
    assert.equal(v.fix, undefined);
  }
});
