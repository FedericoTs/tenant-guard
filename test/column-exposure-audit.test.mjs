/**
 * column-exposure: the four things the audit measured wrong, pinned.
 *
 * Every test here failed on the version before the fix. What was measured:
 *
 *   classifier   token_count / password_changed_at -> 'secret', address_line_type
 *                -> 'pii'. Three correct tables, three hard violations, one of
 *                which told the user to rotate an integer on a pricing page.
 *   PUBLIC grant printed `REVOKE SELECT ... FROM anon` for a privilege held by
 *                PUBLIC. Applied: no error, read still worked, guard re-fired.
 *   fix recipe   `REVOKE SELECT FROM anon` + a `security_invoker` view over the
 *                same table. Applied verbatim: anon got 42501 on the view.
 *   probe loop   one begin/set role/rollback per relation, 241 queries for 60.
 *
 * The last two of those are the 0.26.0 failure mode again — advice that gets
 * pasted in without much thought has to work, and a name heuristic that fires
 * on `token_count` is how a guard teaches people to disable it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyColumn,
  classifyExposure,
  revokeTarget,
  grantPathsSql,
  check,
} from '../src/guards/column-exposure.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('column-exposure-audit integration (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── the classifier ───────────────────────────────────────────────────

test('a fact ABOUT a credential is not the credential', () => {
  // These are the three names test/column-exposure.test.mjs already named in a
  // comment as the ones that must not fire. Two of them did.
  assert.equal(classifyColumn('token_count'), null);
  assert.equal(classifyColumn('address_line_type'), null);
  assert.equal(classifyColumn('password_changed_at'), null);
  assert.equal(classifyColumn('email_verified'), null);
  assert.equal(classifyColumn('token_version'), null);
  assert.equal(classifyColumn('api_key_last_used_at'), null);
  assert.equal(classifyColumn('otp_expires_at'), null);
  assert.equal(classifyColumn('secret_rotated_at'), null);
  assert.equal(classifyColumn('phone_verified'), null);
});

test('the metadata rule does not cost a single true positive', () => {
  // The rejected wider rule (ignore anything ending in `_id`) would have
  // silenced the three at the end of this list. That is a worse bug than the
  // false positive it fixes, so the suppression stays prefix+qualifier only.
  for (const [name, kind] of [
    ['api_key', 'secret'], ['password_hash', 'secret'], ['secret_key', 'secret'],
    ['stripe_secret_key', 'secret'], ['session_token', 'secret'], ['refresh_token', 'secret'],
    ['recovery_code', 'secret'], ['otp', 'secret'], ['password_reset_token', 'secret'],
    ['api_key_hash', 'secret'],
    ['email', 'pii'], ['email_address', 'pii'], ['phone_number', 'pii'], ['ip_address', 'pii'],
    ['address_line_1', 'pii'], ['date_of_birth', 'pii'],
    ['tax_id', 'pii'], ['national_id', 'pii'], ['passport', 'pii'],
  ]) {
    assert.equal(classifyColumn(name), kind, `${name} should classify as ${kind}`);
  }
});

// ── who the REVOKE names ─────────────────────────────────────────────

test('revokeTarget keeps PUBLIC a keyword and quotes real role names', () => {
  assert.equal(revokeTarget(['PUBLIC']), 'PUBLIC');
  assert.equal(revokeTarget(['anon']), '"anon"');
  assert.equal(revokeTarget(['anon', 'PUBLIC']), 'PUBLIC, "anon"');
  // No measured grant path: the caller must not print a confident REVOKE.
  assert.equal(revokeTarget([]), null);
  assert.equal(revokeTarget(undefined), null);
});

test('with no ACL facts the fix says a PUBLIC grant would defeat it', () => {
  // classifyExposure is exported and callable on its own. Called that way it
  // has no catalog to consult, so it must not claim more than it knows.
  const v = classifyExposure({
    rel: { id: 'public.leads', schema: 'public', table: 'leads' },
    columns: [{ column: 'api_key', kind: 'secret' }],
    role: 'anon',
  });
  assert.match(v.fix, /REVOKE SELECT ON public\.leads FROM "anon";/);
  assert.match(v.fix, /granted to PUBLIC[\s\S]*revoke FROM PUBLIC instead/);
});

test('the emitted view recipe never revokes the grant the view depends on', () => {
  const v = classifyExposure({
    rel: { id: 'public.waitlist', schema: 'public', table: 'waitlist', grantees: ['anon'] },
    columns: [{ column: 'email', kind: 'pii' }],
    role: 'anon',
  });
  // The old text went REVOKE -> CREATE VIEW ... security_invoker -> GRANT on the
  // view, with no base-table privilege anywhere in between: 42501.
  const grantIdx = v.fix.indexOf('GRANT SELECT (<the columns that are meant to be public>)');
  const viewIdx = v.fix.indexOf('CREATE VIEW');
  assert.ok(grantIdx > -1, 'the column grant must be part of the recipe, not a footnote');
  assert.ok(viewIdx === -1 || grantIdx < viewIdx, 'the base column grant must come before the view');
  assert.match(v.fix, /security_invoker re-checks the CALLER's own privileges/);
});

if (PGlite) {
  const qq = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

  /** Pull the runnable statements out of a printed fix block (8-space indent). */
  function sqlFrom(fix) {
    const out = [];
    let cur = '';
    for (const line of fix.split('\n')) {
      if (!/^ {8}\S|^ {10}\S/.test(line)) { cur = ''; continue; }
      cur += (cur ? ' ' : '') + line.trim();
      if (cur.endsWith(';')) { out.push(cur); cur = ''; }
    }
    return out;
  }

  async function asRole(db, role, sql) {
    await db.query('begin');
    await db.query(`set local role ${role}`);
    try {
      const r = await db.query(sql);
      return { rows: r.rows };
    } catch (e) {
      return { error: e.message, code: e.code };
    } finally {
      await db.query('rollback');
    }
  }

  test('correct code with metadata columns stays GREEN', async () => {
    // Three tables that leak nothing. Before the classifier fix this returned
    // ok:false with three violations, one of them telling the user to rotate
    // token_count on a public pricing page.
    const db = new PGlite();
    await db.exec(`
      create role anon nologin;
      grant usage on schema public to anon;
      create table pricing_tiers (id int, name text, monthly_price int, token_count int);
      create table shipping_zones (id int, country text, address_line_type text);
      create table authors (id int, display_name text, email_verified boolean, password_changed_at timestamptz);
      insert into pricing_tiers values (1,'Pro',49,100000);
      insert into shipping_zones values (1,'IE','street');
      insert into authors values (1,'Ada',true,now());
      grant select on pricing_tiers, shipping_zones, authors to anon;
    `);
    const res = await check({ query: qq(db), config: { role: 'anon' } });
    assert.equal(res.ok, true, JSON.stringify(res.violations, null, 2));
    assert.equal(res.violations.length, 0);
  });

  test('a PUBLIC grant is revoked FROM PUBLIC, and that actually closes it', async () => {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin;
      grant usage on schema public to anon;
      create table leads (id int, email text, api_key text);
      insert into leads values (1,'a@x.com','sk_live_1');
      grant select on leads to public;
    `);
    const before = await check({ query: qq(db), config: { role: 'anon' } });
    assert.equal(before.ok, false);
    const fix = before.violations[0].fix;
    assert.match(fix, /REVOKE SELECT ON public\.leads FROM PUBLIC;/);
    assert.match(fix, /The privilege is held by PUBLIC, not by anon/);

    // Apply exactly what was printed, first statement only — the "close it" arm.
    await db.exec(sqlFrom(fix)[0]);
    const read = await asRole(db, 'anon', 'select count(api_key)::int as n from leads');
    assert.equal(read.code, '42501', JSON.stringify(read));
    const after = await check({ query: qq(db), config: { role: 'anon' } });
    assert.equal(after.ok, true, JSON.stringify(after.violations, null, 2));
  });

  test('a grant held by a group role names the group, not the member', async () => {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin;
      create role app_reader nologin;
      grant app_reader to anon;
      grant usage on schema public to anon;
      create table leads (id int, email text);
      insert into leads values (1,'a@x.com');
      grant select on leads to app_reader;
    `);
    const before = await check({ query: qq(db), config: { role: 'anon' } });
    assert.equal(before.ok, false);
    const fix = before.violations[0].fix;
    assert.match(fix, /REVOKE SELECT ON public\.leads FROM "app_reader";/);
    await db.exec(sqlFrom(fix)[0]);
    const after = await check({ query: qq(db), config: { role: 'anon' } });
    assert.equal(after.ok, true, JSON.stringify(after.violations, null, 2));
  });

  test('the printed projection recipe WORKS when applied verbatim', async () => {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin;
      grant usage on schema public to anon;
      create table waitlist (id int, display_name text, email text);
      insert into waitlist values (1,'Ada','ada@x.com');
      grant select on waitlist to anon;
    `);
    const before = await check({ query: qq(db), config: { role: 'anon' } });
    assert.equal(before.ok, false);

    // Every statement the fix prints, in the order it prints them, with the one
    // placeholder filled in the way a reader obviously would.
    for (const stmt of sqlFrom(before.violations[0].fix)) {
      await db.exec(
        stmt
          .replace('<the columns that are meant to be public>', 'display_name')
          .replace('<the same public columns>', 'display_name'),
      );
    }

    const viaView = await asRole(db, 'anon', 'select display_name from public.waitlist_public');
    assert.deepEqual(viaView.rows, [{ display_name: 'Ada' }], JSON.stringify(viaView));
    const leak = await asRole(db, 'anon', 'select email from waitlist');
    assert.equal(leak.code, '42501', JSON.stringify(leak));
    const after = await check({ query: qq(db), config: { role: 'anon' } });
    assert.equal(after.ok, true, JSON.stringify(after.violations, null, 2));
  });

  test('one transaction for the whole probe loop, not one per relation', async () => {
    let tables = '';
    for (let i = 0; i < 5; i++) {
      tables += `create table t${i} (id int, email text); insert into t${i} values (1,'a@x.com'); grant select on t${i} to anon;\n`;
    }
    const db = new PGlite();
    await db.exec(`create role anon nologin; grant usage on schema public to anon;\n` + tables);
    const seen = [];
    const res = await check({
      query: (t, v) => { seen.push(String(t).trim().slice(0, 20)); return qq(db)(t, v); },
      config: { role: 'anon' },
    });
    assert.equal(res.scanned, 5);
    assert.equal(seen.filter((s) => s === 'begin').length, 1);
    assert.equal(seen.filter((s) => s === 'set local role anon').length, 1);
    assert.equal(seen.filter((s) => s.startsWith('savepoint')).length, 5);
  });

  test('a relation the role cannot read does not swallow the ones after it', async () => {
    // The savepoint is what makes this hold: without it the first 42501 aborts
    // the shared transaction, every later probe throws "current transaction is
    // aborted", the catch reads that as unreachable, and the guard goes GREEN on
    // proven leaks. Measured on the savepoint-less variant: 3 leaks -> 0.
    //
    // `a_denied` sorts first, so it is probed first. `b_closed` then proves the
    // role is still in effect after the savepoint rollback — a superuser would
    // read straight through its RLS and report a false positive here.
    const db = new PGlite();
    await db.exec(`
      create role anon nologin;
      grant usage on schema public to anon;
      create table a_denied (id int, api_key text);
      create table b_closed (id int, email text);
      create table c_leak (id int, email text);
      create table d_leak (id int, api_key text);
      insert into a_denied values (1,'sk_1');
      insert into b_closed values (1,'closed@x.com');
      insert into c_leak values (1,'c@x.com');
      insert into d_leak values (1,'sk_2');
      grant select on b_closed, c_leak, d_leak to anon;
      alter table b_closed enable row level security;
    `);
    const res = await check({ query: qq(db), config: { role: 'anon' } });
    assert.deepEqual(
      res.violations.map((v) => v.where).sort(),
      ['public.c_leak (email)', 'public.d_leak (api_key)'],
      JSON.stringify(res, null, 2),
    );
    assert.ok(res.notes.some((n) => n.where === 'public.b_closed'));
  });

  test('the hoisted transaction still leaves the database as it found it', async () => {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin;
      grant usage on schema public to anon;
      create table waitlist (id int, email text);
      insert into waitlist values (1,'a@x.com');
      grant select on waitlist to anon;
    `);
    await check({ query: qq(db), config: { role: 'anon' } });
    assert.equal((await db.query('select count(*)::int as n from waitlist')).rows[0].n, 1);
    assert.notEqual((await db.query('select current_user as u')).rows[0].u, 'anon');
    // And the connection is not left inside a transaction.
    assert.equal((await db.query(`select txid_current_if_assigned() is null as clean`)).rows[0].clean, true);
  });

  test('grantPathsSql is parameterised, not string-built', () => {
    const { text, values } = grantPathsSql(['public'], 'anon');
    assert.deepEqual(values, [['public'], 'anon']);
    assert.doesNotMatch(text, /'anon'/);
  });
}
