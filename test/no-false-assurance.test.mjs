/**
 * "A skip is not a pass" — five places where the tool asserted safety it had
 * never tested.
 *
 * This is the worst class of bug a prover can have. A missed leak is a gap; a
 * confident green on a probe that never ran is an active lie, and it is the one
 * thing a user cannot check for themselves.
 *
 * Measured before the fix:
 *
 *   column-exposure, no such role     "1 untenanted relation(s) probed, nothing readable"
 *   column-exposure, 64-char column   ok=true, 0 violations — alias truncated at 63 bytes
 *   trigger-visibility, empty table   "sees every row, so nothing is being missed"
 *   storage-isolation, blind session  "N/N proven isolated"
 *   realtime-isolation, no policy     asserts a denial that does not apply to an RLS-exempt role
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { check as colExp, readableColumns, probeSql } from '../src/guards/column-exposure.mjs';
import { check as triggerCheck } from '../src/guards/trigger-visibility.mjs';
import { classifyBucket } from '../src/guards/storage-isolation.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('no-false-assurance (pglite not installed — skipped)', { skip: true }, () => {});
}

const q = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

// ── the alias truncation, as a pure fact ─────────────────────────────

test('probeSql aliases positionally, so a long column name cannot truncate', () => {
  const long = 'customer_primary_contact_email_address_for_billing_notifications'; // 64 chars
  const sql = probeSql({ schema: 'public', table: 'leads' }, [{ column: long }], 500);
  assert.match(sql, /as c0/);
  assert.doesNotMatch(sql, new RegExp(`as "?n_${long}`));
  assert.ok(!sql.split(/\s+/).some((tok) => tok.replace(/[",]/g, '').length > 63 && tok.startsWith('n_')));
});

test('readableColumns reads the positional keys', () => {
  const cols = [{ column: 'email' }, { column: 'phone' }];
  assert.deepEqual(readableColumns({ c0: 2, c1: 0 }, cols).map((c) => c.column), ['email']);
});

// ── the storage control arm, as a pure verdict ───────────────────────

test('storage: seeing none of your OWN objects is "not proven", not "isolated"', () => {
  const v = classifyBucket({
    bucket: 'avatars', isPublic: false, tenantFolders: ['a', 'b'],
    crossVisible: 0, ownVisible: 0, uploadedIntoOther: false, ownUploadWorked: false,
  });
  assert.equal(v.status, 'not-proven');
  assert.match(v.message, /nothing was actually compared/);
});

test('storage: seeing your own and none of theirs is still isolated', () => {
  const v = classifyBucket({
    bucket: 'avatars', isPublic: false, tenantFolders: ['a', 'b'],
    crossVisible: 0, ownVisible: 3, uploadedIntoOther: false, ownUploadWorked: true,
  });
  assert.equal(v.status, 'isolated');
});

test('storage: a real cross-tenant read still outranks the control arm', () => {
  const v = classifyBucket({
    bucket: 'avatars', isPublic: false, tenantFolders: ['a', 'b'],
    crossVisible: 4, ownVisible: 0, uploadedIntoOther: false, ownUploadWorked: false,
  });
  assert.equal(v.status, 'leak');
});

if (PGlite) {
  test('column-exposure SKIPS when the probe role does not exist', async () => {
    const db = new PGlite();
    await db.exec(`create table waitlist (id int, email text); insert into waitlist values (1,'a@x.com');`);
    const res = await colExp({ query: q(db), config: { role: 'anon' } });
    assert.equal(res.skipped, true, JSON.stringify(res, null, 2));
    assert.match(res.reason, /does not exist/);
  });

  test('column-exposure CATCHES a leak behind a 64-character column name', async () => {
    const long = 'customer_primary_contact_email_address_for_billing_notifications';
    const db = new PGlite();
    await db.exec(`
      create role anon nologin; grant usage on schema public to anon;
      create table leads (id int, "${long}" text);
      insert into leads values (1, 'ada@x.com');
      grant select on leads to anon;`);
    const res = await colExp({ query: q(db), config: { role: 'anon' } });
    assert.equal(res.ok, false, JSON.stringify(res, null, 2));
  });

  test('column-exposure still fires normally', async () => {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin; grant usage on schema public to anon;
      create table w (id int, email text); insert into w values (1,'a@x.com');
      grant select on w to anon;`);
    assert.equal((await colExp({ query: q(db), config: { role: 'anon' } })).ok, false);
  });

  test('trigger-visibility says NOT PROVEN on an empty table, not "nothing is missed"', async () => {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create table profiles (id serial primary key, user_id text, username text);
      alter table profiles enable row level security;
      create policy own on profiles for all to authenticated
        using (user_id = current_setting('app.uid', true));
      grant select, insert on profiles to authenticated;
      create function f() returns trigger language plpgsql as $x$ begin
        if exists (select 1 from profiles where username = new.username) then
          raise exception 'taken'; end if; return new; end; $x$;
      create trigger t before insert on profiles for each row execute function f();`);
    const res = await triggerCheck({ query: q(db), config: { role: 'authenticated' } });
    const note = (res.notes ?? [])[0];
    assert.ok(note, JSON.stringify(res, null, 2));
    assert.match(note.message, /EMPTY|NOT proven/);
    assert.doesNotMatch(note.message, /nothing is being missed/);
  });
}
