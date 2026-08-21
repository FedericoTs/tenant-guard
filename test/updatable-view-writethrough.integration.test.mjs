/**
 * Proof that the static guard is checking something real.
 *
 * The guard reads migration text; this runs the same shape against a real
 * database and shows the write actually passing through, with the base table's
 * RLS evaluated as the view's owner rather than the caller. Without this, the
 * static rule is an assertion about Postgres rather than a fact about it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('updatable-view integration (pglite not installed — skipped)', { skip: true }, () => {});
}

/** The reported shape: a curated view over an RLS-protected table. */
const SETUP = (invoker) => `
  create role anon nologin;
  create table users (id int primary key, email text, display_name text);
  insert into users values (1, 'a@x.com', 'Ann'), (2, 'b@x.com', 'Bob');

  alter table users enable row level security;
  create policy nobody on users for all using (false) with check (false);

  create view public_profiles ${invoker ? 'with (security_invoker = true)' : ''} as
    select id, display_name from users;

  grant select on public_profiles to anon;
  -- Granted on the base table too, so what denies the caller below is the RLS
  -- POLICY and not a missing privilege. Otherwise the demonstration proves the
  -- wrong thing.
  grant select on users to anon;
`;

async function asAnon(db, sql) {
  await db.query('begin');
  await db.query('set local role anon');
  try {
    const r = await db.query(sql);
    return { ok: true, rows: r.rows?.length ?? 0, affected: r.affectedRows ?? r.rowCount ?? 0 };
  } catch (e) {
    return { ok: false, err: `${e.code ?? ''}`.trim() || e.message };
  } finally {
    await db.query('rollback');
  }
}

if (PGlite) {
  test('the write really does pass through, bypassing the base table RLS', async () => {
    const db = new PGlite();
    await db.exec(SETUP(false));
    // Only SELECT was granted — but grant the writes explicitly here, standing in
    // for the platform default privileges the guard warns about.
    await db.exec('grant insert, update, delete on public_profiles to anon;');

    // The base table denies everything to everyone, including reads.
    const direct = await asAnon(db, 'select * from users');
    assert.equal(direct.rows, 0, 'RLS on the base table denies the caller directly');

    // Through the view, which runs as its owner, the rows are readable…
    const viaView = await asAnon(db, 'select * from public_profiles');
    assert.equal(viaView.rows, 2, 'the view returns what its owner can see');

    // …and DELETE passes straight through to the base table.
    const del = await asAnon(db, 'delete from public_profiles');
    assert.equal(del.ok, true, `delete through the view should succeed: ${del.err}`);
    assert.equal(del.affected, 2, 'it deleted the base table rows, RLS notwithstanding');
  });

  test('security_invoker = true is a real fix, not a cosmetic one', async () => {
    const db = new PGlite();
    await db.exec(SETUP(true));
    await db.exec('grant insert, update, delete on public_profiles to anon;');
    await db.exec('grant delete on users to anon;'); // the caller's own grants now apply

    const viaView = await asAnon(db, 'select * from public_profiles');
    assert.equal(viaView.rows, 0, 'the caller sees what THEIR policy allows: nothing');

    const del = await asAnon(db, 'delete from public_profiles');
    assert.equal(del.affected, 0, 'and deletes nothing, because the policy is evaluated as them');
  });

  test('the REVOKE the guard recommends actually blocks the write', async () => {
    const db = new PGlite();
    await db.exec(SETUP(false));
    await db.exec('grant insert, update, delete on public_profiles to anon;');
    await db.exec('revoke insert, update, delete on public_profiles from anon;');

    const del = await asAnon(db, 'delete from public_profiles');
    assert.equal(del.ok, false);
    assert.match(String(del.err), /42501/, 'permission denied — the fix works');
  });
}
