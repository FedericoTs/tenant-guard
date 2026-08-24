/**
 * anon-writes — findings from the audit.
 *
 * anon-writes-stale-comment-contradicts-fix
 * -----------------------------------------
 * The doc comment above viewSurfaceSql() carried the pre-0.36.0 belief that
 * `security_invoker = true` makes the write fail with 42501, full stop
 * ("Verified both ways: 1 row affected with it off, 42501 with it on").
 * Commit 9365c50 corrected that belief in violationForView()'s fix text — the
 * refusal only happens when the role holds NO privilege on the base table —
 * but touched only the message strings, so the file shipped two contradictory
 * measurement claims about the same operation, 60 lines apart.
 *
 * Guard behaviour was never wrong: `runsAsOwner` drops invoker-on views, and
 * under the corrected understanding invoker-on is still not a leak (it is
 * either 42501 or a silent zero rows). What was wrong was the recorded reason.
 * These tests therefore do not test a verdict — they bind the comment to a
 * live measurement, so a claim in it cannot drift from Postgres again without
 * the suite going red.
 *
 * Every test here fails against the old comment.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { check } from '../src/guards/anon-writes.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = fs.readFileSync(path.join(HERE, '..', 'src', 'guards', 'anon-writes.mjs'), 'utf8');

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('anon-writes audit (pglite not installed — skipped)', { skip: true }, () => {});
}

// ── the claim that was falsified ─────────────────────────────────────

test('the comment no longer states the unconditional "42501 with it on"', () => {
  // The exact sentence commit 9365c50 disproved in the fix text but left here.
  assert.ok(
    !/Verified both ways: 1 row affected with[\s*]*it off, 42501 with it on/.test(SRC),
    'the falsified unconditional refusal claim is back in the source',
  );
  // And the conditional the fix text states is present in the comment too.
  assert.match(SRC, /invoker on,\s+no base grant\s*->\s*ERROR 42501/);
  assert.match(SRC, /invoker on,\s+base grant\s*->\s*0 rows affected, and NO error/);
});

// ── the comment, measured ────────────────────────────────────────────

/**
 * Pull the four-case matrix straight out of the doc comment. If someone edits
 * a number in the comment, this is what re-measures it. Lines look like:
 *   `*       invoker off, base grant    -> 1 row affected            <- the leak`
 */
function matrixFromComment() {
  const re = /invoker (off|on),\s+(no base grant|base grant)\s*->\s*([^\n]*)/g;
  const out = [];
  for (const m of SRC.matchAll(re)) {
    out.push({ invoker: m[1] === 'on', baseGrant: m[2] === 'base grant', claim: m[3].trim() });
  }
  return out;
}

if (PGlite) {
  /**
   * A definer view over an RLS-on base table whose policy matches nothing for
   * anon — the shape the guard reports. Each probe runs in its own txn and
   * rolls back, so the cases cannot contaminate each other.
   *
   * NOTE the SELECT grants: without SELECT on the view, every case returns
   * "permission denied for view public_profiles" and the matrix looks uniform.
   * That is a measurement artefact of the WHERE clause, not the RLS behaviour,
   * and it is what makes this easy to get wrong by hand.
   */
  async function freshView() {
    const db = new PGlite();
    await db.exec(`
      create role anon nologin;
      grant usage on schema public to anon;
      create table users (id int primary key, organization_id text not null, email text not null);
      insert into users values (1, 'org-a', 'a@x.test'), (2, 'org-b', 'b@x.test');
      alter table users enable row level security;
      create policy p on users using (organization_id = current_setting('request.org', true));
      create view public_profiles as select id, organization_id, email from users;
    `);
    return db;
  }

  async function probe(db, { invoker, baseGrant }) {
    await db.exec('begin');
    try {
      await db.exec(
        `alter view public_profiles ${invoker ? 'set (security_invoker = true)' : 'reset (security_invoker)'};`,
      );
      await db.exec('grant select, update on public_profiles to anon;');
      if (baseGrant) await db.exec('grant select, update on users to anon;');
      else await db.exec('revoke select, update on users from anon;');
      await db.exec('set local role anon;');
      const r = await db.query(`update public_profiles set email = 'hacked' where id = 1`);
      return { rows: r.affectedRows, error: null };
    } catch (e) {
      return { rows: null, error: e };
    } finally {
      try { await db.exec('rollback'); } catch { /* the probe already failed */ }
    }
  }

  test('every case the comment claims is what Postgres actually does', async () => {
    const matrix = matrixFromComment();
    assert.equal(matrix.length, 4, 'the comment should record all four invoker x base-grant cases');

    const db = await freshView();
    try {
      for (const c of matrix) {
        const got = await probe(db, c);
        const label = `invoker ${c.invoker ? 'on' : 'off'}, ${c.baseGrant ? 'base grant' : 'no base grant'}`;

        if (/ERROR 42501/.test(c.claim)) {
          assert.ok(got.error, `${label}: comment claims 42501, got ${got.rows} rows and no error`);
          assert.equal(got.error.code, '42501', `${label}: ${got.error.message}`);
          // The refusal names the BASE table, not the view — that is the whole
          // point of invoker-on, and the comment says so.
          assert.match(got.error.message, /users/, `${label}: ${got.error.message}`);
        } else {
          const want = Number(c.claim.match(/^(\d+) rows? affected/)?.[1]);
          assert.ok(Number.isInteger(want), `${label}: unparseable claim "${c.claim}"`);
          assert.equal(got.error, null, `${label}: comment claims ${want} rows, got ${got.error?.message}`);
          assert.equal(got.rows, want, label);
        }
      }
    } finally {
      await db.close();
    }
  });

  test('ALTER DEFAULT PRIVILEGES ... ON TABLES arms the view AND the base table', async () => {
    // This is why the zero-row case, not the 42501 case, is the usual one:
    // the caller that inherited the view grant inherited the base grant too.
    assert.match(SRC, /has_table_privilege true for both relkind/);
    const db = new PGlite();
    try {
      await db.exec(`
        create role anon nologin;
        alter default privileges in schema public grant update on tables to anon;
        create table t (id int);
        create view v as select * from t;
      `);
      const { rows } = await db.query(`
        select c.relkind::text as kind, has_table_privilege('anon', c.oid, 'UPDATE') as upd
        from pg_class c join pg_namespace n on n.oid = c.relnamespace
        where n.nspname = 'public' and c.relname in ('t','v') order by c.relname`);
      assert.deepEqual(rows, [{ kind: 'r', upd: true }, { kind: 'v', upd: true }]);
    } finally {
      await db.close();
    }
  });

  test('invoker-on IS a write-through when the base table has RLS off — and the table surface catches it', async () => {
    // The "invoker-on is never a leak" half of the comment is conditional on
    // the base table having RLS on. The comment now says so; this measures it,
    // and measures the reason it is still safe to filter those rows out.
    assert.match(SRC, /Measured with RLS OFF: invoker on \+ base grant -> 1 row affected/);

    const db = new PGlite();
    try {
      await db.exec(`
        create role anon nologin;
        grant usage on schema public to anon;
        create table users (id int primary key, organization_id text not null, email text not null);
        insert into users values (1, 'org-a', 'a@x.test');
        -- RLS deliberately NOT enabled
        create view public_profiles with (security_invoker = true) as select * from users;
        grant select, update on public_profiles to anon;
        grant select, update on users to anon;
      `);

      await db.exec('begin');
      await db.exec('set local role anon;');
      const r = await db.query(`update public_profiles set email = 'hacked' where id = 1`);
      assert.equal(r.affectedRows, 1, 'invoker-on does pass a write through when the base has no RLS');
      await db.exec('rollback');

      const query = (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);
      const res = await check({ query });
      assert.equal(res.ok, false);
      // Reported against the base table, not the view — nothing escapes.
      assert.ok(
        res.violations.some((v) => v.where === 'public.users'),
        JSON.stringify(res.violations),
      );
    } finally {
      await db.close();
    }
  });
}
