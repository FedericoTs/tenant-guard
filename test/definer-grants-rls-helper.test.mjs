/**
 * Regression tests from a real production run (MonkeyTravel, 2026-08-21).
 *
 * `definer-grants` flagged `user_is_trip_owner` — a pure `STABLE SELECT EXISTS`
 * predicate — as "SECURITY DEFINER + mutates", and advised revoking EXECUTE from
 * PUBLIC. That function is called inside nine RLS policies, and **Postgres
 * requires the calling role to hold EXECUTE even for a SECURITY DEFINER function
 * invoked in a policy**. Applying the advice took the app down: `anon` SELECT
 * began failing with 42501.
 *
 * Reproduced here at both layers:
 *   1. the parser read the whole file, so a neighbouring `CREATE POLICY … FOR
 *      INSERT` made a read-only function look like DML;
 *   2. nothing checked whether the function was load-bearing for a policy.
 *
 * A security linter's fixes get applied blind. These pin that they are safe to.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  extractFunctionDefs,
  extractFunctionBody,
  bodyMutates,
  stripSqlComments,
  policyReferencedFunctions,
  findDefinerGrantViolations,
  findRlsHelpers,
  run,
} from '../src/guards/definer-grants.mjs';

/** The shape that caused the outage, reduced. */
const PREDICATE_THEN_POLICY = `
  CREATE FUNCTION public.user_is_trip_owner(p_trip_id uuid, p_user_id uuid)
  RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
  AS $$ SELECT EXISTS (SELECT 1 FROM public.trips WHERE id=p_trip_id AND user_id=p_user_id) $$;

  CREATE POLICY trips_insert ON public.trips FOR INSERT WITH CHECK (public.user_is_trip_owner(id, auth.uid()));
  CREATE POLICY trips_delete ON public.trips FOR DELETE USING (public.user_is_trip_owner(id, auth.uid()));
`;

// ── the parser ───────────────────────────────────────────────────────

test('a STABLE predicate is NOT mutating, whatever follows it in the file', () => {
  const [fn] = extractFunctionDefs(PREDICATE_THEN_POLICY);
  assert.equal(fn.name, 'user_is_trip_owner');
  assert.equal(fn.mutates, false, 'CREATE POLICY … FOR INSERT is a policy verb, not DML');
  assert.equal(fn.volatility, 'stable');
  assert.equal(fn.bodyKnown, true);
});

test('volatility is authoritative — Postgres will not let a STABLE function write', () => {
  const sql = `CREATE FUNCTION f() RETURNS int LANGUAGE sql STABLE SECURITY DEFINER
               AS $$ INSERT INTO t VALUES (1); SELECT 1 $$;`;
  assert.equal(extractFunctionDefs(sql)[0].mutates, false); // the server would reject it anyway
});

test('a VOLATILE definer that really writes is still caught', () => {
  const sql = `CREATE FUNCTION public.attach_referral() RETURNS void LANGUAGE plpgsql SECURITY DEFINER
               AS $$ BEGIN INSERT INTO referrals (a) VALUES (1); END $$;`;
  const [fn] = extractFunctionDefs(sql);
  assert.equal(fn.mutates, true);
  assert.equal(fn.isDefiner, true);
});

test('extractFunctionBody: dollar-quoted with and without a tag, and quoted bodies', () => {
  assert.match(extractFunctionBody(`CREATE FUNCTION f() RETURNS int AS $$ SELECT 1 $$;`), /SELECT 1/);
  assert.match(extractFunctionBody(`CREATE FUNCTION f() RETURNS int AS $body$ SELECT 2 $body$;`), /SELECT 2/);
  assert.match(extractFunctionBody(`CREATE FUNCTION f() RETURNS int AS 'SELECT 3';`), /SELECT 3/);
  assert.equal(extractFunctionBody(`CREATE FUNCTION f() RETURNS int LANGUAGE c;`), null); // unknown, not safe
});

test('the body stops at its own terminator — trailing statements are not part of it', () => {
  const body = extractFunctionBody(PREDICATE_THEN_POLICY);
  assert.match(body, /SELECT EXISTS/);
  assert.doesNotMatch(body, /CREATE POLICY/);
});

test('bodyMutates: statements, not bare words', () => {
  assert.equal(bodyMutates('SELECT * FROM t FOR UPDATE'), false);      // a lock, not a write
  assert.equal(bodyMutates('SELECT updated_at FROM t'), false);        // a column
  assert.equal(bodyMutates('-- we used to DELETE FROM t here\\nSELECT 1'), false); // a comment
  assert.equal(bodyMutates('INSERT INTO t VALUES (1)'), true);
  assert.equal(bodyMutates('DELETE FROM t WHERE x'), true);
  assert.equal(bodyMutates('UPDATE t SET x = 1'), true);
});

test('stripSqlComments removes both comment forms', () => {
  assert.doesNotMatch(stripSqlComments('a -- delete from t\\nb'), /delete/);
  assert.doesNotMatch(stripSqlComments('a /* insert into t */ b'), /insert/);
});

// ── the RLS-helper rule ──────────────────────────────────────────────

test('policyReferencedFunctions finds helpers called from a policy expression', () => {
  const names = policyReferencedFunctions(PREDICATE_THEN_POLICY);
  assert.ok(names.has('user_is_trip_owner'));
  assert.ok(!names.has('using'), 'policy syntax is not a helper');
  assert.ok(!names.has('exists'));
});

test('THE OUTAGE CASE: no violation, and it is reported as a recognised pattern', () => {
  const files = [{ name: '200_trips.sql', sql: PREDICATE_THEN_POLICY }];
  assert.deepEqual(findDefinerGrantViolations(files), []);
  const helpers = findRlsHelpers(files);
  assert.equal(helpers.length, 1);
  assert.equal(helpers[0].fn, 'user_is_trip_owner');
  assert.equal(helpers[0].mutates, false);
});

test('a MUTATING function used by a policy is flagged but never told to revoke', () => {
  // Revoking would still break the policy, so the usual fix is withheld even
  // though the finding stands.
  const sql = `
    CREATE FUNCTION public.touchy() RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    AS $$ BEGIN INSERT INTO audit VALUES (1); RETURN true; END $$;
    CREATE POLICY p ON t FOR SELECT USING (public.touchy());
  `;
  const [v] = findDefinerGrantViolations([{ name: '201_x.sql', sql }]);
  assert.ok(v, 'still a finding');
  assert.equal(v.rlsHelper, true);
});

// ── end to end, through run() ────────────────────────────────────────

test('run(): the outage case produces no violation and one explanatory note', async (t) => {
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');

  const dir = mkdtempSync(join(tmpdir(), 'tg-dg-'));
  try {
    writeFileSync(join(dir, '200_trips.sql'), PREDICATE_THEN_POLICY);
    const res = run({ dir });
    assert.equal(res.ok, true, JSON.stringify(res, null, 2));
    assert.equal(res.violations.length, 0);
    const note = res.notes.find((n) => /user_is_trip_owner/.test(n.message));
    assert.ok(note, JSON.stringify(res.notes, null, 2));
    assert.match(note.message, /RLS helper/);
    assert.match(note.message, /must stay/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('run(): a genuinely mutating definer is still flagged, with the revoke', async () => {
  const { mkdtempSync, writeFileSync, rmSync } = await import('node:fs');
  const { join } = await import('node:path');
  const { tmpdir } = await import('node:os');

  const dir = mkdtempSync(join(tmpdir(), 'tg-dg-'));
  try {
    writeFileSync(join(dir, '200_ref.sql'), `
      CREATE FUNCTION public.attach_referral_on_signup() RETURNS void
      LANGUAGE plpgsql SECURITY DEFINER
      AS $$ BEGIN INSERT INTO referrals (user_id) VALUES (auth.uid()); END $$;
    `);
    const res = run({ dir });
    assert.equal(res.ok, false);
    assert.match(res.violations[0].fix, /REVOKE EXECUTE/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
