/**
 * The tool's own guards, guarded. Every guard ships a test that proves it
 * catches the bug and clears the safe case — this file is the tool eating its
 * own dog food. `node --test`, zero dependencies.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  detectCollisions,
  findNewCollisions,
} from '../src/guards/migration-collisions.mjs';
import {
  extractDefinerFunctions,
  revokesAnonExecute,
  findDefinerGrantViolations,
  migrationNumber,
} from '../src/guards/definer-grants.mjs';
import { classifyRouteFile } from '../src/guards/route-org-scoping.mjs';

// ── migration-collisions ─────────────────────────────────────────────
test('collision: two files sharing a number are detected', () => {
  const c = detectCollisions(['001_a.sql', '002_b.sql', '002_c.sql']);
  assert.equal(c.length, 1);
  assert.equal(c[0].number, '002');
  assert.deepEqual(c[0].files, ['002_b.sql', '002_c.sql']);
});

test('collision: unique numbers are clean', () => {
  assert.deepEqual(findNewCollisions(['001_a.sql', '002_b.sql', '003_c.sql']), []);
});

test('collision: grandfathered numbers are ignored, new ones still fail', () => {
  const files = ['031_a.sql', '031_b.sql', '208_x.sql', '208_y.sql'];
  const fresh = findNewCollisions(files, ['031']);
  assert.equal(fresh.length, 1);
  assert.equal(fresh[0].number, '208');
});

test('collision: non-.sql files are ignored', () => {
  assert.deepEqual(findNewCollisions(['001_a.sql', '001_notes.md']), []);
});

// ── definer-grants ───────────────────────────────────────────────────
const UNSAFE_FN = `
CREATE OR REPLACE FUNCTION public.wipe_org(p_org uuid)
RETURNS void LANGUAGE sql SECURITY DEFINER AS $$
  DELETE FROM invoices WHERE organization_id = p_org;
$$;
`;
const SAFE_FN = UNSAFE_FN + `
REVOKE EXECUTE ON FUNCTION public.wipe_org(uuid) FROM PUBLIC, anon;
`;
const TRIGGER_FN = `
CREATE FUNCTION public.touch_updated_at() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;
`;
const READONLY_FN = `
CREATE FUNCTION public.count_rows() RETURNS int
LANGUAGE sql SECURITY DEFINER AS $$ SELECT count(*) FROM invoices $$;
`;

test('definer: parses a SECURITY DEFINER mutating function', () => {
  const fns = extractDefinerFunctions(UNSAFE_FN);
  assert.equal(fns.length, 1);
  assert.equal(fns[0].name, 'wipe_org');
  assert.equal(fns[0].mutates, true);
  assert.equal(fns[0].returnsTrigger, false);
});

test('definer: detects the revoke from PUBLIC/anon', () => {
  assert.equal(revokesAnonExecute(SAFE_FN, 'wipe_org'), true);
  assert.equal(revokesAnonExecute(UNSAFE_FN, 'wipe_org'), false);
});

test('definer: unsafe function above baseline is a violation', () => {
  const v = findDefinerGrantViolations([{ name: '200_x.sql', sql: UNSAFE_FN }], { baseline: 100 });
  assert.equal(v.length, 1);
  assert.equal(v[0].fn, 'wipe_org');
});

test('definer: revoked function is clean', () => {
  assert.deepEqual(findDefinerGrantViolations([{ name: '200_x.sql', sql: SAFE_FN }], { baseline: 100 }), []);
});

test('definer: trigger + read-only functions are never flagged', () => {
  const files = [
    { name: '200_t.sql', sql: TRIGGER_FN },
    { name: '201_r.sql', sql: READONLY_FN },
  ];
  assert.deepEqual(findDefinerGrantViolations(files, { baseline: 100 }), []);
});

test('definer: migrations at or below baseline are grandfathered', () => {
  assert.deepEqual(findDefinerGrantViolations([{ name: '050_old.sql', sql: UNSAFE_FN }], { baseline: 100 }), []);
});

test('definer: allowlisted function is not flagged', () => {
  const v = findDefinerGrantViolations([{ name: '200_x.sql', sql: UNSAFE_FN }], {
    baseline: 100,
    allowlist: ['wipe_org'],
  });
  assert.deepEqual(v, []);
});

test('definer: migrationNumber parses prefixes', () => {
  assert.equal(migrationNumber('208_role.sql'), 208);
  assert.equal(migrationNumber('no-number.sql'), null);
});

// ── route-org-scoping ────────────────────────────────────────────────
const LEAKY_ROUTE = `
export async function GET(req, { params }) {
  const auth = await withApiAuth(req);
  const { data } = await supabase.from('invoices').select('*').eq('id', params.id).single();
  return Response.json(data);
}`;
const SAFE_ROUTE = `
export async function GET(req, { params }) {
  const auth = await withApiAuth(req);
  const { data } = await supabase.from('invoices').select('*')
    .eq('id', params.id).eq('organization_id', auth.organizationId).single();
  return Response.json(data);
}`;
const AUTHLESS_ROUTE = `
export async function GET(req) {
  const { data } = await supabase.from('public_posts').select('*').eq('id', req.query.id);
  return Response.json(data);
}`;

test('route: authenticated + bare-id + no tenant column = leak', () => {
  const v = classifyRouteFile(LEAKY_ROUTE);
  assert.equal(v.authenticated, true);
  assert.equal(v.filtersById, true);
  assert.equal(v.mentionsTenant, false);
  assert.equal(v.leak, true);
});

test('route: tenant-scoped query is safe', () => {
  assert.equal(classifyRouteFile(SAFE_ROUTE).leak, false);
});

test('route: unauthenticated route is not flagged (no session to abuse)', () => {
  assert.equal(classifyRouteFile(AUTHLESS_ROUTE).leak, false);
});

test('route: custom tenant column via config', () => {
  const custom = LEAKY_ROUTE.replace('organization_id', 'x');
  // default signals -> leak; but if the app's tenant col is account_id and present, it's safe
  const withAccount = custom + '\n// scoped by account_id above';
  assert.equal(classifyRouteFile(withAccount, { tenantSignals: ['account_id'] }).leak, false);
});
