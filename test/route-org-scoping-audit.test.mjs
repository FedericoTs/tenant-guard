/**
 * Two defects in the route heuristic, from opposite directions.
 *
 * **It fired on correct code.** `.eq('user_id', user.id)` — a route scoped by
 * the session user's own id — failed the build as a cross-tenant IDOR, because
 * `user_id` matches the bare-id pattern and the filter's VALUE was never read.
 * So did `.eq('id', user.id)`, the canonical "load my own profile" route. That
 * is every "my notifications" and "my settings" handler in the Next.js +
 * Supabase stack these defaults exist to serve, and a real user reported it.
 *
 * The documented workaround made it worse. Putting `user_id` in `tenantSignals`
 * also silences `.eq('user_id', params.userId)`, which IS an IDOR — trading a
 * false positive for a false negative on the same query shape.
 *
 * **It missed the shape it was written for.** The tenant signal was searched
 * anywhere in the statement, so naming the tenant column in the SELECT
 * projection — `.select('id, organization_id, total').eq('id', params.id)` —
 * counted as scoping. The guard's own canonical service-role IDOR reported
 * clean, and the summary said "all tenant-scoped or authless".
 *
 * The decision is now per MATCH rather than per file, which is what lets both
 * fixes coexist: a file containing a session-scoped filter AND a request-scoped
 * one still fails on the second.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  classifyRouteFile,
  stripProjections,
  isSessionDerived,
  DEFAULTS,
} from '../src/guards/route-org-scoping.mjs';

const AUTH = `const { data: { user } } = await supabase.auth.getUser();`;
const verdict = (src, opts) => {
  const c = classifyRouteFile(src, opts);
  return c.leak ? 'leak' : c.unscopedQuery ? 'note' : 'clean';
};

// ── the helpers ──────────────────────────────────────────────────────

test('stripProjections blanks the argument, keeps the rest of the statement', () => {
  const out = stripProjections(`.select('id, organization_id, total').eq('id', x)`);
  assert.equal(out.includes('organization_id'), false);
  assert.ok(out.includes(`.eq('id', x)`));
});

test('stripProjections survives nested parens (Drizzle/Prisma object literals)', () => {
  const out = stripProjections(`.select({ a: sql(count(x)), b: t.organization_id }).where(eq(t.id, p))`);
  assert.equal(out.includes('organization_id'), false);
  assert.ok(out.includes('where'));
});

test('isSessionDerived reads the VALUE, not the column name', () => {
  const pat = new RegExp(DEFAULTS.idFilterPattern, 'gi');
  const sess = `.eq('user_id', user.id)`;
  const req = `.eq('user_id', params.userId)`;
  assert.equal(isSessionDerived(sess, [...sess.matchAll(pat)][0]), true);
  assert.equal(isSessionDerived(req, [...req.matchAll(pat)][0]), false);
});

// ── fired on correct code ────────────────────────────────────────────

test('a per-user route is NOT a leak', () => {
  assert.equal(verdict(`${AUTH}\nawait supabase.from('notifications').select('*').eq('user_id', user.id);`), 'clean');
});

test('loading your own profile is NOT a leak', () => {
  assert.equal(verdict(`${AUTH}\nawait supabase.from('profiles').select('*').eq('id', user.id).single();`), 'clean');
});

test('…but the request-parameter version of the SAME query still fires', () => {
  // This is what the documented `tenantSignals: ['user_id']` workaround silenced.
  assert.equal(verdict(`${AUTH}\nawait admin.from('notifications').select('*').eq('user_id', params.userId);`), 'leak');
});

test('per-match: one session-scoped filter does not excuse a request-scoped one', () => {
  const src = `${AUTH}
    const a = await supabase.from('x').select('*').eq('user_id', user.id);
    const b = await admin.from('y').select('*').eq('id', params.id);`;
  assert.equal(verdict(src), 'leak');
});

// ── missed the shape it was written for ──────────────────────────────

test('the tenant column in a PROJECTION is not scoping', () => {
  const src = `${AUTH}\nawait admin.from('invoices').select('id, organization_id, total').eq('id', params.id).single();`;
  assert.notEqual(verdict(src), 'clean', 'this is the guard\'s own canonical IDOR');
});

test('…while a real tenant FILTER still counts, in every shape', () => {
  const shapes = [
    `await supabase.from('invoices').select('*').eq('id', params.id).eq('organization_id', orgId);`,
    `await supabase.from('invoices').select('*').eq('id', params.id).in('organization_id', orgs);`,
    `await supabase.from('invoices').select('*').eq('id', params.id).or('organization_id.eq.' + orgId);`,
    `await db.select().from(t).where(and(eq(t.id, params.id), eq(t.organizationId, orgId)));`,
    `await prisma.invoice.findFirst({ where: { id: params.id, organization_id: orgId } });`,
  ];
  for (const s of shapes) {
    assert.equal(verdict(`${AUTH}\n${s}`), 'clean', s);
  }
});

test('an unauthenticated route is still not a leak', () => {
  assert.equal(verdict(`await supabase.from('posts').select('*').eq('id', params.id);`), 'clean');
});

test('sessionValueSignals is configurable', () => {
  const src = `${AUTH}\nawait supabase.from('x').select('*').eq('user_id', ctx.viewer.id);`;
  assert.equal(verdict(src), 'leak');
  assert.equal(verdict(src, { sessionValueSignals: ['ctx.viewer.id'] }), 'clean');
});
