/**
 * rls-drift pure-logic tests. The migration parser and the diff are I/O-free;
 * the live-catalog comparison is proven end-to-end in the integration test.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  stripQuotes,
  normalizeTable,
  parseDeclaredState,
  actualPoliciesSql,
  actualRlsSql,
  diffState,
} from '../src/guards/rls-drift.mjs';

// ── identifier normalisation ─────────────────────────────────────────
test('normalizeTable: defaults schema to public, strips quotes, keeps schema when given', () => {
  assert.equal(normalizeTable('invoices'), 'public.invoices');
  assert.equal(normalizeTable('"invoices"'), 'public.invoices');
  assert.equal(normalizeTable('billing.invoices'), 'billing.invoices');
  assert.equal(normalizeTable('"public"."My Table"'), 'public.My Table');
  assert.equal(stripQuotes('"x"'), 'x');
});

// ── parseDeclaredState ───────────────────────────────────────────────
test('parse: CREATE POLICY + ENABLE RLS are captured', () => {
  const s = parseDeclaredState([
    { name: '001.sql', sql: `alter table invoices enable row level security;\ncreate policy tenant_iso on invoices using (org = current_setting('x'));` },
  ]);
  assert.ok(s.rlsEnabled.has('public.invoices'));
  assert.ok(s.policies.has('public.invoices::tenant_iso'));
});

test('parse: DROP POLICY / DISABLE RLS net out to absent (in order, across files)', () => {
  const s = parseDeclaredState([
    { name: '001_add.sql', sql: `create policy p on t;\nalter table t enable row level security;` },
    { name: '009_remove.sql', sql: `drop policy p on t;\nalter table t disable row level security;` },
  ]);
  assert.equal(s.policies.has('public.t::p'), false);
  assert.equal(s.rlsEnabled.has('public.t'), false);
});

test('parse: create-then-drop-then-recreate within the sequence => present', () => {
  const s = parseDeclaredState([
    { name: '001.sql', sql: `create policy p on t;` },
    { name: '002.sql', sql: `drop policy p on t;` },
    { name: '003.sql', sql: `create policy p on t;` },
  ]);
  assert.ok(s.policies.has('public.t::p'));
});

test('parse: handles IF (NOT) EXISTS, quoting, and schema qualification', () => {
  const s = parseDeclaredState([
    { name: '001.sql', sql: `create policy if not exists "Read" on billing."Ledger" using (true);\nalter table if exists billing."Ledger" enable row level security;` },
  ]);
  assert.ok(s.policies.has('billing.Ledger::Read'));
  assert.ok(s.rlsEnabled.has('billing.Ledger'));
});

test('parse: files are ordered by name, not array order (later drop wins)', () => {
  const s = parseDeclaredState([
    { name: '020_drop.sql', sql: `drop policy p on t;` },
    { name: '010_create.sql', sql: `create policy p on t;` },
  ]);
  assert.equal(s.policies.has('public.t::p'), false); // 010 create then 020 drop
});

// ── catalog SQL builders ─────────────────────────────────────────────
test('actualPoliciesSql / actualRlsSql: read-only catalog queries, schemas bound as $1', () => {
  const p = actualPoliciesSql(['public']);
  assert.match(p.text, /pg_policies/);
  assert.match(p.text, /schemaname = any\(\$1\)/);
  assert.deepEqual(p.values, [['public']]);

  const r = actualRlsSql(['public']);
  assert.match(r.text, /relrowsecurity = true/);
  assert.deepEqual(r.values, [['public']]);
});

// ── the diff (the heart) ─────────────────────────────────────────────
const declared = { rlsEnabled: new Set(['public.t']), policies: new Set(['public.t::good']) };

test('diff: a policy in the DB but not in migrations -> undeclared (build-failing)', () => {
  const actual = { rlsEnabled: new Set(['public.t']), policies: new Set(['public.t::good', 'public.t::hand_edited']) };
  const d = diffState(declared, actual);
  assert.deepEqual(d.undeclaredPolicies, ['public.t::hand_edited']);
  assert.deepEqual(d.missingPolicies, []);
});

test('diff: RLS enabled in the DB but not declared -> undeclared', () => {
  const actual = { rlsEnabled: new Set(['public.t', 'public.secrets']), policies: new Set(['public.t::good']) };
  const d = diffState(declared, actual);
  assert.deepEqual(d.undeclaredRls, ['public.secrets']);
});

test('diff: declared but absent in the DB -> missing (a note, not a failure)', () => {
  const actual = { rlsEnabled: new Set([]), policies: new Set([]) };
  const d = diffState(declared, actual);
  assert.deepEqual(d.missingPolicies, ['public.t::good']);
  assert.deepEqual(d.missingRls, ['public.t']);
  assert.deepEqual(d.undeclaredPolicies, []);
});

test('diff: allowlist silences a whole table or a specific policy', () => {
  const actual = { rlsEnabled: new Set(['public.t']), policies: new Set(['public.t::good', 'public.t::supabase_managed', 'public.audit::x']) };
  const byPolicy = diffState(declared, actual, ['public.t::supabase_managed', 'public.audit']);
  assert.deepEqual(byPolicy.undeclaredPolicies, []); // both silenced (one by id, one by table)
});
