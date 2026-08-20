/**
 * Job-summary tests. The one that matters most is the last: a summary that
 * quietly omits what it did NOT check is how a green run starts meaning less
 * than the person reading it thinks.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { toMarkdown } from '../src/output/markdown.mjs';

const pass = { id: 'migration-collisions', ok: true, summary: '2 migrations scanned', violations: [], notes: [] };
const fail = {
  id: 'rls-proof',
  ok: false,
  summary: '1 leak',
  violations: [{ where: 'public.invoices', message: 'tenant A read tenant B rows', fix: 'alter table … enable row level security;' }],
  notes: [],
};
const skip = { id: 'rls-drift', ok: true, skipped: true, reason: 'no database configured', violations: [], notes: [] };

test('a clean run says so, with the count that ran', () => {
  const md = toMarkdown([pass], { command: 'run' });
  assert.match(md, /All 1 guard passed/);
  assert.match(md, /## tenant-guard `run`/);
});

test('a failing run leads with the failure, not with the table', () => {
  const md = toMarkdown([pass, fail], { command: 'all' });
  assert.match(md, /1 guard failed/);
  assert.ok(md.indexOf('guard failed') < md.indexOf('| | Guard |'));
});

test('the table shows every guard that ran and omits the ones that did not', () => {
  const md = toMarkdown([pass, fail, skip]);
  assert.match(md, /\| ✅ \| `migration-collisions` \|/);
  assert.match(md, /\| ❌ \| `rls-proof` \|/);
  assert.doesNotMatch(md, /\| .. \| `rls-drift` \|/); // skips get their own section
});

test('each finding carries its fix, fenced so SQL survives', () => {
  const md = toMarkdown([fail]);
  assert.match(md, /\*\*public\.invoices\*\* — tenant A read tenant B rows/);
  assert.match(md, /enable row level security/);
  assert.match(md, /```/);
});

test('notes are collapsed and labelled as non-blocking', () => {
  const withNote = { id: 'x', ok: true, summary: 's', violations: [], notes: [{ where: 'public.audit', message: 'no tenant column' }] };
  const md = toMarkdown([withNote]);
  assert.match(md, /never fail the build/);
  assert.match(md, /<details><summary>1 note/);
});

test('a pipe in a message cannot break the table', () => {
  const nasty = { id: 'a|b', ok: true, summary: 'x | y', violations: [], notes: [] };
  const md = toMarkdown([nasty]);
  assert.match(md, /`a\\\|b`/);
  assert.match(md, /x \\\| y/);
});

test('an empty run is reported as "no guards ran", not as a pass', () => {
  const md = toMarkdown([]);
  assert.match(md, /No guards ran/);
  assert.doesNotMatch(md, /passed/);
});

test('SKIPS are always visible and never collapsed behind a <details>', () => {
  const md = toMarkdown([pass, skip]);
  assert.match(md, /### ⏭️ 1 guard skipped — a skip is not a pass/);
  assert.match(md, /`rls-drift` — no database configured/);
  // The heading must not be inside a collapsed block.
  const skipsAt = md.indexOf('a skip is not a pass');
  const detailsBefore = md.lastIndexOf('<details', skipsAt);
  const closeBefore = md.lastIndexOf('</details>', skipsAt);
  assert.ok(detailsBefore === -1 || closeBefore > detailsBefore, 'the skip list must not be nested in a <details>');
});
