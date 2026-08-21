/**
 * Two guards that fired on correct code.
 *
 * This is the most damaging thing this tool can do. A guard that fails a build
 * over a configuration that is already right teaches people to loosen their
 * security to silence it — which is how the 0.26.0 outage happened, from the
 * other direction.
 *
 * 1. **The standard Supabase lockdown did not clear
 *    `updatable-view-writethrough`.** `REVOKE INSERT, UPDATE, DELETE ON ALL
 *    TABLES IN SCHEMA public FROM anon` is the one statement most projects use
 *    to close exactly the hole this guard reports, and the parser could not see
 *    it — it looked for an object name followed by TO/FROM.
 *
 * 2. **`identity-trust` fired on the shape its own fix text recommends.** The
 *    `forgeable-guc` fix says "if the argument is genuinely needed, authorize it
 *    first" and shows a membership check. A function written that way was still
 *    reported as a "become any tenant" primitive, so applying the recommended
 *    remediation could not clear the finding. A closed loop.
 *
 * A third candidate — `dynamicSqlInjection` firing on any `%s` in a `format()`
 * string — was checked and REFUTED: it stays silent on `%s` applied to a
 * literal, to a loop variable, and on `%I`/`%L`, and fires only when a function
 * PARAMETER reaches `%s`. Recorded here so nobody 'fixes' it later.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { run as uvwRun, netWriteGrants } from '../src/guards/updatable-view-writethrough.mjs';
import { authorizesBeforeSettingGuc } from '../src/guards/identity-trust.mjs';
import { dynamicSqlInjection } from '../src/guards/definer-rpc.mjs';

function withMigrations(files, fn) {
  const dir = mkdtempSync(join(tmpdir(), 'tg-fp-'));
  try {
    for (const [name, sql] of Object.entries(files)) writeFileSync(join(dir, name), sql);
    return fn(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const INIT = `
  alter default privileges in schema public grant select, insert, update, delete on tables to anon, authenticated;
  create view public_profiles as select id, display_name from profiles;`;

// ── the lockdown ─────────────────────────────────────────────────────

test('with no lockdown at all, it still fires — the finding is real', () => {
  withMigrations({ '001.sql': INIT }, (dir) => {
    assert.equal(uvwRun({ dir }).ok, false);
  });
});

test('REVOKE ... ON ALL TABLES IN SCHEMA clears it', () => {
  withMigrations({
    '001.sql': INIT,
    '002.sql': 'revoke insert, update, delete on all tables in schema public from anon, authenticated;',
  }, (dir) => {
    assert.equal(uvwRun({ dir }).ok, true, 'the standard Supabase lockdown must not be reported as a leak');
  });
});

test('ORDER decides it: a lockdown then a re-GRANT is still a finding', () => {
  withMigrations({
    '001.sql': INIT,
    '002.sql': 'revoke insert, update, delete on all tables in schema public from anon;',
    '003.sql': 'grant update on public_profiles to anon;',
  }, (dir) => {
    assert.equal(uvwRun({ dir }).ok, false, 'the later grant re-opens it');
  });
});

test('…and a re-GRANT then a lockdown is clean', () => {
  withMigrations({
    '001.sql': INIT,
    '002.sql': 'grant update on public_profiles to anon;',
    '003.sql': 'revoke insert, update, delete on all tables in schema public from anon, authenticated;',
  }, (dir) => {
    assert.equal(uvwRun({ dir }).ok, true);
  });
});

test('a lockdown aimed at some OTHER role does not clear it', () => {
  withMigrations({
    '001.sql': INIT,
    '002.sql': 'revoke insert, update, delete on all tables in schema public from some_reporting_role;',
  }, (dir) => {
    assert.equal(uvwRun({ dir }).ok, false);
  });
});

test('netWriteGrants seeds the views, so a schema-wide revoke reaches one with no explicit grant', () => {
  const files = [
    { name: '001.sql', sql: INIT },
    { name: '002.sql', sql: 'revoke insert, update, delete on all tables in schema public from anon;' },
  ];
  const state = netWriteGrants(files, ['anon', 'authenticated'], ['public_profiles']);
  const entry = state.get('public_profiles');
  assert.ok(entry, 'the view must be tracked even with no GRANT naming it');
  assert.ok(entry.revoked.has('update'));
});

// ── the closed loop ──────────────────────────────────────────────────

test('identity-trust accepts the shape its own fix recommends', () => {
  const gated = `begin
    if not exists (select 1 from memberships where organization_id = p_org
                   and user_id = current_setting('request.jwt.claim.sub', true)) then
      raise exception 'not a member'; end if;
    perform set_config('app.tenant', p_org, true);
  end;`;
  assert.equal(authorizesBeforeSettingGuc(gated, 'app.tenant'), true);
});

test('…but not one that sets the GUC first and asks questions later', () => {
  const after = `begin
    perform set_config('app.tenant', p_org, true);
    if not exists (select 1 from memberships where user_id = auth.uid()) then raise exception 'no'; end if;
  end;`;
  assert.equal(authorizesBeforeSettingGuc(after, 'app.tenant'), false, 'the tenant has already been assumed');
});

test('…nor a gate that never consults the verified identity', () => {
  const nullcheck = `begin
    if p_org is null then raise exception 'no org'; end if;
    perform set_config('app.tenant', p_org, true);
  end;`;
  assert.equal(authorizesBeforeSettingGuc(nullcheck, 'app.tenant'), false);
});

test('…nor an ungated one', () => {
  assert.equal(authorizesBeforeSettingGuc(`begin perform set_config('app.tenant', p_org, true); end;`, 'app.tenant'), false);
});

// ── the refuted candidate, recorded so it is not "fixed" later ───────

test('dynamicSqlInjection does NOT fire on safe format() uses (audit claim refuted)', () => {
  assert.equal(dynamicSqlInjection(`execute format('select * from %I where x = %L', tbl, val);`, ['p_input']), null);
  assert.equal(dynamicSqlInjection(`execute format('select %s', 'count(*)');`, ['p_input']), null);
  assert.equal(dynamicSqlInjection(`execute format('select * from t limit %s', 10);`, ['p_input']), null);
});

test('…and does fire when a PARAMETER reaches %s', () => {
  assert.ok(dynamicSqlInjection(`execute format('select * from t where x = %s', p_input);`, ['p_input']));
});
