/**
 * Every option a guard documents must actually be settable.
 *
 * Each guard's config resolver is a hand-written allowlist of keys, so a key
 * added to `DEFAULTS` and forgotten in the resolver is silently unconfigurable:
 * the user writes it in `tenant-guard.config.json`, nothing complains, and it
 * has no effect. `identityTrust.authorizationColumns` shipped that way — you
 * could not tell the tool your admin column was called something else.
 *
 * This walks every guard rather than testing one, because the failure is a
 * property of the pattern, not of that guard.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as cfg from '../src/config.mjs';
import * as tg from '../src/index.mjs';

/** [config block name, guard module, resolver] */
const GUARD_CONFIGS = [
  ['rlsProof', tg.rlsProof, cfg.resolveProveConfig],
  ['rlsDrift', tg.rlsDrift, cfg.resolveDriftConfig],
  ['anonWrites', tg.anonWrites, cfg.resolveAnonWritesConfig],
  ['anonReads', tg.anonReads, cfg.resolveAnonReadsConfig],
  ['viewIsolation', tg.viewIsolation, cfg.resolveViewIsolationConfig],
  ['identityTrust', tg.identityTrust, cfg.resolveIdentityTrustConfig],
  ['storageIsolation', tg.storageIsolation, cfg.resolveStorageConfig],
  ['constraintOracles', tg.constraintOracles, cfg.resolveOraclesConfig],
  ['realtimeIsolation', tg.realtimeIsolation, cfg.resolveRealtimeConfig],
  ['definerRpc', tg.definerRpc, cfg.resolveDefinerRpcConfig],
  ['shadowTables', tg.shadowTables, cfg.resolveShadowConfig],
  ['roleCapabilities', tg.roleCapabilities, cfg.resolveCapabilitiesConfig],
  ['schemaTenancy', tg.schemaTenancy, cfg.resolveSchemaTenancyConfig],
  ['poolerBleed', tg.poolerBleed, cfg.resolvePoolerBleedConfig],
  ['defaultPrivileges', tg.defaultPrivileges, cfg.resolveDefaultPrivilegesConfig],
  ['crossTenantFk', tg.crossTenantFk, cfg.resolveCrossTenantFkConfig],
  ['createGrants', tg.createGrants, cfg.resolveCreateGrantsConfig],
  ['mfaEnforcement', tg.mfaEnforcement, cfg.resolveMfaEnforcementConfig],
  ['columnExposure', tg.columnExposure, cfg.resolveColumnExposureConfig],
];

for (const [block, mod, resolve] of GUARD_CONFIGS) {
  test(`${block}: every DEFAULTS key survives the resolver`, () => {
    assert.ok(mod?.DEFAULTS, `${block} has no DEFAULTS`);
    assert.equal(typeof resolve, 'function', `${block} has no resolver`);

    const keys = Object.keys(mod.DEFAULTS);
    const supplied = Object.fromEntries(keys.map((k) => [k, '__configured__']));
    const out = resolve({ [block]: supplied });

    const unreachable = keys.filter((k) => out[k] === undefined);
    assert.deepEqual(
      unreachable, [],
      `these ${block} options cannot be set from tenant-guard.config.json: ${unreachable.join(', ')}`,
    );
  });
}

// The three static guards take their config through one shared resolver rather
// than one each, so they are checked the same way against that.
test('route-org-scoping: every DEFAULTS key survives resolveGuardConfigs', () => {
  const keys = Object.keys(tg.routeOrgScoping.DEFAULTS);
  const supplied = Object.fromEntries(keys.map((k) => [k, '__configured__']));
  const out = cfg.resolveGuardConfigs({ routeOrgScoping: supplied })['route-org-scoping'];
  const unreachable = keys.filter((k) => out[k] === undefined);
  assert.deepEqual(
    unreachable, [],
    `these routeOrgScoping options cannot be set: ${unreachable.join(', ')}`,
  );
});

test('every guard with a DEFAULTS block is covered by one of the checks above', () => {
  // Otherwise a new guard is simply omitted and the point of this file is lost.
  const covered = new Set([
    ...GUARD_CONFIGS.map(([, mod]) => mod?.meta?.id),
    ...tg.GUARDS.map((g) => g.meta.id),   // the static three
  ]);
  const withDefaults = Object.values(tg)
    .filter((m) => m && typeof m === 'object' && m.meta?.id && m.DEFAULTS)
    .map((m) => m.meta.id);
  const missed = withDefaults.filter((id) => !covered.has(id));
  assert.deepEqual(missed, [], `not covered by the reachability check: ${missed.join(', ')}`);
});

test('identityTrust.authorizationColumns specifically — the one that was unreachable', () => {
  const out = cfg.resolveIdentityTrustConfig({
    identityTrust: { authorizationColumns: ['account_type', 'permission_level'] },
  });
  assert.deepEqual(out.authorizationColumns, ['account_type', 'permission_level']);
});
