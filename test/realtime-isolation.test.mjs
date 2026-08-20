/**
 * realtime-isolation pure-logic tests. The topic expression is what makes
 * Realtime checkable at all (the tenant is in the topic, not a column), so it
 * carries the most weight here.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  topicTenantExpr,
  realtimePresentSql,
  messagesRlsSql,
  distinctTopicTenantsSql,
  topicMessageCountSql,
  broadcastProbeSql,
  publicationTablesSql,
  classifyRealtime,
} from '../src/guards/realtime-isolation.mjs';

test('topicTenantExpr: one expression covers BOTH topic conventions, and rejects unsafe separators', () => {
  assert.equal(topicTenantExpr(':'), "split_part(topic, ':', 1)");
  assert.equal(topicTenantExpr('/'), "split_part(topic, '/', 1)");
  // With no separator present split_part returns the whole topic, so a bare
  // `org_A` topic and a prefixed `org_A:notifications` both resolve correctly.
  assert.throws(() => topicTenantExpr("'"));   // would break out of the literal
  assert.throws(() => topicTenantExpr(String.fromCharCode(92))); // a backslash
  assert.throws(() => topicTenantExpr('::'));  // must be a single character
  assert.throws(() => topicTenantExpr(null));
});

test('realtimePresentSql / messagesRlsSql: detect the surface and read its RLS state', () => {
  assert.match(realtimePresentSql().text, /nspname = 'realtime'/);
  const r = messagesRlsSql();
  assert.match(r.text, /relrowsecurity/);
  assert.match(r.text, /pg_policy/);
});

test('distinctTopicTenantsSql / topicMessageCountSql: derive the tenant from the topic', () => {
  assert.match(distinctTopicTenantsSql(':', 3).text, /split_part\(topic, ':', 1\)/);
  assert.match(distinctTopicTenantsSql(':', 3).text, /topic is not null/);
  assert.match(topicMessageCountSql(':').text, /split_part\(topic, ':', 1\) = \$1/);
});

test('broadcastProbeSql: publishes on a client-chosen topic — the thing the caller controls', () => {
  assert.match(broadcastProbeSql().text, /insert into realtime\.messages \(topic, extension, event\)/);
});

test('publicationTablesSql: only supabase_realtime, only tenant-column tables', () => {
  const p = publicationTablesSql(['organization_id']);
  assert.match(p.text, /pubname = 'supabase_realtime'/);
  assert.match(p.text, /attname = any\(\$1\)/);
  assert.deepEqual(p.values, [['organization_id']]);
});

test('classify: RLS off on realtime.messages -> leak naming both read AND publish', () => {
  const v = classifyRealtime({ rlsEnabled: false });
  assert.equal(v.status, 'leak');
  assert.match(v.message, /ROW LEVEL SECURITY is not enabled/);
  assert.match(v.message, /publish into it/);
});

test('classify: RLS on with zero policies -> no-policy note, not a leak', () => {
  const v = classifyRealtime({ rlsEnabled: true, policyCount: 0 });
  assert.equal(v.status, 'no-policy');
  assert.match(v.message, /switched off rather than secured/);
});

test('classify: cross-tenant channel read -> read leak', () => {
  const v = classifyRealtime({ rlsEnabled: true, policyCount: 1, tenantCount: 2, crossVisible: 3 });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'read');
});

test('classify: publishing into another channel -> WRITE leak even with reads clean', () => {
  const v = classifyRealtime({ rlsEnabled: true, policyCount: 2, tenantCount: 2, crossVisible: 0, broadcastIntoOther: true, ownBroadcastWorked: true });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'write');
});

test('classify: both directions scoped -> isolated', () => {
  const v = classifyRealtime({ rlsEnabled: true, policyCount: 2, tenantCount: 2, crossVisible: 0, broadcastIntoOther: false, ownBroadcastWorked: true });
  assert.equal(v.status, 'isolated');
});

test('classify: fewer than two tenants, or no access -> never a pass claim', () => {
  assert.equal(classifyRealtime({ rlsEnabled: true, policyCount: 1, tenantCount: 1 }).status, 'insufficient-data');
  assert.equal(classifyRealtime({ rlsEnabled: true, policyCount: 1, tenantCount: 2, noAccess: true }).status, 'no-access');
});
