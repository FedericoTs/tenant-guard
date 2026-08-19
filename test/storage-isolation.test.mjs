/**
 * storage-isolation pure-logic tests. The tenant EXPRESSION is the piece that
 * makes storage checkable at all, so it gets the most attention here.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  tenantExpr,
  storagePresentSql,
  objectsRlsSql,
  bucketsSql,
  distinctFoldersSql,
  folderObjectCountSql,
  uploadProbeSql,
  classifyBucket,
  PROBE_OBJECT,
} from '../src/guards/storage-isolation.mjs';

test('tenantExpr: builds a path-segment expression, and refuses anything unsafe', () => {
  assert.equal(tenantExpr(1), `split_part(name, '/', 1)`);
  assert.equal(tenantExpr(2), `split_part(name, '/', 2)`);
  // The segment is interpolated, so it must be a bounded integer — never a string.
  assert.throws(() => tenantExpr('1); drop table storage.objects --'));
  assert.throws(() => tenantExpr(0));
  assert.throws(() => tenantExpr(1.5));
  assert.throws(() => tenantExpr(99));
  assert.throws(() => tenantExpr(null));
});

test('storagePresentSql: detects a Supabase project by the storage tables', () => {
  const { text } = storagePresentSql();
  assert.match(text, /nspname = 'storage'/);
  assert.match(text, /'objects', 'buckets'/);
});

test('objectsRlsSql: reads RLS status AND policy count for storage.objects', () => {
  const { text } = objectsRlsSql();
  assert.match(text, /relrowsecurity/);
  assert.match(text, /pg_policy/);
});

test('bucketsSql: counts DISTINCT tenant folders per bucket, ignoring root-level objects', () => {
  const { text } = bucketsSql(1);
  assert.match(text, /b\.public/);
  assert.match(text, /count\(distinct split_part\(name, '\/', 1\)\)/);
  // An object with no folder (`logo.svg`) must not be mistaken for a tenant.
  assert.match(text, /name like '%\/%'/);
});

test('distinctFoldersSql / folderObjectCountSql: parameterised, scoped to one bucket', () => {
  assert.match(distinctFoldersSql(1, 3).text, /where bucket_id = \$1 and name like '%\/%'/);
  const c = folderObjectCountSql(1);
  assert.match(c.text, /bucket_id = \$1/);
  assert.match(c.text, /split_part\(name, '\/', 1\) = \$2/);
});

test('uploadProbeSql: inserts a client-chosen path — the thing the caller controls', () => {
  assert.match(uploadProbeSql().text, /insert into storage\.objects \(bucket_id, name\) values \(\$1, \$2\)/);
  assert.match(PROBE_OBJECT, /tenant-guard/); // recognisable if it ever surfaces
});

test('classify: a PUBLIC bucket with 2+ tenant folders -> leak, stated as a catalog fact', () => {
  const v = classifyBucket({ bucket: 'files', isPublic: true, tenantFolders: 2 });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'public-bucket');
  assert.match(v.message, /NO auth and NO row-level security/);
  assert.match(v.message, /catalog fact rather than a probe result/);
});

test('classify: a public bucket with only ONE tenant folder is not a cross-tenant finding', () => {
  const v = classifyBucket({ bucket: 'assets', isPublic: true, tenantFolders: 1 });
  assert.notEqual(v.status, 'leak');
});

test('classify: cross-tenant read -> leak', () => {
  const v = classifyBucket({ bucket: 'docs', isPublic: false, tenantFolders: 2, crossVisible: 2 });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'read');
});

test('classify: upload into another folder -> WRITE leak, even with reads clean', () => {
  const v = classifyBucket({ bucket: 'docs', isPublic: false, tenantFolders: 2, crossVisible: 0, uploadedIntoOther: true, ownUploadWorked: true });
  assert.equal(v.status, 'leak');
  assert.equal(v.kind, 'write');
  assert.match(v.message, /client chooses the object path on upload/);
});

test('classify: reads and writes both scoped -> isolated', () => {
  const v = classifyBucket({ bucket: 'docs', isPublic: false, tenantFolders: 2, crossVisible: 0, uploadedIntoOther: false, ownUploadWorked: true });
  assert.equal(v.status, 'isolated');
});

test('classify: fewer than two tenant folders -> insufficient-data (never a pass)', () => {
  const v = classifyBucket({ bucket: 'docs', isPublic: false, tenantFolders: 1 });
  assert.equal(v.status, 'insufficient-data');
});

test('classify: no read access at all -> no-access, not a leak', () => {
  const v = classifyBucket({ bucket: 'docs', isPublic: false, tenantFolders: 2, noAccess: true });
  assert.equal(v.status, 'no-access');
});
