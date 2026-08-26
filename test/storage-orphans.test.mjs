/**
 * Objects that outlived the row they belonged to.
 *
 * Reported by a user: a signed URL kept serving for its whole expiry with the
 * record long gone. That is not a policy failure and no policy fixes it — a
 * Supabase signed URL is a bearer capability, a JWT checked against its
 * signature and its clock, never against RLS, with no revocation list. So the
 * URL is not the testable thing. The OBJECT is: every orphan is one a still-valid
 * URL keeps serving, and it is invisible to every other check here because the
 * tenant probes compare one tenant against another and an orphan belongs to
 * nobody.
 *
 * The calibration that decides whether this is usable: the link between a table
 * and storage is established BY EVIDENCE — a column whose values actually match
 * object names — not by matching column names like `storage_path`. And when no
 * link can be proven it reports a skip, because otherwise every object in a
 * project that tracks paths elsewhere would look orphaned.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  linkingColumnsSql,
  columnMatchesObjectsSql,
  orphanObjectsSql,
  classifyOrphans,
  check,
} from '../src/guards/storage-isolation.mjs';

let PGlite;
try {
  ({ PGlite } = await import('@electric-sql/pglite'));
} catch {
  test('storage orphans (pglite not installed — skipped)', { skip: true }, () => {});
}

const q = (db) => (t, v) => db.query(t, Array.isArray(v) && v.length ? v : undefined);

// ── pure ─────────────────────────────────────────────────────────────

test('orphanObjectsSql matches nothing when no link was proven', () => {
  // Never "everything is an orphan" — that is the false-positive direction.
  assert.match(orphanObjectsSql([], 10).text, /where false/);
});

test('orphanObjectsSql quotes identifiers', () => {
  const sql = orphanObjectsSql([{ schema: 'pub"lic', table: 'do"cs', column: 'pa"th' }], 5).text;
  assert.match(sql, /"pub""lic"/);
  assert.match(sql, /"do""cs"/);
  assert.match(sql, /"pa""th"/);
});

test('columnMatchesObjectsSql is bounded', () => {
  assert.match(columnMatchesObjectsSql('public', 'docs', 'path', 500).text, /limit 500/);
});

test('linkingColumnsSql looks only at text-ish columns', () => {
  const { text } = linkingColumnsSql(['public']);
  assert.match(text, /'text', 'varchar', 'bpchar'/);
});

test('the verdict names the signed-URL mechanism, and says why no policy helps', () => {
  const v = classifyOrphans({
    orphans: [{ bucket_id: 'docs', name: 'org_B/x.pdf' }],
    links: [{ schema: 'public', table: 'documents', column: 'storage_path' }],
    tenantSegments: ['org_B'],
  });
  assert.match(v.message, /STILL SERVES until it expires/);
  assert.match(v.message, /cannot be revoked/);
  assert.match(v.message, /one tenant's data outliving its record/);
  assert.match(v.fix, /storage\.from/);
  assert.match(v.fix, /shorten the signed-URL expiry/);
});

if (PGlite) {
  async function fixture(extra = '') {
    const db = new PGlite();
    await db.exec(`
      create role authenticated nologin;
      create schema storage;
      grant usage on schema storage to authenticated;
      create table storage.buckets (id text primary key, public bool default false);
      create table storage.objects (id serial primary key, bucket_id text, name text, owner text);
      create or replace function storage.foldername(n text) returns text[]
        language sql immutable as $$ select string_to_array(n, '/') $$;
      grant select on storage.objects, storage.buckets to authenticated;
      insert into storage.buckets values ('docs', false);
      ${extra}
    `);
    return { db, query: q(db) };
  }

  const CFG = {
    role: 'authenticated',
    becomeTenant: ["select set_config('app.tenant', $1, true)"],
    probeWrites: false,
  };
  const orphanNote = (res) => (res.notes ?? []).find((n) => n.where === 'storage.objects (orphaned)');

  test('CATCHES an object whose row was deleted', async () => {
    const { query } = await fixture(`
      create table documents (id serial primary key, organization_id text, storage_path text);
      insert into storage.objects (bucket_id, name) values
        ('docs','org_A/contract.pdf'), ('docs','org_B/deleted-record.pdf');
      insert into documents (organization_id, storage_path) values ('org_A','org_A/contract.pdf');
    `);
    const note = orphanNote(await check({ query, config: CFG }));
    assert.ok(note, 'expected an orphan note');
    assert.match(note.message, /1 object\(s\) are referenced by no row/);
    assert.match(note.message, /org_B/);
  });

  test('says nothing when every object has an owning row', async () => {
    const { query } = await fixture(`
      create table documents (id serial primary key, storage_path text);
      insert into storage.objects (bucket_id, name) values ('docs','org_A/a.pdf'), ('docs','org_A/b.pdf');
      insert into documents (storage_path) values ('org_A/a.pdf'), ('org_A/b.pdf');
    `);
    const note = orphanNote(await check({ query, config: CFG }));
    assert.equal(note, undefined, JSON.stringify(note ?? {}, null, 2));
  });

  test('the link is found by VALUE, not by column name', async () => {
    // `attachments.blob_ref` does not look like a path column; `avatars.url`
    // does and matches nothing. Name-matching would get both backwards.
    const { query } = await fixture(`
      create table attachments (id serial primary key, blob_ref text);
      create table avatars (id serial primary key, url text);
      insert into storage.objects (bucket_id, name) values ('docs','org_A/a.pdf'), ('docs','org_A/orphan.pdf');
      insert into attachments (blob_ref) values ('org_A/a.pdf');
      insert into avatars (url) values ('https://cdn.example.com/nothing.png');
    `);
    const note = orphanNote(await check({ query, config: CFG }));
    assert.ok(note);
    assert.match(note.message, /1 object\(s\) are referenced by no row/);
  });

  test('no provable link is a SKIP, not "everything is orphaned"', async () => {
    const { query } = await fixture(`
      create table notes_tbl (id serial primary key, body text);
      insert into storage.objects (bucket_id, name) values ('docs','org_A/a.pdf'), ('docs','org_B/b.pdf');
      insert into notes_tbl (body) values ('unrelated');
    `);
    const note = orphanNote(await check({ query, config: CFG }));
    assert.ok(note, 'must say it could not look, rather than staying silent');
    assert.match(note.message, /could not identify any column/);
    assert.match(note.message, /not a clean result/i);
  });

  test('an empty storage schema produces no orphan note', async () => {
    const { query } = await fixture(`
      create table documents (id serial primary key, storage_path text);
      insert into documents (storage_path) values ('never/uploaded.pdf');
    `);
    const res = await check({ query, config: CFG });
    const note = orphanNote(res);
    // No objects at all: nothing to be orphaned, and the link cannot be proven
    // either — a skip note is the honest outcome, a violation would not be.
    assert.equal(res.violations.filter((v) => /orphan/i.test(v.kind ?? '')).length, 0);
    if (note) assert.match(note.message, /could not identify any column/);
  });

  test('checkOrphans:false turns the pass off entirely', async () => {
    const { query } = await fixture(`
      create table documents (id serial primary key, storage_path text);
      insert into storage.objects (bucket_id, name) values ('docs','org_A/a.pdf'), ('docs','org_B/orphan.pdf');
      insert into documents (storage_path) values ('org_A/a.pdf');
    `);
    const note = orphanNote(await check({ query, config: { ...CFG, checkOrphans: false } }));
    assert.equal(note, undefined);
  });
}
