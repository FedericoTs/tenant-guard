/**
 * Guard: tenant isolation in Supabase Storage.
 *
 * Every other guard here answers "which tenant owns this row?" by reading a
 * tenant COLUMN. Storage doesn't have one. `storage.objects` keys tenancy off the
 * object **path** — `org_A/invoices/q1.pdf` — so the tenant is an *expression*
 * over `name`, and policies are written as
 * `(storage.foldername(name))[1] = auth.uid()::text`. That single difference is
 * why storage was the last thing on the threat model this tool could not reach.
 *
 * Two consequences make it worth its own guard rather than a config knob:
 *
 *   • **The client picks the path.** On upload the caller supplies `name`, so if
 *     the INSERT policy doesn't pin the first segment, a user writes straight into
 *     another tenant's folder — the same tenant-hop as `SET org_id = <other>`,
 *     one layer up. Nothing about a correct *read* policy prevents it.
 *
 *   • **A public bucket has no RLS at all.** `storage.buckets.public = true` serves
 *     `/storage/v1/object/public/<bucket>/<path>` with no auth and no policy
 *     evaluation. "The path is unguessable" is not a tenant boundary; it is
 *     security through obscurity with a CDN in front of it.
 *
 * `storage.objects` itself IS a normal RLS-guarded table, so reads and writes are
 * probed for real, as your app role, inside a rolled-back transaction. The bucket
 * flag is read from the catalog and reported with that caveat stated — the CDN
 * behaviour is in the Storage service, not in Postgres, so it is named as a
 * catalog fact rather than claimed as probed.
 *
 * Skips cleanly when there is no `storage` schema, so non-Supabase projects are
 * never punished for a surface they don't have.
 */
import {
  safeRole,
  buildBecomeTenant,
  isPermissionDenied,
  isRlsCheckViolation,
  applyClaimShortcut,
  DEFAULTS as PROOF_DEFAULTS,
} from './rls-proof.mjs';

export const meta = {
  id: 'storage-isolation',
  title: 'Supabase Storage tenant isolation (object paths, not columns)',
  why: "Storage keys tenancy off the object PATH, not a column, and the client chooses that path on upload — so a read policy can be perfect while any user writes into another tenant's folder. Also flags public buckets holding multi-tenant objects, which are served with no auth and no RLS at all.",
};

export const DEFAULTS = {
  urlEnv: 'TENANT_GUARD_DATABASE_URL',
  role: PROOF_DEFAULTS.role,
  becomeTenant: PROOF_DEFAULTS.becomeTenant,
  claim: null,
  // Which path segment identifies the tenant: `org_A/invoices/q1.pdf` => 1.
  pathSegment: 1,
  buckets: null, // null = every bucket; or ["docs", "invoices"]
  allowlist: [], // bucket ids that are intentionally public/shared (a CDN asset bucket)
  sampleLimit: 3,
  probeWrites: true,
  // Where to look for the columns that track storage object names.
  schemas: ['public'],
  // Objects that outlived their row. See classifyOrphans.
  checkOrphans: true,
  maxLinkCandidates: 200,
  /**
   * The unauthenticated role, probed separately from the tenant role.
   *
   * Suggested by u/akl773 on r/Supabase: "tables get all the attention and the
   * bucket policies stay wide open, so a public bucket or a leaked signed url
   * hands over the other tenant's invoices while every table check still
   * passes." This guard proved tenant-A-against-tenant-B and read the bucket's
   * public flag, but it never asked the simpler question — can a visitor with
   * no session at all list what is in here. Set to null to skip.
   */
  anonRole: 'anon',
};

/**
 * `anon` listed objects in a private bucket.
 *
 * Conclusive and needs no second tenant: the bucket is not public, so nothing
 * about it is supposed to be readable without a session. Storage keys tenancy
 * off the object PATH, and `storage.objects` is an ordinary RLS-protected
 * table — so a policy written `TO public` (or no policy plus a stray grant)
 * hands the whole listing to anyone with the anon key, which ships in every
 * browser bundle.
 */
export function classifyAnonListing({ bucket, anonVisible, tenantFolders = 0, role = 'anon' }) {
  return {
    kind: 'anon-listing',
    where: `storage.objects (bucket "${bucket}")`,
    message:
      `"${role}" — an unauthenticated visitor holding the public key — listed ${anonVisible} object name(s) in the private bucket "${bucket}"` +
      (tenantFolders >= 2 ? `, which holds ${tenantFolders} tenants' folders` : '') +
      `. The bucket is not marked public, so this is a policy on storage.objects granting SELECT to everyone rather than a deliberate CDN bucket.\n` +
      `      **Blocking downloads does not fix this.** Listing is SELECT on storage.objects; downloading goes through the storage API with its own gate, so a bucket can refuse every download and still hand over every filename — reported from a real deployment. ` +
      `And filenames are not metadata here: "acme-invoice-2024-Q3.pdf" names a customer, dates the relationship and implies the volume, and a name is the one input a signed-URL request needs.`,
    fix:
      `Scope the SELECT policy on storage.objects to an authenticated tenant, and make sure it is not granted TO public:\n` +
      `        DROP POLICY <the permissive one> ON storage.objects;\n` +
      `        CREATE POLICY tenant_read ON storage.objects FOR SELECT TO authenticated\n` +
      `          USING (bucket_id = '${bucket}' AND (storage.foldername(name))[1] = <the caller's tenant>);\n` +
      `      Check for a policy with no TO clause — that is TO public, which includes ${role}:\n` +
      `        SELECT polname, polroles::regrole[] FROM pg_policy WHERE polrelid = 'storage.objects'::regclass;`,
  };
}

/**
 * Can this role list the objects in a bucket at all?
 *
 * Deliberately NOT scoped to a tenant folder. Listing is `SELECT` on
 * `storage.objects`; downloading is a separate path through the storage API with
 * its own gate. **A bucket can refuse every download and still hand over every
 * filename** — reported from a real deployment, and the shape this exists to
 * catch.
 *
 * Filenames are not metadata in this context. `acme-invoice-2024-Q3.pdf` names a
 * customer, dates the relationship and implies the volume; a name is also the
 * one input a signed-URL request needs. So the listing is the finding, whether
 * or not the bytes are reachable.
 */
export function bucketListingSql(limit = 50) {
  return {
    text: `select count(*)::int as n from (select 1 from storage.objects where bucket_id = $1 limit ${Number(limit) || 50}) s`,
    values: [],
  };
}

/**
 * Objects that outlived the row they belonged to.
 *
 * Reported by a user: a signed URL kept serving for its whole expiry window with
 * the record long gone. That is not a policy failure and no policy can fix it — a
 * Supabase signed URL is a **bearer capability**, a JWT signed by the storage
 * service carrying the path and an expiry. The storage API checks the signature
 * and the clock; it does not re-evaluate RLS per request, and there is no
 * revocation list. Deleting the row, the policy, or even the user changes
 * nothing about a URL already in someone's hands.
 *
 * So the URL is not the testable thing. The OBJECT is. Every orphaned object is
 * one a still-valid signed URL keeps serving, and it is invisible to every other
 * check in this file because there is no row left to scope it against — the
 * tenant-folder probes compare tenants, and an orphan belongs to nobody.
 *
 * It is also the shape that quietly breaks a deletion promise: "delete my
 * account" removed the record and left the PDFs.
 *
 * **The link is established by evidence, not by column name.** A column is
 * treated as tracking storage paths only when its values actually match object
 * names — measured, not guessed from `storage_path` / `file_url` / `attachment`.
 * On the fixture this was built against it picked `documents.storage_path` and
 * ignored `avatars.url` and `unrelated.note`, which look similar and match
 * nothing.
 *
 * And if NO column can be proven to reference objects, this reports a skip
 * rather than declaring every object orphaned — an app may track paths in a
 * service the database cannot see.
 */
export function linkingColumnsSql(schemas) {
  return {
    text: `
      select n.nspname as schema, c.relname as table, a.attname as column
      from pg_catalog.pg_class c
      join pg_catalog.pg_namespace n on n.oid = c.relnamespace
      join pg_catalog.pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
      join pg_catalog.pg_type t on t.oid = a.atttypid
      where c.relkind in ('r', 'p')
        and n.nspname = any($1)
        and t.typname in ('text', 'varchar', 'bpchar')
      order by 1, 2, 3
    `,
    values: [schemas],
  };
}

/** Does this column actually hold object names? Bounded, so it stays cheap. */
export function columnMatchesObjectsSql(schema, table, column, limit = 500) {
  const q = (x) => `"${String(x).replace(/"/g, '""')}"`;
  return {
    text: `select count(*)::int as n from (
             select 1 from storage.objects o
             where exists (select 1 from ${q(schema)}.${q(table)} x where x.${q(column)} = o.name)
             limit ${Number(limit) || 500}) s`,
    values: [],
  };
}

/** Objects no proven-link column references. */
export function orphanObjectsSql(links, limit = 200) {
  const q = (x) => `"${String(x).replace(/"/g, '""')}"`;
  const preds = links.map(
    (l) => `exists (select 1 from ${q(l.schema)}.${q(l.table)} x where x.${q(l.column)} = o.name)`,
  );
  return {
    text: `select o.bucket_id, o.name from storage.objects o
           ${preds.length ? `where not (${preds.join(' or ')})` : 'where false'}
           order by o.bucket_id, o.name
           limit ${Number(limit) || 200}`,
    values: [],
  };
}

/** The verdict for a set of orphaned objects. */
export function classifyOrphans({ orphans, links, tenantSegments = [], role = 'authenticated' }) {
  const byBucket = new Map();
  for (const o of orphans) byBucket.set(o.bucket_id, (byBucket.get(o.bucket_id) ?? 0) + 1);
  const buckets = [...byBucket.entries()].map(([b, n]) => `${b} (${n})`).join(', ');
  const tenantOwned = tenantSegments.length;

  return {
    where: 'storage.objects (orphaned)',
    message:
      `${orphans.length} object(s) are referenced by no row: ${buckets}. ` +
      (tenantOwned
        ? `${tenantOwned} of them sit under a tenant folder (${tenantSegments.slice(0, 3).join(', ')}${tenantSegments.length > 3 ? ', …' : ''}), so that is one tenant's data outliving its record. `
        : '') +
      `Any signed URL issued for these before the row was deleted STILL SERVES until it expires — a signed URL is a bearer token checked against its signature and clock, not against RLS, and it cannot be revoked. ` +
      `Deleting the row does not reach the object, and no policy you write will. ` +
      `These are also invisible to every other check here: the tenant probes compare one tenant against another, and an orphan belongs to nobody.\n` +
      `      Reported as a note, not a failure — an app may legitimately hold untracked assets, or track paths somewhere this database cannot see. The count is the thing to look at.`,
    fix:
      `Delete the objects when you delete the row, in the same operation — storage is not covered by ON DELETE CASCADE, so nothing does this for you:\n` +
      `        await supabase.storage.from('<bucket>').remove([path]);   // before, or transactionally with, the row delete\n` +
      `      To find them, and confirm this list:\n` +
      `        select o.bucket_id, o.name from storage.objects o\n` +
      `         where not exists (select 1 from ${links[0] ? `${links[0].schema}.${links[0].table} x where x.${links[0].column} = o.name` : '<your tracking table> x where x.<path column> = o.name'});\n` +
      `      And shorten the signed-URL expiry: it is the ONLY bound on how long a leaked or stale URL keeps working. Minutes for a download link, not days.\n` +
      `      If some of these are deliberately untracked (a logo, a seeded asset), narrow storageIsolation.schemas or add their bucket to storageIsolation.allowlist[].`,
  };
}

/** The filename tenant-guard would upload; never committed. */
export const PROBE_OBJECT = '.tenant-guard-probe';

// ── pure helpers (unit-tested, no I/O) ───────────────────────────────

/** Is this a Supabase project at all? */
export function storagePresentSql() {
  return {
    text: `select count(*)::int as n
             from pg_catalog.pg_class c
             join pg_catalog.pg_namespace n on n.oid = c.relnamespace
            where n.nspname = 'storage' and c.relname in ('objects', 'buckets')`,
    values: [],
  };
}

/**
 * The tenant EXPRESSION over an object path. This is the whole reason storage
 * needed its own guard: there is no tenant column to compare, so the tenant is
 * computed from `name`. `split_part` is used rather than Supabase's
 * `storage.foldername()` so the same SQL runs on vanilla Postgres.
 */
export function tenantExpr(pathSegment) {
  const seg = Number(pathSegment);
  if (!Number.isInteger(seg) || seg < 1 || seg > 10) {
    throw new Error(`unsafe path segment: ${JSON.stringify(pathSegment)} (expected an integer 1-10)`);
  }
  return `split_part(name, '/', ${seg})`;
}

/** RLS status of storage.objects. */
export function objectsRlsSql() {
  return {
    text: `select c.relrowsecurity as rls_enabled,
                  (select count(*) from pg_catalog.pg_policy p where p.polrelid = c.oid)::int as policy_count
             from pg_catalog.pg_class c
             join pg_catalog.pg_namespace n on n.oid = c.relnamespace
            where n.nspname = 'storage' and c.relname = 'objects'`,
    values: [],
  };
}

/** Buckets, with the public flag and how many distinct tenant folders they hold. */
export function bucketsSql(pathSegment) {
  const expr = tenantExpr(pathSegment);
  return {
    text: `select b.id,
                  b.public as is_public,
                  (select count(distinct ${expr})::int
                     from storage.objects o
                    where o.bucket_id = b.id and o.name like '%/%') as tenant_folders,
                  (select count(*)::int from storage.objects o where o.bucket_id = b.id) as object_count
             from storage.buckets b
            order by b.id`,
    values: [],
  };
}

/** Distinct tenant folders in a bucket (privileged — sees everything). */
export function distinctFoldersSql(pathSegment, limit) {
  const expr = tenantExpr(pathSegment);
  return {
    text: `select distinct ${expr} as t
             from storage.objects
            where bucket_id = $1 and name like '%/%'
            order by 1
            limit $2`,
    values: null, // caller supplies [bucketId, limit]
    limit,
  };
}

/** How many objects under a given tenant folder the CURRENT session can see. */
export function folderObjectCountSql(pathSegment) {
  const expr = tenantExpr(pathSegment);
  return {
    text: `select count(*)::int as n from storage.objects where bucket_id = $1 and ${expr} = $2`,
  };
}

/** Upload probe: create an object inside `folder` — the path the CLIENT chooses. */
export function uploadProbeSql() {
  return { text: `insert into storage.objects (bucket_id, name) values ($1, $2)` };
}

/**
 * Verdict for one bucket.
 * @returns {{status:'leak'|'isolated'|'insufficient-data'|'no-access', kind?:string, message?:string, fix?:string}}
 */
export function classifyBucket({ bucket, isPublic, tenantFolders, crossVisible, ownVisible = null, uploadedIntoOther, ownUploadWorked, noAccess, role = 'authenticated' }) {
  if (isPublic && tenantFolders >= 2) {
    return {
      status: 'leak',
      kind: 'public-bucket',
      message: `bucket "${bucket}" is PUBLIC and holds objects under ${tenantFolders} different tenant folders. A public bucket is served at /storage/v1/object/public/${bucket}/<path> with NO auth and NO row-level security — policies are not consulted at all — so every tenant's files are readable by anyone who has or guesses the path. (Read from storage.buckets.public; the CDN behaviour itself is in the Storage service, not in Postgres, so this is a catalog fact rather than a probe result.)`,
      fix:
        `Make the bucket private and serve files through signed URLs:\n` +
        `        UPDATE storage.buckets SET public = false WHERE id = '${bucket}';\n` +
        `      then issue short-lived signed URLs (createSignedUrl) for downloads. If this bucket is genuinely public\n` +
        `      (logos, marketing assets), add "${bucket}" to storageIsolation.allowlist[].`,
    };
  }
  if (noAccess) return { status: 'no-access', message: `"${role}" cannot read storage.objects for bucket "${bucket}" at all — nothing exposed through it` };
  if (tenantFolders < 2) return { status: 'insufficient-data', message: `bucket "${bucket}" holds objects under ${tenantFolders} tenant folder(s) — cannot prove cross-tenant isolation until two exist` };
  if (crossVisible > 0) {
    return {
      status: 'leak',
      kind: 'read',
      message: `a session acting as one tenant listed ${crossVisible} object(s) inside ANOTHER tenant's folder in bucket "${bucket}" — the SELECT policy on storage.objects does not pin the tenant path segment, so users can enumerate (and download) each other's files`,
      fix:
        `Scope the read policy by the tenant path segment:\n` +
        `        CREATE POLICY tenant_read ON storage.objects FOR SELECT\n` +
        `          USING (bucket_id = '${bucket}' AND (storage.foldername(name))[1] = <the caller's tenant>);`,
    };
  }
  if (uploadedIntoOther) {
    return {
      status: 'leak',
      kind: 'write',
      message: `a session acting as one tenant UPLOADED an object into ANOTHER tenant's folder in bucket "${bucket}". The client chooses the object path on upload, so unless the INSERT policy pins the tenant segment, any user can write into anyone's folder — overwriting or planting files. Reads being correctly scoped does not prevent this`,
      fix:
        `Pin the path on WRITE as well as read — INSERT is governed only by WITH CHECK:\n` +
        `        CREATE POLICY tenant_write ON storage.objects FOR INSERT\n` +
        `          WITH CHECK (bucket_id = '${bucket}' AND (storage.foldername(name))[1] = <the caller's tenant>);\n` +
        `      Add matching UPDATE/DELETE policies, or a user can move and remove other tenants' objects too.`,
    };
  }
  // The control arm. Seeing zero of ANOTHER tenant's objects proves isolation
  // only if this session could see its OWN — otherwise it saw nothing at all and
  // "proven isolated" is a claim about a probe that never ran. The write path
  // already had this check (`ownUploadWorked`); the read path did not, so a
  // misconfigured becomeTenant/role reported N/N proven. A note, not a
  // violation: it stops the guard claiming proof, without crying wolf.
  if (ownVisible === 0) {
    return {
      status: 'not-proven',
      message:
        `bucket "${bucket}": the impersonated session listed 0 objects in its OWN tenant folder as well as 0 in the other tenant's, so nothing was actually compared — this bucket is NOT proven isolated. ` +
        `Usually the storageIsolation.becomeTenant/role config does not match your storage policies, or the seeded folders hold no objects.`,
    };
  }
  return { status: 'isolated', ownUploadWorked };
}

// ── async orchestration ──────────────────────────────────────────────

const OK = (extra) => ({ id: meta.id, ok: true, violations: [], scanned: 0, notes: [], ...extra });

export async function check({ query, config = {} }) {
  const cfg = applyClaimShortcut({ ...DEFAULTS, ...config }, config);
  const role = safeRole(cfg.role);
  const q = async (text, values) => (await query(text, values)).rows;
  const skip = new Set(cfg.allowlist);
  const seg = cfg.pathSegment;
  tenantExpr(seg); // validate early, before any I/O

  const present = (await q(storagePresentSql().text, []))[0];
  if (!present || present.n < 2) {
    return OK({ skipped: true, reason: 'no Supabase storage schema (storage.objects / storage.buckets)', summary: 'skipped — no storage schema' });
  }

  const violations = [];
  const notes = [];
  let scanned = 0;
  let proven = 0;

  const rlsRow = (await q(objectsRlsSql().text, []))[0];
  const rlsEnabled = rlsRow && (rlsRow.rls_enabled === true || rlsRow.rls_enabled === 't');
  if (!rlsEnabled) {
    violations.push({
      where: 'storage.objects',
      kind: 'read',
      message: `ROW LEVEL SECURITY is not enabled on storage.objects — every object in every bucket is readable and writable by any role holding a grant, with no policy evaluated at all`,
      fix: `ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;\n      then add per-bucket policies pinning the tenant path segment for SELECT, INSERT, UPDATE and DELETE.`,
    });
  }

  const bs = bucketsSql(seg);
  let buckets = await q(bs.text, []);
  if (Array.isArray(cfg.buckets)) buckets = buckets.filter((b) => cfg.buckets.includes(b.id));
  buckets = buckets.filter((b) => !skip.has(b.id));
  if (buckets.length === 0) {
    return OK({ skipped: true, reason: 'no storage buckets to check', summary: 'skipped — no buckets', violations, notes });
  }

  await query('begin', []);
  try {
    // Negative control: the app role must actually be subject to RLS.
    let canaryReady = false;
    try {
      await query('create temp table tg_storage_canary (x int)', []);
      await query('insert into tg_storage_canary values (1)', []);
      await query('alter table tg_storage_canary enable row level security', []);
      await query('alter table tg_storage_canary force row level security', []);
      await query(`grant select on tg_storage_canary to ${role}`, []);
      canaryReady = true;
    } catch (err) {
      notes.push({ where: '(self-check)', message: `could not set up the RLS self-check canary (${err.message})` });
    }

    for (const b of buckets) {
      scanned++;
      const isPublic = b.is_public === true || b.is_public === 't';
      const tenantFolders = Number(b.tenant_folders || 0);

      // FIRST, before any early return: can a visitor with no session list this
      // bucket at all?
      //
      // This used to sit after the tenant-folder checks, so it never ran on a
      // bucket with fewer than two tenant folders — which is precisely the shape
      // that leaks worst. Measured: a FLAT bucket holding
      // "acme-invoice-2024.pdf" and "globex-invoice-2024.pdf", with SELECT on
      // storage.objects granted to public, produced ZERO findings. The filenames
      // there ARE the customer list. Same for a single-tenant bucket.
      //
      // It needs no second tenant and no folder convention: the bucket is not
      // public, so nothing in it should be listable without a session. Skipped
      // for a bucket that IS public, where listing is the stated intent and the
      // separate public-bucket verdict below covers it.
      if (cfg.anonRole && !isPublic) {
        await query('savepoint tg_anon', []);
        try {
          await query(`set local role ${safeRole(cfg.anonRole)}`, []);
          const l = bucketListingSql(cfg.sampleLimit ? Math.max(cfg.sampleLimit, 50) : 50);
          const anonVisible = (await q(l.text, [b.id]))[0].n;
          if (anonVisible > 0) {
            const v = classifyAnonListing({ bucket: b.id, anonVisible, tenantFolders, role: cfg.anonRole });
            violations.push({ where: v.where, kind: v.kind, message: v.message, fix: v.fix });
          }
        } catch { /* denied, which is the answer we wanted */ }
        finally {
          try { await query('rollback to savepoint tg_anon', []); await query('release savepoint tg_anon', []); }
          catch { /* the outer rollback still discards everything */ }
        }
      }

      // A public bucket is settled from the catalog — no probe can observe the
      // CDN, and none is needed: RLS is not consulted for public reads.
      if (isPublic && tenantFolders >= 2) {
        const v = classifyBucket({ bucket: b.id, isPublic, tenantFolders, role });
        violations.push({ where: `storage.buckets.${b.id}`, kind: v.kind, message: v.message, fix: v.fix });
        continue;
      }

      if (tenantFolders < 2) {
        notes.push({ where: `storage.objects (bucket "${b.id}")`, message: classifyBucket({ bucket: b.id, isPublic, tenantFolders, role }).message });
        continue;
      }

      const df = distinctFoldersSql(seg, cfg.sampleLimit);
      const folders = (await q(df.text, [b.id, cfg.sampleLimit])).map((r) => r.t);
      if (folders.length < 2) {
        notes.push({ where: `storage.objects (bucket "${b.id}")`, message: `could not sample two tenant folders in bucket "${b.id}"` });
        continue;
      }
      const [folderA, folderB] = folders;

      await query(`set local role ${role}`, []);
      if (canaryReady) {
        let seen = null;
        try { seen = (await q('select count(*)::int as n from tg_storage_canary', []))[0].n; } catch { /* denied => enforced */ }
        if (seen !== null && seen > 0) {
          await query('reset role', []);
          try { await query('rollback', []); } catch { /* ignore */ }
          return {
            id: meta.id, ok: false, notes, scanned,
            violations: [{ where: `role "${role}"`, message: `identity self-check FAILED — "${role}" read a deny-all RLS table, so RLS is NOT enforced for it. Every "isolated" result would be a vacuous pass.`, fix: `Set the role to your non-superuser app role (e.g. "authenticated").` }],
            summary: 'identity switch is not enforcing RLS — refusing to report a vacuous pass',
          };
        }
      }

      let noAccess = false;
      let crossVisible = 0;
      let ownVisible = null;
      let uploadedIntoOther = false;
      let ownUploadWorked = false;
      let probeError = null;
      try {
        // Become tenant A, then look inside tenant B's folder.
        for (const s of buildBecomeTenant(cfg.becomeTenant, folderA)) await query(s.text, s.values);
        const cnt = folderObjectCountSql(seg);
        crossVisible = (await q(cnt.text, [b.id, folderB]))[0].n;
        // …and inside its OWN, which is what makes a zero above mean anything.
        ownVisible = (await q(cnt.text, [b.id, folderA]))[0].n;

        // Reverse direction.
        for (const s of buildBecomeTenant(cfg.becomeTenant, folderB)) await query(s.text, s.values);
        crossVisible = Math.max(crossVisible, (await q(cnt.text, [b.id, folderA]))[0].n);

        if (cfg.probeWrites !== false) {
          // The upload path-hop. Control arm first: if this session cannot even
          // upload into its OWN folder, a failure on the other folder proves
          // nothing about tenant scoping — so we don't claim it does.
          const up = uploadProbeSql();
          ownUploadWorked = await probeUpload(query, up.text, [b.id, `${folderB}/${PROBE_OBJECT}`]);
          if (ownUploadWorked) {
            uploadedIntoOther = await probeUpload(query, up.text, [b.id, `${folderA}/${PROBE_OBJECT}`]);
          }
        }
      } catch (err) {
        if (isPermissionDenied(err)) noAccess = true;
        else probeError = err.message;
      }
      await query('reset role', []);

      if (probeError) {
        notes.push({ where: `storage.objects (bucket "${b.id}")`, message: `could not probe — check role/becomeTenant: ${probeError}` });
        continue;
      }

      const verdict = classifyBucket({ bucket: b.id, isPublic, tenantFolders, crossVisible, ownVisible, uploadedIntoOther, ownUploadWorked, noAccess, role });
      if (verdict.status === 'leak') {
        violations.push({ where: `storage.objects (bucket "${b.id}")`, kind: verdict.kind, message: verdict.message, fix: verdict.fix, crossVisible });
      } else if (verdict.status === 'isolated') {
        proven++;
        if (cfg.probeWrites !== false && !ownUploadWorked) {
          notes.push({ where: `storage.objects (bucket "${b.id}")`, message: `reads are proven isolated, but the upload probe was inconclusive — this session could not create an object even in its own folder, so the write path was not exercised. Grant the app role INSERT on storage.objects in a test database to prove it.` });
        }
      } else {
        notes.push({ where: `storage.objects (bucket "${b.id}")`, message: verdict.message });
      }
    }
  } finally {
    try { await query('rollback', []); } catch { /* ignore */ }
  }

  // ── objects that outlived their row ────────────────────────────────
  // Runs outside the impersonation transaction: this is a question about what
  // EXISTS, not about what a role can reach, so it is asked privileged.
  if (cfg.checkOrphans !== false) {
    try {
      const lc = linkingColumnsSql(cfg.schemas ?? ['public']);
      const candidates = (await q(lc.text, lc.values)).slice(0, cfg.maxLinkCandidates ?? 200);

      const links = [];
      for (const c of candidates) {
        const m = columnMatchesObjectsSql(c.schema, c.table, c.column, cfg.sampleLimit ? Math.max(cfg.sampleLimit, 500) : 500);
        try {
          if ((await q(m.text, m.values))[0].n > 0) links.push(c);
        } catch { /* a column we cannot compare tells us nothing */ }
      }

      if (links.length === 0) {
        // A skip, not a pass. With no proven link every object would look
        // orphaned, and an app may track paths somewhere this database cannot
        // see.
        notes.push({
          where: 'storage.objects (orphaned)',
          message:
            `could not identify any column that tracks storage object names, so objects with no owning row were NOT looked for. ` +
            `This is not a clean result — it means the link between your tables and storage could not be established here. ` +
            `A signed URL outlives the row it belonged to (it is a bearer token checked against its signature and clock, never against RLS, and it cannot be revoked), so an object left behind by a delete keeps being served for the whole expiry window.`,
        });
      } else {
        const oq = orphanObjectsSql(links, 200);
        const orphans = await q(oq.text, oq.values);
        if (orphans.length > 0) {
          const seg = Number(cfg.pathSegment ?? 1);
          // Which tenant folders the orphans sit under, if the bucket uses
          // that convention. A path with no separator has no tenant segment.
          const tenantSegments = [...new Set(
            orphans
              .map((o) => String(o.name ?? ''))
              .filter((name) => name.includes('/'))
              .map((name) => name.split('/')[seg - 1])
              .filter(Boolean),
          )].slice(0, 6);
          const v = classifyOrphans({ orphans, links, tenantSegments, role });
          notes.push({ where: v.where, message: v.message, fix: v.fix });
        }
      }
    } catch (err) {
      notes.push({ where: 'storage.objects (orphaned)', message: `could not check for orphaned objects (${String(err.message).slice(0, 90)}) — NOT examined.` });
    }
  }

  return {
    id: meta.id,
    ok: violations.length === 0,
    violations,
    notes,
    scanned,
    summary:
      violations.length > 0
        ? `${violations.length} storage isolation issue(s) across ${scanned} bucket(s)`
        : `${proven}/${scanned} storage bucket(s) proven isolated`,
  };
}

/** One upload attempt in a rolled-back savepoint. True = the object was created. */
async function probeUpload(query, text, values) {
  await query('savepoint tg_up', []);
  try {
    const res = await query(text, values);
    const affected = res.rowCount ?? res.affectedRows ?? 0;
    await query('rollback to savepoint tg_up', []);
    await query('release savepoint tg_up', []);
    return affected > 0;
  } catch (err) {
    try { await query('rollback to savepoint tg_up', []); await query('release savepoint tg_up', []); } catch { /* ignore */ }
    // An RLS/permission rejection is a real "no"; anything else (NOT NULL, FK)
    // means we couldn't build a valid row, which is also a "no" for our purposes
    // — the control arm is what distinguishes the two.
    if (isRlsCheckViolation(err) || isPermissionDenied(err)) return false;
    return false;
  }
}

/** CLI/programmatic entry: resolve a connection, import `pg`, run the check. */
export async function run(config = {}) {
  const cfg = { ...DEFAULTS, ...config };
  const url = cfg.url || process.env[cfg.urlEnv] || process.env.DATABASE_URL;
  if (!url) return OK({ skipped: true, reason: `no database configured — set ${cfg.urlEnv} (or DATABASE_URL)`, summary: 'skipped — no database' });
  let pg;
  try {
    pg = await import('pg');
  } catch {
    return OK({ skipped: true, reason: 'Postgres driver not installed — run `npm i -D pg`', summary: 'skipped — pg not installed' });
  }
  const Client = pg.default?.Client ?? pg.Client;
  const client = new Client({ connectionString: url });
  await client.connect();
  try {
    return await check({ query: (text, values) => client.query(text, values), config: cfg });
  } finally {
    await client.end();
  }
}
