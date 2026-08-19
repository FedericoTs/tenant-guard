const fs = require('fs');
const edit = (f, pairs) => {
  let s = fs.readFileSync(f, 'utf8');
  for (const [a, b] of pairs) {
    if (!s.includes(a)) { console.error('NO MATCH ' + f + ': ' + a.slice(0, 70)); process.exit(1); }
    s = s.replace(a, b);
  }
  fs.writeFileSync(f, s); console.log('patched ' + f);
};

edit('README.md', [
  ['npx tenant-guard identity     # exit 1 if the identity your policies trust is forgeable',
   'npx tenant-guard identity     # exit 1 if the identity your policies trust is forgeable\nnpx tenant-guard storage      # exit 1 if Supabase Storage leaks across tenant folders'],
  ['| `view-isolation` *(runtime)* |',
   '| `storage-isolation` *(runtime)* | Supabase **Storage** leaks across tenant folders | storage has no tenant *column* — tenancy lives in the object **path**, so the tenant is an expression over `name`. Two things follow that a column-based check cannot see: the **client picks the path on upload**, so a perfect read policy still lets a user write into another tenant\'s folder; and a **public bucket** is served with no auth and no RLS at all, making "the path is unguessable" the whole boundary |\n| `view-isolation` *(runtime)* |'],
]);

edit('THREAT-MODEL.md', [
  ["| 5.1 | `storage.objects` — tenancy lives in the **object path** or `owner`, not a column | \u{1F51C} | the metadata table *is* RLS-guarded and probeable; needs tenant-**expression** support (path segment), not just a tenant column. Named as an honest limit in the README today |",
   "| 5.1 | `storage.objects` — tenancy lives in the **object path** or `owner`, not a column | \u2705 | `storage-isolation`. Tenant-**expression** support (`split_part(name,'/',N)` \u2014 deliberately not Supabase's `storage.foldername()`, so the probe runs on vanilla Postgres too). Probes cross-tenant reads AND the **upload path-hop**: the client picks `name` on upload, so an unpinned INSERT policy lets a user write into another tenant's folder. The upload probe has a control arm \u2014 it first uploads into its OWN folder, so a refusal elsewhere is not miscredited to tenant scoping |"],
  ["| 5.2 | **Public bucket** (`storage.buckets.public = true`) \u2014 objects served over the CDN with no auth, no RLS |",
   "| 5.2 | **Public bucket** (`storage.buckets.public = true`) \u2014 objects served over the CDN with no auth, no RLS |"],
]);
