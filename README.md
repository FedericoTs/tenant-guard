# tenant-guard

**Guard tests that fail your CI when multi-tenant code can leak across tenants.**

<p align="center">
  <a href="https://github.com/FedericoTs/tenant-guard/actions/workflows/test.yml"><img src="https://github.com/FedericoTs/tenant-guard/actions/workflows/test.yml/badge.svg" alt="CI status"></a>
  <a href="https://www.npmjs.com/package/tenant-guard"><img src="https://img.shields.io/npm/v/tenant-guard.svg" alt="npm version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/npm/l/tenant-guard.svg" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen.svg" alt="zero dependencies">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/FedericoTs/tenant-guard/main/assets/demo.gif" alt="tenant-guard running against a small multi-tenant app whose main table has correct RLS. Five guards fail anyway: an unprotected table readable across tenants and by anon, a materialized view RLS can never scope, a foreign key that lets one tenant delete another tenant's rows, and a CREATE grant that arms the next SECURITY DEFINER function. Each finding comes with the exact fix." width="820">
</p>

<p align="center">
  <sub>Real output, not a mockup — that's <code>npm run demo</code>, which stands up a throwaway
  Postgres and runs the actual guards. The RLS on the main table is <em>correct</em>;
  every leak is somewhere else.</sub>
</p>

Not a scanner you run and then ignore. These are checks that live in your repo,
run in `npm test` and your CI, and **block the merge** — so the cross-tenant
leak never ships. The static guards have **zero dependencies** and run in CI
without `npm ci`; the runtime guards add real Postgres proofs when you opt in.

```bash
npx tenant-guard init     # detects your migrations + API routes, writes a config
npx tenant-guard run      # static guards — exit 1 if anything can leak
npx tenant-guard all      # everything: static guards + every runtime proof
```

Or run one at a time: `prove`, `drift`, `anon-reads`, `anon-writes`, `identity`,
`rpc`, `views`, `storage`, `realtime`, `oracles`, `shadows`, `caps`, `schemas`, `pooler`, `defaults`, `fks`, `creates`.
The view write-through check runs inside `run`, with no database.
`npx tenant-guard list` describes each, and `--help` documents the rest.

Every command also speaks machine: `--json` for anything downstream, `--sarif`
for GitHub code scanning, `--markdown=$GITHUB_STEP_SUMMARY` for the run page.
The exit code is identical in all of them.

---

## The problem

AI code generators — and tired humans — ship the same multi-tenant bugs over
and over:

- an authenticated route loads a row by **bare id** with no tenant filter, so
  any user of tenant A can read tenant B's data by guessing an id;
- a new `SECURITY DEFINER` Postgres function is left **callable by `anon`**
  because Postgres grants EXECUTE to `PUBLIC` by default;
- two migrations collide on a number and apply in the wrong order.

These aren't exotic. Under [CVE-2025-48757](https://nvd.nist.gov/vuln/detail/CVE-2025-48757),
303 endpoints across 170 Lovable projects had Supabase tables readable by
**unauthenticated** requests using the public anon key — the exact class
`tenant-guard anon-reads` proves against. [Wiz found an auth
bypass in Base44](https://www.wiz.io/blog/critical-vulnerability-base44) that
reached into private enterprise apps. [Veracode's 2025 study](https://www.veracode.com/resources/analyst-reports/2025-genai-code-security-report/)
found 45% of LLM-generated code introduces an OWASP Top 10 flaw — and larger,
newer models were **not** safer.

## What it catches (run against a typical vibe-coded app)

```
tenant-guard  â€” guard tests for multi-tenant isolation

âœ“ migration-collisions â€” 3 migrations scanned; 0 grandfathered duplicate(s) ignored
âœ— definer-grants â€” 1 unsafe function(s)
    â€¢ 200_add_reset_helper.sql
      function "reset_workspace" is SECURITY DEFINER + mutates but EXECUTE is not revoked from PUBLIC/anon
      â†’ In the SAME migration add:  REVOKE EXECUTE ON FUNCTION public.reset_workspace(<args>) FROM PUBLIC, anon;
            If it is intentionally pre-auth, add "reset_workspace" to definerGrants.allowlist[] in your tenant-guard config.
âœ— route-org-scoping â€” 1 route(s) can leak across tenants
    â€¢ src/app/api/invoices/[id]/route.ts
      authenticated + filters by bare id + never scopes by a tenant column
      â†’ Add the tenant column to every query in this route, e.g. .eq('organization_id', auth.organizationId).
            If this route is genuinely tenant-agnostic, add "src/app/api/invoices/[id]/route.ts" to routeOrgScoping.allowlist[] with a one-line justification.
âœ— updatable-view-writethrough â€” 1 view(s) write through to their base table, bypassing its RLS
    â€¢ 202_public_profiles.sql
      view "public_profiles" is auto-updatable (one relation, no aggregation) and runs as its OWNER â€” security_invoker is not set â€” so INSERT/UPDATE/DELETE pass straight through to "users", with that table's RLS evaluated as the owner rather than the caller. No REVOKE of INSERT/UPDATE/DELETE appears in these migrations, and this looks like a Supabase project (it references anon/authenticated), where default privileges grant writes on every new object in public. Granting only SELECT does not make a view read-only: the write privileges arrive on their own.
      â†’ REVOKE INSERT, UPDATE, DELETE ON public_profiles FROM anon, authenticated;
            A view that exists to expose safe columns should be readable only. If writes ARE intended,
            make them go through checks: CREATE VIEW â€¦ WITH (security_invoker = true), or an INSTEAD OF trigger.
            If this view is deliberately writable, add "public_profiles" to updatableViews.allowlist[] with a reason.

âœ— 3 guard(s) failed  (4 ran, 0 skipped)
  A guard fails your build so the leak never merges. Fix it, or allowlist it with a reason.
```

(That output is real — it's `examples/leaky-demo/`. Reproduce it:
`cd examples/leaky-demo && node ../../bin/tenant-guard.mjs run`.)

## The guards

**Static** — read files on disk, zero dependencies, no database:

| Guard | Fails when… | Why a scanner misses it |
|---|---|---|
| `route-org-scoping` | an authenticated route filters by a bare `id` and never mentions a tenant column | catches the *shape* of the IDOR (auth + bare-id + no-tenant), and it lives in your CI so it blocks the merge instead of adding one more report |
| `definer-grants` | a mutating `SECURITY DEFINER` function's **final** definition isn't revoked from `PUBLIC`/`anon` | requires knowing Postgres default grants + PostgREST exposure interact — *revoking from `anon` alone is a no-op*; judged on the net state of history, so a fix in a later repair migration counts |
| `updatable-view-writethrough` | a view built to expose SAFE columns is also **writable through** to its base table | three ordinary defaults collide and nobody writes any of them down: a view over one relation with no aggregation is **auto-updatable**, so Postgres passes `INSERT`/`UPDATE`/`DELETE` to the base table; `security_invoker` is off by default, so those writes run as the view's **owner** and the base table's RLS never applies to the caller; and Supabase's default privileges grant `anon`/`authenticated` writes on every new object, so `GRANT SELECT` does not make it read-only. Reported from production, where `DELETE /rest/v1/public_profiles` with the public anon key wiped the users table. `view-isolation` cannot see it — that proves READ isolation, and this is a write |
| `migration-collisions` | two migrations share a numeric prefix | a project-specific CI invariant (your numbering scheme), not a code smell |

**Runtime — the core proof**, against a seeded test database:

| Guard | Fails when… | Why a scanner misses it |
|---|---|---|
| `rls-proof` | a tenant's session can actually read **or write** another tenant's rows | it isn't reading source at all — it runs real queries as your app role (SELECT, plus `UPDATE`/`DELETE`/tenant-hop/`INSERT`/omitted-tenant probes) and measures the leak; nothing static can prove isolation *holds*, and RLS is per-command so reads passing says nothing about writes |
| `rls-drift` | the database has RLS enabled or a policy that **no migration declares** | catches security posture applied by hand in the dashboard/psql — invisible to code review, absent from CI, changeable with no diff or history |

**Runtime — who can reach your data:**

| Guard | Fails when… | Why a scanner misses it |
|---|---|---|
| `anon-reads` | the **anonymous** role can SELECT a **tenant** table, view, or materialized view | the CVE-2025-48757 class — the public anon key reads every tenant's data with no login; scoped to objects with a tenant column so public content isn't flagged, and it *probes* as `anon` so it evaluates the real policy, not just the grant |
| `anon-writes` | the **anonymous** role can INSERT/UPDATE/DELETE a table | a table with no tenant column, writable by `anon`, is neither a tenant leak nor drift — it's the cache-poisoning class; it proves the real `USING`/`WITH CHECK` by probing, so it doesn't false-flag `TO public USING (auth.uid()…)` policies |
| `definer-rpc` | a `SECURITY DEFINER` **RPC** hands out another tenant's rows, **or lets a caller inject SQL that runs as its owner** | the purest form of "the policy exists but the access path around it doesn't": a definer function runs as its **owner**, so it bypasses RLS on everything it touches, and PostgREST exposes it at `/rest/v1/rpc/<name>`. A function that doesn't re-filter by tenant — or that trusts a tenant id the **caller passes in** — routes around flawless policies, and every table-level check still reports green. It also reads the body for **SQL injection** (a parameter concatenated into `EXECUTE`, or passed through `format()`'s `%s`) — injected SQL runs as the *owner*, so it bypasses RLS wholesale — and for an unpinned `search_path`. Only `STABLE`/`IMMUTABLE` functions are ever *called*: Postgres guarantees those cannot write |
| `identity-trust` | the caller can **forge the identity** your policies authorize from, or **write the thing that grants it** | every other guard asks "given a correct identity, is the data scoped?" — this asks whether the identity itself is controllable. A policy reading `user_metadata` (which the *user* can rewrite) is defeated by forging that claim; a callable `SECURITY DEFINER` that sets your tenant GUC from an argument is a "become any tenant" primitive; a `memberships` table the caller can write makes a *flawless* policy bypassable; and — the one most apps have — **a user can make themselves an admin**: because **RLS is row-level and cannot restrict columns**, the textbook-correct `USING (id = auth.uid()) WITH CHECK (id = auth.uid())` self-update policy pins *which rows* you may touch and says nothing about *which columns*, so `update profiles set is_admin = true where id = me` succeeds. Checked on every table with an update policy — including when the flag is read by a policy on that same table, or by nothing in the database at all because your application checks it. A column-level `GRANT` is the only real fix, and the guard recognises one as such |
| `pooler-bleed` | the tenant identity **outlives the request that set it** | the only guard that has to read the database *and* your source, which is why this one goes unnoticed: the catalog says which custom GUC your policies authorize from, the source says whether you set it with `is_local = false` or a bare `SET` — which lasts for the whole **connection**. On a pooled connection the next request inherits the previous tenant and the policy hands over their rows **working exactly as designed**. Run one request and isolation is perfect, which is why every other check here passes: the leak exists only *between* requests |

**Runtime — the surfaces that aren't base tables:**

| Guard | Fails when… | Why a scanner misses it |
|---|---|---|
| `view-isolation` | a **view** or **materialized view** leaks across tenants | a view runs with its **owner's** rights unless `security_invoker` is set, and RLS **never applies to a materialized view at all** — so a perfectly-RLS'd table can still be handed out wholesale by the view beside it, and every table-only checker (including `rls-proof`) sees nothing wrong |
| `storage-isolation` | Supabase **Storage** leaks across tenant folders | storage has no tenant *column* — tenancy lives in the object **path**. Two things follow that a column-based check cannot see: the **client picks the path on upload**, so a perfect read policy still lets a user write into another tenant's folder; and a **public bucket** is served with no auth and no RLS at all, making "the path is unguessable" the whole boundary |
| `realtime-isolation` | Supabase **Realtime** channels leak across tenants | Realtime is a second way out of the database, easy to forget once REST looks locked down. Broadcast and Presence authorize channels through RLS on `realtime.messages` — with none, any client joins any tenant's channel, reads every payload on it, and (since joining is a write) **publishes into it**. The tenant lives in the *topic*, not a column |

**Runtime — where tenant data goes, and what else the role can reach:**

| Guard | Fails when… | Why a scanner misses it |
|---|---|---|
| `shadow-tables` | a trigger copies tenant data into a table nothing protects | the source has flawless RLS; the audit log, outbox or cache it feeds usually has **no tenant column at all**, so every tenant-aware check walks past it. Verified: the source returns one row to its tenant while the shadow returns both tenants', and `rls-proof` reports green |
| `role-capabilities` | the app role holds a capability that defeats RLS, or a direct grant on the `auth` schema | `dblink` opens a **new connection** as whatever role its string names — RLS on it has nothing to do with the caller's; file reads never touch the policy layer; and `auth.users` is every tenant's email in one table with no policy of yours in front of it. Outbound HTTP (`pg_net`) is surfaced as a **note**: real, but exfiltration rather than a cross-tenant read |
| `schema-tenancy` | one role can read **more than one tenant schema** | the other multi-tenant architecture — a schema per tenant — where the boundary is **GRANTs and nothing else**. `search_path` is not a control: it doesn't stop anyone writing `tenant_b.docs` directly, and the client can reset it. Every column-based check is blind here: point `rls-proof` at such a database and it reports "1/1 proven isolated" while the app role reads both tenants |
| `default-privileges` | a table created **tomorrow** arrives granted and unprotected | the only guard about the database as it *will be*. `ALTER DEFAULT PRIVILEGES` grants on every table created after it, and Postgres never enables RLS by default — so a green run says nothing about the table somebody adds next week: it arrives already granted, with no policy, exposed the instant it exists, and **no migration diff shows a security change**. It proves rather than infers, by creating a table inside a rolled-back transaction and reading what that table actually inherited |
| `cross-tenant-fk` | a foreign key lets one tenant reach — and **destroy** — another tenant's rows | the only finding here where a tenant *deletes* another tenant's data rather than reading it. **Referential integrity checks always bypass RLS** — they must, or a constraint could be defeated by hiding a row. So a key carrying an id but not the tenant lets tenant A point their row at tenant B's (the FK confirms a row A cannot see; the `WITH CHECK` governs the tenant column, not the reference), and then **`ON DELETE CASCADE` means B deleting their own row deletes A's**. Verified end to end, on a database `rls-proof` calls isolated |
| `create-grants` | someone who is not your migration role can **plant objects** in your database | `CREATE` is the quietest privilege in Postgres — nothing about it looks like data access — and it is the precondition that turns an unpinned `SECURITY DEFINER` `search_path` into escalation: you can only shadow an object if you can create one. That is CVE-2018-1058's shape, and why **Postgres 15 stopped granting it on `public` to `PUBLIC`**. Reported **even when no definer function exists yet**, because the grant arms the next one somebody writes — the one state a function-by-function check has nothing to evaluate in |

**Catalog** — the schema's shape rather than its behaviour:

| Guard | Fails when… | Why a scanner misses it |
|---|---|---|
| `constraint-oracles` | a constraint answers questions **across** tenants | RLS hides rows, not constraints — and constraints are enforced *below* it. `users.email UNIQUE` on a tenant table means inserting `victim@corp.com` raises a duplicate-key error even though RLS hides the row that caused it, so anyone can test whether a value exists in another tenant (and `ON CONFLICT DO NOTHING` asks the same question with no error at all). Nothing about the policies is wrong; the *schema* is the leak |

## Which databases this is for

**PostgreSQL, and anything that speaks it.** The runtime guards work by dropping to
your app role and proving row-level security actually holds — so they need an
engine that *has* RLS, and a `pg_catalog` to introspect.

| | Status |
|---|---|
| **Supabase** | Fully supported, and the Supabase-only surfaces (Storage, Realtime, the `auth` schema) have guards of their own |
| **Neon, RDS/Aurora, Cloud SQL, Timescale, self-hosted Postgres** | **Fully supported.** Nothing is Supabase-specific except the guards that say so, and those *skip cleanly* with a stated reason rather than failing you |
| **CockroachDB** | Untested. It speaks the Postgres wire protocol and has Postgres-compatible RLS from v25.2, so this may work as-is — if you try it, a report either way is welcome |
| **MySQL, MariaDB, PlanetScale, SQLite, MongoDB** | **Not supported, and not planned.** These have no row-level security, so there is no policy layer to prove. Isolation there is enforced in application code or by schema/database separation — a genuinely different check, not a port of this one |
| **SQL Server, Oracle** | Not supported. Both have real RLS (predicate functions, VPD), but a different driver, catalog and impersonation model — that's a rewrite sharing a name, not an extension |

If your tenancy is **one schema per tenant** rather than a tenant column, that's
covered too — see `tenant-guard schemas`. It's the usual pattern on engines
without RLS, and it's common on Postgres as well.

A non-Supabase run looks like this — real guards doing real work, and the
Supabase-only ones stepping aside:

```
rls-proof            ok   | 1/1 tenant table(s) proven isolated (read + write)
anon-reads           ok   | 1 tenant table(s) checked; none readable by "app_user"
identity-trust       ok   | 1 tenant policy/policies checked; identity sources look unforgeable
storage-isolation    ok   | skipped — no storage schema
realtime-isolation   ok   | skipped — no realtime schema
```

## How it fits your project

tenant-guard runs **inside your repository**, against the files already on disk.
It is **not** a scanner you point at a URL or a website, and there is no hosted
service — you run it where your code is (locally or in CI). The only thing you
ever "point it at" is a **test database connection string**, and only for the
runtime guards.

| Part | What it reads | What you provide |
|---|---|---|
| static guards (`run`) | your API-route and SQL-migration **files** in the current directory | nothing — it reads the folder |
| runtime guards (`prove`, `drift`, `anon-*`, `identity`, `views`, `storage`, `realtime`, `oracles`) | a live **Postgres** database | a connection string to a *test/staging* DB (never a URL, never prod) |
| everything (`all`) | both of the above, in order | as above — anything without a database **skips**, and a skip is never a pass |

Three places it runs, all inside the repo:

- **Locally** — `cd your-project && npx tenant-guard run` scans that folder.
- **In CI** — your pipeline checks out the repo and runs `npx tenant-guard run`
  (or `all`, with a test database), so a leak **blocks the merge**.
- **In your test suite** — `import { runAll, prove } from 'tenant-guard'` and
  assert no violations, so it runs with `npm test`.

Anyone else uses it identically in **their own** repo: `npx` pulls it from npm
(no clone of this repo, no account, no server), `init` autodetects their layout,
and they commit a `tenant-guard.config.json` so their team and CI share one
baseline. It works on any stack with API-route files and SQL migrations — see
[Config](#config) to point the signals at a non–Next.js/Supabase layout.

It does **not** take a repo URL, crawl GitHub, make HTTP requests to your app, or
run as a SaaS.

## Prove it at runtime — the part no scanner can do

The static guards read source text: they catch the obvious leak cheaply, but they
can't *prove* isolation holds. `tenant-guard prove` can. Against a seeded test
database it:

1. finds every table with a tenant column — including **partitioned** tables and
   each of their partitions — noting whether RLS is even on;
2. as the privileged role (which bypasses RLS, like Supabase `service_role`)
   picks two real tenant ids that already have data;
3. drops to your **non-superuser app role** (e.g. `authenticated`), assumes
   tenant A's identity, and asserts A's session can neither **read nor write**
   tenant B's rows — SELECT, plus the full write path: `UPDATE`/`DELETE` of B's
   rows, a **tenant-hop** (reassigning A's own row *into* B), an **`INSERT`** that
   creates a row in B, and an **omitted-tenant `INSERT`** (tenant column `NULL`)
   that creates an orphan row every tenant can read — then checks the other
   direction.

If RLS is off, a policy is `USING (true)`, a policy forgot the tenant predicate,
**the write path is unprotected** (RLS is per-command — a correct `SELECT` policy
does not cover `UPDATE`/`DELETE`, and `USING` does not cover `INSERT` or where an
update *lands*; those need `WITH CHECK`), or **RLS is on with no policy at all** (a
deny-all that only *looks* isolated), the proof names it and **fails your build**.

**Before trusting any pass it runs a negative control**: it drops to your app role
and asserts that role *cannot* read a deliberately deny-all table. If it can, RLS
isn't being enforced for it — a superuser, a `BYPASSRLS` role, a table owner — so
every "isolated" result would be a vacuous pass, and the run fails instead of
reporting one. A check you can't falsify is worthless.

See it catch a real leak with zero infrastructure:

```bash
npm i @electric-sql/pglite        # embedded Postgres — no Docker
node examples/rls-proof/demo.mjs  # passes a good policy, fails a leaky one
```

Against your own database (a **test/staging** one, never production):

```bash
npm i -D pg
export TENANT_GUARD_DATABASE_URL="postgres://…/your_test_db"
npx tenant-guard prove
```

Every write probe runs inside a `SAVEPOINT` that is rolled back, and the whole run
is one transaction that is rolled back — non-destructive by construction (set
`probeWrites: false` to test reads only). A skip (no database, or `pg` not
installed) is **not** a pass, and the CLI says so. Full setup — including the
Supabase JWT-claim config and seeding mode for an empty CI database — is in
[`examples/rls-proof/`](examples/rls-proof/README.md).

## The rest of the surface

Each of these is one command, inherits the same identity config, and skips cleanly
when it doesn't apply to your stack.

**`drift` — prove your RLS is in version control.** RLS can be enabled and given
policies **by hand in the Supabase dashboard** and never captured in a migration.
When that happens the table's real posture is invisible to code review, absent
from every fresh/CI database, and editable in the UI with no diff and no history.
A permissive policy letting `anon` write a shared table can live in production for
months without appearing in a single pull request. (Not hypothetical — it's how a
real cache-poisoning bug hid in a Supabase app we ran this against.) `drift` diffs
every `ENABLE ROW LEVEL SECURITY` / `CREATE POLICY` in your migrations (net of
`DROP`/`DISABLE`) against the live catalog; anything in the database that no
migration declares fails the build.

**`anon-reads` / `anon-writes` — the unauthenticated surface.** The public anon key
ships in every browser bundle. `anon-reads` proves it can't SELECT tenant data
(the CVE-2025-48757 class); `anon-writes` proves it can't write a shared table (the
cache-poisoning class). Reliability is the point: well-secured Supabase apps write
`TO public USING (auth.uid() = …)`, which a catalog-only check can't evaluate and
would false-flag — so both **probe as `anon`** and evaluate the real
`USING`/`WITH CHECK` rather than guessing from grants.

**`identity` — can the caller forge the identity itself?** Everything above assumes
the identity is honest. This asks whether it is: a policy authorizing from
`user_metadata` (user-writable, unlike `app_metadata`) is *proven* forgeable by
forging exactly that claim; a callable `SECURITY DEFINER` that sets your tenant GUC
from an argument is a "become any tenant" primitive; a membership table you can
write makes a correct policy bypassable; and a self-update policy still lets you
rewrite the `role` column that grants your access, because **RLS cannot restrict
columns** — only a column-level `GRANT` can.

That last one is worth spelling out, because it is the one most applications
have and the one that looks correct in review:

```sql
-- The policy is right. Everyone reviews this and moves on.
CREATE POLICY self ON profiles FOR UPDATE
  USING (id = auth.uid()) WITH CHECK (id = auth.uid());

-- And then:
UPDATE profiles SET is_admin = true WHERE id = auth.uid();   -- succeeds
```

RLS decides *which rows* you may touch. It has nothing to say about *which
columns*, so a policy that correctly confines you to your own row does not stop
you rewriting the field that grants your access. The guard checks every table
carrying an update policy — including when the flag is read by a policy on that
same table, or by **nothing in the database at all** because your application is
what checks it — and grades accordingly: a tenant column or a column some policy
reads **fails the build**; a column merely *named* like an authorization field
(`is_admin`, `role`, `plan`, …) that no policy reads is a **note**, since SQL
cannot see whether your app treats it as one. Add your own names with
`identityTrust.authorizationColumns`. The fix it gives is the only one that
works:

```sql
REVOKE UPDATE ON profiles FROM authenticated;
GRANT UPDATE (display_name, avatar_url) ON profiles TO authenticated;
```

and once that grant is in place the guard goes quiet, because the column really
is unwritable.

**`views`, `storage`, `realtime` — the surfaces that aren't base tables.** A view
runs with its *owner's* rights unless `security_invoker` is set; a materialized
view ignores RLS entirely; Storage and Realtime key tenancy off an object **path**
and a channel **topic** rather than a column, and in both the *client* chooses that
string when it writes. Each is invisible to a table-only check — there is a test
asserting `rls-proof` passes while `view-isolation` fails on the same database.

**`rpc` — the function that runs as its owner.** A `SECURITY DEFINER` function
bypasses RLS on everything it touches and is exposed by PostgREST as an endpoint.
If it doesn't re-filter by an auth-derived tenant — or filters by a tenant id the
*caller* supplies — the policies on the underlying tables never get a say. This is
also where the tool is most careful about its own blast radius: it will only
**call** a function Postgres has classified `STABLE` or `IMMUTABLE`, because the
engine enforces that those cannot write. A `VOLATILE` definer function is never
invoked — it is reported from a read of its body, as a note, saying exactly that.

**`shadows` and `caps` — where the data goes, and what else the role holds.** A
trigger on a protected table writes to an audit log that nothing protects, and the
data is out. Separately, some grants make every table-level question moot: `dblink`
opens a connection RLS knows nothing about, and a direct grant on `auth.users`
hands over every tenant's email.

**`oracles` — the schema itself.** RLS hides rows, not constraints. A globally
`UNIQUE` natural key on a tenant table lets anyone test whether a value exists in
another tenant, through an error message they were never meant to see.

## Why not just a SAST scanner?

There is a good static scanner for this space —
[`mcp-tenant-isolation`](https://www.npmjs.com/package/mcp-tenant-isolation)
(57 rules, SARIF). If you want a report of findings, use it; the two compose.

tenant-guard is a **different tool for a different failure mode**. A scanner
produces a list of findings that a busy team learns to ignore (alert fatigue).
tenant-guard's checks are **tests in your own suite** — red in `npm test`, the
PR can't merge, and they carry a per-project **allowlist**: when you adopt it on
a legacy repo you allowlist the debt you can't fix today, the build goes green,
and *it can only get better from there*. It's the
[ArchUnit](https://www.archunit.org/) philosophy — architecture rules as
executable tests — pointed at tenant isolation, which nobody had done.

## Adopt it

**GitHub Actions** — one step, no config, no install:

```yaml
# .github/workflows/tenant-guard.yml
name: tenant-guard
on: [pull_request]

jobs:
  guard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write     # so findings reach the Security tab
    steps:
      - uses: actions/checkout@v4
      - uses: FedericoTs/tenant-guard@v0
```

That runs the static guards, **blocks the merge** on a finding, writes a result
table to the run summary page, and annotates each finding on the pull-request
diff. Add a database to turn on the runtime proofs:

```yaml
      - uses: FedericoTs/tenant-guard@v0
        with:
          command: all
          database-url: ${{ secrets.TEST_DATABASE_URL }}
```

> **Never point the runtime guards at production.** They write — inside a
> rolled-back transaction, but they write. Use a seeded test or staging database.

Locally, or on any other CI:

```bash
npx tenant-guard init          # writes tenant-guard.config.json
npx tenant-guard run           # allowlist any legacy finding you can't fix yet
npx tenant-guard all --json    # results as data, for anything downstream
```

Adopting on a codebase that will light up on day one? Set `fail-on-error: false`
so findings appear without blocking, or allowlist the debt you can't fix today —
from then on the guard can only ratchet in your favour.

📘 **[docs/CI.md](docs/CI.md)** — inputs and outputs, a Postgres service
container, seeding two tenants on an empty CI database, GitLab and other CI,
troubleshooting.
📗 **[docs/OUTPUT.md](docs/OUTPUT.md)** — `--json`, `--sarif`, `--markdown`, and
the exit-code contract.

Or import the guards into your existing vitest/jest suite:

```js
import { runAll } from 'tenant-guard';
test('no cross-tenant leaks (static)', () => {
  const failed = runAll().filter(r => !r.ok && !r.skipped);
  expect(failed).toEqual([]);
});
```

The runtime guards drop straight into your suite too — hand any of them a Postgres
client whose `query(text, values)` returns `{ rows }` (node-postgres, or an
embedded pglite in tests):

```js
import { prove, checkViews, checkIdentity } from 'tenant-guard';
test('RLS actually isolates tenants', async () => {
  const res = await prove({ query: (t, v) => pool.query(t, v) });
  expect(res.violations).toEqual([]);
});
```

## Config

`tenant-guard.config.json` (see `examples/tenant-guard.config.json` for the
annotated version, or run `tenant-guard init` to generate it). Every guard is
opt-in and autodetects its paths; a guard that doesn't apply to your stack
**skips**, it never fails you.

```json
{
  "migrations":        { "dir": "supabase/migrations", "grandfather": ["031", "101"] },
  "definerGrants":     { "baseline": 189, "allowlist": ["validate_public_token"] },
  "routeOrgScoping":   { "routesDir": "src/app/api", "allowlist": [] },
  "rlsProof":          { "role": "authenticated", "claim": "org_id", "tenantColumns": ["organization_id"], "grandfather": ["shared_lookup"] },
  "rlsDrift":          { "schemas": ["public"], "allowlist": ["public.some_supabase_managed_table"] },
  "anonReads":         { "role": "anon", "allowlist": ["public.published_posts"] },
  "anonWrites":        { "role": "anon", "allowlist": [] },
  "identityTrust":     { "allowlist": [] },
  "viewIsolation":     { "allowlist": ["public.admin_reporting_view"] },
  "storageIsolation":  { "pathSegment": 1, "allowlist": ["brand-assets"] },
  "realtimeIsolation": { "topicSeparator": ":", "allowlist": [] },
  "constraintOracles": { "allowlist": ["public.orgs"] }
}
```

The runtime guards run only when `TENANT_GUARD_DATABASE_URL` (or `DATABASE_URL`)
is set, so they stay skipped until you opt in. **Identity is configured once**:
`viewIsolation`, `identityTrust`, `storageIsolation` and `realtimeIsolation`
inherit `role` / `becomeTenant` / `claim` from `rlsProof` unless you override them.

**Assuming a tenant's identity.** `becomeTenant` defaults to the canonical
Postgres GUC pattern. For Supabase JWT policies the `claim` shortcut is usually all
you need — `"claim": "org_id"` builds the `request.jwt.claims` impersonation and
sets `role` to `authenticated`, so **CI never needs your JWT secret**. Apps that
resolve the tenant through a memberships table use an explicit `becomeTenant`
(arbitrary SQL) plus `rlsProof.seed`, which manufactures two synthetic tenants
inside the rolled-back transaction so the proof works on an **empty CI database**.
Details in [`examples/rls-proof/`](examples/rls-proof/README.md).

**Per-user apps** (the tenant is a *user*, not an org). The defaults key off
`organization_id`/`tenant_id` and deliberately **don't** treat `user_id` as a
tenant column — in a B2B app `user_id` is often just the creator, and treating it
as the tenant boundary would hide real org leaks. If *your* isolation boundary is
the user, add it to both signals:

```json
{
  "routeOrgScoping": { "tenantSignals": ["user_id", "organization_id"] },
  "rlsProof":        { "tenantColumns": ["user_id", "organization_id"] }
}
```

Then **allowlist genuinely shared tables/routes** — a Google-Places cache, a
public reference table — with a one-line reason, rather than scoping data that is
supposed to be global.

Defaults target Next.js App Router + Supabase/Postgres, but every signal
(auth helpers, tenant column names, route glob) is configurable, so it works on
any stack that has API routes and SQL migrations. The bare-id detector ships
with patterns for **Supabase** (`.eq('id')`), **Prisma** (`where: { id }`), and
**Drizzle** (`eq(table.id, …)`) out of the box; raw SQL (`where id = …`) is left
out of the default to avoid false positives on self-loads — widen
`idFilterPattern` in config if you want it. These claims are backed by tests in
[`test/flexibility.test.mjs`](test/flexibility.test.mjs), which also prove
`rls-proof` against Supabase JWT-claim policies and non-Supabase session-GUC
apps.

## Honest limits

**The full map is [`THREAT-MODEL.md`](THREAT-MODEL.md)** — every way tenant
isolation is known to break, each tagged covered / partial / out-of-scope, with
*why* for the ones that are out of scope. It is the coverage target this project
builds against, and the honest statement of what a green run does and doesn't
prove. Read it before trusting one.

The **static** guards are heuristics on source text, deliberately conservative:
they catch a bug *shape*, not every instance. The real defence is row-level
security enforced in the database, which is exactly why the runtime guards exist —
they don't guess from source, they run queries as your app role and measure
whether isolation actually holds.

The **runtime** guards have limits of their own, and report them rather than
papering over them:

- They prove isolation for what they can reach with the tenant identity you
  configure. A mismatch between `becomeTenant` and your real policies shows up as
  *"sees none of its own rows either"* — **not** as a false pass.
- A table holding one tenant's data can often still be proven, by impersonating a
  tenant that exists elsewhere. When it genuinely can't be, it is reported as
  **not proven**, never as passing.
- Some findings are deliberately **notes rather than build failures** — a
  client-settable tenant GUC, `TRUNCATE` privilege, single-column foreign keys —
  because whether they are exploitable depends on architecture SQL cannot see.
  Failing the build on an unfalsifiable finding is how a security tool becomes
  ignorable.

And four classes are **out of scope by construction**, because "run SQL as the app
role" cannot see them. They need a different instrument, and they stay listed in
the threat model rather than being quietly omitted:

- **App-layer IDOR** through a service-role/admin connection that forgets
  `.eq('organization_id', …)`. The database serves it correctly; the bug is in the
  application. (`route-org-scoping` covers the shape of this, statically.)
- **A leaked `service_role` key** in a client bundle — needs a secret scan.
- **Connection-pooler state bleed** (`SET` instead of `SET LOCAL` on a
  transaction-pooled connection) — invisible from inside a single session.
- **A weak or leaked JWT secret** — key management, not RLS.

It is a strong proof on every commit, not a substitute for a pen test.

## Background

These guards were extracted from a production multi-tenant EU SaaS (now retired)
where they ran green on every push. The interesting finding from that codebase
is written up in [`METHODOLOGY.md`](METHODOLOGY.md): **the descriptive docs
written for the AI agent all rotted, while every executable guard survived.**

Since then the project stopped growing one reported bug at a time and started
building down [`THREAT-MODEL.md`](THREAT-MODEL.md) instead — which promptly
surfaced a **false negative in the flagship guard** (partitioned tables reporting
green while leaking) that no amount of waiting for bug reports had found.

## Documentation

| | |
|---|---|
| [`docs/CI.md`](docs/CI.md) | Wiring it into CI — the GitHub Action's inputs and outputs, a Postgres service container, seeding two tenants on an empty CI database, GitLab and other CI, troubleshooting |
| [`docs/OUTPUT.md`](docs/OUTPUT.md) | `--json`, `--sarif`, `--markdown`, the exit-code contract, and programmatic use |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Every way tenant isolation breaks, what is covered, and what this method **cannot** see |
| [`METHODOLOGY.md`](METHODOLOGY.md) | Where these guards came from, and why the executable ones outlived the written ones |
| [`examples/`](examples/) | An annotated config, a CI workflow, a runtime-proof walkthrough, and `leaky-demo` — a repo that fails on purpose |

## Licence

MIT — see [`LICENSE`](LICENSE). By Federico Sciuca.
