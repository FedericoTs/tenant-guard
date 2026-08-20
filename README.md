# tenant-guard

**Guard tests that fail your CI when multi-tenant code can leak across tenants.**

<p align="center">
  <a href="https://github.com/FedericoTs/tenant-guard/actions/workflows/test.yml"><img src="https://github.com/FedericoTs/tenant-guard/actions/workflows/test.yml/badge.svg" alt="CI status"></a>
  <a href="https://www.npmjs.com/package/tenant-guard"><img src="https://img.shields.io/npm/v/tenant-guard.svg" alt="npm version"></a>
  <a href="LICENSE"><img src="https://img.shields.io/npm/l/tenant-guard.svg" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen.svg" alt="zero dependencies">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/FedericoTs/tenant-guard/main/assets/demo.gif" alt="tenant-guard failing CI on two cross-tenant leaks: a SECURITY DEFINER function callable by anon, and an API route that filters by bare id with no tenant scope" width="760">
</p>

Not a scanner you run and then ignore. These are checks that live in your repo,
run in `npm test` and your CI, and **block the merge** — so the cross-tenant
leak never ships. The static guards have **zero dependencies** and run in CI
without `npm ci`; the runtime proof adds a real Postgres check when you opt in.

```bash
npx tenant-guard init     # detects your migrations + API routes, writes a config
npx tenant-guard run      # static guards — exit 1 if anything can leak
npx tenant-guard prove    # runtime proof — exit 1 if a tenant can read/write another tenant
npx tenant-guard drift    # exit 1 if the DB has RLS/policies no migration declares
npx tenant-guard anon-writes  # exit 1 if the anonymous role can write any table
npx tenant-guard anon-reads   # exit 1 if the anonymous role can read any tenant table
npx tenant-guard views        # exit 1 if a view/materialized view leaks across tenants
npx tenant-guard identity     # exit 1 if the identity your policies trust is forgeable
npx tenant-guard storage      # exit 1 if Supabase Storage leaks across tenant folders
npx tenant-guard oracles      # exit 1 if a UNIQUE key reveals another tenant’s rows
npx tenant-guard realtime     # exit 1 if Realtime channels leak across tenants
npx tenant-guard all          # run every guard above, in order
```

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
tenant-guard  — guard tests for multi-tenant isolation

✓ migration-collisions — 2 migrations scanned; 0 grandfathered duplicate(s) ignored
✗ definer-grants — 1 unsafe function(s)
    • 200_add_reset_helper.sql
      function "reset_workspace" is SECURITY DEFINER + mutates but EXECUTE is not revoked from PUBLIC/anon
      → In the SAME migration add:  REVOKE EXECUTE ON FUNCTION public.reset_workspace(<args>) FROM PUBLIC, anon;
✗ route-org-scoping — 1 route(s) can leak across tenants
    • src/app/api/invoices/[id]/route.ts
      authenticated + filters by bare id + never scopes by a tenant column
      → Add the tenant column to every query, e.g. .eq('organization_id', auth.organizationId).

✗ 2 guard(s) failed
```

(That output is real — it's `examples/leaky-demo/`. Reproduce it:
`cd examples/leaky-demo && node ../../bin/tenant-guard.mjs run`.)

## The guards

| Guard | Fails when… | Why a scanner misses it |
|---|---|---|
| `route-org-scoping` | an authenticated route filters by a bare `id` and never mentions a tenant column | catches the *shape* of the IDOR (auth + bare-id + no-tenant), and it lives in your CI so it blocks the merge instead of adding one more report |
| `definer-grants` | a mutating `SECURITY DEFINER` function's **final** definition isn't revoked from `PUBLIC`/`anon` | requires knowing Postgres default grants + PostgREST exposure interact — *revoking from `anon` alone is a no-op*; judged on the net state of history, so a fix in a later repair migration counts |
| `migration-collisions` | two migrations share a numeric prefix | a project-specific CI invariant (your numbering scheme), not a code smell |
| `rls-proof` *(runtime)* | a tenant's session can actually read **or write** another tenant's rows | it isn't reading source at all — it runs real queries as your app role (SELECT, plus `UPDATE`/`DELETE`/tenant-hop/`INSERT` probes) and measures the leak; nothing static can prove isolation *holds*, and RLS is per-command so reads passing says nothing about writes |
| `rls-drift` *(runtime)* | the database has RLS enabled or a policy that **no migration declares** | catches security posture applied by hand in the dashboard/psql — invisible to code review, absent from CI, changeable with no diff or history |
| `anon-writes` *(runtime)* | the **anonymous** role can INSERT/UPDATE/DELETE a table | a table with no tenant column, writable by `anon`, is neither a tenant leak nor drift — it's the cache-poisoning class; it proves the real `USING`/`WITH CHECK` by probing, so it doesn't false-flag `TO public USING (auth.uid()…)` policies |
| `anon-reads` *(runtime)* | the **anonymous** role can SELECT a **tenant** table, view, or materialized view | the CVE-2025-48757 class — the public anon key reads every tenant's data with no login; scoped to objects with a tenant column so public content isn't flagged, and it *probes* as `anon` so it evaluates the real policy, not just the grant |
| `identity-trust` *(runtime)* | the caller can **forge the identity** your policies authorize from, or **write the table that grants it** | every other guard asks "given a correct identity, is the data scoped?" — this asks whether the identity itself is controllable: a policy reading `user_metadata` (which the *user* can rewrite) is defeated by forging that claim; a callable `SECURITY DEFINER` that sets your tenant GUC from an argument is a "become any tenant" primitive; a `memberships` table the caller can write makes a *flawless* policy bypassable — insert yourself into any org and the policy hands over that org's data, legitimately; and because **RLS is row-level and cannot restrict columns**, a correct `USING (id = auth.uid())` self-update policy still lets a user set their own `role` or re-parent their `organization_id` |
| `storage-isolation` *(runtime)* | Supabase **Storage** leaks across tenant folders | storage has no tenant *column* — tenancy lives in the object **path**, so the tenant is an expression over `name`. Two things follow that a column-based check cannot see: the **client picks the path on upload**, so a perfect read policy still lets a user write into another tenant's folder; and a **public bucket** is served with no auth and no RLS at all, making "the path is unguessable" the whole boundary |
| `constraint-oracles` *(catalog)* | a constraint answers questions **across** tenants | RLS hides rows, not constraints — and constraints are enforced *below* it. `users.email UNIQUE` on a tenant table means inserting `victim@corp.com` raises a duplicate-key error even though RLS hides the row that caused it, so anyone can test whether a value exists in another tenant (and `ON CONFLICT DO NOTHING` asks the same question with no error at all). Nothing about the policies is wrong; the *schema* is the leak |
| `realtime-isolation` *(runtime)* | Supabase **Realtime** channels leak across tenants | Realtime is a second way out of the database, and it is easy to forget once REST looks locked down. Broadcast and Presence authorize channels through RLS on `realtime.messages` — with none, any client joins any tenant's channel, reads every payload on it, and (since joining is a write) **publishes into it**. The tenant lives in the *topic*, not a column |
| `view-isolation` *(runtime)* | a **view** or **materialized view** leaks across tenants | a view runs with its **owner's** rights unless `security_invoker` is set, and RLS **never applies to a materialized view at all** — so a perfectly-RLS'd table can still be handed out wholesale by the view beside it, and every table-only checker (including `rls-proof`) sees nothing wrong |

`npx tenant-guard list` describes each.

## How it fits your project

tenant-guard runs **inside your repository**, against the files already on disk.
It is **not** a scanner you point at a URL or a website, and there is no hosted
service — you run it where your code is (locally or in CI). The only thing you
ever "point it at" is a **test database connection string**, and only for the
optional runtime proof.

| Part | What it reads | What you provide |
|---|---|---|
| static guards (`run`) | your API-route and SQL-migration **files** in the current directory | nothing — it reads the folder |
| runtime proof (`prove`) | a live **Postgres** database | a connection string to a *test/staging* DB (never a URL, never prod) |

Three places it runs, all inside the repo:

- **Locally** — `cd your-project && npx tenant-guard run` scans that folder.
- **In CI** — your pipeline checks out the repo and runs `npx tenant-guard run`,
  so a leak **blocks the merge** (that's the CI badge at the top).
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

The three guards above read source text: they catch the obvious leak cheaply,
but they can't *prove* isolation holds. `tenant-guard prove` can. Against a
seeded test database it:

1. finds every table with a tenant column, noting whether RLS is even on;
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

It runs read probes plus `UPDATE`/`DELETE` write probes, each inside a `SAVEPOINT`
that is rolled back, and the whole run is one transaction that is rolled back —
non-destructive by construction (set `probeWrites: false` to test reads only). A
skip (no database, or `pg` not installed) is **not** a pass, and the CLI says so.
Full setup — including the Supabase JWT-claim config — is in
[`examples/rls-proof/`](examples/rls-proof/README.md).

## Prove your RLS is in version control

RLS can be turned on and given policies **by hand in the Supabase dashboard** (or
a psql one-off) and never captured in a migration. When that happens, the table's
real security posture is invisible to code review, absent from every fresh / CI
database, and editable in the UI with no diff and no history. A permissive policy
that lets `anon` write a shared table can live in production for months and never
appear in a single pull request. (That's not hypothetical — it's how a real
cache-poisoning bug hid in a Supabase app we ran this against.)

```bash
export TENANT_GUARD_DATABASE_URL="postgres://…/your_test_db"
npx tenant-guard drift
```

`drift` reads every `ENABLE ROW LEVEL SECURITY` and `CREATE POLICY` in your
migrations (net of `DROP`/`DISABLE`) and compares it to what the database actually
has (`pg_policies` + `pg_class.relrowsecurity`). Anything present in the database
but declared in **no** migration fails the build — so a hand-edited policy can't
stay invisible. It's read-only (two catalog queries, no transaction needed), and
it skips cleanly with no database. Allowlist anything you intentionally manage
outside migrations (e.g. Supabase-managed policies) in `rlsDrift.allowlist`.

## Catch the unauthenticated write surface

The tenant guards ask "can tenant A touch tenant B?" — but a table with **no
tenant column**, writable by `anon`, is neither a tenant leak nor drift. It's how
a shared cache gets poisoned: the public anon key ships in every browser bundle,
so if `anon` can write the table, anyone can rewrite what every user reads. Almost
no table should accept unauthenticated writes.

```bash
export TENANT_GUARD_DATABASE_URL="postgres://…/your_test_db"
npx tenant-guard anon-writes
```

The reliability is the point. Well-secured Supabase apps write policies
`TO public USING (auth.uid() = …)`, which a catalog-only check can't evaluate and
would false-flag. So `anon-writes` is a hybrid: the unambiguous **RLS-off + grant**
case from the catalog, and for **RLS-on** tables it drops to `anon` and *actually
attempts* `UPDATE`/`DELETE` (each in a rolled-back savepoint) — evaluating the real
`USING`/`WITH CHECK`, no guessing. It shares `rls-proof`'s negative control
(aborts if `anon` bypasses RLS), and `anonWrites.allowlist` covers tables that are
public-write by design.

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

```bash
npx tenant-guard init          # writes tenant-guard.config.json
npx tenant-guard run           # allowlist any legacy finding you can't fix yet
```

Then wire it into CI (GitHub Actions example ships in
`examples/ci-github-actions.yml`) — one job, no install:

```yaml
- uses: actions/setup-node@v4
  with: { node-version: '20' }
- run: npx tenant-guard run
```

Or import the guards into your existing vitest/jest suite:

```js
import { runAll } from 'tenant-guard';
test('no cross-tenant leaks (static)', () => {
  const failed = runAll().filter(r => !r.ok && !r.skipped);
  expect(failed).toEqual([]);
});
```

The runtime proof drops straight into your suite too — hand it any Postgres
client whose `query(text, values)` returns `{ rows }` (node-postgres, or an
embedded pglite in tests):

```js
import { prove } from 'tenant-guard';
test('RLS actually isolates tenants', async () => {
  const res = await prove({ query: (t, v) => pool.query(t, v) });
  expect(res.violations).toEqual([]);
});
```

## Config

`tenant-guard.config.json` (see `examples/tenant-guard.config.json` for the
annotated version). Every guard is opt-in and autodetects its paths; a guard
that doesn't apply to your stack **skips**, it never fails you.

```json
{
  "migrations":     { "dir": "supabase/migrations", "grandfather": ["031", "101"] },
  "definerGrants":  { "baseline": 189, "allowlist": ["validate_public_token"] },
  "routeOrgScoping":{ "routesDir": "src/app/api", "allowlist": [] },
  "rlsProof":       { "role": "authenticated", "tenantColumns": ["organization_id"], "grandfather": ["shared_lookup"] },
  "rlsDrift":       { "schemas": ["public"], "allowlist": ["public.some_supabase_managed_table"] }
}
```

`rlsProof` runs only when `TENANT_GUARD_DATABASE_URL` (or `DATABASE_URL`) is set,
so it stays skipped until you opt in. `becomeTenant` (how a session assumes a
tenant identity) defaults to the canonical Postgres GUC pattern; override it for
Supabase JWT policies — see [`examples/rls-proof/`](examples/rls-proof/README.md).

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

The three static guards are **heuristics on source text**, deliberately
conservative — they catch a bug *shape*, not every instance. The real defence
for tenant isolation is **row-level security enforced in the database**, which is
exactly why `rls-proof` exists: it doesn't guess from source, it runs a query as
your app role and measures whether the isolation actually holds.

**The full map is [`THREAT-MODEL.md`](THREAT-MODEL.md)** — every way tenant
isolation is known to break, each tagged covered / partial / planned / out-of-scope
(with *why*). It's the coverage target this project builds against, and the honest
statement of what a green run does and doesn't prove.

`rls-proof` has honest limits of its own. It proves isolation for the tables it
can reach with the tenant identity you configure; it can only test tables that
already hold two tenants' data (it reports the rest as *not proven*, never as
passing); and it's only as good as the `becomeTenant` config matching how your
app assumes a tenant — a mismatch shows up as "sees none of its own rows either",
not a false pass. It reads and writes on a **tenant column** (SELECT + UPDATE /
DELETE / tenant-hop / INSERT), so tables whose tenancy lives somewhere other than
a column — notably Supabase's `storage.objects`, keyed by object path or `owner`
— aren't covered by default yet (on the roadmap). It is a strong proof on every
commit, not a substitute for a pen test.

## Background

These guards were extracted from a production multi-tenant EU SaaS (now retired)
where they ran green on every push. The interesting finding from that codebase
is written up in [`METHODOLOGY.md`](METHODOLOGY.md): **the descriptive docs
written for the AI agent all rotted, while every executable guard survived.**

## Licence

MIT — see [`LICENSE`](LICENSE). By Federico Sciuca.
