# Changelog

## 0.29.0

More of the MonkeyTravel brief — and reviewing it turned up **two real bugs in
this tool**, one of which had been silently corrupting the guards' reasoning
about migration history.

### fix: history was being read in filesystem order

Every guard that reasons about "the net state of history" — `definer-grants`,
`updatable-view-writethrough` — sorted with
`(migrationNumber(a) ?? 0) - (migrationNumber(b) ?? 0)`. For two files sharing a
prefix, which is the ordinary Supabase date convention
(`20260531_a.sql`, `20260531_b.sql`), that comparator returns **0**, so a stable
sort preserved `readdirSync` order — **filesystem order**, which is not
alphabetical and differs by platform.

So "a REVOKE here, a re-GRANT there" and "which `CREATE VIEW` is the final one"
could be evaluated in the **opposite order from the one Postgres will see** — on
exactly the input shape `migration-collisions` was flagging. There is now one
shared `compareMigrations`, ordering by full filename the way the migration
runner does.

### fix: `effectiveCheck` misread every UPDATE policy without a WITH CHECK

Postgres reuses a policy's `USING` as its `WITH CHECK` when none is given — for
`UPDATE` as well as `ALL`. `identity-trust` only did that for `ALL`, so a
correctly constrained `FOR UPDATE ... USING (tenant = ...)` policy read as having
**no check at all**, and its authority-table analysis treated a safe policy as
unconstrained. Proven against a real database:

```
stays 'A': no error, rowCount=1
hops  'B': ERROR 42501 new row violates row-level security policy
```

The old unit test asserted the wrong answer; it now asserts the right one, with
that reproduction recorded next to it.

### `migration-collisions` recalibrated (brief §9)

It failed a real repository on eleven historical same-DATE prefix groups.
Migrations apply in lexicographic full-filename order, so a shared prefix is
deterministic — a naming choice, not a hazard, and failing on it hands
date-prefixed repos a large grandfather list on day one.

It now fails on **dependency inversion**: within a tied group, a migration that
applies FIRST referencing an object a LATER one creates. That is not a surprising
order, it is a migration that cannot apply against a fresh database — and it
passes locally, because the local database already has the object. Ties without
an inversion are a note; unpadded numbering (`9_x.sql` sorting after
`10_y.sql`) gets its own note, because the filenames win.

### Decided NOT to build (brief §6), recorded in the threat model

The **PostgREST embed null-on-deny** and **write-vs-read policy mismatch**
classes are now ⛔ *by decision* rather than absent. The symptom is real, but the
only fixes a tool could emit for the first are "loosen the RLS on the embedded
table" or "drop the embed" — and *weaken your RLS* is precisely the shape of
advice that caused the 0.26.0 outage. It is also not a database fact: the catalog
holds every FK, an app embeds a handful, and which ones the client requests is
not visible. Modelled on a purpose-built 58-table per-user app where every table
was correctly scoped, the proposed rule fires on **165 of 165 FK edges**. The
second half would re-report by inference what §3.1–3.4 already prove by probe.

- 613 tests (was 602), 22 guards.

## 0.28.0

Three items off the MonkeyTravel brief, plus a new guard for a question that came
in alongside it: **is your second factor actually a factor?**

### New guard: `mfa-enforcement` (`tenant-guard mfa`)

PostgREST honours whatever JWT the client presents. Your login screen asked for a
code; the data layer never heard about it. The only thing that can refuse a
single-factor token is a policy that checks the assurance level — and there is a
trap in writing one:

```sql
-- reads exactly right, enforces NOTHING
CREATE POLICY require_mfa ON notes FOR SELECT
  USING ((SELECT auth.jwt()->>'aal') = 'aal2');
```

Postgres **ORs permissive policies** and **ANDs restrictive ones**, so a
permissive gate can only *widen* access alongside your tenancy policy. Verified
against a real database, both ways:

```
PERMISSIVE  aal2 policy -> aal2 sees 1 row, aal1 sees 1 row   <-- not enforced
RESTRICTIVE aal2 policy -> aal2 sees 1 row, aal1 sees 0 rows  (enforced)
```

The guard fails on a permissive gate (conclusive — it is Postgres semantics, not
a judgement about your app), notes when factors are enrolled and **no** policy
checks `aal` at all, and notes partial coverage naming the tenant tables left
out. Catalog-only; skips on a project not using MFA.

### From the brief

- **P1: the tenancy model is now detected from your schema.** Defaulting to
  org-only columns handed every per-user Supabase app a wall of false positives
  on first run — 7 of 7 in the reported case. `route-org-scoping` (and the
  runtime tenant columns) now follow whichever model the migrations actually use,
  counted from column declarations: `user`, `org`, `both`, or `unknown`. An
  explicit config always wins. Confirmed on a per-user fixture: false positive
  before, clean after, with no configuration.

- **P1: the tenant signal must appear in the SAME QUERY as the bare-id filter.**
  A file-wide match let a route call `getUser()`, reference `user.id` for its auth
  check, and still run an unscoped `.eq('id', …)` underneath. Now three outcomes
  rather than two: scoped in the query passes; **no tenant signal at all** still
  fails; and *tenant in the file but not in the query* is a **note** — because
  that is both the IDOR shape and the ordinary fetch-then-check pattern, and the
  source genuinely cannot tell which.

- 601 tests (was 589), 22 guards.

## 0.27.0

New **static** guard `updatable-view-writethrough` — the flagship recommendation
of the MonkeyTravel brief, and the check that would have blocked that app's worst
bug at pull-request time with no database.

- **The bug it catches.** A view created to expose only safe profile columns was
  also writable through to `users`. With the public anon key,
  `DELETE /rest/v1/public_profiles` wiped the table. Three ordinary defaults
  collide, and **not one of them appears in the migration**:
  1. a view over one relation with no aggregation is **auto-updatable** —
     Postgres passes `INSERT`/`UPDATE`/`DELETE` through to the base table;
  2. `security_invoker` is **off by default**, so those writes execute as the
     view's OWNER and the base table's RLS never applies to the caller — which
     is precisely what makes the view useful for reading, so it is not the bug;
  3. Supabase's default privileges grant `anon`/`authenticated` writes on every
     new object, so `GRANT SELECT` does **not** make a view read-only.

  The word `DELETE` never appears anywhere. `view-isolation` cannot see it: that
  guard proves READ isolation across tenants, and this is a write.

- **Static, because every ingredient is in the text.** It parses the view's
  options and shape, tracks the net effect of `GRANT`/`REVOKE` across migration
  history, and detects whether the project looks like one where default
  privileges grant writes — preferring evidence (`ALTER DEFAULT PRIVILEGES` in
  your own migrations) over assuming a platform.

- **Proven against a real database, both directions.** An integration test shows
  the `DELETE` passing through while the base table's policy denies the caller
  outright, that `security_invoker = true` genuinely fixes it, and that the
  `REVOKE` this guard recommends actually blocks the write (42501). A static rule
  about Postgres behaviour should be a fact about Postgres, not an assertion.

- Calibrated: a materialized view, a `security_invoker` view, an aggregate or
  multi-table shape, and an explicit `REVOKE` are all silent. Without evidence of
  default write grants it is a note rather than a failure.

- `examples/leaky-demo` now contains the reported shape, so the README's example
  output demonstrates it — and that block is regenerated from a real run.

### Also

- **fix: an explicitly-`undefined` config value no longer erases its default.**
  `{ ...DEFAULTS, ...config }` treats `undefined` as a value, and
  `resolveGuardConfigs` returns `option: config.block?.option` — so any option a
  user had not set wiped the default. It only surfaced now because the older
  static guards read their config key by key with `??`. Found by wiring the new
  guard in, which crashed immediately.

- 589 tests (was 563), 21 guards.

## 0.26.0

**`definer-grants` recommended a fix that caused a production outage.** Reported
from a real run against a live Supabase app, reproduced here, fixed, and pinned
by tests. If you have applied a `REVOKE EXECUTE` this guard suggested, read on —
you may need to put it back.

### What happened

It flagged `user_is_trip_owner` — a pure `STABLE SELECT EXISTS` predicate — as
"SECURITY DEFINER + mutates", and advised:

```sql
REVOKE EXECUTE ON FUNCTION public.user_is_trip_owner(...) FROM PUBLIC, anon;
```

That function is called inside nine RLS policies. **Postgres requires the
CALLING role to hold EXECUTE even for a `SECURITY DEFINER` function invoked in a
policy**, so the revoke denied `anon` the ability to evaluate its own row policy
and every anonymous read started failing with `42501`. Reproduced in this repo's
tests against a real database, before and after.

### Two bugs behind it

- **fix: the parser read the file, not the function.** It sliced from each
  `CREATE FUNCTION` to the *next one*, so every statement that followed the last
  function was swallowed into its segment — and a neighbouring
  `CREATE POLICY … FOR INSERT` made a read-only predicate match
  `/\b(insert|update|delete)\b/`. The body is now extracted from its own `AS`
  clause (dollar-quoted with or without a tag, quoted, or `BEGIN ATOMIC`), SQL
  comments are stripped, and mutation is judged on statements rather than bare
  words — `FOR UPDATE` is a lock and `updated_at` is a column.

- **fix: volatility is now authoritative.** Postgres *enforces* that a `STABLE`
  or `IMMUTABLE` function cannot write — it rejects the statement at runtime. So
  a non-volatile function is provably non-mutating, and no regex gets a vote.
  This alone clears the reported case.

- **fix: a function referenced by a `CREATE POLICY` expression is never told to
  revoke.** Recognised as an *RLS helper* — the correct, necessary pattern — and
  reported as a note saying its EXECUTE grant is load-bearing. A helper that
  genuinely mutates is still flagged, but with different advice: split it into a
  `STABLE` predicate for the policy and a `VOLATILE` function for the writes,
  because revoking would break the policy either way.

### Why this mattered more than the finding

A security linter's fixes get applied blind — that is the point of printing
them. So they have to be safe to apply blind. This one was not, and the guard
was wrong about the fact it was reasoning from.

- 563 tests (was 551), 20 guards.

## 0.25.1

Documents the self-escalation check properly, and fixes a config option that
could not be set.

- **fix: `identityTrust.authorizationColumns` was unreachable.** The list of
  column names that mean "this decides access" (`role`, `is_admin`, `plan`, …)
  was in the guard's `DEFAULTS` but missing from the config resolver — so if your
  admin column is called `account_type` or `permission_level`, you could write it
  in `tenant-guard.config.json`, nothing would complain, and it would have no
  effect. Found while documenting it.

- **test: `config-reachability.test.mjs` walks EVERY guard** and asserts each
  `DEFAULTS` key survives its resolver, plus a check that no guard escapes the
  walk. Each resolver is a hand-written key allowlist, so this failure is a
  property of the pattern rather than of one guard; the audit found exactly one
  other candidate (`route-org-scoping`, configured through the shared static
  resolver) and it was already correct.

- **docs: the README now spells out the escalation case** rather than leaving it
  as the last clause of a long table row — with the SQL, because the policy looks
  right and that is the whole problem:

  ```sql
  CREATE POLICY self ON profiles FOR UPDATE
    USING (id = auth.uid()) WITH CHECK (id = auth.uid());   -- reviewed, approved
  UPDATE profiles SET is_admin = true WHERE id = auth.uid(); -- succeeds
  ```

  It states what is checked (every table with an update policy, including when
  the flag is read by a policy on that same table or by nothing in the database
  at all), the three severity tiers, the `authorizationColumns` knob, and that a
  column-level `GRANT` is both the fix and something the guard recognises.

- docs: the guard's own description, the annotated example config and
  `tenant-guard init` all updated to match.
- 551 tests (was 531), 20 guards.

## 0.25.0

Fixes a coverage gap in `identity-trust` that the documentation did not have:
the threat model claimed self-row privilege escalation was covered, with
`profiles.is_admin` as the example, and that exact example was not detected.

- **fix: self-row escalation now runs over every table with an UPDATE-applicable
  policy.** It was scoped to tables reached through `pg_depend` — so it only
  examined a `profiles` table when *another* table's policy consulted it. Two
  shapes, both common, were therefore never looked at:
  - `profiles.is_admin` read by a policy **on `profiles` itself**
  - an admin flag the **application** checks, which no policy mentions at all

  Both are now reported. Verified before and after: with only a same-table
  policy the old code found nothing; the new code names `is_admin` and
  `organization_id` and gives the column-GRANT fix.

- **The wrong source was the root cause.** The candidate list came from a query
  scoped to tables *carrying a tenant column* — correct for tenant questions, and
  wrong here, because a `profiles` table usually has no tenant column and is
  exactly where escalation lives. There is now a query for every policy in scope.

- **A third severity tier.** A column named like an authorization field
  (`is_admin`, `role`, `plan`, `tier`…) that **no policy reads** is now a
  **note** rather than silence: the database does not treat it as a boundary, but
  the name says the application does, and RLS cannot restrict columns either way.
  A column the role cannot UPDATE stays silent — a column-level GRANT is the fix,
  and the guard recognises it as one.

- **docs: the threat model's §3.8 row now describes what the code does.** A
  security tool claiming coverage it does not have is the worst defect it can
  ship, and this one had shipped since 0.12.0.

- 531 tests (was 527), 20 guards.

## 0.24.2

A bug hunt across the guards written this week. Nothing was failing — these were
found by going looking, and each one is now pinned by a test that fails without
the fix.

- **fix (`default-privileges`): the probe's own answer was being thrown away.**
  The guard creates a table and reads back whether row-level security came on —
  and then decided the question by regexing an event trigger's *body* instead.
  A trigger scoped to some other schema therefore downgraded a real finding to a
  note, because the body matched while the table it created had no RLS at all.
  The observed fact now decides it and the trigger only explains *why*, which is
  what this guard claims to do in the first place. Verified both ways: the flag
  reads `true` under an RLS-forcing trigger and `false` without one.

- **fix (`create-grants`): a role holding its OWN grant was hidden behind the
  PUBLIC one.** `has_schema_privilege` is true for both, so a schema granted to
  `PUBLIC` *and* directly to `anon` reported only the PUBLIC finding — whose fix,
  `REVOKE … FROM PUBLIC`, would have left `anon` still able to create. Direct
  grants are now read separately and reported alongside, each with its own fix.

- **fix (`create-grants`): `scanned` counted (schema, role) pairs.** One schema
  and two roles reported `scanned: 2`, while the summary line printed `1` from a
  different source — two numbers for one thing, in the published JSON contract.
  It counts schemas, both places agree, and the schema filter moved into the SQL
  instead of being applied after the fact.

- **fix (`cross-tenant-fk`): two SQL helpers returned `values: []` while their
  text carried `$1`/`$2`.** They worked only because their single caller passed
  the parameters separately — every other helper in the file is callable as
  `q(spec.text, spec.values)`, and these two would have broken the next person to
  assume that. A test now asserts every helper's placeholder count matches its
  values.

- **fix (`scripts/make-demo-gif.py`): dead code and fragile index-peeking in the
  line wrapper**, replaced with character-level wrapping that carries styling and
  indentation exactly. Output is unchanged; the GIF is regenerated so the
  committed asset matches what the current script produces.

- 527 tests (was 518), 20 guards.

## 0.24.1

Housekeeping the README hero, which had been showing 0.5.0-era output — three
static guards — long after the tool grew to twenty.

- **feat: `npm run demo`** (`examples/demo/demo.mjs`). A throwaway Postgres,
  in-process via pglite, shaped like a small SaaS built quickly: the RLS on the
  main table is genuinely **correct**, and six other things around it are not.
  It runs the real guards through the real reporter, so it makes the tool's
  actual point — *every leak is somewhere other than the policy everybody
  checks*: an unprotected table, a materialized view RLS can never scope, a
  foreign key that lets one tenant delete another tenant's rows, and a CREATE
  grant that arms the next definer function.
- **docs: a new README GIF, generated from that demo's real output.**
  `scripts/make-demo-gif.py` parses the ANSI the demo actually printed and
  animates it — so the hero image cannot drift from what the tool does, and
  anyone can reproduce it with one command. Not shipped in the package.
- **feat: `FORCE_COLOR`.** Colour was previously tied to `stdout.isTTY`, so any
  piped capture lost it. `NO_COLOR` still wins — an accessibility opt-out should
  not be overridable by a convenience one, and there is a test for that order.
- **fix: a copy bug in `cross-tenant-fk`** — the message read "…not the
  reference. and `ON DELETE CASCADE` means…", a conjunction opening a sentence.
  Found by reading the demo's output rather than by a test, which is the point
  of having a demo.
- 518 tests (was 516), 20 guards.

## 0.24.0

New guard `create-grants` (`tenant-guard creates`) — threat-model §7.3, and the
last row on the map worth building. Catalog-only: nothing is created and nothing
is executed.

- **`CREATE` is the quietest privilege in Postgres.** Nothing about it looks like
  data access, and it is not a tenant leak by itself — it is the **precondition**
  that turns other things into escalations. A `SECURITY DEFINER` function with an
  unpinned `search_path` resolves unqualified names through the *caller's* path,
  so a caller who can CREATE plants an object earlier on that path and the
  function operates on **theirs**, executing as its owner with RLS bypassed. That
  is CVE-2018-1058's shape, and why **Postgres 15 stopped granting `CREATE` on
  `public` to `PUBLIC` by default**.

- **Deliberately not a duplicate of §4.4.** `definer-rpc` already fails when an
  unpinned definer function exists *and* the app role can CREATE. It reports the
  **function** and the fix is to pin the path; this reports the **grant** and the
  fix is to revoke it. What it adds are the three things §4.4 structurally cannot
  see:
  1. the grant when there is **no definer function yet** — verified in the tests:
     `definer-rpc` reports clean because it has nothing to evaluate, while the
     precondition sits armed for the next function somebody writes without
     `SET search_path`, and no diff will show a security change when they do
  2. **`anon`** — §4.4 only ever evaluates the configured app role
  3. **`CREATE` on the database**, the right to create whole schemas, which is
     strictly stronger than writing into an existing one

- **Calibration.** `PUBLIC` fails (every role, including ones that do not exist
  yet) and unauthenticated roles fail (an anonymous client creating objects in
  your database is not a legitimate configuration under any architecture). The
  **app role is a note**: running migrations as it is legitimate, and SQL cannot
  tell which it is. Findings state whether they are exploitable *now* or latent,
  and point at `tenant-guard rpc` rather than re-reporting it.

- On Postgres below 15 the `PUBLIC` finding names itself as the pre-15 default,
  so it reads as context rather than pedantry.
- A grant to `PUBLIC` is reported once per schema, not once per role — it is one
  grant.
- **docs: THREAT-MODEL 7.3 closed** — 42 rows covered, 4 planned, none of them
  high-value or cheap, and §4.4 now carries the reciprocal pointer.
- 516 tests (was 495), 20 guards.

## 0.23.0

New guard `cross-tenant-fk` (`tenant-guard fks`) — threat-model §3.11, and the
only finding in this tool where one tenant **destroys** another tenant's data
rather than reading it.

- **The mechanism is documented Postgres behaviour that almost nobody accounts
  for: referential integrity checks ALWAYS bypass row-level security.** They have
  to — a constraint that could be defeated by hiding a row would not be a
  constraint. So when a foreign key carries an id but not the tenant:
  1. Tenant A points one of their own rows at tenant B's parent. The FK cheerfully
     confirms that row exists even though RLS hides it, and the child policy's
     `WITH CHECK` never objects, because it governs the tenant column and not the
     reference.
  2. Tenant B later deletes their own row. `ON DELETE CASCADE` **deletes tenant
     A's rows**, with no policy consulted at any point.

- **Verified end to end before it was built, and demonstrated in the tests.**
  Tenant A re-pointed a task at a project it could not see; tenant B then ran an
  ordinary `delete` on their own project and tenant A's task was gone. Neither
  tenant did anything unusual, and `rls-proof` reports that same database as
  fully isolated.

- **Two conclusive paths.** Rows that **already** cross tenants are observed
  corruption — a bad migration, an import, a bug fixed later — and need no probe
  at all. Where the data is still clean, a re-point probe inside a rolled-back
  transaction proves whether one can be created. A refused probe is reported as a
  genuine pass rather than silence.

- **`RESTRICT`/`NO ACTION` inverts the impact rather than removing it**: tenant
  A's reference **pins** tenant B's row, so tenant B can no longer delete their
  own data. Still a finding, worded for what it actually does.

- **Quiet by construction.** A key that already carries the tenant is skipped —
  the bad row is then unrepresentable, which is exactly why the fix is a composite
  `(organization_id, parent_id) → (organization_id, id)`. References to shared
  lookup tables (no tenant column) and self-references (a hierarchy inside one
  tenant) are excluded too.

- **`constraint-oracles` now hands this off instead of duplicating it.** It had
  been reporting single-column FKs as a note whose wording — "exploiting one needs
  a guessable parent id" — *understated* what is now proven, and reporting the
  same key from two guards is one finding twice. It states the catalog fact and
  points at `tenant-guard fks`.

- **docs: THREAT-MODEL 3.11 closed** — 41 rows covered, 5 planned, none of them
  high-value, and the counts in the prose match the tables.
- 495 tests (was 466), 19 guards.

## 0.22.0

New guard `default-privileges` (`tenant-guard defaults`) — threat-model §7.2.
Every other guard here answers a question about the tables that exist. This one
is about the table somebody adds **next week**.

- **The time bomb.** `ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON
  TABLES TO anon` grants on every table created *after* it, and Postgres never
  enables row-level security by default. So the day someone adds a table and
  forgets `ENABLE ROW LEVEL SECURITY`, it is readable the instant it exists —
  with no `GRANT` in the migration, **no security statement of any kind in the
  diff**, and no guard having failed, because when this tool last ran the table
  did not exist. That is the CVE-2025-48757 shape, pre-armed.

- **Demonstrated in the tests.** `anon-reads` passes against the database as it
  stands. One ordinary `create table` later — nothing unusual in it, no grant,
  no policy — and `anon-reads` fails on the new table. That progression is the
  guard's reason to exist.

- **It proves rather than infers.** Reading `pg_default_acl` and reasoning about
  what it implies gets the interaction with schema grants, role membership and
  `FOR ROLE` wrong in exactly the cases that matter. So the guard **creates a
  table inside a transaction it rolls back** and reads what that table actually
  inherited — grantees, privileges, and the RLS flag. The answer is a fact about
  your database rather than a deduction. A test asserts the probe table is gone
  afterwards; identifiers are validated, never interpolated blind.

- **Calibration, deliberately conservative.** This condition is latent — nothing
  is exposed until a table is created — and granting to `anon`/`authenticated`
  in `public` is the **stock configuration of a Supabase project**. Failing the
  build on it would fire on essentially every user of the platform this tool
  targets, which is how a security tool gets deleted. So the default fails only
  on **PUBLIC**: every role that exists or ever will, and nobody's platform
  default. Everything else is a note that states exactly what the next table
  inherits and why the green run is conditional. `failRoles` escalates it for
  teams that want it stricter — one knob, tested both ways.

- **Mitigation is detected.** An enabled `ddl_command_end` event trigger whose
  body enables RLS closes this the other way, and downgrades the finding rather
  than nagging a database that has already solved the problem. Read from the
  function body, since plpgsql records no catalog dependency for what it runs.

- **docs: THREAT-MODEL 7.2 closed** — 40 rows covered, 6 still planned, and the
  counts in the prose match the tables.
- 466 tests (was 439), 18 guards.

## 0.21.0

New guard `pooler-bleed` (`tenant-guard pooler`) — threat-model §6.1, the last
high-value row on the map, and the only failure mode here that **no
single-request test can see**. Run one request and isolation is perfect. The
leak exists only *between* requests.

- **The mechanism.** Your policies authorize from a custom GUC
  (`current_setting('app.tenant')`). Your app sets it with
  `set_config('app.tenant', $1, false)` or a bare `SET` — and that third
  argument is `is_local`, so `false` means *for the rest of this **connection***,
  not *for the rest of this transaction*. Connections are pooled. The next
  request to check that connection out inherits the previous request's tenant
  and reads their rows, with the policy working exactly as written. Supabase's
  pooler defaults to transaction mode, which is precisely the configuration that
  leaves a session-scoped `SET` behind on a backend another client is handed.

- **Verified before it was built, and demonstrated in the tests.** On one
  connection: set the tenant session-wide, then issue a later statement that
  sets *nothing* — it returns the previous tenant's rows. With the same code
  using `is_local = true`, that later statement returns nothing at all. And
  `rls-proof` reports that same database as fully isolated, with zero
  violations. That contrast is the guard's reason to exist.

- **It reads BOTH halves of the repository, which is why this went uncovered.**
  The database alone can only say "your policies trust a settable GUC" — which
  is why `identity-trust` reports that as a *note* and never a failure. The
  source alone can only say "something is set session-wide", which is
  unremarkable (`app.locale` is nobody's security boundary). Together the
  finding is conclusive and specific: *this* GUC, authorized by *that* policy,
  written with connection scope at *this* line. **This guard is what upgrades
  the §2.8 note to a build failure.**

- **Calibration.** A session-scoped write to a policy GUC fails the build. A
  non-literal `is_local` (a variable, a ternary) is a note — unreadable, not
  assumed safe. A GUC nothing in the repo sets is a note naming that. `DISCARD
  ALL` / `RESET ALL` in the codebase downgrades the finding, since that closes
  the hole the other way. Scanning is restricted to GUCs the policies actually
  use, which is what stops it matching the `set x.y =` in everyone's source.

- **Skips cleanly on the common Supabase case**: policies reading `auth.uid()` /
  `auth.jwt()` are set per transaction by PostgREST from a verified token, so
  there is nothing to outlive a request. `request.jwt.*` is excluded throughout.

- The runtime probe is a **demonstration, not the verdict** — it shows a
  session-scoped setting surviving into a later transaction while a
  transaction-scoped one does not (the second is its control arm), and reports
  the result as a note. It writes no data, touches no table, and opens no
  explicit transaction.

- **docs: THREAT-MODEL.md no longer contradicts itself.** The roadmap section
  claimed "there is no planned item left" while seven rows were still tagged
  planned. Those seven are now listed explicitly, each with why it hasn't been
  built, ordered by (severity × prevalence) ÷ cost.
- docs: fixed an orphaned `schema-tenancy` row in the README that rendered as a
  headerless one-row table.
- 439 tests (was 407), 17 guards.

## 0.20.3

- **fix: upload SARIF with `github/codeql-action/upload-sarif@v4`.** v3 is
  deprecated in December 2026, and an action that pins a dependency past its
  end of life breaks its users on a date they did not choose.
- The SARIF itself is confirmed good, not assumed: GitHub's own validator
  accepted it in CI — *"Validating … Successfully uploaded results … Analysis
  upload status is complete."*
- chore: the repo's own workflow moves to `checkout@v5` / `setup-node@v5`.

## 0.20.2

The second half of the Action fix, and a regression test so this class of bug
cannot ship a third time.

- **fix: `set +e` around the CLI call.** GitHub runs composite `run` steps with
  errexit already on — `bash --noprofile --norc -e -o pipefail`. The CLI exiting
  1, which is its normal behaviour when a guard fails, therefore killed the step
  before a single output was written and before the SARIF upload could run.
  The script carried a comment claiming it deliberately avoided `set -e`; not
  writing `set -e` does not turn off an inherited one. Only `set +e` does.
- **test: `test/action.test.mjs` executes the Action's shell** under that exact
  shell invocation, against `examples/leaky-demo` (which really does fail), and
  asserts the step survives with `result=fail` and a SARIF file on disk. Nothing
  else in the suite could see this: action.yml is YAML and shell, invisible to
  every unit test.
  - Verified falsifiable — with the fix removed, both the executable test and
    the textual one fail. The textual one initially did *not*, because a
    substring search for `set +e` was satisfied by the comment explaining it;
    it now matches line-by-line.

## 0.20.1

Fixes the Action, which 0.20.0 shipped broken. Caught by the self-test added in
the same release — the repo's own CI runs the action via `uses: ./`, and it
failed on the first invocation with `sh: 1: tenant-guard: not found` (exit 127).

- **fix: install the CLI into a dedicated prefix instead of going through
  `npx`.** `npx` resolves a locally-provided bin *before* fetching from the
  registry, so in any repository whose `package.json` declares a `tenant-guard`
  bin it tried to run a `node_modules/.bin` shim that need not exist. An
  explicit `npm install --prefix "$RUNNER_TEMP/tenant-guard-cli"` plus a direct
  `node <path>/bin/tenant-guard.mjs` has no such heuristics.
- **fix: `pg` is installed into that same prefix**, so `await import('pg')`
  resolves upward from the installed guard modules. As a side effect the Action
  **no longer writes to your `node_modules`** at all, which it previously did
  via `npm install --no-save pg`.
- The install step now verifies the CLI is actually on disk and fails with a
  named error rather than letting a missing binary surface as exit 127.

## 0.20.0

CI plumbing. Sixteen guards protect nobody while the tool isn't in anyone's
pipeline, and until now wiring it in meant writing your own workflow YAML and
parsing terminal text. No new guards in this release — on purpose.

- **feat: a GitHub Action.** The whole thing is now one step:

  ```yaml
  - uses: actions/checkout@v4
  - uses: FedericoTs/tenant-guard@v0
  ```

  It runs the guards, blocks the merge on a finding, uploads SARIF, and writes a
  result table to the run summary. `command: all` plus `database-url:` turns on
  the runtime proofs. The Action defaults to **its own version** of the CLI, so
  pinning the Action pins the tool.
  - `fail-on-error: false` reports findings without blocking — the honest way to
    adopt this on a codebase that will light up on day one.
  - A guard failure does **not** abort the step: the exit code is captured so the
    SARIF upload and the summary still run. Only exit 2 (bad usage) aborts early.
- **feat: `--sarif[=FILE]`** — SARIF 2.1.0, so findings land in the GitHub
  Security tab and as annotations on the pull-request diff, instead of in a log
  nobody reads twice.
  - The honest problem this had to solve: SARIF wants a file and a line, and most
    of these guards find things in a **database**. Nothing here invents one.
    Static findings point at the real file; runtime findings are anchored at
    `tenant-guard.config.json` — the file you would actually edit to allowlist
    them — with the database object carried in `logicalLocations`, which is the
    field SARIF has for exactly that. A path that isn't on disk yields **no**
    location rather than a broken pointer, because GitHub silently discards
    results pointing at missing files, which would turn a real finding green.
  - Every **skip** becomes a tool notification. A green upload still has to say
    what it didn't check.
- **feat: `--json[=FILE]`** — the results as data, and a documented contract with
  a `schemaVersion`. Deterministic on purpose: no timestamps, no durations, no
  absolute paths, so you can commit a baseline and diff against it.
  `tenant-guard list --json` emits the guard catalogue.
- **feat: `--markdown[=FILE]`** — a job summary for `$GITHUB_STEP_SUMMARY`.
  Findings carry their fix; notes are collapsed; the **skip list never is**.
- **feat: `--help`, `--version`, `--quiet`, `--no-color`.** The CLI previously
  took a command and nothing else — `tenant-guard --version` didn't work.
  - Unknown commands and options now exit **2**, distinct from 1 (a guard
    failed), so a typo in a workflow can't read as a clean run.
  - Writing a machine format to stdout suppresses the human report, so `--json`
    output is parseable. Two formats can't share stdout; that's an exit 2.
- **docs: [`docs/CI.md`](docs/CI.md)** — the full wiring guide: inputs, outputs,
  a Postgres service container, seeding two tenants on an empty CI database,
  GitLab and other CI, pre-commit, and troubleshooting (including the
  `security-events: write` permission everyone hits first).
- **docs: [`docs/OUTPUT.md`](docs/OUTPUT.md)** — the format reference and the
  exit-code contract.
- fix: an absolute output path (`--sarif=$RUNNER_TEMP/tg.sarif`) was joined onto
  the cwd instead of used — which is the normal case in the environment the flag
  exists for. Found while writing the test for it.
- 407 tests (was 352), 16 guards — no new guards in this release.

## 0.19.0

The other multi-tenant architecture, and an honest answer to "which databases is
this for?".

- **feat: new guard `schema-tenancy`** (`tenant-guard schemas`). Every guard until
  now assumed tenancy is a **column** guarded by RLS. The other major architecture
  gives each tenant its **own schema** — and tenant-guard was completely blind to
  it. Verified: with `tenant_a.docs` and `tenant_b.docs` both granted to the app
  role, `rls-proof` reports **"1/1 proven isolated"**, having found the one table
  in `public` and never noticed the role reads both tenants.
  - In that architecture the boundary is **GRANTs and nothing else**. In
    particular it is **not `search_path`** — setting the path to `tenant_a` does
    not stop anyone writing `select * from tenant_b.docs`, and the client can
    reset it anyway. Same failure shape as trusting a client-settable GUC, one
    level up: a convention mistaken for a control.
  - So it asks one question and answers it by probing: **how many tenant schemas
    can this role actually read?** More than one and the database isolates
    nothing. Reachability is *read*, not inferred from grants — schema `USAGE`
    without a table grant is correctly not counted as access.
  - Tenant schemas are found **by shape** (two or more schemas holding identically
    named tables), so it needs no configuration — and an ordinary multi-schema
    database (`public` + `analytics` + `audit`, all holding different things) is
    correctly not mistaken for one. `schemaPattern` overrides that for irregular
    layouts.
- **docs: "Which databases this is for".** Neon, RDS/Aurora, Cloud SQL, Timescale
  and self-hosted Postgres were **always** fully supported — the Supabase-only
  guards skip cleanly with a stated reason — but every document said "Supabase",
  so nobody could tell. Now stated, with a verified non-Supabase run shown. Also
  stated plainly: **MySQL, SQLite and MongoDB are not supported and not planned**,
  because they have no row-level security, so there is no policy layer to prove;
  SQL Server and Oracle have RLS but would be a rewrite sharing a name.
  CockroachDB is listed as untested-but-plausible rather than claimed.
- 352 tests (was 334), 16 guards.

## 0.18.0

Three candidates from a scope review, built with their severities kept apart
rather than flattened into one "security finding" bucket.

- **feat: new guard `shadow-tables`** (`tenant-guard shadows`). Follows triggers on
  tenant tables to the tables they **write into**. A trigger writes an audit row,
  an outbox event, a denormalised cache — the source has flawless RLS and the
  destination usually has **no tenant column at all**, so every tenant-aware guard
  here walks straight past it. Verified: as tenant A, `invoices` correctly returns
  one row while the `audit_log` its trigger fills returns **both** tenants' rows,
  and `rls-proof` reports green. Fails only on the conclusive case — the
  destination is readable by your app role **and** has no RLS.
  - Detection reads the **function body**, because plpgsql is not parsed at
    creation time and so records no `pg_depend` entry for what it writes. That is
    stated as a limitation: a dynamically-assembled target isn't followed, and
    unresolvable targets are listed rather than dropped.
  - A destination that already carries a tenant column is still checked, because
    this finding is **structural** where `rls-proof` is behavioural — an outbox
    that has been drained reports "cannot prove" there, and the trigger will
    refill it.
- **feat: new guard `role-capabilities`** (`tenant-guard caps`). Catalog-only —
  nothing is executed, since checking whether you *can* call `dblink` by calling
  it would be a poor idea. Two families, deliberately at different severities:
  - **Fails the build:** capabilities that defeat RLS outright. `dblink` opens a
    *new connection* as whatever role its connection string names, so RLS on it
    has nothing to do with the caller's; `pg_read_file` and friends never touch
    the policy layer. Plus **direct grants on the `auth` schema**, where every
    tenant's email and identity lives with no policy of yours in front of it.
  - **A note, never a failure:** outbound HTTP (`pg_net`, the `http` extension).
    Real — SSRF into your network, exfiltration of whatever the caller can already
    see — but it is *not* a cross-tenant read, and this tool doesn't fail builds
    on findings it can't stand behind as tenant isolation. It says so in the note.
  - Every `REVOKE` fix names `PUBLIC` as well as the role, because revoking from
    the role alone is a no-op when the grant lives on `PUBLIC` — which is
    Postgres's default for every new function.
- 334 tests (was 303), 15 guards.

## 0.17.0

Still in 4.3's neighbourhood, and the answer to "should this do SQL-injection
checks too?" — which is **yes, for exactly one shape, and no for the rest**.

- **feat(definer-rpc): SQL injection inside a `SECURITY DEFINER` function.**
  Generic injection scanning belongs in semgrep/CodeQL, and bolting it on here
  would produce precisely the alert fatigue this project argues against. But in
  *this* shape injection isn't a generic bug — it is a **tenant-isolation
  failure**, because the injected SQL executes as the function's **owner** and so
  bypasses RLS wholesale. Verified before building: a table with a flawless policy
  returns 1 row to its tenant, while `search_notes` with a payload of
  `%' or true --` returns every tenant's rows. Both existing guards reported green.
  - Read from the **body**, so unlike the call-probe it also covers `VOLATILE`
    functions — which matters, because plpgsql defaults to VOLATILE and that is
    exactly where dynamic SQL lives.
  - Deliberately narrow, so a finding is never a guess: `||`-concatenation of a
    parameter into `EXECUTE`, and `format()`'s **`%s`** (which escapes nothing).
    `EXECUTE … USING`, `quote_literal`, `quote_ident`, `%L` and `%I` are correct
    and produce nothing. Anything it cannot read confidently produces nothing
    either — silence beats a guess.
- **feat(definer-rpc): unpinned `search_path` (threat-model 4.4).** Unqualified
  names inside a definer function resolve through the **caller's** `search_path`,
  so a caller who can create objects can make the function operate on theirs —
  executing as the owner. Fails **only when that precondition holds**: the role
  must hold `CREATE` somewhere to plant the shadowing object. Otherwise it is a
  note, because you cannot exploit what you cannot create.
- Threat model **4.4 covered**, and **4.10 added** — the first row the map gained
  from someone asking a question it had no entry for.
- 303 tests (was 292).

## 0.16.0

A Reddit reviewer asked for "RPCs where SECURITY DEFINER + grants can quietly
undermine otherwise-correct RLS". Checking rather than assuming turned up a real
**false negative**, and a catalog fact that unblocked the check that had been
parked as too dangerous to build.

- **feat: new guard `definer-rpc`** (`tenant-guard rpc`). A `SECURITY DEFINER`
  function runs as its **owner**, so it bypasses RLS on everything it touches, and
  PostgREST exposes it at `/rest/v1/rpc/<name>`. This:

      create function get_invoices(org text) returns setof invoices
        language sql security definer stable
        as $$ select * from invoices where organization_id = org $$;
      grant execute on function get_invoices(text) to authenticated;

  hands out every tenant's invoices while `invoices` itself has flawless RLS —
  and before this release **every guard here reported green on it**. There is a
  test asserting exactly that: `rls-proof` passes while `definer-rpc` fails, on
  the same database.
- **The safety objection had a catalog answer.** Calling an arbitrary definer
  function is genuinely unsafe — an unknown body can commit autonomously and
  outlive the rollback that makes every other guard harmless, which is why the
  threat model had this parked as "gated". But Postgres *enforces* that a
  non-`VOLATILE` function cannot write (*"INSERT is not allowed in a non-volatile
  function"*). So `STABLE`/`IMMUTABLE` definer functions are **called and
  measured**, and `VOLATILE` ones are **never invoked** — reported from a read of
  their body, as a note that says plainly it is not proven and why.
- Distinguishes **trusts-argument** (called with another tenant's id, returned
  their rows) from **no-filter** (returns rows even for a tenant id that cannot
  exist) using a control arm, because the fix differs. Probes zero-arg and
  single-tenant-arg functions; anything else is skipped rather than guessed at,
  and says so.
- Threat model **4.3 and 4.5 → covered**.
- 292 tests (was 270), 13 guards.

## 0.15.0

**The map is closed.** Threat-model 5.4 was the last planned item; everything
still open is out of scope by construction and says so.

- **feat: new guard `realtime-isolation`** (`tenant-guard realtime`). Realtime is a
  second way out of the database, and easy to forget once the REST surface looks
  locked down.
  - **Broadcast and Presence authorize channels through RLS on
    `realtime.messages`.** With no policy there, any client joins any tenant's
    channel: reads every payload flowing through it and — because joining is a
    write — **publishes into it**. Injecting fabricated events into another
    tenant's live channel is the realtime analogue of writing into their storage
    folder, and a correct read policy does not prevent it.
  - The tenant lives in the **topic**, not a column, so it uses a tenant
    expression like storage: `split_part(topic, ':', 1)`. That one expression
    covers both conventions — with no separator present `split_part` returns the
    whole topic, so a bare `org_A` channel resolves correctly too.
  - Same control arm as the storage upload probe: it publishes into its **own**
    channel first, so a refusal elsewhere is never miscredited to tenant scoping.
  - RLS on with **no policy** is reported as a note, not a leak — broadcast is
    switched off rather than secured, which is almost certainly unintended but is
    not a leak.
  - For **`postgres_changes`** (5.3) it deliberately does *not* re-litigate the
    SELECT policy `rls-proof` already proves; it names **which tenant tables are
    actually in the `supabase_realtime` publication**, because on a streaming
    table a permissive policy is a live firehose rather than one request at a
    time, and people rarely know that list.
- **feat: `tenant-guard all`** — runs every guard in order. With a dozen of them,
  "how do I check everything?" needed a one-command answer. Runtime guards with no
  database skip, and a skip is still never a pass.
- 270 tests (was 251).

## 0.14.0

Threat-model **2.11**, and the last planned read-path item: **RLS hides rows, not
constraints** — and constraints are enforced *below* it.

- **feat: new guard `constraint-oracles`** (`tenant-guard oracles`). Catalog-only,
  no probing, no transaction.
  - **A globally UNIQUE natural key on a tenant-scoped table fails the build.**
    `users.email UNIQUE` means inserting `victim@corp.com` raises `duplicate key
    value violates unique constraint` **even though RLS hides the row that caused
    it** — so anyone who can attempt an insert can test whether a value exists in
    another tenant, and `ON CONFLICT DO NOTHING` asks the same question silently,
    with no error at all. Nothing about the policies is wrong here; the schema is
    the leak. Fix: `UNIQUE (organization_id, email)`.
  - Deliberately quiet where it should be: **primary keys** are skipped (globally
    unique by design), **single-UUID** unique columns are skipped (you cannot
    enumerate random UUIDs, so the answer is worthless), **expression indexes** are
    skipped rather than guessed at, and tables with no tenant column are ignored
    entirely.
  - **Single-column foreign keys between tenant tables are an aggregated note, not
    a failure.** Referential-integrity checks run with RLS not applied, so a child
    row can confirm a parent in another tenant — but composite tenant FKs are rare
    enough that failing on them would flag nearly every schema, and exploiting one
    needs both a guessable parent id and an insert that passes `WITH CHECK`.
  - An integration test **proves the premise** rather than asserting it: as tenant
    A, `SELECT` returns 0 rows while the duplicate insert still raises `23505`.
- 251 tests (was 231).

## 0.13.0

The last surface on the threat model this tool could not reach: **Supabase
Storage** (5.1/5.2). It needed a genuinely new capability rather than a reuse of
existing machinery — storage has **no tenant column**.

- **feat: new guard `storage-isolation`** (`tenant-guard storage`). Tenancy in
  storage lives in the object **path** (`org_A/invoices/q1.pdf`), so the tenant is
  an *expression* over `name` rather than a column. That single difference is why
  every other guard here was blind to it.
  - **Tenant-expression support**, via `split_part(name, '/', N)` — deliberately
    *not* Supabase's `storage.foldername()`, so the same SQL also runs on vanilla
    Postgres and the guard is testable without a Supabase instance. The segment is
    validated as a bounded integer, never interpolated as a string.
  - **The upload path-hop.** The client supplies the object name on upload, so an
    INSERT policy that doesn't pin the tenant segment lets a user write straight
    into another tenant's folder — overwriting or planting files — no matter how
    correct the read policy is. The probe has a **control arm**: it first uploads
    into its *own* folder, so a refusal elsewhere is never miscredited to tenant
    scoping when the session simply can't upload at all.
  - **Public buckets.** `storage.buckets.public = true` serves
    `/storage/v1/object/public/…` with no auth and **no RLS evaluated at all**;
    "the path is unguessable" is not a boundary. Flagged when the bucket holds
    objects under two or more tenant folders — a single-folder asset bucket
    (logos, marketing) is not. Stated as a **catalog fact**, not claimed as probed:
    the CDN behaviour lives in the Storage service, not in Postgres.
  - Also flags RLS disabled outright on `storage.objects`, and **skips cleanly on
    non-Supabase databases** so nobody is punished for a surface they don't have.
- 231 tests (was 210).

## 0.12.0

Threat-model **3.8**, and it rhymes with 0.11.0: the policy is right, the thing it
trusts is writable. This time the write is to your **own row**.

- **feat(identity-trust): self-row escalation.** `CREATE POLICY self ON profiles
  FOR UPDATE USING (id = auth.uid()) WITH CHECK (id = auth.uid())` is exactly
  right, and exactly the bug — because **RLS is ROW-level and cannot restrict
  columns.** It decides *which rows* you may touch and says nothing about *which
  fields*, so it happily lets a user rewrite every column of their own row:
  the `role` another policy reads to grant admin, or the `organization_id` that
  decides which tenant they are in.
  - Read from **`has_column_privilege` per column**, not inferred from the policy,
    because a **column-level GRANT is the only thing that actually stops it** — and
    that is what the fix says (`REVOKE UPDATE … ; GRANT UPDATE (safe_cols) …`),
    not a policy change.
  - Scoped so it doesn't cry wolf: a writable column counts only when a policy
    that depends on the table actually **reads** it — plus tenant columns, which
    always count, since re-parenting your own row is escalation by definition.
- 210 tests (was 199).

## 0.11.0

Threat-model **2.10**: the policy is flawless and still bypassable, because the
thing it *derives authority from* is soft.

- **feat(identity-trust): user-writable policy authority.** The textbook
  multi-tenant policy —
  `USING (org_id IN (SELECT org_id FROM memberships WHERE user_id = auth.uid()))`
  — is completely bypassable if the caller can write `memberships`: insert
  yourself a row for someone else's org and every policy that trusts that table
  now returns their data, **legitimately**. Nothing is "leaking"; the authority was
  soft. Per-table checking can never find this, because the flaw is one table away
  from the table you're checking.
  - Dependencies are read from **`pg_depend`**, which records every relation a
    policy's subqueries touch — exact, where a regex over `pg_policies.qual` would
    be a guess.
  - Fails when the authority table has **RLS off with a write grant**, or an
    INSERT/UPDATE policy whose check **never constrains its tenant column**. That
    second case is the one worth naming: `WITH CHECK (user_id = auth.uid())` looks
    careful and is the most common real-world shape — it pins WHO you are and
    leaves WHICH TENANT wide open.
  - Covers the UPDATE shape too (re-point your own membership row at another
    tenant), and reports **unknown → a note** when the authority table has no
    recognisable tenant column, rather than guessing either way.
- 199 tests (was 184).

## 0.10.0

Built down the [threat model](THREAT-MODEL.md), not down a bug queue — and the
most important thing in this release is a **false negative it found in the
flagship guard**.

- **fix(rls-proof): partitioned tables reported GREEN while leaking.** Two
  compounding causes. A partitioned parent is `relkind = 'p'` and the
  introspection only looked at `'r'`, so the parent was never scanned. And
  list-partitioning by tenant means every partition holds exactly ONE tenant *by
  construction*, so the two-tenant probe could never fire — each partition was
  written off as "only 1 tenant, cannot prove". Net effect: `ok: true` on a
  database where any authenticated user reads every other tenant by naming the
  partition directly (PostgREST exposes each partition as its own endpoint).
  Fixed by scanning parents **and** adding a **foreign-tenant probe**: impersonate
  a tenant that exists elsewhere and check whether this table's rows are visible
  to them. That also upgrades ordinary **single-tenant tables** from "cannot
  prove" to a real verdict.
- **feat: new guard `identity-trust`** (`tenant-guard identity`). Asks the question
  every other guard assumes away: can the caller **forge the identity** your
  policies authorize from?
  - **`user_metadata` used for authorization → FAIL.** It is writable by the user
    (`supabase.auth.updateUser({ data })`) while `app_metadata` is not. Detected
    in the policy text (conclusive on its own) and then *proven* by forging that
    exact claim and re-reading the victim's rows — with a **control arm** forging a
    nonexistent tenant, so a table that is simply open to everyone is never
    misattributed to the claim.
  - **A callable `SECURITY DEFINER` function that sets your tenant GUC from an
    ARGUMENT → FAIL.** That is a "become any tenant" primitive. A function that
    derives the tenant from the verified session instead is only a note.
  - **Bare dependence on a client-settable GUC → NOTE, never a build failure.**
    Whether that is exploitable depends on architecture SQL cannot see (and it is
    how this tool itself impersonates). Failing on it would be exactly the
    unfalsifiable finding this project exists to avoid.
- **feat(rls-proof): `TRUNCATE` capability surfaced.** `TRUNCATE` ignores RLS
  completely — no policy can stop it — and `GRANT ALL` includes it. Read from the
  catalog and reported as **one aggregated note**, deliberately **never probed**: a
  `TRUNCATE` probe takes an `ACCESS EXCLUSIVE` lock and is the one statement you
  must not fire at a database by surprise.
- **fix(rls-proof): "not proven" count was counting notes, not tables** — advisory
  notes inflated it.
- 184 tests (was 155).

## 0.9.0

Closes the highest-severity item on the [threat model](THREAT-MODEL.md): the
objects that **aren't base tables**. Every table-only checker — including this
tool's own `rls-proof` until now — is blind to these.

- **feat: new guard `view-isolation`** (`tenant-guard views`). Proves a tenant's
  session can't read another tenant's rows through a **view** or **materialized
  view**. Two different Postgres mechanisms, and the guard distinguishes them
  because *the fix is different*:
  - A **view runs with its OWNER's privileges** unless created `WITH
    (security_invoker = true)` — which is **off by default**. So a convenience
    view over a perfectly-RLS'd table evaluates that RLS *as the owner* and hands
    back every tenant. Fix: `ALTER VIEW … SET (security_invoker = true)` (and the
    guard says so only when your Postgres is 15+; older servers get the honest
    alternative).
  - A **materialized view ignores RLS entirely** — it's a stored snapshot owned by
    whoever refreshes it, and *no policy can scope it per caller*. The fix text
    never suggests `security_invoker` here, because it would not work.
  - A view that **already** sets `security_invoker` and still leaks is reported as
    the *base table's* bug, pointing at `tenant-guard prove` — precise blame
    instead of a generic finding.
  - Scoped to views exposing a tenant column, so public/reference views aren't
    flagged; identity (`role`/`becomeTenant`/`claim`) is inherited from `rlsProof`
    so you configure it once.
- **feat(anon-reads): also covers views and materialized views.** An
  anon-readable matview of every tenant — auto-granted and auto-exposed in
  Supabase — is the CVE-2025-48757 class at its worst, and a base-table-only scan
  never sees it. Important asymmetry, deliberately encoded: for a base table
  "RLS off + grant" is a structural leak, but views *always* report
  `relrowsecurity = false`, so applying that rule to them would false-flag every
  safe `security_invoker` view. **Views are therefore always judged by the probe.**
- **refactor:** the `claim` shortcut moved to a shared `applyClaimShortcut()` so
  every impersonating guard uses one implementation.
- 155 tests (was 128).

## 0.8.0

Stop growing one reported bug at a time. This release derives the **whole failure
surface** up front, publishes it, and closes the biggest gaps it exposed.

- **docs: [`THREAT-MODEL.md`](THREAT-MODEL.md).** An enumeration of how
  multi-tenant isolation breaks in Postgres/Supabase — identity/probe integrity,
  read path, write path, non-table objects (views, matviews, definer functions,
  partitions), Supabase surfaces, pooling, privileges — each tagged **covered /
  partial / planned / out-of-scope**, with *why* for the out-of-scope ones. A
  security tool that hides its blind spots is worse than one that names them, so
  the app-layer IDOR, leaked-service-key, public-bucket-CDN and pooler-bleed
  classes are listed explicitly as **not** provable by this method.
- **feat: new guard `anon-reads`.** Proves the anonymous role cannot `SELECT`
  tenant tables — the CVE-2025-48757 class (303 endpoints across 170 Lovable
  projects readable with the public anon key) that this README has cited from day
  one while nothing actually checked it by default. Scoped to tables **with a
  tenant column**, so public content isn't flagged. Hybrid: RLS-off + grant is
  structural (true even when the table is empty); RLS-on is **probed as `anon`**,
  which proves the safe `TO public USING (auth.uid() = …)` idiom is safe instead
  of crying wolf the way a catalog-only linter does. Empty table → *not proven*,
  never a silent pass. New `anon-reads` command + `anonReads` config/init/exports.
- **fix(rls-proof): the owner-bypass false pass.** A table's **owner** is exempt
  from its own RLS unless `FORCE ROW LEVEL SECURITY` is set. If the probe role
  owns the table, RLS is silently inert there — and the deny-all canary could not
  catch it, because the canary isn't owned by the probe role. Such tables are now
  reported as **not proven**, naming the exact `ALTER TABLE … FORCE ROW LEVEL
  SECURITY` fix, instead of producing a vacuous pass or blaming the wrong policy.
- 128 tests (was 109).

## 0.7.0

Another sharp one from the same reviewer: alongside the wrong-tenant INSERT, probe
the **omitted tenant**.

- **feat(rls-proof): the omitted-tenant / orphan-row probe.** As each tenant, the
  proof now also inserts a row with the tenant column **NULL** (the client simply
  doesn't claim a tenant). A strict `tenant = current` policy rejects it cleanly —
  `NULL = 'org_A'` is not true — but where the column is **nullable** and the read
  policy treats NULL as global (`… OR tenant IS NULL`), you get a row **owned by
  nobody and readable by every tenant**. A wrong-tenant probe walks straight past
  it, because it never omits the tenant. Detected by whether the acting session can
  then *read* the row it created (its visible-row count grows). A `NOT NULL` tenant
  column makes such orphans schema-impossible — reported as a safe block, not a
  leak; a `NOT NULL` on some *other* column is inconclusive (a note).
- 109 tests (was 104).

## 0.6.0

Closes the last write path the runtime proof was missing — **INSERT isolation** —
the second half of a reviewer's ask (the first, the `claim` shortcut, shipped in
0.5.0).

- **feat(rls-proof): prove INSERT isolation.** As each tenant, the proof now tries
  to `INSERT` a row belonging to the *other* tenant. INSERT is governed only by a
  `WITH CHECK` clause, so a table can scope `SELECT`/`UPDATE` correctly yet let any
  session create rows in any tenant — a real per-command gap the read/update
  probes couldn't see. Three honest outcomes:
  - **leak** — the row was accepted into the other tenant (fails the build);
  - **blocked** — `WITH CHECK` rejected it, or a `BEFORE` trigger rewrote the
    tenant column back to the acting tenant, or the role has no INSERT grant;
  - **inconclusive** — a `NOT NULL`/FK/sequence error meant we couldn't build a
    valid row, so nothing is proven. Reported as a **note**, never a silent pass.
  - The probe deliberately uses **no `RETURNING`**: `RETURNING` re-applies the
    SELECT policy, and a row `WITH CHECK` accepted but SELECT hides then raises the
    *same* error a `WITH CHECK` block raises — which would mask the leak. Instead
    it reads where the row landed from the acting tenant's own-row count, so it's
    driver-agnostic and trigger-aware.
- 104 tests (was 98).

## 0.5.0

More from Reddit.

- **feat(rls-proof): catch the tenant-HOP.** The write probe now also tries to set
  the tenant column to the *other* tenant (`SET org = <B>`), moving a session's
  OWN row INTO another tenant. A correct read policy passes it — the row is yours
  on the way in — and with no `WITH CHECK` on the destination, nothing validates
  where it lands (especially when the policy is scoped by `created_by`/owner
  rather than the tenant column). This is a distinct cross-tenant write from the
  steal/delete cases, and it was previously missed. A correct `FOR ALL … WITH
  CHECK (tenant = current)` policy still passes cleanly (no false positive).
- **feat(rls-proof): `claim` shortcut.** `rlsProof.claim: "org_id"` (or
  `"team_id"` / `"account_id"`, or `{ key, role }`) builds the
  `request.jwt.claims` `becomeTenant` for you and sets `role` to `authenticated`
  — impersonation via `set_config`, so CI never needs the JWT secret. An explicit
  `becomeTenant` still wins (use it as the SQL hook for membership-table apps).
- 98 tests (was 96).

## 0.4.0

New guard: **`anon-writes`** — the unauthenticated write surface.

This closes the one class a real review found in the wild that no guard caught:
a table with no tenant column that the `anon` role can write. It's how a shared
cache gets poisoned — the public key ships in every browser bundle, so if `anon`
can write the table, anyone can rewrite what every user reads.

- **feat(anon-writes):** `tenant-guard anon-writes` flags tables the anonymous
  role can INSERT/UPDATE/DELETE. Reliability was the hard part: well-secured
  Supabase apps write policies `TO public USING (auth.uid() = …)`, which a
  catalog-only check can't evaluate and would false-positive on. So it's a
  hybrid — the unambiguous **RLS-off + grant** case from the catalog, and for
  **RLS-on** tables it drops to `anon` and actually attempts UPDATE/DELETE (each
  in a rolled-back savepoint), which evaluates the real `USING`/`WITH CHECK`. Same
  identity negative-control as `rls-proof` (aborts if `anon` bypasses RLS).
  Allowlist for intentionally-public tables. Honest limit: pure INSERT-only anon
  surfaces under RLS aren't probed yet (roadmap).
- New `anon-writes` command + `anonWrites` config/init/exports/subpath. 96 tests
  (was 85).

## 0.3.0

Both items in this release came straight from Reddit feedback.

- **feat(rls-proof): seeding mode.** `rlsProof.seed` makes the proof
  **manufacture two synthetic tenants** inside the rolled-back transaction
  instead of requiring two tenants to already have data. This closes two gaps:
  it works on an **empty / CI database**, and it handles **membership-table
  policies** (`org_id IN (SELECT … WHERE user_id = auth.uid())`) — your
  `seed.setup` creates the membership rows the impersonated identity needs, which
  a bare claim can't. Tenant ids default to two UUIDs (pass `seed.tenants` for
  other types); a broken seed statement fails with a clear message. Nothing
  persists.
- **fix(definer-grants): judge the FINAL state of history, not each file.** A
  function that ships unsafe and is fixed by a `REVOKE` (or by dropping
  `SECURITY DEFINER`) in a *later* repair migration is no longer flagged — it
  used to be, because the guard only looked for a same-file revoke. Now it takes
  the latest definition of each function across all migrations and whether it's
  ever revoked, matching an ArchUnit-style "assert on the final definition" test.
  Genuinely-unsafe functions introduced late are still caught.
- 85 tests (was 79).

## 0.2.1

Two improvements to `rls-proof`, both from sharp reviewer feedback.

- **feat(rls-proof): a built-in negative control.** Before trusting any pass, the
  proof drops to your app role and asserts it **cannot** read a deliberately
  deny-all RLS table (RLS on + `FORCE`, no policy). If it can, RLS isn't being
  enforced for that role — a superuser, a `BYPASSRLS` role, a table owner, or a
  `SET ROLE` that didn't take effect — so every "isolated" result would be a
  *vacuous pass*. The guard now fails with a clear message instead of reporting
  one. (Runs inside the same rolled-back transaction; the canary is a temp table.)
- **docs: membership-table policies.** Policies that read a membership/junction
  table (`org_id IN (SELECT … WHERE user_id = auth.uid())`) need a *seeded
  membership row* for the impersonated identity, not just a claim — otherwise the
  table reports as "not proven." Documented in the rls-proof example, and the
  over-restrictive note now points at it. 79 tests (was 77).

## 0.2.0

New guard: **`rls-drift`** — prove your RLS is in version control.

Motivated by a real review: running the tool against a Supabase app surfaced a
permissive policy that let `anon` write a shared table — and the reason it had
hidden was that the policy existed **only in production**, applied by hand and
never captured in a migration. Its security posture was invisible to code review.

- **feat(rls-drift):** `tenant-guard drift` reads every `ENABLE ROW LEVEL
  SECURITY` / `CREATE POLICY` in your migrations (net of `DROP`/`DISABLE`) and
  diffs it against the live catalog (`pg_policies` + `pg_class.relrowsecurity`).
  Anything present in the database but declared in **no** migration fails the
  build; declared-but-absent is a note (migrations may be unapplied). The diff is
  name/flag-presence, not policy-expression parsing — reliable, no false drift.
  Read-only (two catalog queries, no transaction). Skips cleanly with no DB;
  `rlsDrift.allowlist` for policies intentionally managed outside migrations.
- New CLI command `drift`; `rlsDrift` config block + init stub; `drift`/`runDrift`
  exported; `./guards/rls-drift` subpath. 77 tests (was 61).

## 0.1.4

Docs only. Validated end-to-end against two real, independently-built Supabase
codebases (a ~500k-line org-multi-tenant app and a ~per-user travel app); the
guards behaved correctly on both, so no code changed.

- **docs: per-user apps.** The run surfaced a common adoption case worth naming:
  when the tenant is a *user*, add `user_id` to `routeOrgScoping.tenantSignals`
  and `rlsProof.tenantColumns`. It's intentionally **not** a default — in a B2B
  app `user_id` is often just the creator, and treating it as the boundary would
  hide real org leaks. Also: allowlist genuinely shared tables/routes (a
  places-cache, a reference table) with a reason instead of scoping global data.

## 0.1.3

The runtime proof (`rls-proof`) now tests the **write path**, not just reads —
prompted by sharp reviewer feedback that the leaks that actually bite are on
`UPDATE`.

- **feat(rls-proof): write-path proving.** As each tenant, the proof now probes
  `UPDATE`/`DELETE` of other tenants' rows and reports a **write leak** when they
  succeed — a distinct violation from a read leak. RLS is per-command, so a
  correct `SELECT` policy can leave `UPDATE`/`DELETE` wide open; this catches it.
  Each write probe runs in a `SAVEPOINT` that is rolled back inside the
  already-rolled-back transaction, so it stays non-destructive. Toggle with
  `probeWrites` (default `true`).
  - The probe deliberately uses whole-table `UPDATE`/`DELETE` with **no `WHERE`**
    and compares the affected-row count to the tenant's own: a `WHERE tenant =
    'other'` probe is *masked* by a correct read policy (you can't target rows
    you can't see), which would hide the very leak we're hunting.
- **feat(rls-proof): name the RLS-on-no-policy trap.** A table with RLS enabled
  and **no policy** denies every row — which looks exactly like isolation but is
  really an unfinished table. It's now detected from `pg_policy` and reported
  explicitly (`no policy`) instead of passing silently or as a vague note.
- **docs:** README, METHODOLOGY, and the rls-proof example updated; the demo gains
  a third scenario — reads correctly scoped, `UPDATE` wide open — the exact case
  a SELECT-only test misses.
- 61 tests (was 48).

## 0.1.2

Docs only — no code changes since 0.1.1.

- README: animated demo GIF, CI / npm / license / zero-dependency badges, and a
  "How it fits your project" section clarifying that tenant-guard runs **in your
  repo** against files on disk (plus an optional test-database connection for the
  runtime proof) — it is not a scanner you point at a URL.
- Corrected the CVE-2025-48757 reference to the primary-sourced figure: 303
  endpoints across 170 Lovable projects, readable by unauthenticated requests via
  the public anon key.

## 0.1.1

Everything here came out of trying to *prove* the flexibility claims rather than
assert them — see `test/flexibility.test.mjs`.

- **fix(rls-proof):** a misconfigured `becomeTenant` now degrades to a clear,
  actionable note (`could not probe — … cast the placeholder, e.g. $1::text`)
  instead of crashing the entire proof with a cryptic driver stack.
- **fix(docs):** the Supabase JWT-claim `becomeTenant` example now casts the
  placeholder (`$1::text`). Without it Postgres can't infer the type inside
  `json_build_object` and the proof errored (SQLSTATE 42P18).
- **feat(route-org-scoping):** the default bare-id detector now also catches
  **Drizzle** (`eq(table.id, …)`), alongside Supabase (`.eq('id')`) and Prisma
  (`where: { id }`). Re-validated false-positive-free against a real
  493k-line codebase. Raw SQL (`where id = …`) stays out of the default and is
  configurable via `idFilterPattern`.
- **test:** add `test/flexibility.test.mjs` — proofs for Supabase JWT-claim
  policies, non-Supabase session-GUC apps, Prisma/Drizzle routes, custom tenant
  columns, robustness, and the documented boundaries. 48 tests total; the test
  suite now ships in the package.

## 0.1.0

Initial release: three zero-dependency static guards (`route-org-scoping`,
`definer-grants`, `migration-collisions`) plus the runtime `rls-proof`, the CLI
(`run` / `prove` / `init` / `list`), config, and runnable examples.
