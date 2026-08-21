# tenant-guard — improvement brief from a real production run (MonkeyTravel, 2026-08-21)

> **How to use this file.** It is written as a prompt you can hand to a coding
> agent working on tenant-guard, and as a design doc a human can read top to
> bottom. Everything below was observed running tenant-guard 0.25.1 against a
> live Supabase app (Next.js + PostgREST, ~60 tables, per-USER tenancy). Every
> claim is reproduced, not theoretical. Priorities are P0 (fix before next
> release — a security tool that is wrong here loses trust) down to P3.

---

## 0. Context you need

- The target app is **per-user multi-tenant**, not org-per-tenant. The "tenant"
  is `auth.uid()`; isolation is RLS keyed on `user_id`. There is no
  `organization_id`.
- It is a **Supabase** app: PostgREST over Postgres, the public `anon` key ships
  in the browser bundle, `authenticated` = any signed-up user (free, instant).
- The run found **one CRITICAL live vulnerability**, hardened three definer
  grants, and cleared seven route flags as false positives after one config
  line. It also surfaced **two false positives in tenant-guard itself, one of
  which would cause a production outage if its recommended fix were applied.**

Take that last sentence as the thesis. The tool is good — it found a real
critical bug class — but its **advice** was, in one case, an outage.

---

## 1. What tenant-guard got RIGHT (keep these, they earned trust)

- **`definer-grants` found the real one.** `attach_referral_on_signup` is
  SECURITY DEFINER, mutates (awards currency, writes referral rows), and held
  EXECUTE via PUBLIC. Correct flag, correct severity, correct fix.
- **Net-state-of-history works and is delightful.** After I added a *separate*
  repair migration that revoked EXECUTE, the guard cleared the finding on the
  next run without any allowlist edit. That is exactly right and rare.
- **The escape hatches are well-judged:** `grandfather`, per-guard `allowlist`,
  `baseline`. They let you adopt on a legacy repo without lying.
- **`--json` is clean and complete.** Machine-readable triage was trivial.
- **The fix text is specific** — it names the exact REVOKE statement and the
  exact allowlist key. When the model matches, it is copy-paste correct.

---

## 2. P0 — `definer-grants` recommends a fix that causes a production outage

**The finding.** The guard flagged `user_is_trip_owner` — "SECURITY DEFINER +
mutates but EXECUTE is not revoked from PUBLIC/anon" — and advised:

```
REVOKE EXECUTE ON FUNCTION public.user_is_trip_owner(...) FROM PUBLIC, anon;
```

**Two things are wrong.**

### 2a. The function does not mutate. The scanner conflated file with body.

`user_is_trip_owner` is a pure predicate:

```sql
CREATE FUNCTION public.user_is_trip_owner(p_trip_id uuid, p_user_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
AS $$ SELECT EXISTS (SELECT 1 FROM public.trips WHERE id=p_trip_id AND user_id=p_user_id) $$;
```

It was labelled "mutates" because the **same migration file** also contains
`CREATE POLICY ... FOR INSERT / FOR UPDATE / FOR DELETE`. Those are *policy
verbs*, not DML the function runs. **Fix: detect mutation from the function
body/AST between its `AS $$ … $$`, not by scanning the whole migration file for
insert|update|delete tokens.** A `CREATE POLICY … FOR DELETE` must never make a
neighbouring `STABLE` function look mutating.

### 2b. Applying the recommended REVOKE breaks RLS. Reproduced.

`user_is_trip_owner` (and its siblings `user_can_access_trip`, `user_can_vote`,
`user_is_trip_collaborator`) are **called inside RLS policy expressions** — 9, 6,
4, 2 policies respectively, several with role `public`. Postgres requires the
**calling** role to hold EXECUTE even for a SECURITY DEFINER function invoked
inside a policy's `USING`/`WITH CHECK`. So the "fix" denies anon the function it
needs to evaluate its own row policy:

```sql
-- proven in a rolled-back transaction against the live DB
REVOKE EXECUTE ON FUNCTION public.user_can_access_trip(uuid,uuid) FROM PUBLIC, anon;
SET ROLE anon;
SELECT count(*) FROM public.activity_votes;
-- ERROR: 42501 permission denied for function user_can_access_trip
```

Every anonymous read of `activity_votes`, `proposal_votes`, `activity_status`,
… would start throwing. That is an outage, shipped by following a security
tool's advice.

**Fix (both a guard change and a doc change):**
- Before recommending `REVOKE EXECUTE` on any function, cross-check
  `pg_policies` (or, statically, `CREATE POLICY … (expr)` bodies in the
  migrations) for a reference to that function name. If referenced, **do not
  recommend revoke** — either suppress the finding or downgrade it to a note
  that says "this predicate is used by RLS; its EXECUTE grant is load-bearing."
- The static analogue: a definer function that is (a) non-mutating and (b)
  referenced by a `CREATE POLICY` expression is an *RLS helper*, a known-safe
  and necessary pattern. Recognize it as a category, not a violation.

This single item is why the brief exists. A security linter's fixes must be safe
to apply blind, because people *will* apply them blind.

---

## 3. P0 — the CRITICAL bug the STATIC guards missed, and how to catch it statically

The most severe issue in the target app was **not** flagged by `run` (static).
Only reproducing the runtime `anon-writes` class caught it. But it was
**statically detectable**, and adding that detection is the highest-value new
check tenant-guard could ship.

**The bug.** A view created to safely expose public profile columns:

```sql
CREATE VIEW public.public_profiles WITH (security_invoker = false) AS
  SELECT id, display_name, avatar_url, username, ... FROM public.users;
GRANT SELECT ON public.public_profiles TO anon, authenticated;   -- intent: read-only
```

Three facts combine into a critical write-through-RLS-bypass:

1. `security_invoker = false` → writes execute as the **view owner**, bypassing
   the base table's RLS. (This is *required* for the view's read purpose, so it
   is not itself the bug.)
2. The view is a **simple single-table projection → auto-updatable** by Postgres
   default. `INSERT/UPDATE/DELETE` pass through to `users`.
3. Supabase's **default privileges** grant `anon`/`authenticated`
   INSERT/UPDATE/DELETE on *every new object in `public`* — including this view.
   The author wrote only `GRANT SELECT` and reasonably assumed read-only.

Result, reproduced with the **public anon key** against production:

```
PATCH  /rest/v1/public_profiles?id=eq.<ANY user>  {"display_name":"x"}  -> 200
DELETE /rest/v1/public_profiles?id=eq.<ANY user>                        -> 200
DELETE /rest/v1/public_profiles                                          -> wipes users
```

Anyone could rewrite or delete **any or all** user rows, bypassing RLS. Strictly
worse than the read leak the view was built to fix.

**Why static analysis can catch this without a database.** All three facts are
in the schema/migrations:

> Flag any VIEW that is **(security_invoker = false or unset)** AND
> **auto-updatable-shaped** (single base relation in FROM; no DISTINCT, GROUP BY,
> aggregate/window, set-op, or computed target column) AND for which
> **INSERT/UPDATE/DELETE is reachable by anon/authenticated** — either via an
> explicit GRANT or, for Supabase, via the default-privilege baseline unless an
> explicit `REVOKE … ON <view> FROM anon, authenticated` exists.

Recommend the exact fix: `REVOKE INSERT, UPDATE, DELETE ON <view> FROM anon,
authenticated;` (or `CREATE VIEW … WITH (security_barrier)` + trigger if writes
are actually intended). This is a new static guard — call it
**`updatable-view-writethrough`** — and it would have blocked this at PR time
with no DB. **This is the flagship recommendation of the whole brief.**

(The existing `view-isolation` guard checks *read* leakage across tenants; it is
blind to the *write*-through case. They are different bugs.)

---

## 4. P1 — `route-org-scoping` assumes the wrong tenancy model by default

Out of the box it flagged 7 authenticated routes as "filters by bare id, no
tenant column." All 7 were false positives: this app's tenant column is
`user_id`, and adding `user_id`/`userId`/`user.id` to `tenantSignals` cleared
every one (each was hand-verified as genuinely user-scoped or public-by-design).

Two improvements:

- **Auto-detect the tenancy model.** Scan the migrations: if `organization_id` /
  `tenant_id` / `account_id` columns dominate, use org signals; if `user_id`
  dominates and there is no org column, default `tenantSignals` to the user set.
  Per-user apps are a huge fraction of the Supabase population you cite in the
  README (Lovable/Base44 are user-tenant). Defaulting to org-only guarantees a
  wall of false positives on first run for them.
- **Tighten the heuristic so the signal doesn't over-clear.** "mentions a tenant
  signal *anywhere in the file*" is coarse in the other direction: a route can
  reference `user.id` for the auth check and still run an **unscoped bare-id data
  query** that leaks. Prefer: the tenant signal must appear in the **same query**
  (same `.from(...).eq(...)` chain / same SQL statement) as the bare-id filter,
  not merely somewhere in the module. Otherwise a real IDOR hides behind an
  unrelated `getUser()` call.

---

## 5. P1 — audit EFFECTIVE grants on existing objects, not just default-privilege config

The critical bug (§3) came from Supabase's `ALTER DEFAULT PRIVILEGES` silently
arming a new object. `default-privileges` reportedly checks *what a table created
tomorrow inherits*. But the live hole was on an object that **already existed**.

Add (or extend a guard to) an **effective-grant audit**: for every table AND
view in the exposed schemas, compute what `anon`/`authenticated` can actually do
right now (`has_table_privilege`, or statically: base default-privilege baseline
minus explicit REVOKEs plus explicit GRANTs), and diff it against an expected
posture. "anon can DELETE from `public_profiles`" should scream regardless of how
the grant got there. Default-privilege *config* and *effective reality* drift;
audit the reality.

---

## 6. P2 — PostgREST-specific surfaces generic RLS checks don't see

These are Supabase/PostgREST-shaped leaks that a table-level RLS proof can miss.
The target app was bitten by two of them during the same week.

- **Embed-returns-null-on-deny.** PostgREST resource embedding
  (`select=*,users(display_name)`) applies the embedded table's RLS but returns
  **null on denial rather than erroring**. When the app author restricted
  `users`, four routes that embedded `users:user_id(...)` silently rendered every
  teammate as "Unknown" — no error, nothing in logs. A guard could flag FK-based
  embed sites where the embedded table's RLS is stricter than the parent's, or at
  least enumerate "these tables are reachable by embed from an anon-readable
  parent." This is a *silent correctness + potential-leak* class unique to
  PostgREST.
- **Write-policy vs read-policy (`return=representation`) mismatch.** An
  INSERT/UPDATE may be allowed by the write policy, but the row PostgREST returns
  is gated by the **SELECT** policy. Mismatches either leak (write policy looser
  than read) or silently return null (read looser than write). Worth a check that
  a table's write policies and select policy agree on tenant scope.
- **Anon-reachable RPC surface.** Every `anon`-executable SECURITY DEFINER
  function is a live endpoint at `/rest/v1/rpc/<name>`. `definer-rpc` exists;
  consider emitting the **full anon RPC attack surface** as an artifact ("these 9
  functions are callable by an unauthenticated request") so a reviewer sees the
  perimeter, not just the violations.

---

## 7. P2 — column-level exposure (RLS is row-level; the first bug here was a column)

Before the write hole, the app's *original* bug was **column-level**: correct-ish
row policy, but `anon` held `SELECT` on all 48 columns of `users`, so
`?select=email` dumped every address. RLS cannot express "these columns only";
the fix was column GRANTs.

`anon-reads` proves row access. Add a **column-sensitivity** pass: flag
`anon`/`authenticated` SELECT on columns whose names match a sensitive
dictionary (`email`, `phone`, `token`, `secret`, `hash`, `password`, `ssn`,
`*_key`, `ip`, `stripe_*`, `address`, `dob`, `birth`) unless explicitly
allowlisted. This is the single most common real-world Supabase leak and it is
invisible to row-level checks.

---

## 8. P2 — SECURITY DEFINER search_path hardening

A SECURITY DEFINER function without a pinned `SET search_path` is hijackable if
any lower-privileged role can create objects on the resolved path (your
`create-grants` guard is the adjacent half). Flag definer functions lacking an
explicit, non-mutable `SET search_path`. Supabase's own advisor does this; it
pairs naturally with your definer guards and would have context here (several of
the app's functions do pin it — reward that, flag the ones that don't).

---

## 9. P3 — smaller, concrete

- **`migration-collisions` is stricter than Supabase ordering.** It flagged 11
  historical same-DATE groups. But Supabase applies migrations in **lexicographic
  full-filename** order, so `20260531_a.sql` deterministically precedes
  `20260531_b.sql`. A shared numeric *prefix* is only a real hazard when the
  ordering between the two actually matters (one depends on the other) or when
  the **full** sort keys collide. Consider flagging on full-filename ties or true
  dependency inversions, not on prefix reuse alone — otherwise date-prefixed repos
  (a common Supabase convention) start with a large grandfather list.
- **README CI snippet points at a tag that doesn't exist.** The README shows
  `uses: FedericoTs/tenant-guard@v0`, but only exact tags (`v0.25.1`, …) are
  published — no moving `v0`. The snippet fails as written. Either publish/maintain
  a moving `v0` major tag (standard for Actions) or change the README to pin an
  exact version. (We pinned `@v0.25.1` in our CI to work around it.)
- **Positive controls in the runtime proofs.** Our real-world pain was often the
  *over-restriction* direction (a legit cross-tenant read that broke: referral
  landing said "A friend", Settle Up showed blank names). `rls-proof` proves "A
  cannot see B." Consider also asserting "A **can** see exactly its own N seeded
  rows" so a policy that is accidentally too tight fails the guard too. Isolation
  has two failure modes; the tool names one.

---

## 10. Outside the box — classes tenant-guard may be ignoring entirely

1. **Auto-updatable view write-through (§3).** The flagship gap. Static,
   database-free, would have caught a critical bug. Highest ROI.
2. **Effective-grant reality vs default-privilege config drift (§5).** The
   mechanism by which "I only granted SELECT" becomes "anon can DELETE."
3. **Column-level sensitive exposure (§7).** RLS is row-level by construction;
   the most common Supabase leak lives one dimension over.
4. **PostgREST embed null-on-deny (§6).** A leak-*and*-silent-breakage class
   that is invisible to table-level proofs and unique to this stack.
5. **The silent-failure meta-principle.** Everything that bit this app —
   RLS denial → 0 rows, embed denial → null, best-effort handlers → swallowed
   errors — shares one shape: **isolation failures are silent by default.** A
   guard philosophy note (and seeded positive/negative controls) around "make the
   silent failure loud" would be a differentiator. Your runtime guards already
   lean this way; make it the headline.
6. **Trigger-time cross-role divergence.** A BEFORE trigger that queries an
   RLS-protected table behaves differently depending on the inserting role
   (this app had a username-uniqueness trigger that, once the base table was
   locked down, silently stopped seeing collisions and would have broken signup
   — a definer fix was needed). `shadow-tables` covers trigger *copies*; this is
   trigger *reads* that change meaning per role.
7. **Storage/Realtime beyond paths.** Realtime `broadcast`/`presence` channels
   (as opposed to `postgres_changes`) do **not** inherit table RLS; a channel
   named by a guessable tenant id leaks. Worth a note in `realtime-isolation`.

---

## 11. Suggested priority order for the next release

1. **P0 §2** — stop recommending EXECUTE-revoke on RLS-referenced functions;
   fix body-vs-file mutation detection. (Prevents your tool from causing outages.)
2. **P0 §3** — ship `updatable-view-writethrough` static guard. (Catches a
   critical class, no DB, would have caught our worst bug.)
3. **P1 §5, §4** — effective-grant audit; per-user tenancy autodetect + tighter
   route heuristic.
4. **P2 §7, §6** — column-sensitivity pass; PostgREST embed guard.
5. **P2 §8, P3 §9** — search_path; migration-ordering realism; README `v0` tag;
   positive controls.

---

## 12. Reproduction appendix (so a maintainer can verify each claim)

- **§2b outage:** in a rolled-back tx, `REVOKE EXECUTE ON user_can_access_trip
  FROM PUBLIC, anon; SET ROLE anon; SELECT FROM activity_votes;` → 42501.
- **§3 write-through:** with the public anon key,
  `PATCH /rest/v1/public_profiles?id=eq.<id>` and `DELETE …` returned 200 before
  `REVOKE INSERT,UPDATE,DELETE ON public.public_profiles FROM anon, authenticated`;
  401 after. `SELECT` unaffected.
- **§4 false positives:** all 7 flagged routes cleared after adding `user_id`,
  `userId`, `user.id` to `routeOrgScoping.tenantSignals`.
- **§9 collisions:** 11 grandfathered date prefixes, all long-applied, all
  deterministically ordered by full filename.
```
```
Environment: tenant-guard 0.25.1, Supabase (Postgres 15-line), PostgREST,
Next.js App Router, ~60 public tables, per-user tenancy, run 2026-08-21.
