# Guards, not docs: what survives an AI-built codebase

tenant-guard came out of building a ~500,000-line multi-tenant EU SaaS mostly
solo, with heavy AI-agent assistance. This is the thing that codebase taught me,
and the reason the tool takes the shape it does.

## The finding

I gave the AI agent two kinds of guidance.

**Descriptive** — prose telling it how the system worked: a `CLAUDE.md`, a
component catalog, a database-schema doc, an architecture doc describing the
org-scoping contract. Thousands of words of "here is how things are."

**Executable** — tests and CI scripts that *fail the build* when a rule is
broken: an org-scoping check, a migration-collision check, a
`SECURITY DEFINER` grant check, and dozens of invariant tests.

A year later, every descriptive doc had **rotted**:

- `CLAUDE.md` said "95 migrations (next: 096)." There were 204.
- the database-schema doc said "next: 105."
- the progress file was stamped three months stale.
- the project config still carried the product's *first* name.

And every executable guard was still **green on every push.**

The reason is simple once you see it: **descriptive docs decay at exactly the
rate the agent ships, because nothing forces them to keep up.** An agent (or a
human) reads the doc, does the work, moves on — the doc is now one commit out of
date, then ten, then irrelevant. An executable guard cannot rot, because the
moment reality diverges from it, the build goes red and someone has to
reconcile them. The guard and the code are forced to agree.

This matters more the more code an AI writes for you. The volume that makes
agents valuable is the same volume that outruns any documentation you write to
keep them safe. The only guidance that survives contact with an agent shipping
at speed is guidance that is **enforced, not described.**

## The policy that follows

**When you fix the same class of bug twice, promote it to a guard.**

The cross-tenant IDOR that `route-org-scoping` catches wasn't invented — it was
found and fixed three separate times in that codebase before it became a test.
The pattern is:

1. a bug ships;
2. you fix it and write it up in a doc ("remember to scope by org");
3. it ships **again**, because the doc didn't stop it;
4. so you write the check that *fails the build* on that shape, and it never
   ships a third time.

Steps 2 and 3 are the waste. The lesson is to jump from 1 to 4: the second
occurrence of a bug class is the signal to spend an hour writing a guard instead
of another paragraph of documentation.

## Three techniques worth stealing

**Allowlist with a reason, not a mute.** When you adopt a guard on a legacy
codebase it will find real debt you can't fix today. Don't weaken the guard —
add the specific offenders to an allowlist *with a one-line justification*, so
the build goes green and the debt is now visible and finite. New code can't add
to it. This is how a guard goes from "impossible to adopt" to "run once, green,
only improves."

**Encode the bug shape, not a keyword.** The strongest guards don't grep for a
banned string; they assert on the *shape* of the mistake. `route-org-scoping`
doesn't flag "id" — it flags the conjunction *authenticated AND filters-by-bare-id
AND never-mentions-a-tenant-column*, because that conjunction is the bug and each
part alone is fine. In that original codebase one guard even constructed the
naive (buggy) computation and asserted it *diverged* from the correct one — the
test's job was to prove the wrong answer stayed wrong.

**Grandfather history, guard the future.** Both migration guards enforce their
rule only above a baseline / outside a grandfather set, because already-applied
history can't be changed and shouldn't block you. A guard that fails on
immoverable past is a guard people delete. A guard that only polices *new*
commits is one they keep.

## From tripwire to proof (shipped)

The three static guards are heuristics on source text. They catch the obvious
leak cheaply, but they can't *prove* isolation holds. So there is a runtime guard
that can — `tenant-guard prove`, the first of nine database-backed guards.
Against a real Postgres it drops to your non-superuser app role, assumes one tenant's identity, and asserts that session
literally cannot read **or write** another tenant's rows, across every table with
a tenant column. A static scanner can never do this; a query can.

It catches the ways real apps leak that no source scan proves: RLS switched
**off** on a tenant table (the [CVE-2025-48757](https://nvd.nist.gov/vuln/detail/CVE-2025-48757)
class — 303 endpoints across 170 Lovable projects were readable unauthenticated),
a policy left `USING (true)`, a policy that forgot the tenant predicate, an
unprotected **write path** (RLS is per-command, so a correct `SELECT` policy
leaves `UPDATE`/`DELETE` open), and RLS **enabled with no policy at all** — a
deny-all that only *looks* isolated. It runs inside a rolled-back transaction
(reads plus `UPDATE`/`DELETE` probes in savepoints), and distinguishes "proven
isolated" from "couldn't be proven" so a single-tenant fixture is never mistaken
for a pass.

The write-path check exists because a practitioner pointed out that read-only
isolation tests miss the leaks that actually bite — `UPDATE`. Building it
surfaced a subtlety worth writing down: a `WHERE tenant = 'other'` probe is
*masked* by a correct `SELECT` policy — you can't target rows you can't see — so
the probe rewrites the whole table with no `WHERE` and compares the affected-row
count to the tenant's own. A later reviewer named a third shape the probe was
missing: a user updates their **own** row and moves it *into* another tenant
(`SET organization_id = <other>`). The `USING` clause passes — the row is theirs
on the way in — and with no `WITH CHECK` on the destination, nothing validates
where it lands (worst when the policy is scoped by `created_by`/owner rather than
the tenant column). So the write probe now also tries setting the tenant column to
the *other* tenant, not just stealing/deleting the other tenant's rows. And a
third reviewer named the last write path — `INSERT`, governed only by `WITH
CHECK`, which a scoped `SELECT`/`UPDATE` says nothing about — so the probe now also
tries to *create* a row in the other tenant. Building that one surfaced its own
subtlety worth recording: you cannot use `INSERT … RETURNING` to see where the row
landed, because `RETURNING` re-applies the `SELECT` policy and a row `WITH CHECK`
*accepted* but `SELECT` hides then raises the very same error a `WITH CHECK` *block*
raises — masking the leak. The probe instead reads the acting tenant's own-row
count before and after, which is driver-agnostic and correctly ignores a `BEFORE`
trigger that rewrites the tenant back. The same reviewer then named the case a
wrong-tenant probe walks straight past: the **omitted** tenant. Insert a row with
the tenant column `NULL` — the client simply never claims a tenant — and where the
column is nullable and the read policy treats `NULL` as global (`… OR tenant IS
NULL`), you get a row owned by nobody that every tenant can read. So the probe now
also inserts a `NULL`-tenant row and checks whether the acting session can then
*read* it. That is the meta-pattern of this whole project: the strongest guard is
the one a real failure — or a sharp reviewer — taught you to write. The mechanism, the config,
and a zero-infrastructure demo are in
[`examples/rls-proof/`](examples/rls-proof/README.md).

The most interesting thing that fell out of writing the failure surface down
first, rather than waiting for the next bug report, was a class nobody had
reported: **the objects that aren't tables.** A Postgres view executes with its
*owner's* privileges unless it is created `WITH (security_invoker = true)` — off
by default — so a convenience view over a perfectly-protected table evaluates that
table's RLS as the owner and returns every tenant's rows. A materialized view is
worse: RLS never applies to it at all, and no policy exists that could scope it.
In both cases the base table proves clean, which is precisely why a table-only
checker reports success. There is a test that asserts exactly that: `rls-proof`
passes while `view-isolation` fails, on the same database. A guard suite is only
as good as its inventory of *what to point itself at*.

The same discipline runs one level deeper. Another reviewer pointed out that a
prover you can't falsify is worthless: if the identity switch silently fails and
the session still bypasses RLS, every isolation test can go green for the wrong
reason. So before trusting a pass, the prover now checks its own negative
control — it drops to the app role and asserts it *cannot* read a deliberately
deny-all table. A guard that can't detect a deliberately-broken case can't be
trusted on a passing one; make it prove it isn't vacuous.

## The guard the review taught us to write

We ran the tool against a real Supabase app and reviewed the two routes it
flagged. The routes were fine (shared cache) — but the review found a permissive
policy that let `anon` write that shared table, and the deeper finding was *why it
had hidden*: **the policy existed only in production**, applied by hand and never
captured in a migration. Its whole security posture was invisible to code review.

So there's a guard for exactly that — `rls-drift`. It reads every `ENABLE ROW LEVEL
SECURITY` and `CREATE POLICY` your migrations declare (net of `DROP`/`DISABLE`)
and diffs it against the live catalog (`pg_policies`). Anything in the database
that no migration declares fails the build. That turns "our RLS is in git" from a
hope into a checked fact — and it's the honest version of the mistake we almost
shipped in the review: *don't trust the declared state; exercise the real one.*
(The diff is name-and-flag presence, not policy-expression parsing — reliable by
design, no false drift.)

## Stop waiting for the next bug report

Every guard described so far was taught by something: a real failure, or a sharp
reviewer. That works, and it produced good checks — but it has a structural
problem. **A security tool that grows one reported bug at a time is always one
reviewer behind.** Its coverage is a function of who happened to look, not of how
the thing actually breaks.

So the project stopped doing that. [`THREAT-MODEL.md`](THREAT-MODEL.md) enumerates
the failure surface up front — every way multi-tenant isolation is known to break
in Postgres/Supabase — each entry tagged **covered / partial / out-of-scope**, with
the reason spelled out for the ones that will never be covered. Then the work
became: build down the map.

Two things came out of that which no amount of waiting would have produced.

**It found a false negative in the flagship guard.** Partitioned tables reported
*green while leaking*. Two causes compounded: a partitioned parent is
`relkind = 'p'` and the introspection only looked at `'r'`, so the parent was
never scanned; and list-partitioning by tenant means each partition holds exactly
one tenant *by construction*, so the two-tenant probe could never fire and every
partition was written off as "cannot prove". The result was `ok: true` on a
database where any authenticated user could read every other tenant by naming the
partition directly. Nobody had reported it. Writing the surface down found it in
an afternoon — and the fix (impersonate a tenant that exists *elsewhere*) also
upgraded ordinary single-tenant tables from "cannot prove" to a real verdict.

**It forced the calibration question.** Once you are working from a list rather
than a queue, you meet failure modes that are real but whose *exploitability
depends on architecture SQL cannot see* — a client-settable tenant GUC, `TRUNCATE`
privilege, single-column foreign keys. The temptation is to fail the build on all
of them and call it thorough. That is how a security tool becomes ignorable. Each
of those is a **note**, never a failure, and the note says why. The corollary
matters just as much: where a finding *is* conclusive — `user_metadata` used for
authorization, a globally-unique natural key on a tenant table — it fails hard,
with no hedging.

The map is now closed: every failure mode on it that is reachable by "run SQL as
the app role" has a guard behind it. What remains open is open on purpose, and
says so. **The most useful contribution now is a failure mode that isn't in the
table at all.**

---

*If any of this is useful, or wrong, open an issue — the whole point is guidance
that's checkable.*
