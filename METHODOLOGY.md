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

The first three guards are heuristics on source text. They catch the obvious
leak cheaply, but they can't *prove* isolation holds. So there's now a fourth,
runtime guard — `tenant-guard prove`. Against a real Postgres it drops to your
non-superuser app role, assumes one tenant's identity, and asserts that session
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
the *other* tenant, not just stealing/deleting the other tenant's rows. That is
the meta-pattern of this whole project: the strongest guard is the one a real
failure — or a sharp reviewer — taught you to write. The mechanism, the config,
and a zero-infrastructure demo are in
[`examples/rls-proof/`](examples/rls-proof/README.md).

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

So there's now a fifth guard — `rls-drift`. It reads every `ENABLE ROW LEVEL
SECURITY` and `CREATE POLICY` your migrations declare (net of `DROP`/`DISABLE`)
and diffs it against the live catalog (`pg_policies`). Anything in the database
that no migration declares fails the build. That turns "our RLS is in git" from a
hope into a checked fact — and it's the honest version of the mistake we almost
shipped in the review: *don't trust the declared state; exercise the real one.*
(The diff is name-and-flag presence, not policy-expression parsing — reliable by
design, no false drift.)

## Roadmap: what's next

Two of those roadmap items shipped, both taught by real use. Seeding mode
(`rlsProof.seed`) manufactures two synthetic tenants for databases that don't
already have them, so coverage no longer depends on fixture data — and it's what
makes membership-table policies provable. And a review of a real app found a
class every tenant guard missed: a table with no tenant column that `anon` could
write (that's how a shared cache gets poisoned). `anon-writes` closes it — and
the interesting part is *how*: a catalog-only check would false-flag the
well-secured `TO public USING (auth.uid() = …)` policies real apps use, so it
proves the write path by actually attempting it as `anon` and reading the real
result. Same lesson, again: don't infer what you can exercise. The remaining
steps: an `INSERT` probe under RLS, and a Supabase preset that discovers the app
role and JWT shape automatically.

---

*If any of this is useful, or wrong, open an issue — the whole point is guidance
that's checkable.*
