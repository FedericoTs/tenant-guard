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
literally cannot read another tenant's rows, across every table with a tenant
column. A static scanner can never do this; a query can.

It catches the three ways real apps leak that no source scan proves: RLS switched
**off** on a tenant table (the [CVE-2025-48757](https://nvd.nist.gov/vuln/detail/CVE-2025-48757)
class — 10.3% of a sample of AI-built apps), a policy left `USING (true)`, and a
policy that simply forgot the tenant predicate. It runs read-only inside a
rolled-back transaction, and it distinguishes "proven isolated" from "couldn't
be proven" so a single-tenant fixture is never mistaken for a pass.

That is the guard that turns "we think RLS is on" into "the build proves it, on
every commit." The mechanism, the config, and a zero-infrastructure demo are in
[`examples/rls-proof/`](examples/rls-proof/README.md).

## Roadmap: what's next

The proof tests the tables that already carry two tenants' data. The natural next
step is a **seeding** mode that manufactures two synthetic tenants for tables
that don't, so coverage doesn't depend on fixture data — plus a Supabase preset
that discovers the app role and JWT shape automatically. Those are conveniences
on top of a mechanism that already holds.

---

*If any of this is useful, or wrong, open an issue — the whole point is guidance
that's checkable.*
