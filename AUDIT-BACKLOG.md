# Audit backlog — closed

Two adversarial audit rounds against a real database produced **213 candidates**;
**107 survived verification**. As of **0.44.0 all of them are closed** — 106
fixed, and one closed as won't-fix with the reasoning recorded below.

This file is kept because the method turned out to be worth more than the list,
and because "here is everything that was wrong with it" is a more useful thing to
publish than a clean slate.

## What the rounds found

| Cluster | Found | Outcome |
|---|---|---|
| False assurance — "proven" about a probe that never ran | 9 | closed |
| Fires on correct code | 14 | closed |
| Fix text that breaks the app when applied | 10 | closed |
| Fix text that silently does nothing | 9 | closed |
| Emitted SQL that will not run | 6 | closed |
| Parsing: comments, quoted bodies, string literals | 8 | closed |
| Probe coverage gaps | 22 | closed |
| Privilege resolution — PUBLIC, role membership, column grants | 10 | closed |
| Shared-helper drift | 7 | closed |
| Cosmetic, perf, packaging | 12 | closed |

The last two, and how they closed:

**Gating `definer-rpc`'s probe — closed with an opt-OUT, not an opt-in.** The
proposal was to stop calling definer functions unless asked. That would silently
turn off the guard's headline capability for everyone, to address a case the
rolled-back transaction already contains. `probeCalls: true` is the default and
`probeCalls: false` is there for a schema with `STABLE` functions that reach
something with external side effects — dblink, an FDW, a NOTIFY. The two
directions are not symmetric: a missed leak ships, a surprising probe gets a bug
report.

**Escalating every unpinned `SECURITY DEFINER` function to a build failure —
closed as WON'T FIX, deliberately.** It stays a note, and this is the answer
rather than a deferral.

Three attempts, in order:

1. The broad version — fail on any unpinned definer function where the role can
   plant. Built, and **measured firing on ordinary correct code**: three existing
   integration tests asserting a clean result flipped red, including a function
   that re-filters from the session and is proven tenant-scoped by the probe in
   the same run.
2. A narrower version — fail only when the body *decides* something from the
   shadowed object (an authorization lookup). Rejected on design: detecting
   "decides" from body text is exactly the kind of inference that produced most
   of the findings in this file.
3. A narrower version still — fail only when the body *writes* to an unqualified
   relation, which would be conclusive: the planted table receives the write and
   the real one silently does not. **Could not be measured.** The fixture does
   not run under the embedded Postgres used for verification (`0A000 input of
   anonymous composite types is not implemented`, with or without a planted
   table), so there is no reproduction. The read-shadow is proven; the
   write-shadow is only inferred from the same name resolution, and inference is
   what this project keeps getting wrong.

So it remains a note — one that states the `pg_temp` fact outright, names the
unqualified relations the body reads, and says plainly that whether the
substituted object buys the caller anything depends on what the body does with
it. The tool asserts nothing it has not shown.

Worth reopening if someone can produce the write-shadow reproduction against a
real server rather than an embedded one.

## The findings worth remembering

**The tool said "proven isolated (read + write)" about writes it never ran.** A
single-tenant table took a read-only code path and still counted toward the
read-and-write total.

**Whether a real leak failed the build depended on alphabetical ordering.** One
transaction, no savepoints: a benign helper that errors when probed aborted it,
and everything scanned afterwards was downgraded to a reassuring note. The
catalog query sorts by name.

**One fix would have taken a production database down.** Revoking `EXECUTE` on a
`SECURITY DEFINER` function that an RLS policy calls — Postgres requires the
*calling* role to hold EXECUTE for that.

**One guard fired on the exact fix it recommended.** Apply the remediation, keep
failing. The only exit was to ignore the tool.

**A code comment could disable a guard.** `DISCARD ALL` was substring-matched
across every scanned file and OR'd into one boolean, so a comment saying the
pooler does *not* issue it downgraded the only build-failing verdict.

**A policy the tool told you to write did not compile.** `USING (org_id =
current_setting('app.tenant'))` raises 42883 against a `uuid` column — the most
common tenant type, and the one the tool's own seed generates.

## The method

Fan out over guards; each worker builds the scenario against embedded Postgres
and tries to make the opposite happen. Then a **second pass whose only job is to
refute the first**. That stage is not optional: it rejected 19 of 126 verified
claims, including one where the guard was behaving correctly and the proposed
"fix" would have introduced a mass false positive on every Supabase project.

Two rules earned their place:

- **Ask Postgres, not your tests.** Every one of these was covered by a passing
  test. They were written from the same beliefs as the code, on the same
  afternoon, so they encoded the wrong premise and then guarded it. There was a
  green test asserting `pg_catalog, app` was a safe pin.
- **A guard must prove it can fail.** `test/negative-control.test.mjs` now builds
  a database broken exactly the way each guard exists to detect and requires a
  violation, then the corrected version and requires silence. Suggested by
  u/Guidondor, whose own smoke test sat green for weeks because the assertion was
  unreachable — *a suite that can't fail looks exactly like a suite that passes.*
  It caught a bad fixture of ours on its first run.

Anything a future audit reports without a reproduction should be re-verified
before it is acted on.
