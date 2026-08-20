/**
 * Machine-readable JSON output.
 *
 * This is the escape hatch: whatever tenant-guard grows next, `--json` is the
 * one surface anything downstream can consume without parsing terminal text.
 * It is therefore a CONTRACT — `schemaVersion` is bumped when a field changes
 * meaning or disappears, never when one is added. Documented in docs/OUTPUT.md.
 *
 * Deliberately deterministic: no timestamps, no durations, no absolute paths.
 * Two runs against an unchanged repo and database produce byte-identical JSON,
 * so you can commit a baseline and diff against it in CI.
 */
import { VERSION } from '../version.mjs';

/** Bumped only on a BREAKING change to the shape below. */
export const SCHEMA_VERSION = 1;

const DOCS = 'https://github.com/FedericoTs/tenant-guard/blob/main/docs/OUTPUT.md';

/**
 * One guard's status, reduced to three words tooling can switch on.
 * A skip is never a pass — that distinction is the whole point of the field.
 * @returns {'pass'|'fail'|'skip'}
 */
export function statusOf(result) {
  if (result.skipped) return 'skip';
  return result.ok ? 'pass' : 'fail';
}

/**
 * Roll the results up into the counts a CI summary wants.
 * `ran` excludes skips, so "0 failed of 0 ran" can't be mistaken for a clean run.
 */
export function summarise(results) {
  const list = results ?? [];
  let passed = 0;
  let failed = 0;
  let skipped = 0;
  let violations = 0;
  let notes = 0;
  for (const r of list) {
    const status = statusOf(r);
    if (status === 'skip') skipped++;
    else if (status === 'fail') failed++;
    else passed++;
    violations += r.violations?.length ?? 0;
    notes += r.notes?.length ?? 0;
  }
  return {
    guards: list.length,
    ran: list.length - skipped,
    passed,
    failed,
    skipped,
    violations,
    notes,
    ok: failed === 0,
    // The same code the process exits with, so a wrapper never has to re-derive it.
    exitCode: failed > 0 ? 1 : 0,
  };
}

/** A violation, with only the fields that are part of the contract. */
function violation(v) {
  const out = { where: v.where, message: v.message };
  if (v.kind) out.kind = v.kind;
  if (v.fix) out.fix = v.fix;
  return out;
}

/**
 * @param {Array} results  guard result objects
 * @param {object} opts    { command }
 */
export function toJson(results, { command = 'run' } = {}) {
  const list = results ?? [];
  return {
    $schema: DOCS,
    schemaVersion: SCHEMA_VERSION,
    tool: { name: 'tenant-guard', version: VERSION },
    command,
    summary: summarise(list),
    guards: list.map((r) => {
      const out = {
        id: r.id,
        status: statusOf(r),
        summary: r.summary ?? '',
      };
      // Only present on a skip — and always present on one, because "why was
      // this skipped" is the first question anyone reading a green run asks.
      if (r.skipped) out.reason = r.reason ?? 'unknown';
      if (typeof r.scanned === 'number') out.scanned = r.scanned;
      out.violations = (r.violations ?? []).map(violation);
      out.notes = (r.notes ?? []).map((n) => ({ where: n.where, message: n.message }));
      return out;
    }),
  };
}

/** Pretty-printed and newline-terminated, so it survives shell redirection. */
export function toJsonString(results, opts) {
  return JSON.stringify(toJson(results, opts), null, 2) + '\n';
}
