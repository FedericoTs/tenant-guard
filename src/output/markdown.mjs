/**
 * Markdown output, for a GitHub Actions job summary.
 *
 * `--markdown=$GITHUB_STEP_SUMMARY` puts the result on the run page itself, so
 * the answer to "what did the guard say?" is visible without expanding a log.
 * Findings are collapsed behind <details> so a run with many notes stays
 * skimmable, and the SKIPPED list is never collapsed — the whole point is that
 * a green summary has to admit what it did not check.
 */
import { summarise, statusOf } from './json.mjs';

const ICON = { pass: '✅', fail: '❌', skip: '⏭️' };

/** Table cells cannot contain a raw pipe or newline. */
const cell = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

/** Fenced so that SQL fixes with backticks/underscores survive intact. */
const fence = (s) => '```\n' + String(s).replace(/```/g, "'''").trimEnd() + '\n```';

export function toMarkdown(results, { command = 'run' } = {}) {
  const list = results ?? [];
  const s = summarise(list);
  const out = [];

  const headline = s.failed > 0
    ? `❌ **${s.failed} guard${s.failed === 1 ? '' : 's'} failed** — ${s.violations} finding${s.violations === 1 ? '' : 's'}`
    : s.ran === 0
      ? '⚠️ **No guards ran.**'
      : `✅ **All ${s.ran} guard${s.ran === 1 ? '' : 's'} passed.**`;

  out.push(`## tenant-guard \`${command}\``, '', headline, '');

  if (s.ran > 0) {
    out.push('| | Guard | Result |', '|---|---|---|');
    for (const r of list) {
      const st = statusOf(r);
      if (st === 'skip') continue;
      out.push(`| ${ICON[st]} | \`${cell(r.id)}\` | ${cell(r.summary)} |`);
    }
    out.push('');
  }

  for (const r of list) {
    const findings = r.violations ?? [];
    if (findings.length === 0) continue;
    out.push(`<details open><summary><b>${cell(r.id)}</b> — ${findings.length} finding${findings.length === 1 ? '' : 's'}</summary>`, '');
    for (const v of findings) {
      out.push(`- **${cell(v.where)}** — ${cell(v.message)}`);
      if (v.fix) out.push('', '  ' + fence(v.fix).split('\n').join('\n  '), '');
    }
    out.push('</details>', '');
  }

  const notes = list.flatMap((r) => (r.notes ?? []).map((n) => ({ guard: r.id, ...n })));
  if (notes.length > 0) {
    out.push(`<details><summary>${notes.length} note${notes.length === 1 ? '' : 's'} (informational — these never fail the build)</summary>`, '');
    for (const n of notes) out.push(`- \`${cell(n.guard)}\` **${cell(n.where)}** — ${cell(n.message)}`);
    out.push('', '</details>', '');
  }

  const skips = list.filter((r) => r.skipped);
  if (skips.length > 0) {
    // Deliberately NOT collapsed: an unnoticed skip is how a green badge starts
    // meaning less than the person reading it thinks.
    out.push(`### ⏭️ ${skips.length} guard${skips.length === 1 ? '' : 's'} skipped — a skip is not a pass`, '');
    for (const r of skips) out.push(`- \`${cell(r.id)}\` — ${cell(r.reason ?? 'unknown')}`);
    out.push('');
  }

  out.push('<sub>[tenant-guard](https://github.com/FedericoTs/tenant-guard) — guard tests for multi-tenant isolation</sub>', '');
  return out.join('\n');
}
