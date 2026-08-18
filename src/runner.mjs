/**
 * Result formatting for the CLI. Zero dependencies, no colour libs — a couple
 * of ANSI escapes, disabled when NO_COLOR is set or output is not a TTY.
 */
const useColor = !process.env.NO_COLOR && process.stdout.isTTY;
const c = (code, s) => (useColor ? `[${code}m${s}[0m` : s);
export const green = (s) => c('32', s);
export const red = (s) => c('31', s);
export const yellow = (s) => c('33', s);
export const dim = (s) => c('2', s);
export const bold = (s) => c('1', s);

/**
 * Print results and return the process exit code (0 pass, 1 any violation).
 * @param {Array} results  guard result objects
 */
export function report(results, { title = true, emptyHint = true } = {}) {
  if (title) console.log(bold('\ntenant-guard') + dim('  — guard tests for multi-tenant isolation\n'));

  let failed = 0;
  let skipped = 0;
  for (const r of results) {
    if (r.skipped) {
      skipped++;
      console.log(`${yellow('○')} ${r.id} ${dim('— skipped (' + r.reason + ')')}`);
      continue;
    }
    if (r.ok) {
      console.log(`${green('✓')} ${r.id} ${dim('— ' + r.summary)}`);
      continue;
    }
    failed++;
    console.log(`${red('✗')} ${r.id} ${dim('— ' + r.summary)}`);
    for (const v of r.violations) {
      console.log(`    ${red('•')} ${bold(v.where)}`);
      console.log(`      ${v.message}`);
      if (v.fix) console.log(dim('      → ' + v.fix.replace(/\n/g, '\n      ')));
    }
  }

  // Informational notes (e.g. tables that couldn't be proven) — never fail the build.
  for (const r of results) {
    if (!r.notes || r.notes.length === 0) continue;
    for (const n of r.notes) console.log(dim(`  ${r.id}: ${n.where} — ${n.message}`));
  }

  const ran = results.length - skipped;
  console.log('');
  if (failed > 0) {
    console.log(red(bold(`✗ ${failed} guard(s) failed`)) + dim(`  (${ran} ran, ${skipped} skipped)`));
    console.log(dim('  A guard fails your build so the leak never merges. Fix it, or allowlist it with a reason.\n'));
    return 1;
  }
  if (ran === 0) {
    if (emptyHint) {
      console.log(yellow('No guards applied to this project.') + dim(' Run `tenant-guard init` to configure paths.\n'));
    }
    return 0;
  }
  console.log(green(bold(`✓ all ${ran} guard(s) passed`)) + dim(skipped ? `  (${skipped} skipped)` : '') + '\n');
  return 0;
}
