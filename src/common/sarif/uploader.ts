import * as fs from 'fs';
import * as zlib from 'zlib';
import * as core from '@actions/core';
import * as github from '@actions/github';

// GitHub's SARIF processor rejects any result that has no `message` — even
// when the result has a `ruleId`, `message` is only conditionally optional
// per the SARIF 2.1.0 schema and GitHub enforces it unconditionally. Qualys
// qcscli intermittently emits findings with no `message` (rules whose catalog
// entry lacks description text), which makes the upload fail with
// "expected a result message" and leaves the repo's Security tab showing a
// failed analysis. Patch every offending result (and its rule's
// shortDescription, which GitHub uses as the fallback) before upload.
// GitHub's code-scanning ruleset merge protection ("Require code scanning
// results") gates pull requests on an alert's *security severity* bucket
// (critical/high/medium/low). GitHub derives that bucket solely from the
// SARIF rule's `properties.security-severity` CVSS string — it never reads
// qcscli's numeric `properties.severity` (Qualys 1-5 scale). qcscli omits
// `security-severity`, so every Qualys alert lands on the Security tab with a
// null security severity and the security_alerts_threshold knob can never
// match. Map the Qualys 1-5 severity onto a CVSS-string `security-severity`
// so GitHub buckets the alerts and merge protection can gate on them.
//
// Qualys severity (per the action's own counting in QScannerRunner):
//   5 = critical, 4 = high, 3 = medium, 2 = low, 1 = informational.
// We pick a representative CVSS score inside each GitHub band:
//   critical (9.0-10.0) -> 9.8, high (7.0-8.9) -> 8.0,
//   medium (4.0-6.9) -> 5.0, low (0.1-3.9) -> 2.0, info/none -> 0.0.
function qualysSeverityToSecuritySeverity(severity: number | undefined): string | undefined {
  switch (severity) {
    case 5:
      return '9.8'; // critical
    case 4:
      return '8.0'; // high
    case 3:
      return '5.0'; // medium
    case 2:
      return '2.0'; // low
    case 1:
      return '0.0'; // informational / none
    default:
      return undefined;
  }
}

function injectSecuritySeverity(report: {
  runs?: Array<{
    tool?: { driver?: { name?: string; rules?: Array<Record<string, unknown>> } };
    results?: Array<Record<string, unknown>>;
  }>;
}): number {
  let injected = 0;

  for (const run of report.runs ?? []) {
    // Rules carry the authoritative numeric severity; stamp security-severity
    // on each rule so GitHub buckets the rule, then mirror it onto results
    // that don't resolve to a rule (GitHub falls back to the result's own
    // properties when present).
    const ruleSeverity = new Map<string, number>();
    const rules = run.tool?.driver?.rules;
    if (Array.isArray(rules)) {
      for (const rule of rules) {
        if (!rule || typeof rule.id !== 'string') continue;
        const props = (rule.properties ??= {}) as Record<string, unknown>;
        const sev = props.severity as number | undefined;
        if (typeof sev === 'number') ruleSeverity.set(rule.id, sev);
        if (typeof props['security-severity'] !== 'string') {
          const mapped = qualysSeverityToSecuritySeverity(sev);
          if (mapped !== undefined) {
            props['security-severity'] = mapped;
            injected++;
          }
        }
      }
    }

    for (const result of run.results ?? []) {
      const props = (result.properties ??= {}) as Record<string, unknown>;
      if (typeof props['security-severity'] === 'string') continue;
      let sev = props.severity as number | undefined;
      if (typeof sev !== 'number' && typeof result.ruleId === 'string') {
        sev = ruleSeverity.get(result.ruleId);
      }
      const mapped = qualysSeverityToSecuritySeverity(sev);
      if (mapped !== undefined) {
        props['security-severity'] = mapped;
        injected++;
      }
    }
  }

  return injected;
}

function sanitizeSarifForGitHub(sarifContent: string): string {
  let report: {
    runs?: Array<{
      tool?: { driver?: { name?: string; rules?: Array<Record<string, unknown>> } };
      results?: Array<Record<string, unknown>>;
    }>;
  };
  try {
    report = JSON.parse(sarifContent);
  } catch {
    // Not parseable — hand it to GitHub as-is and let it report the problem.
    return sarifContent;
  }

  // Stamp CVSS-string security-severity (derived from Qualys 1-5 severity) so
  // GitHub code-scanning rulesets can gate merges on critical/high/etc.
  const sevInjected = injectSecuritySeverity(report);
  if (sevInjected > 0) {
    core.info(`Injected security-severity on ${sevInjected} SARIF rule(s)/result(s) for GitHub severity bucketing`);
  }

  const ruleDescriptionText = (rule: Record<string, unknown> | undefined): string => {
    if (!rule) return '';
    const sd = rule.shortDescription as { text?: unknown } | undefined;
    const fd = rule.fullDescription as { text?: unknown } | undefined;
    for (const c of [sd?.text, fd?.text]) {
      if (typeof c === 'string' && c.trim()) return c.trim();
    }
    return '';
  };
  const ruleAnyText = (rule: Record<string, unknown> | undefined): string => {
    const desc = ruleDescriptionText(rule);
    if (desc) return desc;
    const name = rule?.name;
    return typeof name === 'string' && name.trim() ? name.trim() : '';
  };

  let patched = 0;
  for (const run of report.runs ?? []) {
    const rules = run.tool?.driver?.rules;
    const ruleById = new Map<string, Record<string, unknown>>();
    if (Array.isArray(rules)) {
      for (const r of rules) {
        if (r && typeof r.id === 'string') ruleById.set(r.id, r);
      }
    }

    for (const result of run.results ?? []) {
      const message = result.message as { text?: unknown } | undefined;
      if (typeof message?.text === 'string' && message.text.trim()) continue;

      const ruleId = typeof result.ruleId === 'string' ? result.ruleId : '';
      const rule = ruleById.get(ruleId);
      let fallback = ruleAnyText(rule);

      if (!fallback) {
        const props = result.properties as Record<string, unknown> | undefined;
        const pkg = typeof props?.packageName === 'string' ? props.packageName : '';
        fallback = [ruleId, pkg].filter(Boolean).join(' - ') || 'Qualys qscanner finding';
        patched++;
        core.warning(
          `SARIF result${ruleId ? ` for rule "${ruleId}"` : ''} has no message; injecting fallback: "${fallback}"`
        );
      } else {
        patched++;
        core.warning(
          `SARIF result for rule "${ruleId}" has no message; using rule description as message`
        );
      }
      result.message = { text: fallback };

      // GitHub also needs shortDescription on every referenced rule; if the
      // rule itself is bare, give it one so the result can render.
      if (rule && !ruleDescriptionText(rule)) {
        rule.shortDescription = { text: fallback };
      }
    }
  }

  if (patched > 0) {
    core.info(`Patched ${patched} SARIF result(s) missing a message before upload`);
  }
  // Re-serialize whenever we mutated the report — either via message patching
  // or security-severity injection — otherwise the in-memory changes are lost.
  if (patched > 0 || sevInjected > 0) {
    return JSON.stringify(report);
  }
  return sarifContent;
}

export async function uploadSarifToGitHub(
  sarifPath: string,
  token: string,
  ref?: string,
  sha?: string
): Promise<void> {
  if (!fs.existsSync(sarifPath)) {
    throw new Error(`SARIF file not found: ${sarifPath}`);
  }

  const sarifContent = sanitizeSarifForGitHub(fs.readFileSync(sarifPath, 'utf-8'));
  const compressed = zlib.gzipSync(Buffer.from(sarifContent, 'utf-8'));
  const base64Sarif = compressed.toString('base64');

  const octokit = github.getOctokit(token);
  const context = github.context;

  const commitSha = sha || context.sha;
  const gitRef = ref || context.ref;

  core.info(`Uploading SARIF to GitHub Security tab...`);
  core.info(`Repository: ${context.repo.owner}/${context.repo.repo}`);
  core.info(`Commit SHA: ${commitSha}`);
  core.info(`Ref: ${gitRef}`);

  try {
    await octokit.rest.codeScanning.uploadSarif({
      owner: context.repo.owner,
      repo: context.repo.repo,
      commit_sha: commitSha,
      ref: gitRef,
      sarif: base64Sarif,
    });

    core.info('SARIF report uploaded successfully to GitHub Security tab');
  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('403') || error.message.includes('Resource not accessible')) {
        core.warning(
          'Unable to upload SARIF to GitHub Security tab. ' +
            'Ensure the repository has GitHub Advanced Security enabled and ' +
            'the workflow has "security-events: write" permission.'
        );
      } else {
        throw error;
      }
    } else {
      throw error;
    }
  }
}
