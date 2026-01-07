import * as fs from 'fs';
import * as zlib from 'zlib';
import * as core from '@actions/core';
import * as github from '@actions/github';

export async function uploadSarifToGitHub(
  sarifPath: string,
  token: string,
  ref?: string,
  sha?: string
): Promise<void> {
  if (!fs.existsSync(sarifPath)) {
    throw new Error(`SARIF file not found: ${sarifPath}`);
  }

  const sarifContent = fs.readFileSync(sarifPath, 'utf-8');
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
