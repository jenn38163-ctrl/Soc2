/**
 * Production GitHub Security & Compliance Evidence Scanner (SOC 2 CC8.1, CC7.1, CC7.2)
 * Collects real GitHub telemetry: branch protection, CODEOWNERS, secret scanning, CodeQL, Actions CI runs.
 * Identifies: tenant -> organization -> repository -> control -> observation -> timestamp -> source -> evidence hash.
 */

import { GitHubEvidenceObservation, EvidenceVerificationStatus } from '../types/soc2';
import { createCanonicalEvidenceRecord } from '../lib/canonicalHasher';
import { auditLogStore } from '../lib/auditLogger';
import { multiTenantStore } from '../lib/multiTenantStore';

export interface GitHubScanOptions {
  token?: string;
  organization?: string;
  repositories?: string[];
  enforceSimulatedFallback?: boolean;
}

export interface GitHubScanSummary {
  tenantId: string;
  organization: string;
  scannedAt: string;
  verificationStatus: EvidenceVerificationStatus;
  repositoriesScanned: number;
  compliantCount: number;
  violationsCount: number;
  observations: GitHubEvidenceObservation[];
  ledgerSnapshotIds: string[];
}

/**
 * Executes a real or explicitly isolated verification scan across GitHub repositories.
 */
export async function executeGitHubSecurityScan(
  tenantId: string,
  options?: GitHubScanOptions
): Promise<GitHubScanSummary> {
  const token = options?.token || process.env.GITHUB_TOKEN || '';
  const organization = options?.organization || 'enterprise-compliance-org';
  const repoNames = options?.repositories || [
    'compliance-control-center-api',
    'compliance-frontend-portal',
    'payment-gateway-service'
  ];

  const scanTimestamp = new Date().toISOString();
  const observations: GitHubEvidenceObservation[] = [];
  const snapshotIds: string[] = [];

  const isLiveTokenAvailable = Boolean(token && token.trim().length > 0 && !options?.enforceSimulatedFallback);
  const verificationStatus: EvidenceVerificationStatus = isLiveTokenAvailable ? 'OBSERVED' : 'SIMULATED';

  for (const repo of repoNames) {
    let observation: GitHubEvidenceObservation;

    if (isLiveTokenAvailable) {
      try {
        // 1. Fetch Repository Metadata
        const repoHeaders = {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'SOC2-Compliance-Scanner/2026.2.0'
        };

        const repoRes = await fetch(`https://api.github.com/repos/${organization}/${repo}`, {
          headers: repoHeaders
        });

        if (!repoRes.ok) {
          throw new Error(`GitHub API HTTP ${repoRes.status} for ${organization}/${repo}`);
        }

        const repoData = await repoRes.json();
        const defaultBranch = repoData.default_branch || 'main';

        // 2. Fetch Branch Protection Rules
        let branchProtection: GitHubEvidenceObservation['branchProtection'] | undefined = undefined;
        const protectionRes = await fetch(
          `https://api.github.com/repos/${organization}/${repo}/branches/${defaultBranch}/protection`,
          { headers: repoHeaders }
        );

        if (protectionRes.ok) {
          const protData = await protectionRes.json();
          branchProtection = {
            required_approving_review_count: protData.required_pull_request_reviews?.required_approving_review_count || 0,
            dismiss_stale_reviews: Boolean(protData.required_pull_request_reviews?.dismiss_stale_reviews),
            require_code_owner_reviews: Boolean(protData.required_pull_request_reviews?.require_code_owner_reviews),
            allow_force_pushes: Boolean(protData.allow_force_pushes?.enabled),
            required_status_checks: protData.required_status_checks?.contexts || [],
            enforce_admins: Boolean(protData.enforce_admins?.enabled)
          };
        }

        // 3. Fetch Workflow Security Runs
        let workflowRuns: GitHubEvidenceObservation['workflowRuns'] = [];
        const actionsRes = await fetch(
          `https://api.github.com/repos/${organization}/${repo}/actions/runs?per_page=5`,
          { headers: repoHeaders }
        );
        if (actionsRes.ok) {
          const actionsData = await actionsRes.json();
          workflowRuns = (actionsData.workflow_runs || []).map((run: any) => ({
            id: run.id,
            name: run.name,
            status: run.status,
            conclusion: run.conclusion || 'pending',
            head_branch: run.head_branch
          }));
        }

        // 4. Fetch Secret Scanning Alerts (if authorized)
        let secretScanningAlerts: GitHubEvidenceObservation['secretScanningAlerts'] = [];
        const secretRes = await fetch(
          `https://api.github.com/repos/${organization}/${repo}/secret-scanning/alerts?per_page=5`,
          { headers: repoHeaders }
        );
        if (secretRes.ok) {
          const secretData = await secretRes.json();
          if (Array.isArray(secretData)) {
            secretScanningAlerts = secretData.map((alert: any) => ({
              number: alert.number,
              state: alert.state,
              secret_type: alert.secret_type
            }));
          }
        }

        // 5. Fetch Code Scanning (CodeQL) Alerts
        let codeScanningAlerts: GitHubEvidenceObservation['codeScanningAlerts'] = [];
        const codeScanRes = await fetch(
          `https://api.github.com/repos/${organization}/${repo}/code-scanning/alerts?per_page=5`,
          { headers: repoHeaders }
        );
        if (codeScanRes.ok) {
          const codeData = await codeScanRes.json();
          if (Array.isArray(codeData)) {
            codeScanningAlerts = codeData.map((alert: any) => ({
              number: alert.number,
              state: alert.state,
              rule_id: alert.rule?.id || 'sast-alert'
            }));
          }
        }

        const isCompliant = Boolean(
          branchProtection &&
          branchProtection.required_approving_review_count >= 1 &&
          !branchProtection.allow_force_pushes &&
          branchProtection.require_code_owner_reviews
        );

        const rawObsPayload = {
          tenantId,
          organization,
          repository: repo,
          visibility: repoData.visibility || 'private',
          defaultBranch,
          branchProtection,
          workflowRuns,
          secretScanningAlerts,
          codeScanningAlerts,
          isCompliant
        };

        const canonicalRecord = await createCanonicalEvidenceRecord({
          tenantId,
          controlId: 'CC8.1_CHANGE_MANAGEMENT',
          sourceSystem: `github.api:${organization}/${repo}`,
          rawPayload: rawObsPayload,
          previousEvidenceHash: 'GENESIS_BLOCK_0000000000000000',
          verificationStatus: 'OBSERVED',
          organization,
          repository: repo
        });

        observation = {
          tenantId,
          organization,
          repository: repo,
          control: 'CC8.1_BRANCH_PROTECTION',
          observationStatus: 'OBSERVED',
          repoVisibility: repoData.visibility,
          defaultBranch,
          branchProtection,
          workflowRuns,
          secretScanningAlerts,
          codeScanningAlerts,
          observationTimestamp: scanTimestamp,
          source: `https://api.github.com/repos/${organization}/${repo}`,
          evidenceHash: canonicalRecord.currentEvidenceHash
        };

        const snapshot = await multiTenantStore.recordSnapshot(
          tenantId,
          'CC8.1_GIT_BRANCH_PROTECTION',
          'github',
          `GitHub Repository Branch Protection (${repo}) [LIVE OBSERVED]`,
          rawObsPayload,
          isCompliant
        );
        snapshotIds.push(snapshot.id);
      } catch (err: any) {
        // Record observation as FAILED if live API error occurs
        const fallbackPayload = {
          tenantId,
          organization,
          repository: repo,
          error: err.message,
          scannedAt: scanTimestamp
        };
        const canonicalRecord = await createCanonicalEvidenceRecord({
          tenantId,
          controlId: 'CC8.1_CHANGE_MANAGEMENT',
          sourceSystem: `github.api:${organization}/${repo}`,
          rawPayload: fallbackPayload,
          previousEvidenceHash: 'GENESIS_BLOCK_0000000000000000',
          verificationStatus: 'FAILED',
          organization,
          repository: repo
        });

        observation = {
          tenantId,
          organization,
          repository: repo,
          control: 'CC8.1_BRANCH_PROTECTION',
          observationStatus: 'FAILED',
          observationTimestamp: scanTimestamp,
          source: `https://api.github.com/repos/${organization}/${repo}`,
          evidenceHash: canonicalRecord.currentEvidenceHash
        };
      }
    } else {
      // EXPLICIT SIMULATED TEST FIXTURE (Labeled strictly as SIMULATED, never pretending to be verified production evidence)
      const isSimulatedCompliant = repo !== 'payment-gateway-service';
      const simPayload = {
        tenantId,
        organization,
        repository: repo,
        simulationNote: 'TEST_SANDBOX_FIXTURE_NO_LIVE_GITHUB_TOKEN_CONFIGURED',
        defaultBranch: 'main',
        branchProtection: {
          required_approving_review_count: isSimulatedCompliant ? 2 : 0,
          dismiss_stale_reviews: isSimulatedCompliant,
          require_code_owner_reviews: isSimulatedCompliant,
          allow_force_pushes: !isSimulatedCompliant,
          required_status_checks: isSimulatedCompliant ? ['test-suite', 'trufflehog-secrets', 'sast-codeql'] : [],
          enforce_admins: isSimulatedCompliant
        },
        workflowRuns: [
          { id: 910283, name: 'Security & CI Pipeline', status: 'completed', conclusion: isSimulatedCompliant ? 'success' : 'failure', head_branch: 'main' }
        ],
        secretScanningAlerts: isSimulatedCompliant ? [] : [{ number: 1, state: 'open', secret_type: 'aws_access_key' }],
        codeScanningAlerts: [],
        isCompliant: isSimulatedCompliant
      };

      const canonicalRecord = await createCanonicalEvidenceRecord({
        tenantId,
        controlId: 'CC8.1_CHANGE_MANAGEMENT',
        sourceSystem: `simulation.sandbox:${organization}/${repo}`,
        rawPayload: simPayload,
        previousEvidenceHash: 'GENESIS_BLOCK_0000000000000000',
        verificationStatus: 'SIMULATED',
        organization,
        repository: repo,
        reproducibilityNotes: 'EXPLICIT TEST SIMULATION - Requires GITHUB_TOKEN for production verification.'
      });

      observation = {
        tenantId,
        organization,
        repository: repo,
        control: 'CC8.1_BRANCH_PROTECTION',
        observationStatus: 'SIMULATED',
        repoVisibility: 'private',
        defaultBranch: 'main',
        branchProtection: simPayload.branchProtection,
        workflowRuns: simPayload.workflowRuns,
        secretScanningAlerts: simPayload.secretScanningAlerts,
        observationTimestamp: scanTimestamp,
        source: `sandbox.simulation://${organization}/${repo}`,
        evidenceHash: canonicalRecord.currentEvidenceHash
      };

      const snapshot = await multiTenantStore.recordSnapshot(
        tenantId,
        'CC8.1_GIT_BRANCH_PROTECTION',
        'github',
        `GitHub Repository Branch Protection (${repo}) [SIMULATED SANDBOX]`,
        simPayload,
        isSimulatedCompliant
      );
      snapshotIds.push(snapshot.id);
    }

    observations.push(observation);
  }

  const compliantCount = observations.filter(
    (o) => o.branchProtection && o.branchProtection.required_approving_review_count >= 1 && !o.branchProtection.allow_force_pushes
  ).length;

  const violationsCount = observations.length - compliantCount;

  await auditLogStore.record({
    traceId: `trc_gh_scan_${Date.now().toString(36)}`,
    actorId: `github_scanner:${tenantId}`,
    action: 'github.repository_security_scanned',
    resource: `github:${organization}`,
    ipAddress: '127.0.0.1',
    status: 'SUCCESS',
    metadata: {
      tenantId,
      organization,
      verificationStatus,
      repositoriesScanned: observations.length,
      compliantCount,
      violationsCount,
      isLiveScan: isLiveTokenAvailable
    }
  });

  return {
    tenantId,
    organization,
    scannedAt: scanTimestamp,
    verificationStatus,
    repositoriesScanned: observations.length,
    compliantCount,
    violationsCount,
    observations,
    ledgerSnapshotIds: snapshotIds
  };
}
