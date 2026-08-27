import { PipelineRun, PipelineStep } from '../types/soc2';
import { auditLogStore } from './auditLogger';

export const SOC2_WORKFLOW_YAML = `name: SOC 2 Compliance & Security Checks

on:
  pull_request:
    branches: [ main ]
  push:
    branches: [ main ]

jobs:
  # 1. CC6.1: Secret Detection (Prevent hardcoded credentials)
  secret-scan:
    name: Secret Detection (TruffleHog)
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: TruffleHog Secret Scan
        uses: trufflesecurity/trufflehog-actions-experimental@v3.82.6
        with:
          path: ./
          base: \${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --debug --only-verified

  # 2. CC7.1: Software Composition Analysis / Dependency Scanning
  dependency-scan:
    name: Dependency Audit & Vulnerability Check
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'

      - name: Audit Production Dependencies
        run: npm audit --audit-level=high

      - name: Container & Filesystem Vulnerability Scan (Trivy)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          ignore-unfixed: true
          severity: 'CRITICAL,HIGH'
          exit-code: '1'

  # 3. CC7.1 / CC8.1: Static Application Security Testing (SAST) & Code Quality
  sast-scan:
    name: SAST Scan (CodeQL)
    runs-on: ubuntu-latest
    permissions:
      security-events: write
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Initialize CodeQL
        uses: github/codeql-action/init@v3
        with:
          languages: 'javascript-typescript'

      - name: Perform CodeQL Analysis
        uses: github/codeql-action/analyze@v3

  # 4. CC8.1: Build Verification & Automated Testing
  test-and-build:
    name: Automated Testing & Build Gate
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'

      - name: Install Dependencies
        run: npm ci

      - name: Run Unit & Integration Tests
        run: npm test -- --coverage

      - name: Verify Production Build
        run: npm run build`;

export const INITIAL_PIPELINE_RUNS: PipelineRun[] = [
  {
    runId: 'run_soc2_9942',
    commitHash: '8f2a1b9',
    branch: 'main',
    triggeredBy: 'jenngremicinc@gmail.com',
    startedAt: '2026-08-27T15:10:00Z',
    completedAt: '2026-08-27T15:13:22Z',
    status: 'passed',
    steps: [
      {
        id: 'step_1_secrets',
        name: 'Secret Detection (TruffleHog)',
        criteria: 'CC6.1',
        tool: 'trufflesecurity/trufflehog-actions-experimental@v3.82.6',
        status: 'success',
        durationMs: 34200,
        findingsCount: 0,
        logs: [
          'Checking out repository git tree...',
          'Loading TruffleHog detector suite (AWS, GCP, Stripe, RSA, GitHub, Slack tokens)...',
          'Scanning diff between main and HEAD (12 changed files)...',
          '✔ Scanned 1,420 lines of code. 0 verified secrets detected.',
          '✔ CC6.1 credential prevention check PASSED.'
        ]
      },
      {
        id: 'step_2_deps',
        name: 'Dependency Audit & Vulnerability Check',
        criteria: 'CC7.1',
        tool: 'npm audit + aquasecurity/trivy-action@master',
        status: 'success',
        durationMs: 51200,
        findingsCount: 0,
        logs: [
          'Running npm audit --audit-level=high...',
          'found 0 vulnerabilities (342 packages scanned)',
          'Initializing Trivy fs scanner (DB version: 2026.08.27)...',
          'Scanning filesystem for CVEs (CRITICAL, HIGH)...',
          '✔ Trivy analysis complete: 0 vulnerabilities found.',
          '✔ CC7.1 software composition analysis PASSED.'
        ]
      },
      {
        id: 'step_3_sast',
        name: 'Static Application Security Testing (CodeQL)',
        criteria: 'CC7.1, CC8.1',
        tool: 'github/codeql-action/analyze@v3',
        status: 'success',
        durationMs: 82100,
        findingsCount: 0,
        logs: [
          'Initializing CodeQL database for javascript-typescript...',
          'Compiling AST and taint-tracking graphs...',
          'Analyzing for SQLi, XSS, NoSQL Injection, Insecure Deserialization, SSRF...',
          '✔ CodeQL query execution finished. 0 alerts generated.',
          '✔ CC7.1/CC8.1 SAST compliance gate PASSED.'
        ]
      },
      {
        id: 'step_4_build',
        name: 'Automated Testing & Build Gate',
        criteria: 'CC8.1',
        tool: 'npm test --coverage && npm run build',
        status: 'success',
        durationMs: 44000,
        findingsCount: 0,
        logs: [
          'Running test suite with Vitest / Jest...',
          'PASS src/lib/auditLogger.test.ts (100% coverage)',
          'PASS src/lib/accessPolicy.test.ts (100% coverage)',
          'PASS src/lib/encryption.test.ts (100% coverage)',
          'Total coverage: 98.4% (Threshold: >80%)',
          'Executing production build (vite build)...',
          '✔ Production bundle compiled successfully.',
          '✔ CC8.1 build verification gate PASSED.'
        ]
      }
    ]
  }
];

export async function executePipelineSimulation(options: {
  branch?: string;
  injectSecret?: boolean;
  injectVulnerableDep?: boolean;
  actorId?: string;
  onStepProgress?: (step: PipelineStep, run: PipelineRun) => void;
}): Promise<PipelineRun> {
  const runId = `run_soc2_${Date.now().toString().slice(-4)}`;
  const commitHash = Math.random().toString(16).substring(2, 9);
  const branch = options.branch || 'feat/soc2-rbac-enhancement';
  const startedAt = new Date().toISOString();
  const actorId = options.actorId || 'jenngremicinc@gmail.com';

  const run: PipelineRun = {
    runId,
    commitHash,
    branch,
    triggeredBy: actorId,
    startedAt,
    status: 'running',
    steps: [
      {
        id: 'step_1_secrets',
        name: 'Secret Detection (TruffleHog)',
        criteria: 'CC6.1',
        tool: 'trufflesecurity/trufflehog-actions-experimental@v3.82.6',
        status: 'pending',
        logs: [],
        findingsCount: 0
      },
      {
        id: 'step_2_deps',
        name: 'Dependency Audit & Vulnerability Check',
        criteria: 'CC7.1',
        tool: 'npm audit + aquasecurity/trivy-action@master',
        status: 'pending',
        logs: [],
        findingsCount: 0
      },
      {
        id: 'step_3_sast',
        name: 'Static Application Security Testing (CodeQL)',
        criteria: 'CC7.1, CC8.1',
        tool: 'github/codeql-action/analyze@v3',
        status: 'pending',
        logs: [],
        findingsCount: 0
      },
      {
        id: 'step_4_build',
        name: 'Automated Testing & Build Gate',
        criteria: 'CC8.1',
        tool: 'npm test --coverage && npm run build',
        status: 'pending',
        logs: [],
        findingsCount: 0
      }
    ]
  };

  // Step 1: Secret Scan
  run.steps[0].status = 'running';
  options.onStepProgress?.(run.steps[0], run);
  await new Promise((r) => setTimeout(r, 600));

  if (options.injectSecret) {
    run.steps[0].status = 'failed';
    run.steps[0].findingsCount = 1;
    run.steps[0].logs = [
      'Checking out repository git tree...',
      'Loading TruffleHog detector suite...',
      '🚨 DETECTED VERIFIED SECRET in commit diff: AWS Secret Access Key (AKIAIOSFODNN7EXAMPLE)',
      'File: src/config/aws-legacy.ts:14',
      '❌ TruffleHog Secret Scan FAILED. SOC 2 CC6.1 violation prevents merge.'
    ];
    run.status = 'blocked';
    run.completedAt = new Date().toISOString();
    options.onStepProgress?.(run.steps[0], run);

    await auditLogStore.record({
      traceId: `trc_${commitHash}`,
      actorId,
      action: 'ci.security_gate.block',
      resource: 'GitHub_Actions_Workflow',
      ipAddress: '140.82.112.4',
      status: 'DENIED',
      metadata: {
        runId,
        branch,
        failedStep: 'secret-scan',
        criteria: 'CC6.1',
        reason: 'Hardcoded secret detected by TruffleHog'
      }
    });

    return run;
  } else {
    run.steps[0].status = 'success';
    run.steps[0].durationMs = 28400;
    run.steps[0].logs = [
      'Checking out repository git tree...',
      'Scanning diff between main and HEAD...',
      '✔ 0 verified secrets detected across 18 changed files.',
      '✔ CC6.1 credential prevention check PASSED.'
    ];
    options.onStepProgress?.(run.steps[0], run);
  }

  // Step 2: Dependency Scan
  run.steps[1].status = 'running';
  options.onStepProgress?.(run.steps[1], run);
  await new Promise((r) => setTimeout(r, 600));

  if (options.injectVulnerableDep) {
    run.steps[1].status = 'failed';
    run.steps[1].findingsCount = 2;
    run.steps[1].logs = [
      'Running npm audit --audit-level=high...',
      '🚨 Found 1 HIGH severity vulnerability in package: jsonwebtoken@8.5.1 (CVE-2022-23529)',
      'Trivy fs scan identified 1 CRITICAL CVE in base image: openssl@1.1.1 (CVE-2023-0286)',
      '❌ CC7.1 software composition scan FAILED. Vulnerable packages must be updated.'
    ];
    run.status = 'blocked';
    run.completedAt = new Date().toISOString();
    options.onStepProgress?.(run.steps[1], run);

    await auditLogStore.record({
      traceId: `trc_${commitHash}`,
      actorId,
      action: 'ci.security_gate.block',
      resource: 'GitHub_Actions_Workflow',
      ipAddress: '140.82.112.4',
      status: 'DENIED',
      metadata: {
        runId,
        branch,
        failedStep: 'dependency-scan',
        criteria: 'CC7.1',
        reason: 'High/Critical CVEs detected in dependencies'
      }
    });

    return run;
  } else {
    run.steps[1].status = 'success';
    run.steps[1].durationMs = 41200;
    run.steps[1].logs = [
      'Running npm audit --audit-level=high...',
      'found 0 vulnerabilities (342 dependencies scanned)',
      'Trivy scanning filesystem for CVEs (CRITICAL, HIGH)...',
      '✔ 0 vulnerabilities detected.',
      '✔ CC7.1 software composition analysis PASSED.'
    ];
    options.onStepProgress?.(run.steps[1], run);
  }

  // Step 3: SAST CodeQL
  run.steps[2].status = 'running';
  options.onStepProgress?.(run.steps[2], run);
  await new Promise((r) => setTimeout(r, 700));
  run.steps[2].status = 'success';
  run.steps[2].durationMs = 64000;
  run.steps[2].logs = [
    'Initializing CodeQL database for javascript-typescript...',
    'Analyzing code for security flaws (CWE-89, CWE-79, CWE-94, CWE-502)...',
    '✔ CodeQL query execution finished. 0 alerts found.',
    '✔ CC7.1/CC8.1 SAST compliance gate PASSED.'
  ];
  options.onStepProgress?.(run.steps[2], run);

  // Step 4: Test & Build Gate
  run.steps[3].status = 'running';
  options.onStepProgress?.(run.steps[3], run);
  await new Promise((r) => setTimeout(r, 600));
  run.steps[3].status = 'success';
  run.steps[3].durationMs = 38500;
  run.steps[3].logs = [
    'Running test suite with Vitest / Jest...',
    'PASS src/lib/auditLogger.test.ts',
    'PASS src/lib/accessPolicy.test.ts',
    'PASS src/lib/encryption.test.ts',
    'Test Coverage: 98.7% (Threshold: 80%)',
    'Building production bundle...',
    '✔ Vite build finished with 0 errors.',
    '✔ CC8.1 build verification gate PASSED.'
  ];
  options.onStepProgress?.(run.steps[3], run);

  run.status = 'passed';
  run.completedAt = new Date().toISOString();

  // Log successful pipeline run in audit store
  await auditLogStore.record({
    traceId: `trc_${commitHash}`,
    actorId,
    action: 'ci.security_gate.pass',
    resource: 'GitHub_Actions_Workflow',
    ipAddress: '140.82.112.4',
    status: 'SUCCESS',
    metadata: {
      runId,
      branch,
      commitHash,
      stepsPassed: 4,
      totalDurationMs: 172100,
      evidenceRecorded: true
    }
  });

  return run;
}
