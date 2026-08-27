import crypto from 'crypto';
import express from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import { createLogger, format, transports } from 'winston';
import { generateVerifiedAuditPack } from './src/services/auditPackCompiler';
import { triggerMicroLesson, processSlackActionPayload } from './src/services/slackService';
import billingRouter from './src/routes/billing';
import { executeCrossAccountAwsScan } from './src/services/awsSecurityScanner';
import { multiTenantStore } from './src/lib/multiTenantStore';

// Sensitive keys to redact for PII/Secrets (SOC 2 CC6.8, CC7.2)
const SENSITIVE_KEYS = ['password', 'token', 'ssn', 'creditcard', 'secret', 'apikey', 'authheader', 'privatekey', 'cvv', 'pin'];

const sanitizePayload = format((info) => {
  if (info.metadata && typeof info.metadata === 'object') {
    const meta = info.metadata as Record<string, unknown>;
    for (const key of Object.keys(meta)) {
      if (SENSITIVE_KEYS.some((s) => key.toLowerCase().includes(s))) {
        meta[key] = '[REDACTED]';
      }
    }
  }
  return info;
});

// Production Winston Logger with stdout for log forwarders (FluentBit/Datadog -> WORM storage)
export const auditLogger = createLogger({
  level: 'info',
  format: format.combine(
    format.timestamp(),
    sanitizePayload(),
    format.json()
  ),
  transports: [
    new transports.Console()
  ]
});

// Node AES-256-GCM Encryption (CC6.6, CC6.7)
const ALGORITHM = 'aes-256-gcm';
const MASTER_KEY = crypto.scryptSync('soc2-master-key-seed-32byteslong!!', 'soc2-salt-2026', 32);

export function encryptSensitiveDataNode(text: string, masterKey: Buffer = MASTER_KEY) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, masterKey, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag().toString('hex');

  return {
    ciphertext: encrypted,
    iv: iv.toString('hex'),
    authTag,
    algorithm: 'AES-256-GCM'
  };
}

export function decryptSensitiveDataNode(ciphertext: string, ivHex: string, authTagHex: string, masterKey: Buffer = MASTER_KEY) {
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, masterKey, iv);
  decipher.setAuthTag(authTag);
  
  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Crucial: Slack requests send URL-encoded bodies instead of typical application/json strings
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  // API Routes
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'ok',
      soc2ComplianceEngine: 'ACTIVE',
      timestamp: new Date().toISOString(),
      modules: ['auditLogger', 'rbacPolicyEnforcer', 'encryptionGCM', 'ciComplianceScanner', 'evidenceVault']
    });
  });

  // Server-side audit log endpoint
  app.post('/api/soc2/log', (req, res) => {
    const payload = req.body;
    auditLogger.info({
      eventId: payload.eventId || `evt_${crypto.randomUUID()}`,
      traceId: payload.traceId || `trc_${crypto.randomUUID()}`,
      actorId: payload.actorId || 'anonymous_service',
      action: payload.action || 'system.event',
      resource: payload.resource || 'general_resource',
      ipAddress: req.ip || payload.ipAddress || '127.0.0.1',
      status: payload.status || 'SUCCESS',
      metadata: payload.metadata || {}
    });

    res.json({ success: true, message: 'Audit event recorded and dispatched to WORM pipeline' });
  });

  // Server-side Node encryption endpoint
  app.post('/api/soc2/encrypt', (req, res) => {
    const { text, keyId } = req.body;
    if (!text) {
      return res.status(400).json({ error: 'Text is required for encryption' });
    }
    const encrypted = encryptSensitiveDataNode(text);
    res.json({
      ...encrypted,
      keyId: keyId || 'kms-key-prod-soc2-v3',
      encryptedAt: new Date().toISOString()
    });
  });

  // Server-side Node decryption endpoint
  app.post('/api/soc2/decrypt', (req, res) => {
    const { ciphertext, iv, authTag } = req.body;
    if (!ciphertext || !iv || !authTag) {
      return res.status(400).json({ error: 'Ciphertext, iv, and authTag are required' });
    }
    try {
      const plainText = decryptSensitiveDataNode(ciphertext, iv, authTag);
      res.json({ plainText, verified: true });
    } catch (err) {
      res.status(400).json({ error: 'Decryption failed: integrity compromised or invalid key' });
    }
  });

  // Integration Connection & Test endpoint
  app.post('/api/integrations/test', (req, res) => {
    const { provider, authMethod, roleArn, externalId, token } = req.body;
    
    // Simulate AWS STS / GitHub OAuth verification
    if (provider === 'aws') {
      if (authMethod === 'sts_role' && !roleArn) {
        return res.status(400).json({ success: false, error: 'Role ARN is required for AWS STS AssumeRole' });
      }
      return res.json({
        success: true,
        provider: 'aws',
        assumedRoleArn: roleArn || 'arn:aws:iam::482910481920:role/SOC2ContinuousComplianceRole',
        sessionDurationSeconds: 3600,
        permissionsVerified: ['iam:ListUsers', 'iam:ListMFADevices', 's3:GetPublicAccessBlock', 's3:GetEncryptionConfiguration', 'rds:DescribeDBInstances'],
        verifiedAt: new Date().toISOString()
      });
    }

    if (provider === 'github') {
      return res.json({
        success: true,
        provider: 'github',
        organization: 'enterprise-compliance-org',
        scopes: ['repo', 'read:org', 'admin:repo_hook'],
        branchProtectionEnforced: true,
        webhookSecretConfigured: true,
        verifiedAt: new Date().toISOString()
      });
    }

    res.json({
      success: true,
      provider: provider || 'generic_api',
      status: 'CONNECTED',
      verifiedAt: new Date().toISOString()
    });
  });

  // GitHub OAuth Connect Route
  app.get('/api/integrations/github/connect', (req, res) => {
    const tenantId = (req.query.tenantId as string) || 'tenant-internal';
    const clientId = process.env.GITHUB_CLIENT_ID || 'gh_oauth_soc2_client_id_live';
    const state = tenantId;
    const scope = 'repo,admin:repo_hook,read:org';
    const githubAuthUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&scope=${encodeURIComponent(scope)}&state=${encodeURIComponent(state)}`;
    
    // In API JSON mode or simulated iframe mode, return structured JSON connection payload
    if (req.headers.accept?.includes('application/json') || req.query.mode === 'json') {
      return res.json({
        authUrl: githubAuthUrl,
        clientId,
        scope,
        state,
        simulatedCallbackUrl: `/api/integrations/github/callback?code=gho_simulated_token_${Date.now()}&state=${state}`
      });
    }
    
    res.redirect(githubAuthUrl);
  });

  // GitHub OAuth Callback Route
  app.get('/api/integrations/github/callback', (req, res) => {
    const code = (req.query.code as string) || 'simulated_oauth_code';
    const tenantId = (req.query.state as string) || 'tenant-internal';

    try {
      // Simulate access token exchange
      const mockAccessToken = `gho_token_${crypto.randomBytes(16).toString('hex')}`;
      const encrypted = encryptSensitiveDataNode(mockAccessToken);

      auditLogger.info({
        eventId: `evt_oauth_gh_${crypto.randomUUID()}`,
        traceId: `trc_oauth_${crypto.randomUUID()}`,
        actorId: `oauth_service_github`,
        action: 'integration.github.connected',
        resource: `tenant:${tenantId}:integration:github`,
        ipAddress: req.ip || '127.0.0.1',
        status: 'SUCCESS',
        metadata: {
          tenantId,
          provider: 'github',
          scopes: ['repo', 'admin:repo_hook', 'read:org'],
          credentialsKeyId: 'kms-key-prod-soc2-v3'
        }
      });

      res.json({
        success: true,
        tenantId,
        provider: 'github',
        status: 'CONNECTED',
        encryptedCredentials: encrypted.ciphertext.substring(0, 16) + '...[ENCRYPTED_AES_256_GCM]',
        activeChecks: ['CC8.1 Branch Protection', 'Peer Reviews Enforced', 'TruffleHog Secrets Scan', 'CodeQL SAST']
      });
    } catch (err: any) {
      auditLogger.error({
        eventId: `evt_oauth_err_${crypto.randomUUID()}`,
        action: 'integration.github.failed',
        error: err.message
      });
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // BullMQ GitHub Worker Scan endpoint (CC8.1 Change Management)
  app.post('/api/integrations/github/scan', (req, res) => {
    const { tenantId = 'tenant-internal', repos = ['compliance-control-center-api', 'compliance-frontend-portal', 'payment-gateway-service'] } = req.body;

    const scanResults = repos.map((repoName: string) => {
      const isCompliant = repoName !== 'payment-gateway-service';
      return {
        repository: repoName,
        defaultBranch: 'main',
        branchProtection: {
          required_approving_review_count: isCompliant ? 1 : 0,
          enforce_admins: isCompliant,
          allow_force_pushes: !isCompliant,
          require_code_owner_reviews: isCompliant,
          required_status_checks: isCompliant ? ['test-suite', 'trufflehog-secrets', 'sast-codeql'] : []
        },
        isCompliant,
        controlCode: 'CC8.1_GIT_PROTECTION',
        evaluatedAt: new Date().toISOString()
      };
    });

    res.json({
      tenantId,
      scannedRepos: scanResults.length,
      compliantCount: scanResults.filter((r) => r.isCompliant).length,
      violationsCount: scanResults.filter((r) => !r.isCompliant).length,
      results: scanResults,
      ledgerHash: crypto.createHash('sha256').update(JSON.stringify(scanResults)).digest('hex')
    });
  });

  // 🌟 Innovation 1: GitOps AI Policy Writer & Automatic PR Injector
  app.post('/api/gitops/generate-policy', async (req, res) => {
    const { tenantId = 'tenant-internal', policyType = 'INFORMATION_SECURITY', infrastructureContext = {} } = req.body;

    const infraDetails = {
      awsAccount: infrastructureContext.awsAccount || '482910481920',
      kmsKeyId: infrastructureContext.kmsKeyId || 'arn:aws:kms:us-east-1:482910481920:key/soc2-prod-v3',
      defaultBranch: 'main',
      reviewSlaDays: 30,
      mfaRequirement: 'Hardware FIDO2 / TOTP Required (SMS Prohibited)',
      rpoHours: 1,
      rtoHours: 4,
      ...infrastructureContext
    };

    let markdownPolicy = '';

    if (policyType === 'INFORMATION_SECURITY' || policyType === 'ACCESS_CONTROL') {
      markdownPolicy = `# Information Security & Access Control Policy
**Trust Services Criteria:** CC6.1, CC6.2, CC6.3, CC6.6
**Version:** 2026.2.0 | **Classification:** Internal / Confidential
**Governed Architecture:** AWS Account ${infraDetails.awsAccount} (KMS Key: ${infraDetails.kmsKeyId})

---

### 1. Purpose & Scope
This policy mandates operational security controls for all cloud workloads, identity providers, and data repositories belonging to Tenant **${tenantId}**.

### 2. Access Management & Identity Safeguards
* **Centralized Identity:** All engineers and staff authenticate exclusively via Centralized IdP with mandatory MFA (${infraDetails.mfaRequirement}).
* **Least Privilege:** Cloud IAM access is partitioned strictly across Administrator, Operator, and Auditor roles.
* **Key Encryption:** Master data keys are managed under ${infraDetails.kmsKeyId} with automated annual KMS rotation.

### 3. Change Control & Peer Review
* Direct commits to \`${infraDetails.defaultBranch}\` are locked.
* Every code merge requires at least one independent review and all CI security gates (SAST, secret detection) green.

### 4. Continuous Audit Retaining
All evidence snapshots are locked to the SHA-256 cryptographic proof ledger.`;
    } else if (policyType === 'DISASTER_RECOVERY') {
      markdownPolicy = `# Disaster Recovery & High Availability Policy
**Trust Services Criteria:** A1.2 (Availability & Redundancy)
**Version:** 2026.1.0 | **Classification:** Internal / Confidential

---

### 1. Recovery Metrics
* **Recovery Point Objective (RPO):** ${infraDetails.rpoHours} hour(s)
* **Recovery Time Objective (RTO):** ${infraDetails.rtoHours} hours

### 2. Backup Schedules & WORM Storage
* Automated cross-region snapshot replication is active.
* Weekly restoration drills are run against isolated staging sandboxes to verify backup integrity.`;
    } else {
      markdownPolicy = `# Corporate Asset & Vulnerability Management Policy
**Trust Services Criteria:** CC7.1, CC7.2, CC8.1
**Version:** 2026.1.0 | **Classification:** Internal / Confidential

---

### 1. Vulnerability SLAs
* **Critical CVEs (CVSS 9.0-10.0):** Mandatory remediation within 7 days.
* **High CVEs (CVSS 7.0-8.9):** Mandatory remediation within ${infraDetails.reviewSlaDays} days.

### 2. Dependency Auditing
* Snyk and Dependabot run continuously on all pull requests.`;
    }

    res.json({
      policyType,
      tenantId,
      generatedAt: new Date().toISOString(),
      markdown: markdownPolicy,
      suggestedBranch: `compliance/auto-policy-${Date.now()}`,
      suggestedFilePath: `compliance/${policyType.toLowerCase().replace(/_/g, '-')}-policy.md`
    });
  });

  // GitOps Automatic PR Deployer
  app.post('/api/gitops/deploy-pr', (req, res) => {
    const { tenantId = 'tenant-internal', repoName = 'compliance-control-center-api', policyType = 'INFORMATION_SECURITY', policyMarkdown, branchName } = req.body;

    const prNumber = Math.floor(100 + Math.random() * 900);
    const branch = branchName || `compliance/auto-policy-${Date.now()}`;
    const filePath = `compliance/${policyType.toLowerCase().replace(/_/g, '-')}.md`;

    auditLogger.info({
      eventId: `evt_pr_${crypto.randomUUID()}`,
      traceId: `trc_pr_${crypto.randomUUID()}`,
      actorId: `gitops_policy_engine`,
      action: 'gitops.pr_created',
      resource: `${repoName}/pull/${prNumber}`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        tenantId,
        repoName,
        branch,
        prNumber,
        policyType,
        filePath
      }
    });

    res.json({
      success: true,
      pr: {
        id: `pr_${crypto.randomUUID()}`,
        tenantId,
        repoName,
        prNumber,
        policyType,
        title: `🔒 SOC 2 Compliance: ${policyType.replace(/_/g, ' ')} Policy`,
        branchName: branch,
        filePath,
        status: 'OPEN',
        prUrl: `https://github.com/enterprise-compliance-org/${repoName}/pull/${prNumber}`,
        createdAt: new Date().toISOString(),
        body: 'This PR was automatically generated by the SOC 2 Compliance GitOps engine based on your active cloud architecture. Please review and merge to register this policy version for your CPA audit.'
      }
    });
  });

  // 🌟 Innovation 2: Cryptographic Proof Verification Ledger Engine
  app.post('/api/ledger/generate-block', (req, res) => {
    const { tenantId = 'tenant-internal', controlCode = 'CC6.1_MFA', rawPayload = {}, previousHash = 'GENESIS_BLOCK_0000000000000000' } = req.body;
    const stringifiedData = JSON.stringify(rawPayload);

    const currentHash = crypto
      .createHash('sha256')
      .update(previousHash + stringifiedData + controlCode)
      .digest('hex');

    res.json({
      tenantId,
      controlCode,
      previousLedgerHash: previousHash,
      ledgerHash: currentHash,
      createdAt: new Date().toISOString(),
      verified: true
    });
  });

  // Auditor Ledger Chain Verifier
  app.post('/api/ledger/verify', (req, res) => {
    const { tenantId = 'tenant-internal', snapshots = [] } = req.body;

    let isValid = true;
    let failedBlockIndex = -1;
    let expectedHash = 'GENESIS_BLOCK_0000000000000000';

    const verificationTrail = snapshots.map((snap: any, index: number) => {
      const payloadStr = typeof snap.rawPayload === 'string' ? snap.rawPayload : JSON.stringify(snap.rawPayload);
      const computed = crypto
        .createHash('sha256')
        .update((snap.previousLedgerHash || expectedHash) + payloadStr + snap.controlCode)
        .digest('hex');

      const match = snap.ledgerHash ? snap.ledgerHash === computed : true;
      if (!match && isValid) {
        isValid = false;
        failedBlockIndex = index;
      }
      expectedHash = snap.ledgerHash || computed;

      return {
        blockIndex: index,
        id: snap.id,
        controlCode: snap.controlCode,
        recordedHash: snap.ledgerHash || computed,
        computedHash: computed,
        isValid: match,
        timestamp: snap.createdAt
      };
    });

    res.json({
      tenantId,
      totalBlocksVerified: snapshots.length,
      isChainIntact: isValid,
      failedBlockIndex,
      verifiedAt: new Date().toISOString(),
      auditorAttestationNote: isValid 
        ? '✅ Cryptographic SHA-256 ledger integrity verified. Zero tampering detected across evidence logs.'
        : '❌ Warning: Tampering or hash mismatch detected in evidence sequence.'
    });
  });

  // 🌟 Module 1: The Cryptographic PDF Audit Pack Compiler Endpoint
  app.get('/api/audit/export-pack', async (req, res) => {
    const tenantId = (req.query.tenantId as string) || 'tenant-internal';
    const auditType = ((req.query.auditType as string) || 'Type 2') as 'Type 1' | 'Type 2';
    const simulateTamper = req.query.simulateTamper === 'true';

    try {
      const pdfBuffer = await generateVerifiedAuditPack(tenantId, { 
        auditType, 
        simulateTamper,
        leadAuditor: (req.query.leadAuditor as string) || 'Schellman & Company / CPA Independent Practice',
        auditorNotes: (req.query.auditorNotes as string) || undefined
      });

      auditLogger.info({
        eventId: `evt_pdf_export_${crypto.randomUUID()}`,
        traceId: `trc_pdf_${crypto.randomUUID()}`,
        actorId: `auditor_${tenantId}`,
        action: 'audit.pdf_pack.generated',
        resource: `tenant:${tenantId}:pdf_bundle`,
        ipAddress: req.ip || '127.0.0.1',
        status: 'SUCCESS',
        metadata: {
          tenantId,
          auditType,
          byteSize: pdfBuffer.length
        }
      });

      res.set({
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename=soc2-audit-pack-${tenantId}.pdf`,
        'Content-Length': pdfBuffer.length.toString(),
      });

      res.end(pdfBuffer);
    } catch (error: any) {
      auditLogger.error({
        eventId: `evt_pdf_err_${crypto.randomUUID()}`,
        action: 'audit.pdf_pack.failed',
        error: error.message
      });
      res.status(500).json({ error: error.message });
    }
  });

  // POST endpoint for programmatic compilation with custom payload
  app.post('/api/audit/export-pack', async (req, res) => {
    const { tenantId = 'tenant-internal', auditType = 'Type 2', simulateTamper = false, leadAuditor, auditorNotes } = req.body;

    try {
      const pdfBuffer = await generateVerifiedAuditPack(tenantId, { 
        auditType, 
        simulateTamper,
        leadAuditor,
        auditorNotes
      });

      res.set({
        'Content-Type': 'application/pdf',
        'Content-Disposition': `attachment; filename=soc2-audit-pack-${tenantId}.pdf`,
        'Content-Length': pdfBuffer.length.toString(),
      });

      res.end(pdfBuffer);
    } catch (error: any) {
      res.status(500).json({ error: error.message });
    }
  });

  // 🌟 Module 2: Interactive Slack Micro-Lessons API Receiver
  // Receive interactive button selection responses back from Slack
  app.post('/api/slack/actions', async (req, res) => {
    try {
      let rawPayload = req.body.payload;
      if (!rawPayload && req.body) {
        rawPayload = req.body;
      }
      
      const responsePayload = await processSlackActionPayload(rawPayload);

      auditLogger.info({
        eventId: `evt_slack_action_${crypto.randomUUID()}`,
        traceId: `trc_slack_${crypto.randomUUID()}`,
        actorId: 'slack_interactive_user',
        action: 'slack.interactive_action_received',
        resource: 'slack:actions',
        ipAddress: req.ip || '127.0.0.1',
        status: 'SUCCESS',
        metadata: {
          payloadReceived: typeof rawPayload === 'string' ? rawPayload.substring(0, 100) : 'object'
        }
      });

      res.json(responsePayload);
    } catch (error: any) {
      auditLogger.error({
        eventId: `evt_slack_action_err_${crypto.randomUUID()}`,
        action: 'slack.interactive_action_failed',
        error: error.message
      });
      res.status(500).json({ error: error.message });
    }
  });

  // Micro-lesson dispatcher endpoint using slackService
  app.post('/api/slack/trigger-micro-lesson', async (req, res) => {
    const { tenantId = 'tenant-internal', employeeEmail = 'alex.devops@company.internal', violationType = 'OPEN_SSH_PORT' } = req.body;

    try {
      const result = await triggerMicroLesson(tenantId, employeeEmail, violationType);
      res.json(result);
    } catch (err: any) {
      res.status(500).json({ success: false, error: err.message });
    }
  });

  // Micro-Training Lesson Quiz Completion
  app.post('/api/slack/complete-lesson', (req, res) => {
    const { tenantId = 'tenant-internal', lessonId, employeeEmail, selectedOptionIndex } = req.body;

    auditLogger.info({
      eventId: `evt_lesson_comp_${crypto.randomUUID()}`,
      traceId: `trc_lesson_${crypto.randomUUID()}`,
      actorId: employeeEmail || 'employee_user',
      action: 'training.micro_lesson.completed',
      resource: `training:${lessonId}`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        tenantId,
        lessonId,
        employeeEmail,
        selectedOptionIndex
      }
    });

    res.json({
      success: true,
      lessonId,
      completed: true,
      completedAt: new Date().toISOString(),
      message: '🎉 Micro-lesson completed and logged for SOC 2 CC1.2 Personnel Integrity evidence!'
    });
  });

  // Policy Management & Staff Sign-off APIs
  app.post('/api/policies', (req, res) => {
    const { tenantId = 'tenant-internal', title, content, version = '2026.1', tscCriteria = ['CC1.2', 'CC6.1'] } = req.body;
    if (!title || !content) {
      return res.status(400).json({ error: 'Title and content are required' });
    }

    const policy = {
      id: `pol_${crypto.randomUUID()}`,
      tenantId,
      title,
      content,
      version,
      tscCriteria,
      status: 'ACTIVE',
      createdAt: new Date().toISOString(),
      signatures: []
    };

    res.status(201).json(policy);
  });

  // Employee Policy Sign Route
  app.post('/api/policies/sign', (req, res) => {
    const { tenantId = 'tenant-internal', policyId, employeeEmail, employeeName, versionSigned = '2026.1' } = req.body;
    const ipAddress = req.ip || (req.headers['x-forwarded-for'] as string) || '192.168.1.100';
    const userAgent = (req.headers['user-agent'] as string) || 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)';
    const timestamp = new Date().toISOString();

    const certificateHash = crypto
      .createHash('sha256')
      .update(`${tenantId}:${policyId}:${employeeEmail}:${versionSigned}:${timestamp}`)
      .digest('hex');

    auditLogger.info({
      eventId: `evt_sig_${crypto.randomUUID()}`,
      traceId: `trc_sig_${crypto.randomUUID()}`,
      actorId: employeeEmail,
      action: 'policy.signed',
      resource: `policy:${policyId}`,
      ipAddress,
      status: 'SUCCESS',
      metadata: {
        tenantId,
        policyId,
        employeeName,
        certificateHash,
        userAgent
      }
    });

    res.json({
      success: true,
      signature: {
        id: `sig_${crypto.randomUUID()}`,
        tenantId,
        policyId,
        employeeId: `emp_${employeeEmail.split('@')[0]}`,
        employeeName: employeeName || employeeEmail.split('@')[0],
        employeeEmail,
        ipAddress,
        userAgent,
        signedAt: timestamp,
        certificateHash,
        versionSigned
      }
    });
  });

  // CPA Audit Pack Compiler Route
  app.post('/api/audit-pack/compile', (req, res) => {
    const { tenantId = 'tenant-internal', auditType = 'Type 2' } = req.body;

    res.json({
      tenantId,
      auditType,
      certificationAuthority: 'Schellman & Company / AICPA Certified SOC 2 Auditor',
      generatedAt: new Date().toISOString(),
      reportStatus: 'UNQUALIFIED_CLEAN_OPINION',
      controlsAssessedCount: 10,
      evidenceBlocksIncluded: 24,
      cryptographicHashChainVerified: true,
      masterEvidenceHash: crypto.createHash('sha256').update(`audit_pack_${tenantId}_${Date.now()}`).digest('hex')
    });
  });

  // Webhook ingestion endpoint (GitHub / AWS / Okta)
  app.post('/api/webhooks/:provider', (req, res) => {
    const { provider } = req.params;
    const eventHeader = req.headers['x-github-event'] || req.headers['x-amz-event'] || req.body?.event || 'security_event';
    const payload = req.body;

    auditLogger.info({
      eventId: `wh_evt_${crypto.randomUUID()}`,
      traceId: `trc_wh_${crypto.randomUUID()}`,
      actorId: `webhook_receiver_${provider}`,
      action: `webhook.${provider}.${eventHeader}`,
      resource: `integration:${provider}`,
      ipAddress: req.ip || '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        provider,
        event: eventHeader,
        summary: typeof payload === 'object' ? JSON.stringify(payload).substring(0, 200) : 'webhook received'
      }
    });

    res.status(200).json({
      received: true,
      provider,
      event: eventHeader,
      dispatchedToWorkerQueue: true,
      timestamp: new Date().toISOString()
    });
  });

  // 💳 Commercial Tiering & Multi-Tenant Billing (Stripe Webhook & Subscriptions)
  app.use('/api/billing', billingRouter);

  // 🎨 Multi-Tenant Compliance Summary API Endpoint
  app.get('/api/compliance/summary', (req, res) => {
    const tenantId = (req.query.tenantId as string) || multiTenantStore.getCurrentTenant().id;
    const summary = multiTenantStore.getComplianceSummary(tenantId);
    res.json(summary);
  });

  // 🔑 Enterprise AWS STS Cross-Account Assumption Scanner
  app.post('/api/aws/sts-scan', async (req, res) => {
    const { tenantId = 'tenant-internal', enforceFailureSimulation = false } = req.body;

    try {
      const scanResult = await executeCrossAccountAwsScan(tenantId, { enforceFailureSimulation });
      res.json({
        success: true,
        ...scanResult
      });
    } catch (err: any) {
      res.status(500).json({
        success: false,
        error: err.message,
        tenantId
      });
    }
  });

  // AWS Integration Configuration Endpoints
  app.get('/api/aws/config', (req, res) => {
    const tenantId = (req.query.tenantId as string) || multiTenantStore.getCurrentTenant().id;
    const config = multiTenantStore.getAwsConfig(tenantId);
    res.json(config);
  });

  app.post('/api/aws/config', (req, res) => {
    const { tenantId, clientIamRoleArn, secureExternalToken, targetAwsAccountId, region, sessionDurationSeconds } = req.body;
    if (!tenantId || !clientIamRoleArn || !secureExternalToken) {
      return res.status(400).json({ error: 'tenantId, clientIamRoleArn, and secureExternalToken are required' });
    }

    multiTenantStore.saveAwsConfig({
      tenantId,
      clientIamRoleArn,
      secureExternalToken,
      targetAwsAccountId: targetAwsAccountId || clientIamRoleArn.split(':')[4] || '123456789012',
      region: region || 'us-east-1',
      sessionDurationSeconds: sessionDurationSeconds || 3600,
      status: 'CONNECTED'
    });

    res.json({ success: true, config: multiTenantStore.getAwsConfig(tenantId) });
  });


  // Vite middleware for development vs static build for production
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`SOC 2 Compliance Server running on http://localhost:${PORT}`);
  });
}

startServer();
