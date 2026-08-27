import { 
  Tenant, 
  Integration, 
  EvidenceSnapshot, 
  ComplianceIssue, 
  WorkerJob, 
  WebhookEventLog, 
  SteampipeTableDef,
  IntegrationProvider,
  Employee,
  StaffPolicySignature,
  AutomatedPR,
  MicroLessonLog,
  AccountStatus,
  SubscriptionTier,
  AwsIntegrationConfig,
  IssueSeverity,
  IssueStatus
} from '../types/soc2';
import { auditLogStore } from './auditLogger';

// Helper to generate SHA-256 for WORM Evidence Snapshots & Cryptographic Ledger
async function computeSha256(data: string): Promise<string> {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle) {
    const msgUint8 = new TextEncoder().encode(data);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  let hash = 0;
  for (let i = 0; i < data.length; i++) {
    const char = data.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return `worm_sha256_${Math.abs(hash).toString(16).padStart(16, '0')}`;
}

export const INITIAL_TENANTS: Tenant[] = [
  {
    id: 'tenant-internal',
    name: 'Our Company (Internal Audit)',
    slug: 'our-company-dogfood',
    mode: 'internal',
    createdAt: '2026-01-15T09:00:00Z',
    complianceScore: 100,
    contactEmail: 'jenngremicinc@gmail.com',
    awsAccountId: '482910481920',
    externalId: 'soc2-dogfood-prod-994821',
    clientIamRoleArn: 'arn:aws:iam::482910481920:role/SOC2ContinuousComplianceRole',
    secureExternalToken: 'soc2-dogfood-prod-994821',
    accountStatus: 'ACTIVE',
    subscriptionTier: 'enterprise',
    stripeCustomerId: 'cus_dogfood_internal_99182',
    stripeSubscriptionId: 'sub_live_ent_8849102',
    workersActive: true
  },
  {
    id: 'tenant-acme',
    name: 'Acme FinTech Corp',
    slug: 'acme-fintech',
    mode: 'commercial',
    createdAt: '2026-04-10T14:30:00Z',
    complianceScore: 78,
    contactEmail: 'security@acmefintech.io',
    awsAccountId: '918239019231',
    externalId: 'soc2-acme-tenant-882190',
    clientIamRoleArn: 'arn:aws:iam::918239019231:role/AcmeComplianceRole',
    secureExternalToken: 'soc2-acme-tenant-882190',
    accountStatus: 'ACTIVE',
    subscriptionTier: 'growth',
    stripeCustomerId: 'cus_acme_fintech_774910',
    stripeSubscriptionId: 'sub_live_growth_992819',
    workersActive: true
  },
  {
    id: 'tenant-nova',
    name: 'Nova Health Cloud',
    slug: 'nova-health',
    mode: 'commercial',
    createdAt: '2026-06-01T11:15:00Z',
    complianceScore: 86,
    contactEmail: 'compliance@novahealth.org',
    awsAccountId: '772183901293',
    externalId: 'soc2-nova-tenant-119302',
    clientIamRoleArn: 'arn:aws:iam::772183901293:role/NovaHealthComplianceRole',
    secureExternalToken: 'soc2-nova-tenant-119302',
    accountStatus: 'ACTIVE',
    subscriptionTier: 'starter',
    stripeCustomerId: 'cus_nova_health_663910',
    stripeSubscriptionId: 'sub_live_starter_551902',
    workersActive: true
  }
];

export const INITIAL_INTEGRATIONS: Record<string, Integration[]> = {
  'tenant-internal': [
    {
      id: 'int-aws-internal',
      tenantId: 'tenant-internal',
      provider: 'aws',
      name: 'AWS Production (Primary)',
      authMethod: 'sts_role',
      roleArn: 'arn:aws:iam::482910481920:role/SOC2ContinuousComplianceRole',
      externalId: 'soc2-dogfood-prod-994821',
      region: 'us-east-1',
      credentialsMasked: 'STS-AssumeRole:arn:aws:iam::482910481920:role/SOC2ContinuousComplianceRole (AES-256-GCM encrypted)',
      status: 'connected',
      lastSyncAt: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
      syncIntervalMinutes: 60,
      activeChecks: ['IAM MFA', 'S3 Public Block', 'RDS Encryption', 'Security Groups Port 22/3389', 'KMS Master Key Rotation']
    },
    {
      id: 'int-gh-internal',
      tenantId: 'tenant-internal',
      provider: 'github',
      name: 'GitHub Organization (Main)',
      authMethod: 'oauth_token',
      credentialsMasked: 'ghp_live_token_•••••••••••••••••••••••• (AES-256-GCM encrypted)',
      status: 'connected',
      lastSyncAt: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
      syncIntervalMinutes: 30,
      activeChecks: ['Branch Protection on main', '1+ Peer Review Enforcement', 'No Direct Commits/Force Push', 'CodeQL SAST Gating', 'Webhook Alerts Active']
    },
    {
      id: 'int-gw-internal',
      tenantId: 'tenant-internal',
      provider: 'google_workspace',
      name: 'Google Workspace Directory',
      authMethod: 'api_key',
      credentialsMasked: 'gsuite_service_account_key_•••••••• (AES-256-GCM encrypted)',
      status: 'connected',
      lastSyncAt: new Date(Date.now() - 1000 * 60 * 25).toISOString(),
      syncIntervalMinutes: 60,
      activeChecks: ['Directory MFA Enforced (100%)', 'Offboarded Staff 0 Active Keys', '24h SLA Revocation Verified']
    },
    {
      id: 'int-snyk-internal',
      tenantId: 'tenant-internal',
      provider: 'snyk',
      name: 'Snyk Vulnerability Intelligence',
      authMethod: 'api_key',
      credentialsMasked: 'snyk_api_token_•••••••••••••••••••• (AES-256-GCM encrypted)',
      status: 'connected',
      lastSyncAt: new Date(Date.now() - 1000 * 60 * 40).toISOString(),
      syncIntervalMinutes: 120,
      activeChecks: ['High/Critical CVE 30-day SLA Tracker', 'Container Image Vulnerabilities', 'License Compliance Checks']
    }
  ],
  'tenant-acme': [
    {
      id: 'int-aws-acme',
      tenantId: 'tenant-acme',
      provider: 'aws',
      name: 'AWS Banking Core (us-west-2)',
      authMethod: 'sts_role',
      roleArn: 'arn:aws:iam::918239019231:role/AcmeComplianceRole',
      externalId: 'soc2-acme-tenant-882190',
      region: 'us-west-2',
      credentialsMasked: 'STS-AssumeRole:arn:aws:iam::918239019231:role/AcmeComplianceRole (AES-256-GCM encrypted)',
      status: 'connected',
      lastSyncAt: new Date(Date.now() - 1000 * 60 * 55).toISOString(),
      syncIntervalMinutes: 60,
      activeChecks: ['IAM MFA', 'S3 Public Block', 'RDS Encryption', 'Security Groups Port 22/3389']
    },
    {
      id: 'int-gh-acme',
      tenantId: 'tenant-acme',
      provider: 'github',
      name: 'Acme GitHub Enterprise',
      authMethod: 'oauth_token',
      credentialsMasked: 'ghp_enterprise_token_•••••••••••• (AES-256-GCM encrypted)',
      status: 'connected',
      lastSyncAt: new Date(Date.now() - 1000 * 60 * 45).toISOString(),
      syncIntervalMinutes: 30,
      activeChecks: ['Branch Protection on main', 'Peer Review Enforcement']
    },
    {
      id: 'int-okta-acme',
      tenantId: 'tenant-acme',
      provider: 'okta',
      name: 'Acme Okta SSO & Directory',
      authMethod: 'api_key',
      credentialsMasked: '00okta_api_token_•••••••••••••••• (AES-256-GCM encrypted)',
      status: 'connected',
      lastSyncAt: new Date(Date.now() - 1000 * 60 * 60).toISOString(),
      syncIntervalMinutes: 60,
      activeChecks: ['Okta MFA Policy', 'Offboarding SLA Tracker']
    }
  ],
  'tenant-nova': [
    {
      id: 'int-aws-nova',
      tenantId: 'tenant-nova',
      provider: 'aws',
      name: 'Nova HIPAA-Compliant AWS VPC',
      authMethod: 'sts_role',
      roleArn: 'arn:aws:iam::772183901293:role/NovaHealthComplianceRole',
      externalId: 'soc2-nova-tenant-119302',
      region: 'us-east-1',
      credentialsMasked: 'STS-AssumeRole:arn:aws:iam::772183901293:role/NovaHealthComplianceRole',
      status: 'connected',
      lastSyncAt: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
      syncIntervalMinutes: 60,
      activeChecks: ['IAM MFA', 'S3 Encryption', 'RDS Snapshot PITR']
    }
  ]
};

// Initial Evidence Snapshots (Raw API Payloads)
export const INITIAL_SNAPSHOTS: Record<string, EvidenceSnapshot[]> = {
  'tenant-internal': [
    {
      id: 'snp-aws-mfa-internal',
      tenantId: 'tenant-internal',
      controlCode: 'CC6.1_MFA',
      provider: 'aws',
      title: 'AWS IAM ListUsers & ListMFADevices State',
      createdAt: '2026-08-27T14:30:00Z',
      sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      recordCount: 14,
      isCompliant: true,
      rawPayload: [
        {
          UserName: 'jenngremicinc@gmail.com',
          UserId: 'AIDA482910481920JENN',
          Arn: 'arn:aws:iam::482910481920:user/jenngremicinc@gmail.com',
          CreateDate: '2026-01-10T12:00:00Z',
          PasswordLastUsed: '2026-08-27T14:10:00Z',
          MFAEnabled: true,
          MFADevices: [
            {
              SerialNumber: 'arn:aws:iam::482910481920:mfa/jenn-yubikey-fido2',
              EnableDate: '2026-01-10T12:15:00Z'
            }
          ],
          AccessKeys: []
        },
        {
          UserName: 'svc_ci_cd_deployment_agent',
          UserId: 'AIDA482910481920SVC1',
          Arn: 'arn:aws:iam::482910481920:user/svc_ci_cd_deployment_agent',
          CreateDate: '2026-01-15T08:00:00Z',
          MFAEnabled: true, // Machine role via STS AssumeRole
          MFADevices: [{ SerialNumber: 'virtual_device_sts_session', EnableDate: '2026-01-15T08:00:00Z' }],
          AccessKeys: [{ AccessKeyId: 'AKIA482910481920SVC1', Status: 'Active', CreateDate: '2026-01-15T08:00:00Z' }]
        },
        {
          UserName: 'alex.devops@company.internal',
          UserId: 'AIDA482910481920ALEX',
          Arn: 'arn:aws:iam::482910481920:user/alex.devops@company.internal',
          CreateDate: '2026-02-01T10:00:00Z',
          PasswordLastUsed: '2026-08-27T13:40:00Z',
          MFAEnabled: true,
          MFADevices: [{ SerialNumber: 'arn:aws:iam::482910481920:mfa/alex-totp-authenticator', EnableDate: '2026-02-01T10:10:00Z' }],
          AccessKeys: []
        }
      ]
    },
    {
      id: 'snp-aws-s3-internal',
      tenantId: 'tenant-internal',
      controlCode: 'CC6.6_S3_PUBLIC_BLOCK',
      provider: 'aws',
      title: 'AWS S3 GetPublicAccessBlock & Encryption Inventory',
      createdAt: '2026-08-27T14:31:00Z',
      sha256Hash: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
      recordCount: 6,
      isCompliant: true,
      rawPayload: [
        {
          BucketName: 'soc2-prod-immutable-audit-logs-worm',
          CreationDate: '2026-01-15T09:00:00Z',
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true,
            IgnorePublicAcls: true,
            BlockPublicPolicy: true,
            RestrictPublicBuckets: true
          },
          ServerSideEncryptionConfiguration: {
            Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms', KMSMasterKeyId: 'kms-key-prod-soc2-v3' } }]
          },
          ObjectLockConfiguration: {
            ObjectLockEnabled: 'Enabled',
            Rule: { DefaultRetention: { Mode: 'COMPLIANCE', Years: 7 } }
          }
        },
        {
          BucketName: 'soc2-prod-customer-attachments-vault',
          CreationDate: '2026-01-16T10:00:00Z',
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true,
            IgnorePublicAcls: true,
            BlockPublicPolicy: true,
            RestrictPublicBuckets: true
          },
          ServerSideEncryptionConfiguration: {
            Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: 'aws:kms', KMSMasterKeyId: 'kms-key-prod-soc2-v3' } }]
          }
        }
      ]
    },
    {
      id: 'snp-gh-branch-internal',
      tenantId: 'tenant-internal',
      controlCode: 'CC8.1_BRANCH_PROTECT',
      provider: 'github',
      title: 'GitHub Repositories Branch Protection Rules',
      createdAt: '2026-08-27T14:32:00Z',
      sha256Hash: '7c9f8a6b5d4e3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b',
      recordCount: 3,
      isCompliant: true,
      rawPayload: [
        {
          Repository: 'compliance-control-center-api',
          Branch: 'main',
          ProtectionEnabled: true,
          RequiredStatusChecks: {
            Strict: true,
            Contexts: ['Secret Detection (TruffleHog)', 'Dependency Audit (Trivy)', 'SAST Scan (CodeQL)', 'Build Verification']
          },
          EnforceAdmins: true,
          RequiredPullRequestReviews: {
            DismissStaleReviews: true,
            RequireCodeOwnerReviews: true,
            RequiredApprovingReviewCount: 1
          },
          AllowForcePushes: false,
          AllowDeletions: false
        }
      ]
    },
    {
      id: 'snp-snyk-cve-internal',
      tenantId: 'tenant-internal',
      controlCode: 'CC7.1_VULNERABILITIES',
      provider: 'snyk',
      title: 'Snyk Dependency & Container Vulnerability Scan',
      createdAt: '2026-08-27T14:33:00Z',
      sha256Hash: 'b4a3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3',
      recordCount: 0,
      isCompliant: true,
      rawPayload: {
        totalVulnerabilities: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        slaViolationsOver30Days: 0,
        scannedAt: '2026-08-27T14:33:00Z',
        scanStatus: 'ALL_CLEAR_ZERO_FINDINGS'
      }
    }
  ],
  'tenant-acme': [
    {
      id: 'snp-aws-mfa-acme',
      tenantId: 'tenant-acme',
      controlCode: 'CC6.1_MFA',
      provider: 'aws',
      title: 'AWS IAM ListUsers Scan',
      createdAt: '2026-08-27T13:00:00Z',
      sha256Hash: '5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344',
      recordCount: 8,
      isCompliant: false,
      rawPayload: [
        {
          UserName: 'cfo_accounting_backup',
          UserId: 'AIDA918239019231CFO',
          MFAEnabled: false,
          AccessKeys: [{ AccessKeyId: 'AKIA918239019231CFO', Status: 'Active' }]
        },
        {
          UserName: 'dev_contractor_dan',
          UserId: 'AIDA918239019231DAN',
          MFAEnabled: true,
          AccessKeys: []
        }
      ]
    },
    {
      id: 'snp-aws-s3-acme',
      tenantId: 'tenant-acme',
      controlCode: 'CC6.6_S3_PUBLIC_BLOCK',
      provider: 'aws',
      title: 'AWS S3 Bucket Configurations',
      createdAt: '2026-08-27T13:05:00Z',
      sha256Hash: '99887766554433221100ffeeddccbbaa99887766554433221100ffeeddccbbaa',
      recordCount: 4,
      isCompliant: false,
      rawPayload: [
        {
          BucketName: 'acme-legacy-public-assets',
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: false,
            IgnorePublicAcls: false,
            BlockPublicPolicy: false,
            RestrictPublicBuckets: false
          },
          ServerSideEncryptionConfiguration: { Rules: [] }
        }
      ]
    }
  ]
};

// Initial Compliance Issues (Failing Controls to Remediate)
export const INITIAL_ISSUES: Record<string, ComplianceIssue[]> = {
  'tenant-internal': [],
  'tenant-acme': [
    {
      id: 'iss-acme-1',
      tenantId: 'tenant-acme',
      controlCode: 'CC6.1_MFA',
      resourceId: 'AIDA918239019231CFO',
      title: 'MFA Disabled on AWS IAM User (cfo_accounting_backup)',
      description: 'IAM account has direct console and API access without hardware or virtual MFA device configured.',
      severity: 'HIGH',
      status: 'OPEN',
      assignee: 'security@acmefintech.io',
      openedAt: '2026-08-20T09:00:00Z',
      slaDeadline: '2026-09-19T09:00:00Z',
      provider: 'aws',
      autoRemediationAvailable: true,
      autoRemediationAction: 'Enforce Virtual MFA Device on IAM User'
    },
    {
      id: 'iss-acme-2',
      tenantId: 'tenant-acme',
      controlCode: 'CC6.6_S3_PUBLIC_BLOCK',
      resourceId: 'acme-legacy-public-assets',
      title: 'S3 Bucket Missing Public Access Block & KMS Encryption',
      description: 'S3 bucket has BlockPublicAcls set to false and default server-side encryption disabled.',
      severity: 'CRITICAL',
      status: 'OPEN',
      assignee: 'devops@acmefintech.io',
      openedAt: '2026-08-22T11:00:00Z',
      slaDeadline: '2026-09-21T11:00:00Z',
      provider: 'aws',
      autoRemediationAvailable: true,
      autoRemediationAction: 'Apply s3:PutPublicAccessBlock and Enable AES-256-KMS'
    },
    {
      id: 'iss-acme-3',
      tenantId: 'tenant-acme',
      controlCode: 'CC8.1_BRANCH_PROTECT',
      resourceId: 'payment-gateway-service',
      title: 'GitHub Branch Protection Missing on main',
      description: 'Developers can push commits directly to main without 1+ approving peer review or CI status checks.',
      severity: 'HIGH',
      status: 'OPEN',
      assignee: 'engineering-lead@acmefintech.io',
      openedAt: '2026-08-24T15:00:00Z',
      slaDeadline: '2026-09-23T15:00:00Z',
      provider: 'github',
      autoRemediationAvailable: true,
      autoRemediationAction: 'Enforce GitHub Branch Protection (1+ Review & CI Gating)'
    }
  ],
  'tenant-nova': [
    {
      id: 'iss-nova-1',
      tenantId: 'tenant-nova',
      controlCode: 'CC6.2_OFFBOARDING',
      resourceId: 'user_mark_contractor',
      title: 'Deactivated Employee Has Active AWS API Key',
      description: 'Contractor marked deactivated in directory retains active credentials in AWS IAM.',
      severity: 'CRITICAL',
      status: 'OPEN',
      assignee: 'compliance@novahealth.org',
      openedAt: '2026-08-25T08:00:00Z',
      slaDeadline: '2026-08-26T08:00:00Z', // 24hr SLA
      provider: 'aws',
      autoRemediationAvailable: true,
      autoRemediationAction: 'Deactivate and Delete Stale AWS Access Key'
    }
  ]
};

// Initial Webhook Event Logs
export const INITIAL_WEBHOOK_LOGS: WebhookEventLog[] = [
  {
    id: 'wh-log-1',
    tenantId: 'tenant-internal',
    provider: 'github',
    event: 'branch_protection_rule.updated',
    receivedAt: '2026-08-27T14:32:00Z',
    payloadSummary: 'Protected branch main: 1 approving review required, status checks enforced',
    actionTaken: 'Verified CC8.1 compliance - No issue opened',
    severity: 'INFO'
  },
  {
    id: 'wh-log-2',
    tenantId: 'tenant-internal',
    provider: 'aws',
    event: 'aws.iam.CreateUser',
    receivedAt: '2026-08-27T12:15:00Z',
    payloadSummary: 'Created user alex.devops@company.internal with attached MFA requirement policy',
    actionTaken: 'Recorded in WORM audit log stream',
    severity: 'INFO'
  }
];

// Steampipe SQL Virtual Cloud Tables
export const STEAMPIPE_TABLES: SteampipeTableDef[] = [
  {
    name: 'aws_iam_user',
    description: 'Queries AWS IAM user directory, MFA devices, access key count, and password status',
    provider: 'aws',
    queryExample: 'SELECT user_name, mfa_enabled, password_last_used, access_keys_count FROM aws_iam_user WHERE mfa_enabled = false;',
    data: [
      { user_name: 'jenngremicinc@gmail.com', user_id: 'AIDA482910481920JENN', mfa_enabled: true, mfa_type: 'FIDO2 YubiKey', password_last_used: '2026-08-27 14:10', access_keys_count: 0 },
      { user_name: 'svc_ci_cd_deployment_agent', user_id: 'AIDA482910481920SVC1', mfa_enabled: true, mfa_type: 'STS Session', password_last_used: '2026-08-27 15:00', access_keys_count: 1 },
      { user_name: 'alex.devops@company.internal', user_id: 'AIDA482910481920ALEX', mfa_enabled: true, mfa_type: 'TOTP Authenticator', password_last_used: '2026-08-27 13:40', access_keys_count: 0 },
      { user_name: 'cfo_accounting_backup', user_id: 'AIDA918239019231CFO', mfa_enabled: false, mfa_type: 'NONE', password_last_used: '2026-08-20 09:00', access_keys_count: 1 }
    ]
  },
  {
    name: 'aws_s3_bucket',
    description: 'Queries AWS S3 buckets for Public Access Block settings, KMS encryption, and Object Lock',
    provider: 'aws',
    queryExample: 'SELECT bucket_name, block_public_acls, default_encryption, object_lock_mode FROM aws_s3_bucket WHERE block_public_acls = false;',
    data: [
      { bucket_name: 'soc2-prod-immutable-audit-logs-worm', region: 'us-east-1', block_public_acls: true, default_encryption: 'aws:kms (AES-256)', object_lock_mode: 'COMPLIANCE (7y)' },
      { bucket_name: 'soc2-prod-customer-attachments-vault', region: 'us-east-1', block_public_acls: true, default_encryption: 'aws:kms (AES-256)', object_lock_mode: 'GOVERNANCE' },
      { bucket_name: 'acme-legacy-public-assets', region: 'us-west-2', block_public_acls: false, default_encryption: 'NONE', object_lock_mode: 'DISABLED' }
    ]
  },
  {
    name: 'github_branch_protection',
    description: 'Queries GitHub repository branch protections, peer review counts, and force push settings',
    provider: 'github',
    queryExample: 'SELECT repository, branch, required_approvals, enforce_admins, allow_force_pushes FROM github_branch_protection WHERE required_approvals < 1;',
    data: [
      { repository: 'compliance-control-center-api', branch: 'main', required_approvals: 1, enforce_admins: true, allow_force_pushes: false, status_checks_count: 4 },
      { repository: 'compliance-frontend-portal', branch: 'main', required_approvals: 1, enforce_admins: true, allow_force_pushes: false, status_checks_count: 3 },
      { repository: 'payment-gateway-service', branch: 'main', required_approvals: 0, enforce_admins: false, allow_force_pushes: true, status_checks_count: 0 }
    ]
  },
  {
    name: 'okta_directory_users',
    description: 'Queries Okta Identity Provider users, deactivation timestamps, and active credential count',
    provider: 'okta',
    queryExample: 'SELECT email, status, mfa_enforced, active_credentials_count FROM okta_directory_users WHERE status = "DEACTIVATED" AND active_credentials_count > 0;',
    data: [
      { email: 'jenngremicinc@gmail.com', status: 'ACTIVE', mfa_enforced: true, last_login: '2026-08-27 14:10', active_credentials_count: 1 },
      { email: 'alex.devops@company.internal', status: 'ACTIVE', mfa_enforced: true, last_login: '2026-08-27 13:40', active_credentials_count: 1 },
      { email: 'user_mark_contractor@legacy.io', status: 'DEACTIVATED', mfa_enforced: false, last_login: '2026-08-24 10:00', active_credentials_count: 1 }
    ]
  }
];

// In-Memory Multi-Tenant Store with Subscriber pattern
class MultiTenantStore {
  private tenants: Tenant[] = INITIAL_TENANTS;
  private currentTenantId: string = 'tenant-internal';
  private integrations: Record<string, Integration[]> = INITIAL_INTEGRATIONS;
  private snapshots: Record<string, EvidenceSnapshot[]> = INITIAL_SNAPSHOTS;
  private issues: Record<string, ComplianceIssue[]> = INITIAL_ISSUES;
  private webhookLogs: WebhookEventLog[] = INITIAL_WEBHOOK_LOGS;
  private workerJobs: WorkerJob[] = [];
  private listeners: Array<() => void> = [];

  constructor() {
    this.recalculateScores();
  }

  public subscribe(listener: () => void) {
    this.listeners.push(listener);
    return () => {
      this.listeners = this.listeners.filter((l) => l !== listener);
    };
  }

  private notify() {
    this.recalculateScores();
    this.listeners.forEach((l) => l());
  }

  private recalculateScores() {
    this.tenants = this.tenants.map((t) => {
      const openIssues = (this.issues[t.id] || []).filter((i) => i.status === 'OPEN');
      const criticalCount = openIssues.filter((i) => i.severity === 'CRITICAL').length;
      const highCount = openIssues.filter((i) => i.severity === 'HIGH').length;
      const medCount = openIssues.filter((i) => i.severity === 'MEDIUM').length;

      const penalty = criticalCount * 15 + highCount * 8 + medCount * 4;
      const score = Math.max(20, 100 - penalty);
      return { ...t, complianceScore: score };
    });
  }

  // Tenant methods
  public getTenants(): Tenant[] {
    return this.tenants;
  }

  public getTenant(tenantId: string): Tenant | undefined {
    return this.tenants.find((t) => t.id === tenantId);
  }

  public getCurrentTenant(): Tenant {
    return this.tenants.find((t) => t.id === this.currentTenantId) || this.tenants[0];
  }

  public setCurrentTenant(tenantId: string) {
    this.currentTenantId = tenantId;
    this.notify();
  }

  public updateTenant(tenantId: string, partial: Partial<Tenant>): Tenant | undefined {
    const idx = this.tenants.findIndex((t) => t.id === tenantId);
    if (idx === -1) return undefined;
    this.tenants[idx] = { ...this.tenants[idx], ...partial };
    this.notify();
    return this.tenants[idx];
  }

  public updateAccountStatus(tenantId: string, status: AccountStatus): void {
    const tenant = this.getTenant(tenantId);
    if (tenant) {
      tenant.accountStatus = status;
      // If suspended, pause worker processes; if active, resume
      tenant.workersActive = status === 'ACTIVE' || status === 'TRIALING';
      this.notify();
    }
  }

  public toggleWorkers(tenantId: string, active: boolean): void {
    const tenant = this.getTenant(tenantId);
    if (tenant) {
      tenant.workersActive = active;
      this.notify();
    }
  }

  // AWS Integration Config (Cross-Account STS Assumption)
  private awsConfigs: Record<string, AwsIntegrationConfig> = {
    'tenant-internal': {
      tenantId: 'tenant-internal',
      clientIamRoleArn: 'arn:aws:iam::482910481920:role/SOC2ContinuousComplianceRole',
      secureExternalToken: 'soc2-dogfood-prod-994821',
      targetAwsAccountId: '482910481920',
      region: 'us-east-1',
      sessionDurationSeconds: 3600,
      status: 'CONNECTED',
      lastScannedAt: new Date(Date.now() - 1000 * 60 * 12).toISOString()
    },
    'tenant-acme': {
      tenantId: 'tenant-acme',
      clientIamRoleArn: 'arn:aws:iam::918239019231:role/AcmeComplianceRole',
      secureExternalToken: 'soc2-acme-tenant-882190',
      targetAwsAccountId: '918239019231',
      region: 'us-west-2',
      sessionDurationSeconds: 3600,
      status: 'CONNECTED',
      lastScannedAt: new Date(Date.now() - 1000 * 60 * 55).toISOString()
    },
    'tenant-nova': {
      tenantId: 'tenant-nova',
      clientIamRoleArn: 'arn:aws:iam::772183901293:role/NovaHealthComplianceRole',
      secureExternalToken: 'soc2-nova-tenant-119302',
      targetAwsAccountId: '772183901293',
      region: 'us-east-1',
      sessionDurationSeconds: 3600,
      status: 'CONNECTED',
      lastScannedAt: new Date(Date.now() - 1000 * 60 * 15).toISOString()
    }
  };

  public getAwsConfig(tenantId: string = this.currentTenantId): AwsIntegrationConfig {
    if (!this.awsConfigs[tenantId]) {
      const tenant = this.getTenant(tenantId);
      this.awsConfigs[tenantId] = {
        tenantId,
        clientIamRoleArn: tenant?.clientIamRoleArn || `arn:aws:iam::${tenant?.awsAccountId || '123456789012'}:role/SOC2ComplianceRole`,
        secureExternalToken: tenant?.secureExternalToken || tenant?.externalId || `soc2-ext-${tenantId}-${Math.random().toString(36).substring(2, 8)}`,
        targetAwsAccountId: tenant?.awsAccountId || '123456789012',
        region: 'us-east-1',
        sessionDurationSeconds: 3600,
        status: 'CONNECTED'
      };
    }
    return this.awsConfigs[tenantId];
  }

  public saveAwsConfig(config: AwsIntegrationConfig): void {
    this.awsConfigs[config.tenantId] = { ...config };
    const tenant = this.getTenant(config.tenantId);
    if (tenant) {
      tenant.clientIamRoleArn = config.clientIamRoleArn;
      tenant.secureExternalToken = config.secureExternalToken;
      if (config.targetAwsAccountId) tenant.awsAccountId = config.targetAwsAccountId;
    }
    this.notify();
  }

  // Compliance Summary API Helper (Scoring & Open Issues)
  public getComplianceSummary(tenantId: string = this.currentTenantId) {
    const tenant = this.getTenant(tenantId) || this.getCurrentTenant();
    const allIssues = this.getIssues(tenantId);
    const openIssues = allIssues.filter((i) => i.status === 'OPEN');

    return {
      metrics: {
        healthScore: tenant.complianceScore,
        itemsOpen: openIssues.length,
        ledgerChainValid: true,
        accountStatus: tenant.accountStatus || 'ACTIVE',
        subscriptionTier: tenant.subscriptionTier || 'growth',
        workersActive: tenant.workersActive !== false
      },
      issues: allIssues
    };
  }

  public upsertComplianceIssue(issueData: {
    tenantId: string;
    resourceId: string;
    title: string;
    description?: string;
    severity?: IssueSeverity;
    status?: IssueStatus;
    controlCode?: string;
    provider?: IntegrationProvider;
    autoRemediationAvailable?: boolean;
    autoRemediationAction?: string;
  }): ComplianceIssue {
    const { tenantId, resourceId } = issueData;
    if (!this.issues[tenantId]) this.issues[tenantId] = [];

    const existingIdx = this.issues[tenantId].findIndex((i) => i.resourceId === resourceId);
    if (existingIdx >= 0) {
      this.issues[tenantId][existingIdx] = {
        ...this.issues[tenantId][existingIdx],
        title: issueData.title || this.issues[tenantId][existingIdx].title,
        description: issueData.description || this.issues[tenantId][existingIdx].description,
        severity: issueData.severity || this.issues[tenantId][existingIdx].severity,
        status: issueData.status || 'OPEN',
        controlCode: issueData.controlCode || this.issues[tenantId][existingIdx].controlCode
      };
      this.notify();
      return this.issues[tenantId][existingIdx];
    }

    const newIssue: ComplianceIssue = {
      id: `iss_aws_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`,
      tenantId,
      controlCode: issueData.controlCode || 'CC6.1_PASSWORD_POLICY',
      resourceId,
      title: issueData.title,
      description: issueData.description || 'Discovered during automated AWS STS cross-account compliance scan.',
      severity: issueData.severity || 'HIGH',
      status: issueData.status || 'OPEN',
      assignee: this.getTenant(tenantId)?.contactEmail || 'security-lead@company.internal',
      openedAt: new Date().toISOString(),
      slaDeadline: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
      provider: issueData.provider || 'aws',
      autoRemediationAvailable: issueData.autoRemediationAvailable ?? true,
      autoRemediationAction: issueData.autoRemediationAction || 'Update AWS Account Password Policy via IAM API'
    };

    this.issues[tenantId].unshift(newIssue);
    this.notify();
    return newIssue;
  }

  public createTenant(name: string, mode: 'internal' | 'commercial', contactEmail: string): Tenant {
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-');
    const id = `tenant-${slug}-${Date.now().toString(36).slice(-4)}`;
    const newTenant: Tenant = {
      id,
      name,
      slug,
      mode,
      createdAt: new Date().toISOString(),
      complianceScore: 100,
      contactEmail,
      awsAccountId: `${Math.floor(100000000000 + Math.random() * 900000000000)}`,
      externalId: `soc2-ext-${slug}-${Math.random().toString(36).substring(2, 8)}`,
      clientIamRoleArn: `arn:aws:iam::${Math.floor(100000000000 + Math.random() * 900000000000)}:role/SOC2ComplianceRole`,
      secureExternalToken: `soc2-ext-${slug}-${Math.random().toString(36).substring(2, 8)}`,
      accountStatus: 'ACTIVE',
      subscriptionTier: 'growth',
      stripeCustomerId: `cus_${slug}_${Math.random().toString(36).substring(2, 8)}`,
      stripeSubscriptionId: `sub_${slug}_${Math.random().toString(36).substring(2, 8)}`,
      workersActive: true
    };

    this.tenants.push(newTenant);
    this.integrations[id] = [];
    this.snapshots[id] = [];
    this.issues[id] = [];
    this.notify();
    return newTenant;
  }

  // Integrations methods
  public getIntegrations(tenantId: string = this.currentTenantId): Integration[] {
    return this.integrations[tenantId] || [];
  }

  public addOrUpdateIntegration(tenantId: string, integration: Partial<Integration> & { provider: IntegrationProvider; name: string }): Integration {
    if (!this.integrations[tenantId]) {
      this.integrations[tenantId] = [];
    }

    const existingIdx = this.integrations[tenantId].findIndex((i) => i.provider === integration.provider);
    const fullIntegration: Integration = {
      id: integration.id || `int-${integration.provider}-${tenantId}`,
      tenantId,
      provider: integration.provider,
      name: integration.name,
      authMethod: integration.authMethod || 'sts_role',
      roleArn: integration.roleArn,
      externalId: integration.externalId || this.getCurrentTenant().externalId,
      region: integration.region || 'us-east-1',
      credentialsMasked: integration.credentialsMasked || `AES-256-GCM Encrypted Credentials (Key ID: kms-key-prod-soc2-v3)`,
      status: 'connected',
      lastSyncAt: new Date().toISOString(),
      syncIntervalMinutes: integration.syncIntervalMinutes || 60,
      activeChecks: integration.activeChecks || ['Automated API Scans', 'WORM Snapshot Archive', 'Rule Evaluation']
    };

    if (existingIdx >= 0) {
      this.integrations[tenantId][existingIdx] = fullIntegration;
    } else {
      this.integrations[tenantId].push(fullIntegration);
    }

    auditLogStore.record({
      traceId: `trc_int_${Math.random().toString(36).substring(2, 10)}`,
      actorId: this.getCurrentTenant().contactEmail,
      action: 'integration.configured',
      resource: `integration:${integration.provider}:${tenantId}`,
      ipAddress: '192.168.1.1',
      status: 'SUCCESS',
      metadata: {
        provider: integration.provider,
        authMethod: integration.authMethod,
        tenant: tenantId
      }
    });

    this.notify();
    return fullIntegration;
  }

  // Evidence Snapshots
  public getSnapshots(tenantId: string = this.currentTenantId): EvidenceSnapshot[] {
    return this.snapshots[tenantId] || [];
  }

  public async recordSnapshot(
    tenantId: string,
    controlCode: string,
    provider: IntegrationProvider,
    title: string,
    rawPayload: Record<string, unknown> | Array<Record<string, unknown>>,
    isCompliant: boolean
  ): Promise<EvidenceSnapshot> {
    if (!this.snapshots[tenantId]) {
      this.snapshots[tenantId] = [];
    }

    const payloadStr = JSON.stringify(rawPayload);
    const sha256Hash = await computeSha256(payloadStr);
    const recordCount = Array.isArray(rawPayload) ? rawPayload.length : Object.keys(rawPayload).length;

    // Cryptographic ledger chaining: hash is SHA256(previousHash + payloadStr + controlCode)
    const latestSnapshot = this.snapshots[tenantId][0];
    const previousLedgerHash = latestSnapshot?.ledgerHash || 'GENESIS_BLOCK_0000000000000000';
    const ledgerHash = await computeSha256(previousLedgerHash + payloadStr + controlCode);

    const newSnapshot: EvidenceSnapshot = {
      id: `snp-${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 6)}`,
      tenantId,
      controlCode,
      provider,
      title,
      rawPayload,
      createdAt: new Date().toISOString(),
      sha256Hash,
      previousLedgerHash,
      ledgerHash,
      recordCount,
      isCompliant
    };

    this.snapshots[tenantId].unshift(newSnapshot);
    this.notify();
    return newSnapshot;
  }

  // Compliance Issues / Failing Controls
  public getIssues(tenantId: string = this.currentTenantId): ComplianceIssue[] {
    return this.issues[tenantId] || [];
  }

  public async remediateIssue(tenantId: string, issueId: string): Promise<boolean> {
    const list = this.issues[tenantId] || [];
    const issue = list.find((i) => i.id === issueId);
    if (!issue) return false;

    issue.status = 'RESOLVED';
    issue.resolvedAt = new Date().toISOString();

    // Log the remediation
    await auditLogStore.record({
      traceId: `trc_rem_${Math.random().toString(36).substring(2, 10)}`,
      actorId: this.getCurrentTenant().contactEmail,
      action: 'control.remediated',
      resource: `issue:${issue.resourceId}`,
      ipAddress: '192.168.1.1',
      status: 'SUCCESS',
      metadata: {
        issueId: issue.id,
        controlCode: issue.controlCode,
        title: issue.title,
        actionApplied: issue.autoRemediationAction
      }
    });

    this.notify();
    return true;
  }

  public assignIssue(tenantId: string, issueId: string, assignee: string) {
    const list = this.issues[tenantId] || [];
    const issue = list.find((i) => i.id === issueId);
    if (issue) {
      issue.assignee = assignee;
      this.notify();
    }
  }

  // BullMQ Worker Simulator
  public getWorkerJobs(): WorkerJob[] {
    return this.workerJobs;
  }

  public async executeWorkerScan(tenantId: string = this.currentTenantId): Promise<WorkerJob[]> {
    const jobsToRun: Array<{ name: string; provider: IntegrationProvider; controlCode: string }> = [
      { name: 'AWS IAM MFA & Credential Inspector', provider: 'aws', controlCode: 'CC6.1_MFA' },
      { name: 'AWS S3 Public Access Block & KMS Auditor', provider: 'aws', controlCode: 'CC6.6_S3_PUBLIC_BLOCK' },
      { name: 'GitHub Branch Protection & SAST Gatekeeper', provider: 'github', controlCode: 'CC8.1_BRANCH_PROTECT' },
      { name: 'Snyk CVE & 30-Day SLA Vulnerability Scanner', provider: 'snyk', controlCode: 'CC7.1_VULNERABILITIES' }
    ];

    const results: WorkerJob[] = [];

    for (const j of jobsToRun) {
      const jobId = `job_${Math.random().toString(36).substring(2, 9)}`;
      const job: WorkerJob = {
        id: jobId,
        tenantId,
        name: j.name,
        provider: j.provider,
        controlCode: j.controlCode,
        status: 'active',
        startedAt: new Date().toISOString(),
        logs: [
          `[BullMQ] Worker picked up job ${jobId} from Redis queue (tenant: ${tenantId})`,
          `[1. Decrypt] Decrypted AES-256-GCM credentials for integration provider: ${j.provider}`,
          `[2. SDK Init] Initialized dynamic cloud client using STS AssumeRole / API Token`,
          `[3. API Query] Queried external infrastructure state for control ${j.controlCode}`,
          `[4. WORM Snapshot] Archived immutable point-in-time EvidenceSnapshot with SHA-256 verification`,
          `[5. Evaluation] Evaluated AICPA Trust Services Criteria rule -> Status: OPERATIONAL`
        ],
        findingsCount: 0
      };

      this.workerJobs.unshift(job);
      this.notify();

      // Simulate step duration
      await new Promise((r) => setTimeout(r, 400));

      job.status = 'completed';
      job.completedAt = new Date().toISOString();
      job.durationMs = 380 + Math.floor(Math.random() * 250);
      results.push(job);
      this.notify();
    }

    // Record audit event for worker run
    await auditLogStore.record({
      traceId: `trc_worker_${Math.random().toString(36).substring(2, 10)}`,
      actorId: 'bullmq_compliance_worker_pool',
      action: 'worker.full_scan_completed',
      resource: `tenant:${tenantId}:all_controls`,
      ipAddress: '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        tenantId,
        jobsRun: jobsToRun.length,
        status: 'ALL_GATES_VERIFIED'
      }
    });

    this.notify();
    return results;
  }

  // Webhook Receiver Simulator
  public getWebhookLogs(tenantId?: string): WebhookEventLog[] {
    if (tenantId) {
      return this.webhookLogs.filter((w) => w.tenantId === tenantId);
    }
    return this.webhookLogs;
  }

  public async receiveWebhook(
    tenantId: string,
    provider: IntegrationProvider,
    event: string,
    payloadSummary: string,
    actionTaken: string,
    severity: 'INFO' | 'WARNING' | 'ALERT'
  ): Promise<WebhookEventLog> {
    const log: WebhookEventLog = {
      id: `wh_${Date.now().toString(36)}_${Math.random().toString(36).slice(-4)}`,
      tenantId,
      provider,
      event,
      receivedAt: new Date().toISOString(),
      payloadSummary,
      actionTaken,
      severity
    };

    this.webhookLogs.unshift(log);

    // If alert severity, also create an issue in real time
    if (severity === 'ALERT') {
      if (!this.issues[tenantId]) this.issues[tenantId] = [];
      this.issues[tenantId].unshift({
        id: `iss_wh_${Date.now().toString(36)}`,
        tenantId,
        controlCode: provider === 'github' ? 'CC8.1_BRANCH_PROTECT' : 'CC6.1_MFA',
        resourceId: `webhook_trigger_${event}`,
        title: `Real-time Alert: ${event}`,
        description: payloadSummary,
        severity: 'CRITICAL',
        status: 'OPEN',
        assignee: this.getCurrentTenant().contactEmail,
        openedAt: new Date().toISOString(),
        slaDeadline: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
        provider,
        autoRemediationAvailable: true,
        autoRemediationAction: 'Auto-Remediate Real-Time Webhook Policy Violation'
      });
    }

    await auditLogStore.record({
      traceId: `trc_wh_${Math.random().toString(36).substring(2, 10)}`,
      actorId: `webhook_receiver_${provider}`,
      action: `webhook.${event}`,
      resource: `webhook:${provider}:${tenantId}`,
      ipAddress: '140.82.112.4',
      status: severity === 'ALERT' ? 'FAILURE' : 'SUCCESS',
      metadata: {
        event,
        payloadSummary,
        actionTaken
      }
    });

    this.notify();
    return log;
  }

  // Steampipe SQL Runner
  public runSteampipeQuery(query: string): { columns: string[]; rows: Array<Record<string, unknown>> } {
    const lower = query.toLowerCase();
    let matchedTable = STEAMPIPE_TABLES.find((t) => lower.includes(t.name));

    if (!matchedTable) {
      matchedTable = STEAMPIPE_TABLES[0];
    }

    let rows = [...matchedTable.data];

    if (lower.includes('where mfa_enabled = false')) {
      rows = rows.filter((r) => r.mfa_enabled === false);
    } else if (lower.includes('where block_public_acls = false')) {
      rows = rows.filter((r) => r.block_public_acls === false);
    } else if (lower.includes('where required_approvals < 1')) {
      rows = rows.filter((r) => Number(r.required_approvals) < 1);
    }

    const columns = rows.length > 0 ? Object.keys(rows[0]) : ['result'];
    return { columns, rows };
  }

  // -------------------------------------------------------------
  // EMPLOYEES & STAFF SIGN-OFF METHODS (SOC 2 CC1.2 / CC5.2)
  // -------------------------------------------------------------
  private employees: Record<string, Employee[]> = INITIAL_EMPLOYEES;
  private staffSignatures: Record<string, StaffPolicySignature[]> = INITIAL_STAFF_SIGNATURES;
  private automatedPRs: Record<string, AutomatedPR[]> = INITIAL_AUTOMATED_PRS;
  private microLessons: Record<string, MicroLessonLog[]> = INITIAL_MICRO_LESSONS;

  public getEmployees(tenantId: string = this.currentTenantId): Employee[] {
    return this.employees[tenantId] || [];
  }

  public addEmployee(tenantId: string, employee: Omit<Employee, 'id' | 'tenantId'>): Employee {
    if (!this.employees[tenantId]) this.employees[tenantId] = [];
    const newEmp: Employee = {
      id: `emp_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`,
      tenantId,
      ...employee
    };
    this.employees[tenantId].push(newEmp);
    this.notify();
    return newEmp;
  }

  public getStaffSignatures(tenantId: string = this.currentTenantId, policyId?: string): StaffPolicySignature[] {
    const sigs = this.staffSignatures[tenantId] || [];
    if (policyId) {
      return sigs.filter((s) => s.policyId === policyId);
    }
    return sigs;
  }

  public async signPolicyAsEmployee(
    tenantId: string,
    policyId: string,
    employeeEmail: string,
    ipAddress: string = '192.168.1.100',
    userAgent: string = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
  ): Promise<StaffPolicySignature> {
    if (!this.staffSignatures[tenantId]) this.staffSignatures[tenantId] = [];
    
    const employees = this.getEmployees(tenantId);
    const emp = employees.find((e) => e.email.toLowerCase() === employeeEmail.toLowerCase());
    const employeeName = emp ? emp.name : employeeEmail.split('@')[0];
    const employeeId = emp ? emp.id : `emp_${employeeEmail.split('@')[0]}`;
    const timestamp = new Date().toISOString();
    const versionSigned = '2026.1';

    const certString = `${tenantId}:${policyId}:${employeeEmail}:${versionSigned}:${timestamp}`;
    const certificateHash = await computeSha256(certString);

    // Prevent double sign for same version
    const existingIdx = this.staffSignatures[tenantId].findIndex(
      (s) => s.policyId === policyId && s.employeeEmail.toLowerCase() === employeeEmail.toLowerCase()
    );

    const signature: StaffPolicySignature = {
      id: `sig_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`,
      tenantId,
      policyId,
      employeeId,
      employeeName,
      employeeEmail,
      ipAddress,
      userAgent,
      signedAt: timestamp,
      certificateHash,
      versionSigned
    };

    if (existingIdx >= 0) {
      this.staffSignatures[tenantId][existingIdx] = signature;
    } else {
      this.staffSignatures[tenantId].push(signature);
    }

    await auditLogStore.record({
      traceId: `trc_sig_${Date.now().toString(36)}`,
      actorId: employeeEmail,
      action: 'policy.staff_signed',
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

    this.notify();
    return signature;
  }

  public getPolicyCompletion(tenantId: string = this.currentTenantId, policyId: string): {
    totalActiveStaff: number;
    signedStaffCount: number;
    completionPercentage: number;
    pendingStaff: Employee[];
    signedStaff: Array<{ employee: Employee; signature: StaffPolicySignature }>;
  } {
    const activeStaff = this.getEmployees(tenantId).filter((e) => e.status === 'ACTIVE');
    const signatures = this.getStaffSignatures(tenantId, policyId);
    
    const signedEmails = new Set(signatures.map((s) => s.employeeEmail.toLowerCase()));
    const pendingStaff = activeStaff.filter((e) => !signedEmails.has(e.email.toLowerCase()));
    
    const signedStaff = signatures.map((sig) => {
      const emp = activeStaff.find((e) => e.email.toLowerCase() === sig.employeeEmail.toLowerCase()) || {
        id: sig.employeeId,
        tenantId,
        name: sig.employeeName,
        email: sig.employeeEmail,
        department: 'Engineering',
        role: 'Staff Member',
        status: 'ACTIVE' as const
      };
      return { employee: emp, signature: sig };
    });

    const completionPercentage = activeStaff.length > 0
      ? Math.round((signedStaff.length / activeStaff.length) * 100)
      : 100;

    return {
      totalActiveStaff: activeStaff.length,
      signedStaffCount: signedStaff.length,
      completionPercentage,
      pendingStaff,
      signedStaff
    };
  }

  // -------------------------------------------------------------
  // 🌟 INNOVATION 1: GITOPS AUTOMATED PRS (CC8.1)
  // -------------------------------------------------------------
  public getAutomatedPRs(tenantId: string = this.currentTenantId): AutomatedPR[] {
    return this.automatedPRs[tenantId] || [];
  }

  public async deployAutomatedPolicyPR(
    tenantId: string = this.currentTenantId,
    repoName: string,
    policyType: string,
    policyMarkdown: string
  ): Promise<AutomatedPR> {
    if (!this.automatedPRs[tenantId]) this.automatedPRs[tenantId] = [];

    const prNumber = Math.floor(100 + Math.random() * 900);
    const branchName = `compliance/auto-policy-${Date.now()}`;
    const title = `🔒 SOC 2 Compliance: ${policyType.replace(/_/g, ' ')} Policy`;
    const prUrl = `https://github.com/enterprise-compliance-org/${repoName}/pull/${prNumber}`;

    const newPR: AutomatedPR = {
      id: `pr_${Date.now().toString(36)}`,
      tenantId,
      repoName,
      prNumber,
      policyType,
      title,
      branchName,
      status: 'OPEN',
      prUrl,
      createdAt: new Date().toISOString()
    };

    this.automatedPRs[tenantId].unshift(newPR);

    await auditLogStore.record({
      traceId: `trc_gitops_${Date.now().toString(36)}`,
      actorId: 'gitops_policy_daemon',
      action: 'gitops.pr_created',
      resource: `${repoName}#${prNumber}`,
      ipAddress: '140.82.112.4',
      status: 'SUCCESS',
      metadata: {
        tenantId,
        repoName,
        branchName,
        prNumber,
        policyType
      }
    });

    this.notify();
    return newPR;
  }

  public async mergeAutomatedPR(tenantId: string, prId: string): Promise<boolean> {
    const list = this.automatedPRs[tenantId] || [];
    const pr = list.find((p) => p.id === prId);
    if (!pr) return false;

    pr.status = 'MERGED';

    await auditLogStore.record({
      traceId: `trc_merge_${Date.now().toString(36)}`,
      actorId: this.getCurrentTenant().contactEmail,
      action: 'gitops.pr_merged',
      resource: `${pr.repoName}#${pr.prNumber}`,
      ipAddress: '192.168.1.1',
      status: 'SUCCESS',
      metadata: {
        tenantId,
        prId: pr.id,
        policyType: pr.policyType
      }
    });

    this.notify();
    return true;
  }

  // -------------------------------------------------------------
  // 🌟 INNOVATION 2: CRYPTOGRAPHIC LEDGER CHAIN VERIFIER
  // -------------------------------------------------------------
  public async verifyLedgerIntegrity(tenantId: string = this.currentTenantId): Promise<{
    isChainValid: boolean;
    totalBlocks: number;
    failedBlockIndex: number;
    blocks: Array<{
      index: number;
      id: string;
      controlCode: string;
      recordedHash: string;
      computedHash: string;
      previousHash: string;
      isValid: boolean;
      timestamp: string;
    }>;
  }> {
    const snapshots = [...(this.snapshots[tenantId] || [])].reverse(); // Oldest to newest
    let previousHash = 'GENESIS_BLOCK_0000000000000000';
    let isChainValid = true;
    let failedBlockIndex = -1;

    const blockResults = [];

    for (let i = 0; i < snapshots.length; i++) {
      const snap = snapshots[i];
      const payloadStr = JSON.stringify(snap.rawPayload);
      const computedHash = await computeSha256((snap.previousLedgerHash || previousHash) + payloadStr + snap.controlCode);
      const recordedHash = snap.ledgerHash || snap.sha256Hash;
      
      const isValid = snap.ledgerHash ? snap.ledgerHash === computedHash : true;
      if (!isValid && isChainValid) {
        isChainValid = false;
        failedBlockIndex = i;
      }

      blockResults.push({
        index: i,
        id: snap.id,
        controlCode: snap.controlCode,
        recordedHash,
        computedHash,
        previousHash: snap.previousLedgerHash || previousHash,
        isValid,
        timestamp: snap.createdAt
      });

      previousHash = recordedHash;
    }

    return {
      isChainValid,
      totalBlocks: snapshots.length,
      failedBlockIndex,
      blocks: blockResults
    };
  }

  // -------------------------------------------------------------
  // 🌟 INNOVATION 3: SLACK MICRO-TRAINING LOGS & EVENT RECEIVER (CC1.2)
  // -------------------------------------------------------------
  public getMicroLessons(tenantId: string = this.currentTenantId): MicroLessonLog[] {
    return this.microLessons[tenantId] || [];
  }

  public async triggerMicroLesson(
    tenantId: string = this.currentTenantId,
    triggerRule: string,
    employeeEmail: string
  ): Promise<MicroLessonLog> {
    if (!this.microLessons[tenantId]) this.microLessons[tenantId] = [];

    const employees = this.getEmployees(tenantId);
    const emp = employees.find((e) => e.email.toLowerCase() === employeeEmail.toLowerCase());
    const employeeName = emp ? emp.name : employeeEmail.split('@')[0];
    const employeeId = emp ? emp.id : `emp_${employeeEmail.split('@')[0]}`;

    const lessonTemplates: Record<string, { title: string; content: string; question: string; options: string[]; correctIdx: number; explanation: string }> = {
      'OPEN_SSH_PORT': {
        title: '⚠️ Security Drift Alert: Open SSH Port 22 on AWS Security Group',
        content: 'An AWS Security Group rule was modified to permit inbound SSH traffic (port 22) from 0.0.0.0/0. SOC 2 Criteria CC6.6 requires network perimeter boundary isolation. Bastion hosts or public SSH exposure introduce severe brute-force and credential stuffing risks.',
        question: 'What is the SOC 2 compliant method for remote shell access to production EC2 instances?',
        options: [
          'Open port 22 globally so developers can SSH from any home network',
          'Use AWS SSM Session Manager with IAM MFA authentication, keeping port 22 closed',
          'Disable firewalls on staging environments to simplify troubleshooting',
          'Commit the SSH private key to a shared Git repo for team access'
        ],
        correctIdx: 1,
        explanation: 'AWS SSM Session Manager enables secure shell connectivity without open inbound ports or public IP addresses, with full audit logging.'
      },
      'BRANCH_PROTECTION_DROPPED': {
        title: '⚠️ Change Control Alert: GitHub Branch Protection Disabled on Main',
        content: 'A repository main branch was modified to allow direct pushes without peer approvals. SOC 2 CC8.1 mandates strict segregation of duties where authors cannot approve their own pull requests.',
        question: 'Why does SOC 2 CC8.1 require at least 1 approving peer review before merging code?',
        options: [
          'To intentionally delay release velocity',
          'To provide an independent verification check and prevent single-point accidental or malicious defects',
          'Because pull requests are optional for senior software engineers',
          'To allow developers to approve their own PRs from alternate emails'
        ],
        correctIdx: 1,
        explanation: 'Mandatory peer reviews ensure segregation of duties and prevent unreviewed code or secrets from entering production systems.'
      },
      'SECRET_COMMITTED': {
        title: '🚨 High-Entropy Secret Detected in Version Control',
        content: 'TruffleHog detected a live API key or private certificate pushed in a Git commit. Unencrypted credentials in code repositories compromise CC6.7 encryption and confidentiality controls.',
        question: 'What is the mandatory remediation procedure when a production credential is committed to Git?',
        options: [
          'Run git commit --amend and assume the key is safe if no one noticed',
          'Immediately revoke and rotate the credential in KMS/Vault, then remove it from code history',
          'Leave it alone if the GitHub repository is private',
          'Email the team asking them not to use that credential'
        ],
        correctIdx: 1,
        explanation: 'Any committed credential must be treated as permanently compromised and rotated immediately at the credential provider.'
      }
    };

    const template = lessonTemplates[triggerRule] || lessonTemplates['OPEN_SSH_PORT'];

    const newLesson: MicroLessonLog = {
      id: `lesson_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`,
      tenantId,
      employeeId,
      employeeName,
      employeeEmail,
      triggerRule,
      title: template.title,
      content: template.content,
      quizQuestion: template.question,
      quizOptions: template.options,
      correctAnswerIndex: template.correctIdx,
      explanation: template.explanation,
      completed: false,
      sentAt: new Date().toISOString()
    };

    this.microLessons[tenantId].unshift(newLesson);

    await auditLogStore.record({
      traceId: `trc_slack_${Date.now().toString(36)}`,
      actorId: 'slack_micro_training_bot',
      action: 'training.micro_lesson_dispatched',
      resource: `employee:${employeeEmail}`,
      ipAddress: '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        tenantId,
        triggerRule,
        employeeEmail,
        lessonTitle: template.title
      }
    });

    this.notify();
    return newLesson;
  }

  public async completeMicroLesson(
    tenantId: string,
    lessonId: string,
    selectedOptionIndex: number
  ): Promise<{ success: boolean; isCorrect: boolean; explanation: string }> {
    const list = this.microLessons[tenantId] || [];
    const lesson = list.find((l) => l.id === lessonId);
    if (!lesson) return { success: false, isCorrect: false, explanation: 'Lesson not found' };

    lesson.userAnswerIndex = selectedOptionIndex;
    const isCorrect = selectedOptionIndex === lesson.correctAnswerIndex;
    lesson.completed = true;
    lesson.completedAt = new Date().toISOString();

    await auditLogStore.record({
      traceId: `trc_quiz_${Date.now().toString(36)}`,
      actorId: lesson.employeeEmail,
      action: 'training.micro_lesson_completed',
      resource: `lesson:${lesson.id}`,
      ipAddress: '192.168.1.100',
      status: isCorrect ? 'SUCCESS' : 'FAILURE',
      metadata: {
        tenantId,
        lessonId: lesson.id,
        triggerRule: lesson.triggerRule,
        selectedOptionIndex,
        isCorrect
      }
    });

    this.notify();
    return {
      success: true,
      isCorrect,
      explanation: lesson.explanation
    };
  }

  // -------------------------------------------------------------
  // GITHUB BULLMQ SCANNER (CC8.1 CHANGE MANAGEMENT)
  // -------------------------------------------------------------
  public async processGithubScan(tenantId: string = this.currentTenantId): Promise<{
    scannedReposCount: number;
    violationsCount: number;
    isCompliant: boolean;
  }> {
    const repos = [
      { name: 'compliance-control-center-api', isCompliant: true, reviewCount: 1, enforceAdmins: true },
      { name: 'compliance-frontend-portal', isCompliant: true, reviewCount: 1, enforceAdmins: true },
      { name: 'payment-gateway-service', isCompliant: false, reviewCount: 0, enforceAdmins: false }
    ];

    const violations = repos.filter((r) => !r.isCompliant);
    
    // Save raw snapshot to evidence vault with chained ledger hash
    await this.recordSnapshot(
      tenantId,
      'CC8.1_GIT_PROTECTION',
      'github',
      'GitHub Organization Repositories Branch Protection Audit',
      repos,
      violations.length === 0
    );

    // If violations, ensure issue is present
    if (violations.length > 0) {
      if (!this.issues[tenantId]) this.issues[tenantId] = [];
      const hasIssue = this.issues[tenantId].some((i) => i.resourceId === 'payment_gateway_branch_rule' && i.status === 'OPEN');
      if (!hasIssue) {
        this.issues[tenantId].unshift({
          id: `iss_gh_${Date.now().toString(36)}`,
          tenantId,
          controlCode: 'CC8.1_BRANCH_PROTECT',
          resourceId: 'payment_gateway_branch_rule',
          title: 'Repository [payment-gateway-service] has no branch protection configured',
          description: 'Default main branch allows direct pushes without approving reviews or CI gates. Violates SOC 2 CC8.1.',
          severity: 'CRITICAL',
          status: 'OPEN',
          assignee: this.getCurrentTenant().contactEmail,
          openedAt: new Date().toISOString(),
          slaDeadline: new Date(Date.now() + 1000 * 60 * 60 * 24 * 30).toISOString(),
          provider: 'github',
          autoRemediationAvailable: true,
          autoRemediationAction: 'Enable 1+ Peer Approval & CI Status Checks via GitHub API'
        });
      }
    }

    this.notify();
    return {
      scannedReposCount: repos.length,
      violationsCount: violations.length,
      isCompliant: violations.length === 0
    };
  }
}

// -------------------------------------------------------------
// INITIAL SEED DATASETS FOR EMPLOYEES, SIGNATURES, PRS, & LESSONS
// -------------------------------------------------------------
export const INITIAL_EMPLOYEES: Record<string, Employee[]> = {
  'tenant-internal': [
    {
      id: 'emp-jenn',
      tenantId: 'tenant-internal',
      name: 'Jennifer Gremic',
      email: 'jenngremicinc@gmail.com',
      department: 'Security & Compliance',
      role: 'Lead Security Officer',
      status: 'ACTIVE'
    },
    {
      id: 'emp-alex',
      tenantId: 'tenant-internal',
      name: 'Alex Hayes',
      email: 'alex.devops@company.internal',
      department: 'Engineering & DevOps',
      role: 'Lead Infrastructure Engineer',
      status: 'ACTIVE'
    },
    {
      id: 'emp-sarah',
      tenantId: 'tenant-internal',
      name: 'Sarah Chen',
      email: 'sarah.chen@company.internal',
      department: 'Backend Engineering',
      role: 'Senior Staff Engineer',
      status: 'ACTIVE'
    },
    {
      id: 'emp-marcus',
      tenantId: 'tenant-internal',
      name: 'Marcus Vance',
      email: 'marcus.vance@company.internal',
      department: 'Product Management',
      role: 'Director of Product',
      status: 'ACTIVE'
    },
    {
      id: 'emp-elena',
      tenantId: 'tenant-internal',
      name: 'Elena Rostova',
      email: 'elena.rostova@company.internal',
      department: 'People Operations & HR',
      role: 'VP of People',
      status: 'ACTIVE'
    }
  ],
  'tenant-acme': [
    {
      id: 'emp-acme-1',
      tenantId: 'tenant-acme',
      name: 'David Miller',
      email: 'security@acmefintech.io',
      department: 'Information Security',
      role: 'CISO',
      status: 'ACTIVE'
    },
    {
      id: 'emp-acme-2',
      tenantId: 'tenant-acme',
      name: 'Rachel Green',
      email: 'rachel@acmefintech.io',
      department: 'Core Banking Engineering',
      role: 'Staff Software Engineer',
      status: 'ACTIVE'
    },
    {
      id: 'emp-acme-3',
      tenantId: 'tenant-acme',
      name: 'John Doe',
      email: 'johndoe@acmefintech.io',
      department: 'Cloud Platform',
      role: 'Site Reliability Engineer',
      status: 'ACTIVE'
    }
  ],
  'tenant-nova': [
    {
      id: 'emp-nova-1',
      tenantId: 'tenant-nova',
      name: 'Dr. Emily Watson',
      email: 'compliance@novahealth.org',
      department: 'Clinical Compliance',
      role: 'Chief Compliance Officer',
      status: 'ACTIVE'
    },
    {
      id: 'emp-nova-2',
      tenantId: 'tenant-nova',
      name: 'Kevin Brooks',
      email: 'k.brooks@novahealth.org',
      department: 'Healthcare Systems',
      role: 'Director of IT',
      status: 'ACTIVE'
    }
  ]
};

export const INITIAL_STAFF_SIGNATURES: Record<string, StaffPolicySignature[]> = {
  'tenant-internal': [
    {
      id: 'sig-jenn-access',
      tenantId: 'tenant-internal',
      policyId: 'pol-access-control',
      employeeId: 'emp-jenn',
      employeeName: 'Jennifer Gremic',
      employeeEmail: 'jenngremicinc@gmail.com',
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/126.0',
      signedAt: '2026-08-15T11:20:00Z',
      certificateHash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
      versionSigned: '2.4.0'
    },
    {
      id: 'sig-alex-access',
      tenantId: 'tenant-internal',
      policyId: 'pol-access-control',
      employeeId: 'emp-alex',
      employeeName: 'Alex Hayes',
      employeeEmail: 'alex.devops@company.internal',
      ipAddress: '192.168.1.105',
      userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0',
      signedAt: '2026-08-16T09:15:00Z',
      certificateHash: '4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9a8b7c6d5e',
      versionSigned: '2.4.0'
    },
    {
      id: 'sig-jenn-change',
      tenantId: 'tenant-internal',
      policyId: 'pol-change-mgmt',
      employeeId: 'emp-jenn',
      employeeName: 'Jennifer Gremic',
      employeeEmail: 'jenngremicinc@gmail.com',
      ipAddress: '192.168.1.100',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      signedAt: '2026-08-20T11:05:00Z',
      certificateHash: '1c0d9e8f7a6b5c4d3e2f1a0b9a8b7c6d5e4f3a2b',
      versionSigned: '3.1.0'
    },
    {
      id: 'sig-sarah-change',
      tenantId: 'tenant-internal',
      policyId: 'pol-change-mgmt',
      employeeId: 'emp-sarah',
      employeeName: 'Sarah Chen',
      employeeEmail: 'sarah.chen@company.internal',
      ipAddress: '192.168.1.142',
      userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
      signedAt: '2026-08-21T14:30:00Z',
      certificateHash: '7a6b5c4d3e2f1a0b9a8b7c6d5e4f3a2b1c0d9e8f',
      versionSigned: '3.1.0'
    }
  ],
  'tenant-acme': [
    {
      id: 'sig-acme-david',
      tenantId: 'tenant-acme',
      policyId: 'pol-access-control',
      employeeId: 'emp-acme-1',
      employeeName: 'David Miller',
      employeeEmail: 'security@acmefintech.io',
      ipAddress: '10.0.4.12',
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
      signedAt: '2026-08-10T10:00:00Z',
      certificateHash: '3e2f1a0b9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d',
      versionSigned: '2.4.0'
    }
  ]
};

export const INITIAL_AUTOMATED_PRS: Record<string, AutomatedPR[]> = {
  'tenant-internal': [
    {
      id: 'pr-int-01',
      tenantId: 'tenant-internal',
      repoName: 'compliance-control-center-api',
      prNumber: 104,
      policyType: 'INFORMATION_SECURITY',
      title: '🔒 SOC 2 Compliance: Information Security Policy',
      branchName: 'compliance/auto-policy-infosec-v1',
      status: 'MERGED',
      prUrl: 'https://github.com/enterprise-compliance-org/compliance-control-center-api/pull/104',
      createdAt: '2026-08-20T10:30:00Z'
    },
    {
      id: 'pr-int-02',
      tenantId: 'tenant-internal',
      repoName: 'compliance-frontend-portal',
      prNumber: 108,
      policyType: 'ACCESS_CONTROL',
      title: '🔒 SOC 2 Compliance: Access Control Policy',
      branchName: 'compliance/auto-policy-access-v2',
      status: 'MERGED',
      prUrl: 'https://github.com/enterprise-compliance-org/compliance-frontend-portal/pull/108',
      createdAt: '2026-08-22T14:15:00Z'
    }
  ],
  'tenant-acme': [
    {
      id: 'pr-acme-01',
      tenantId: 'tenant-acme',
      repoName: 'acme-core-banking-service',
      prNumber: 221,
      policyType: 'DATA_PROTECTION',
      title: '🔒 SOC 2 Compliance: Data Protection & Encryption Policy',
      branchName: 'compliance/auto-policy-data-protect-2026',
      status: 'OPEN',
      prUrl: 'https://github.com/acme-fintech-org/acme-core-banking-service/pull/221',
      createdAt: '2026-08-26T09:00:00Z'
    }
  ]
};

export const INITIAL_MICRO_LESSONS: Record<string, MicroLessonLog[]> = {
  'tenant-internal': [
    {
      id: 'lesson-01',
      tenantId: 'tenant-internal',
      employeeId: 'emp-alex',
      employeeName: 'Alex Hayes',
      employeeEmail: 'alex.devops@company.internal',
      triggerRule: 'OPEN_SSH_PORT',
      title: '⚠️ Security Drift Alert: Open SSH Port 22 on AWS Security Group',
      content: 'An AWS Security Group rule was modified to permit inbound SSH traffic (port 22) from 0.0.0.0/0. SOC 2 Criteria CC6.6 requires network perimeter boundary isolation.',
      quizQuestion: 'What is the SOC 2 compliant method for remote shell access to production EC2 instances?',
      quizOptions: [
        'Open port 22 globally so developers can SSH from any home network',
        'Use AWS SSM Session Manager with IAM MFA authentication, keeping port 22 closed',
        'Disable firewalls on staging environments to simplify troubleshooting',
        'Commit the SSH private key to a shared Git repo for team access'
      ],
      correctAnswerIndex: 1,
      userAnswerIndex: 1,
      explanation: 'AWS SSM Session Manager enables secure shell connectivity without open inbound ports or public IP addresses, with full audit logging.',
      completed: true,
      sentAt: '2026-08-24T10:00:00Z',
      completedAt: '2026-08-24T10:02:15Z'
    },
    {
      id: 'lesson-02',
      tenantId: 'tenant-internal',
      employeeId: 'emp-sarah',
      employeeName: 'Sarah Chen',
      employeeEmail: 'sarah.chen@company.internal',
      triggerRule: 'SECRET_COMMITTED',
      title: '🚨 High-Entropy Secret Detected in Version Control',
      content: 'TruffleHog detected a live API key or private certificate pushed in a Git commit. Unencrypted credentials in code repositories compromise CC6.7 encryption and confidentiality controls.',
      quizQuestion: 'What is the mandatory remediation procedure when a production credential is committed to Git?',
      quizOptions: [
        'Run git commit --amend and assume the key is safe if no one noticed',
        'Immediately revoke and rotate the credential in KMS/Vault, then remove it from code history',
        'Leave it alone if the GitHub repository is private',
        'Email the team asking them not to use that credential'
      ],
      correctAnswerIndex: 1,
      userAnswerIndex: 1,
      explanation: 'Any committed credential must be treated as permanently compromised and rotated immediately at the credential provider.',
      completed: true,
      sentAt: '2026-08-25T16:20:00Z',
      completedAt: '2026-08-25T16:23:40Z'
    }
  ],
  'tenant-acme': [
    {
      id: 'lesson-03',
      tenantId: 'tenant-acme',
      employeeId: 'emp-acme-2',
      employeeName: 'Rachel Green',
      employeeEmail: 'rachel@acmefintech.io',
      triggerRule: 'BRANCH_PROTECTION_DROPPED',
      title: '⚠️ Change Control Alert: GitHub Branch Protection Disabled on Main',
      content: 'A repository main branch was modified to allow direct pushes without peer approvals. SOC 2 CC8.1 mandates strict segregation of duties where authors cannot approve their own pull requests.',
      quizQuestion: 'Why does SOC 2 CC8.1 require at least 1 approving peer review before merging code?',
      quizOptions: [
        'To intentionally delay release velocity',
        'To provide an independent verification check and prevent single-point accidental or malicious defects',
        'Because pull requests are optional for senior software engineers',
        'To allow developers to approve their own PRs from alternate emails'
      ],
      correctAnswerIndex: 1,
      explanation: 'Mandatory peer reviews ensure segregation of duties and prevent unreviewed code or secrets from entering production systems.',
      completed: false,
      sentAt: '2026-08-27T08:30:00Z'
    }
  ]
};

export const multiTenantStore = new MultiTenantStore();
