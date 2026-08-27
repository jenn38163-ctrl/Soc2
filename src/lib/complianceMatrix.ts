import { ComplianceControl } from '../types/soc2';

export const SOC2_CONTROLS: ComplianceControl[] = [
  {
    id: 'ctrl-cc6-1',
    code: 'CC6.1',
    name: 'Logical Access Controls & Secret Prevention',
    category: 'Security',
    description: 'The entity implements logical access security software, infrastructure, and architectures to protect information assets and prevents hardcoded credentials.',
    status: 'Compliant',
    score: 100,
    automatedCheck: true,
    lastAudited: '2026-08-27T15:00:00Z',
    evidenceItems: [
      'CI/CD TruffleHog automated secret scan on every PR',
      'Centralized Okta / Google Workspace SSO enforcement',
      'Mandatory Hardware / TOTP MFA (SMS prohibited)',
      'AWS Secrets Manager / Vault integration'
    ],
    operationalControl: 'Pre-commit hooks and GitHub Actions block PRs containing secrets or API keys.',
    technicalImplementation: 'GitHub Actions workflow secret-scan job with trufflehog-actions-experimental.'
  },
  {
    id: 'ctrl-cc6-2',
    code: 'CC6.2',
    name: 'User Registration, Access Rights & Least Privilege',
    category: 'Security',
    description: 'User access rights to systems and data are authenticated and authorized prior to granting access and follow least privilege principles.',
    status: 'Compliant',
    score: 100,
    automatedCheck: true,
    lastAudited: '2026-08-27T15:10:00Z',
    evidenceItems: [
      'accessPolicy.ts RBAC enforcement matrix (Admin, Editor, Viewer)',
      'Explicit authorization decision logs with correlation traceId',
      '24-hour offboarding SLA tracked in HR/IT ticketing'
    ],
    operationalControl: 'Default zero-access on onboarding. Formal manager approval required for role changes.',
    technicalImplementation: 'Runtime RBAC interceptor with auditLogger.info policy decision logging.'
  },
  {
    id: 'ctrl-cc6-3',
    code: 'CC6.3',
    name: 'Access Modification & Quarterly Recertification',
    category: 'Security',
    description: 'Access rights are modified or revoked in accordance with changes in job responsibilities and verified via quarterly user access reviews.',
    status: 'Compliant',
    score: 95,
    automatedCheck: true,
    lastAudited: '2026-08-15T11:20:00Z',
    evidenceItems: [
      'Q3 2026 signed Access Review certification',
      'Stale account automated detection script output',
      'Tracked Jira access de-provisioning tickets'
    ],
    operationalControl: 'Quarterly system owner review with digital sign-off and audit trail retention.',
    technicalImplementation: 'Automated quarterly access audit report generation & digital signature vault.'
  },
  {
    id: 'ctrl-cc6-6',
    code: 'CC6.6',
    name: 'Boundary Protection & Environment Segregation',
    category: 'Security',
    description: 'The entity implements boundary protection and logically segregates environments (Development, Staging, Production).',
    status: 'Compliant',
    score: 100,
    automatedCheck: true,
    lastAudited: '2026-08-20T08:00:00Z',
    evidenceItems: [
      'AWS Organizations Multi-Account separation (isolated IAM)',
      'Service Control Policy (SCP) blocking cross-account assumption',
      'No customer production data in staging/dev rule'
    ],
    operationalControl: 'Hard isolation of cloud accounts, zero shared database credentials or secrets.',
    technicalImplementation: 'Terraform multi-account AWS Organization configuration and SCP rules.'
  },
  {
    id: 'ctrl-cc6-7',
    code: 'CC6.7',
    name: 'Transmission & Data Encryption at Rest',
    category: 'Confidentiality',
    description: 'The entity protects data in transit and at rest using approved cryptographic algorithms and key management.',
    status: 'Compliant',
    score: 100,
    automatedCheck: true,
    lastAudited: '2026-08-27T15:20:00Z',
    evidenceItems: [
      'AES-256-GCM field-level encryption with 128-bit AuthTag',
      'AWS KMS Customer-Managed Key (CMK) annual rotation logs',
      'TLS 1.3 / strict HTTPS enforcement with HSTS header'
    ],
    operationalControl: 'Mandatory field encryption for PII, SSN, tokens, and billing fields.',
    technicalImplementation: 'encryption.ts module with WebCrypto AES-GCM and KMS key envelope simulation.'
  },
  {
    id: 'ctrl-cc6-8',
    code: 'CC6.8',
    name: 'Unauthorized Activity Prevention & Audit Logging',
    category: 'Security',
    description: 'The entity prevents unauthorized activity and maintains immutable audit logs with correlation IDs and PII sanitization.',
    status: 'Compliant',
    score: 100,
    automatedCheck: true,
    lastAudited: '2026-08-27T15:30:00Z',
    evidenceItems: [
      'Structured JSON Winston audit logs with eventId and traceId',
      'Automated PII/Secret regex & key redaction filter',
      'AWS S3 Object Lock in COMPLIANCE mode (WORM storage)'
    ],
    operationalControl: 'All write, delete, export, and policy actions logged with actor identity.',
    technicalImplementation: 'auditLogger.ts with SHA-256 hash chaining and Winston WORM output.'
  },
  {
    id: 'ctrl-cc7-1',
    code: 'CC7.1',
    name: 'Vulnerability Scanning & SAST Code Analysis',
    category: 'Security',
    description: 'The entity uses vulnerability detection tools (SCA, SAST, container scanning) to identify and remediate vulnerabilities before release.',
    status: 'Compliant',
    score: 100,
    automatedCheck: true,
    lastAudited: '2026-08-27T15:13:00Z',
    evidenceItems: [
      'GitHub Actions CodeQL SAST workflow passing clean',
      'npm audit --audit-level=high dependency audit in CI',
      'Trivy container & filesystem scanner blocking high/critical CVEs'
    ],
    operationalControl: 'Automated CI gates block merging if high or critical vulnerabilities exist.',
    technicalImplementation: 'GitHub Actions soc2-compliance.yml with CodeQL, Trivy, and npm audit.'
  },
  {
    id: 'ctrl-cc7-2',
    code: 'CC7.2',
    name: 'Incident Response & Anomaly Monitoring',
    category: 'Security',
    description: 'The entity monitors system components to detect anomalies and security incidents, executing formal incident response plans.',
    status: 'Compliant',
    score: 95,
    automatedCheck: true,
    lastAudited: '2026-08-27T14:00:00Z',
    evidenceItems: [
      'Real-time SIEM log forwarding and alert rules',
      'Documented Incident Response Plan with on-call rotation',
      'Post-mortem template and retro-documentation procedures'
    ],
    operationalControl: '24/7 automated alerts on repeated unauthorized access attempts (DENIED events).',
    technicalImplementation: 'SIEM log forwarder integration and automated incident trigger threshold.'
  },
  {
    id: 'ctrl-cc8-1',
    code: 'CC8.1',
    name: 'Software Change Management & CI/CD Gating',
    category: 'Change Management',
    description: 'The entity authorizes, designs, tests, and implements changes to software, infrastructure, and databases under strict change control.',
    status: 'Compliant',
    score: 100,
    automatedCheck: true,
    lastAudited: '2026-08-27T15:13:22Z',
    evidenceItems: [
      'GitHub branch protection on main (1+ peer approval, no force push)',
      'Segregation of duties (authors cannot approve their own PRs)',
      'Automated CI build & test coverage verification (>80% required)'
    ],
    operationalControl: 'Every production commit traces to a Pull Request, code review, and issue tracker item.',
    technicalImplementation: 'GitHub repository branch protection rules + soc2-compliance.yml workflow.'
  },
  {
    id: 'ctrl-a1-2',
    code: 'A1.2',
    name: 'Backup, Retention & Point-in-Time Recovery (Availability)',
    category: 'Availability',
    description: 'The entity implements environmental protections, automated backups, and recovery procedures to meet availability commitments.',
    status: 'Compliant',
    score: 100,
    automatedCheck: true,
    lastAudited: '2026-08-26T04:00:00Z',
    evidenceItems: [
      'Automated daily database snapshots (35-day retention)',
      'Continuous Point-in-Time Recovery (PITR) enabled',
      'Weekly automated restoration drill logs with RTO < 4 hrs, RPO < 1 hr'
    ],
    operationalControl: 'Weekly simulated disaster recovery drills in isolated sandbox environment.',
    technicalImplementation: 'Terraform Aurora PostgreSQL cluster with 35-day backup retention and AWS Backup Vault.'
  }
];
