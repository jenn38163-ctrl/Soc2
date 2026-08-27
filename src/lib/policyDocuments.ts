import { PolicyDocument, PolicySignature } from '../types/soc2';
import { auditLogStore } from './auditLogger';

export const INITIAL_POLICIES: PolicyDocument[] = [
  {
    id: 'pol-access-control',
    title: 'Access Control Policy',
    tscCriteria: ['CC6.1', 'CC6.2', 'CC6.3'],
    version: '2.4.0',
    lastUpdated: '2026-08-15T09:00:00Z',
    owner: 'Chief Information Security Officer (CISO)',
    reviewFrequency: 'Quarterly',
    nextReviewDate: '2026-11-15T09:00:00Z',
    summary: 'Defines mandatory rules for provisioning, least privilege enforcement, MFA, and automated offboarding.',
    content: `# Policy 1: Access Control Policy
**Trust Services Criteria:** CC6.1, CC6.2, CC6.3
**Effective Date:** August 15, 2026 | **Classification:** Internal / Confidential

---

### 1. Purpose & Scope
This policy defines the rules for provisioning, managing, and revoking access to internal systems, customer data, and production infrastructure. It applies to all employees, contractors, third-party vendors, and automated service accounts.

### 2. Principle of Least Privilege
Access to systems, infrastructure, databases, and third-party tools is granted strictly based on role necessity (Least Privilege). Default access for any new account is zero/denied.

* **Admin Role:** Full administrative access for system configurations and emergency operations only.
* **Editor Role:** Operational access for content updates and day-to-day workflow changes.
* **Viewer Role:** Read-only access strictly conforming to least privilege principles.

### 3. Identity & Authentication Requirements
* **Centralized IdP:** All user access must be authenticated through the company’s centralized Identity Provider (e.g., Okta, Google Workspace SSO).
* **Multi-Factor Authentication (MFA):** MFA is mandatory for all user accounts across all platforms. Acceptable authentication methods include hardware keys (FIDO2/WebAuthn) and TOTP authenticator apps. SMS-based MFA is strictly prohibited.
* **Password Standards:** Passwords must be at least 16 characters in length and evaluated against common breach databases (HaveIBeenPwned / NIST SP 800-63B).

### 4. Access Provisioning & Offboarding
* **Provisioning:** Access requires explicit written approval from the team manager and system owner via a tracked ticket (e.g., Jira / GitHub Issue).
* **Immediate Offboarding:** Upon employee or contractor termination, HR notifies IT/Security. Access across all systems must be revoked within 24 hours of departure (immediately for involuntary terminations).

### 5. User Access Reviews
* Formal access reviews are conducted **quarterly**.
* System owners review current permission sets for all active users to identify and remove stale or excessive access. Signed evidence of completed reviews is retained for audit inspection.`,
    signatures: [
      {
        id: 'sig-01',
        policyId: 'pol-access-control',
        signerName: 'Jennifer Gremic',
        signerEmail: 'jenngremicinc@gmail.com',
        signerRole: 'Lead Security Officer',
        signedAt: '2026-08-15T11:20:00Z',
        certificateHash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
        versionSigned: '2.4.0',
        status: 'active'
      },
      {
        id: 'sig-02',
        policyId: 'pol-access-control',
        signerName: 'Alexander Hayes',
        signerEmail: 'a.hayes@enterprise.io',
        signerRole: 'Chief Technology Officer',
        signedAt: '2026-08-15T14:45:00Z',
        certificateHash: '4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9a8b7c6d5e',
        versionSigned: '2.4.0',
        status: 'active'
      }
    ]
  },
  {
    id: 'pol-change-mgmt',
    title: 'Software Change Management Policy',
    tscCriteria: ['CC8.1'],
    version: '3.1.0',
    lastUpdated: '2026-08-20T10:00:00Z',
    owner: 'VP of Engineering',
    reviewFrequency: 'Quarterly',
    nextReviewDate: '2026-11-20T10:00:00Z',
    summary: 'Governs GitHub branch protection rules, mandatory peer approvals, automated CI gates, and emergency hotfix procedures.',
    content: `# Policy 2: Software Change Management Policy
**Trust Services Criteria:** CC8.1
**Effective Date:** August 20, 2026 | **Classification:** Internal / Confidential

---

### 1. Purpose & Scope
This policy ensures all changes to production software, infrastructure, and databases are tested, reviewed, authorized, and logged prior to deployment.

### 2. Source Code Management & Branch Protection
* **Version Control:** All application code and Infrastructure as Code (IaC) must reside in the centralized version control repository (GitHub/GitLab).
* **Branch Protection:** Direct commits to \`main\` / \`production\` branches are strictly disabled.

### 3. Peer Review & Approval Controls
* **Peer Reviews:** Every code change requires at least one independent code review and explicit approval from a qualified engineer prior to merging.
* **Segregation of Duties:** Authors cannot approve their own pull requests.
* **Automated CI Gating:** Pull requests cannot be merged unless all automated checks (unit tests, secret scans, dependency vulnerability audits, SAST) pass cleanly.

### 4. Environment Separation
* **Isolation:** Development, Staging, and Production environments are physically and logically segregated with isolated IAM roles and zero shared API credentials.
* **Data Handling:** Production customer data is strictly prohibited in Non-Production environments.

### 5. Emergency Hotfix Procedure
In the event of a critical security incident or operational outage requiring an expedited fix:
* The emergency fix may be applied directly after verbal approval from the Engineering Lead / CTO.
* A post-deployment code review and retro-documentation (PR creation and incident log update) must occur within 24 hours of the emergency release.`,
    signatures: [
      {
        id: 'sig-03',
        policyId: 'pol-change-mgmt',
        signerName: 'Jennifer Gremic',
        signerEmail: 'jenngremicinc@gmail.com',
        signerRole: 'Lead Security Officer',
        signedAt: '2026-08-20T11:05:00Z',
        certificateHash: '1c0d9e8f7a6b5c4d3e2f1a0b9a8b7c6d5e4f3a2b',
        versionSigned: '3.1.0',
        status: 'active'
      }
    ]
  },
  {
    id: 'pol-encryption-rest',
    title: 'Data Protection & Encryption Policy',
    tscCriteria: ['CC6.6', 'CC6.7'],
    version: '1.9.0',
    lastUpdated: '2026-07-10T08:00:00Z',
    owner: 'Security Architecture Team',
    reviewFrequency: 'Annual',
    nextReviewDate: '2027-07-10T08:00:00Z',
    summary: 'Mandates AES-256-GCM encryption for stored data, TLS 1.3 in transit, and automatic annual KMS key rotation.',
    content: `# Policy 3: Data Protection & Encryption Policy
**Trust Services Criteria:** CC6.6, CC6.7
**Effective Date:** July 10, 2026 | **Classification:** Internal / Confidential

---

### 1. Purpose
Mandates rigorous cryptographic standards across all sensitive data tiers (at rest and in transit).

### 2. Encryption at Rest
* Cloud database storage, EBS volumes, and S3 objects must use AWS KMS / GCP Cloud KMS with AES-256 keys.
* Customer PII, tokens, and billing fields require field-level AES-256-GCM encryption with 128-bit authentication tags.

### 3. Encryption in Transit
* All external API communication must enforce TLS 1.3 (or minimum TLS 1.2 with strict cipher suites). Plain HTTP is rejected.

### 4. Key Management & Rotation
* Master keys stored in KMS/Vault must undergo automated annual rotation or immediate re-keying in case of suspected compromise.`,
    signatures: [
      {
        id: 'sig-04',
        policyId: 'pol-encryption-rest',
        signerName: 'Jennifer Gremic',
        signerEmail: 'jenngremicinc@gmail.com',
        signerRole: 'Lead Security Officer',
        signedAt: '2026-07-10T09:30:00Z',
        certificateHash: '7a6b5c4d3e2f1a0b9a8b7c6d5e4f3a2b1c0d9e8f',
        versionSigned: '1.9.0',
        status: 'active'
      }
    ]
  },
  {
    id: 'pol-disaster-recovery',
    title: 'Disaster Recovery & Backup Policy',
    tscCriteria: ['A1.2'],
    version: '2.0.0',
    lastUpdated: '2026-06-25T14:00:00Z',
    owner: 'Site Reliability Engineering (SRE)',
    reviewFrequency: 'Semi-Annual',
    nextReviewDate: '2026-12-25T14:00:00Z',
    summary: 'Establishes Recovery Point Objective (RPO <= 1 hr), Recovery Time Objective (RTO <= 4 hrs), and daily automated restoration drill logs.',
    content: `# Policy 4: Disaster Recovery & Backup Policy
**Trust Services Criteria:** A1.2 (Availability)
**Effective Date:** June 25, 2026 | **Classification:** Internal / Confidential

---

### 1. Purpose
Guarantees continuous system availability, automated data redundancy, and proven recovery capabilities.

### 2. Backup Schedules
* Automated daily full database snapshots with continuous point-in-time recovery (PITR) logs (35-day retention).
* Cross-region replication of critical databases and immutable S3 buckets with Object Lock (WORM).

### 3. Recovery Objectives
* **Recovery Point Objective (RPO):** Maximum 1 hour.
* **Recovery Time Objective (RTO):** Maximum 4 hours.

### 4. Restoration Drills
* Automated restoration tests execute weekly in an isolated sandbox to verify snapshot integrity and RTO adherence. Signed drill evidence is retained for auditor review.`,
    signatures: [
      {
        id: 'sig-05',
        policyId: 'pol-disaster-recovery',
        signerName: 'Jennifer Gremic',
        signerEmail: 'jenngremicinc@gmail.com',
        signerRole: 'Lead Security Officer',
        signedAt: '2026-06-25T16:15:00Z',
        certificateHash: '5c4d3e2f1a0b9a8b7c6d5e4f3a2b1c0d9e8f7a6b',
        versionSigned: '2.0.0',
        status: 'active'
      }
    ]
  }
];

class PolicyStore {
  private policies: PolicyDocument[] = [...INITIAL_POLICIES];

  public getPolicies(): PolicyDocument[] {
    return [...this.policies];
  }

  public getPolicyById(id: string): PolicyDocument | undefined {
    return this.policies.find((p) => p.id === id);
  }

  public async signPolicy(
    policyId: string,
    signerName: string,
    signerEmail: string,
    signerRole: string
  ): Promise<PolicySignature> {
    const policy = this.getPolicyById(policyId);
    if (!policy) {
      throw new Error(`Policy not found: ${policyId}`);
    }

    const timestamp = new Date().toISOString();
    const certificateHash = Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2);

    const signature: PolicySignature = {
      id: `sig_${Date.now()}`,
      policyId,
      signerName,
      signerEmail,
      signerRole,
      signedAt: timestamp,
      certificateHash,
      versionSigned: policy.version,
      status: 'active'
    };

    policy.signatures = [signature, ...policy.signatures.filter((s) => s.signerEmail !== signerEmail)];

    await auditLogStore.record({
      traceId: `trc_sig_${Date.now()}`,
      actorId: signerEmail,
      action: 'policy.sign_off',
      resource: policy.id,
      ipAddress: '192.168.1.100',
      status: 'SUCCESS',
      metadata: {
        policyTitle: policy.title,
        policyVersion: policy.version,
        signerRole,
        certificateHash
      }
    });

    return signature;
  }
}

export const policyStore = new PolicyStore();
