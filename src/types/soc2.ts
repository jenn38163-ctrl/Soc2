export type Role = 'admin' | 'editor' | 'viewer';
export type Action = 'read' | 'write' | 'delete' | 'export';

export interface AuditLogPayload {
  eventId: string;
  traceId: string;       // Request correlation ID
  actorId: string;       // User or Service Account ID
  action: string;        // E.g., 'user.delete', 'data.export', 'policy.update'
  resource: string;      // E.g., 'workspace_123', 'RBAC_Policy', 'customer_pii'
  ipAddress: string;
  status: 'SUCCESS' | 'FAILURE' | 'DENIED';
  timestamp?: string;
  previousHash?: string;
  currentHash?: string;
  metadata?: Record<string, unknown>;
}

export interface RbacDecision {
  allowed: boolean;
  role: Role;
  action: Action;
  actorId: string;
  traceId: string;
  resource: string;
  timestamp: string;
  policyReason: string;
}

export interface EncryptedPayload {
  ciphertext: string;
  iv: string;
  authTag: string;
  algorithm: string;
  keyId: string;
  encryptedAt: string;
  originalFieldSample?: string;
}

export interface PipelineStep {
  id: string;
  name: string;
  criteria: string;
  tool: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  durationMs?: number;
  logs: string[];
  findingsCount: number;
}

export interface PipelineRun {
  runId: string;
  commitHash: string;
  branch: string;
  triggeredBy: string;
  startedAt: string;
  completedAt?: string;
  status: 'pending' | 'running' | 'passed' | 'blocked';
  steps: PipelineStep[];
}

export interface PolicySignature {
  id: string;
  policyId: string;
  signerName: string;
  signerEmail: string;
  signerRole: string;
  signedAt: string;
  certificateHash: string;
  versionSigned: string;
  status: 'active' | 'expired' | 'pending';
}

export interface PolicyDocument {
  id: string;
  title: string;
  tscCriteria: string[];
  version: string;
  lastUpdated: string;
  owner: string;
  reviewFrequency: string;
  nextReviewDate: string;
  summary: string;
  content: string;
  signatures: PolicySignature[];
}

export interface ComplianceControl {
  id: string;
  code: string; // e.g. "CC6.1"
  name: string;
  category: 'Security' | 'Availability' | 'Confidentiality' | 'Change Management';
  description: string;
  status: 'Compliant' | 'In Review' | 'Action Required';
  score: number; // 0-100
  automatedCheck: boolean;
  lastAudited: string;
  evidenceItems: string[];
  operationalControl: string;
  technicalImplementation: string;
}

// -------------------------------------------------------------
// MULTI-TENANT & CONTINUOUS AUTOMATION TYPES (Prisma & Worker Models)
// -------------------------------------------------------------

export type AccountStatus = 'ACTIVE' | 'SUSPENDED_PAST_DUE' | 'TRIALING' | 'CANCELED';
export type SubscriptionTier = 'starter' | 'growth' | 'enterprise';

export interface Tenant {
  id: string;
  name: string;
  slug: string;
  mode: 'internal' | 'commercial';
  createdAt: string;
  complianceScore: number;
  contactEmail: string;
  awsAccountId?: string;
  externalId?: string;
  clientIamRoleArn?: string;
  secureExternalToken?: string;
  accountStatus?: AccountStatus;
  subscriptionTier?: SubscriptionTier;
  stripeCustomerId?: string;
  stripeSubscriptionId?: string;
  workersActive?: boolean;
}

export interface AwsIntegrationConfig {
  tenantId: string;
  clientIamRoleArn: string;
  secureExternalToken: string;
  targetAwsAccountId?: string;
  region?: string;
  sessionDurationSeconds?: number;
  lastScannedAt?: string;
  status?: 'CONNECTED' | 'SCANNING' | 'ERROR' | 'ROLE_UNVERIFIED';
  errorMessage?: string;
}

export interface AwsStsScanFinding {
  ruleCode: string;
  title: string;
  resourceId: string;
  severity: IssueSeverity;
  status: IssueStatus;
  description: string;
  remediationGuidance: string;
}

export interface AwsStsScanResult {
  tenantId: string;
  assumedRoleArn: string;
  sessionTokenPreview: string;
  externalIdUsed: string;
  scanTimestamp: string;
  isCompliant: boolean;
  findings: AwsStsScanFinding[];
  evaluatedRules: {
    passwordPolicy: boolean;
    rootMfa: boolean;
    s3PublicAccessBlock: boolean;
    s3KmsEncryption: boolean;
    securityGroupsSSH: boolean;
  };
  ledgerSnapshotId?: string;
}

export type IntegrationProvider = 'aws' | 'github' | 'google_workspace' | 'okta' | 'snyk' | 'prowler';

export interface Integration {
  id: string;
  tenantId: string;
  provider: IntegrationProvider;
  name: string;
  authMethod: 'sts_role' | 'api_key' | 'oauth_token';
  roleArn?: string;
  externalId?: string;
  region?: string;
  credentialsMasked: string; // AES-256 encrypted behind the scenes
  status: 'connected' | 'error' | 'syncing' | 'pending_setup';
  lastSyncAt: string;
  syncIntervalMinutes: number;
  activeChecks: string[];
  meta?: Record<string, unknown>;
}

export interface EvidenceSnapshot {
  id: string;
  tenantId: string;
  controlCode: string; // e.g., "CC6.1_MFA", "CC6.6_S3_ENCRYPT", "CC8.1_BRANCH_PROTECT"
  provider: IntegrationProvider;
  title: string;
  rawPayload: Record<string, unknown> | Array<Record<string, unknown>>;
  createdAt: string;
  sha256Hash: string;
  ledgerHash?: string;
  previousLedgerHash?: string;
  recordCount: number;
  isCompliant: boolean;
  remediationGuidance?: string;
}

export interface Employee {
  id: string;
  tenantId: string;
  email: string;
  name: string;
  department: string;
  role: string;
  status: 'ACTIVE' | 'TERMINATED';
  avatarUrl?: string;
}

export interface StaffPolicySignature {
  id: string;
  tenantId: string;
  policyId: string;
  employeeId: string;
  employeeName: string;
  employeeEmail: string;
  ipAddress: string;
  userAgent: string;
  signedAt: string;
  certificateHash: string;
  versionSigned: string;
}

export interface AutomatedPR {
  id: string;
  tenantId: string;
  repoName: string;
  prNumber: number;
  policyType: string;
  title: string;
  branchName: string;
  status: 'OPEN' | 'MERGED' | 'CLOSED';
  prUrl: string;
  createdAt: string;
}

export interface MicroLessonLog {
  id: string;
  tenantId: string;
  employeeId: string;
  employeeName: string;
  employeeEmail: string;
  triggerRule: string; // e.g. "OPEN_SSH_PORT", "BRANCH_PROTECTION_DROPPED", "SECRET_COMMITTED"
  title: string;
  content: string;
  quizQuestion: string;
  quizOptions: string[];
  correctAnswerIndex: number;
  explanation: string;
  userAnswerIndex?: number;
  completed: boolean;
  sentAt: string;
  completedAt?: string;
}

export type IssueSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
export type IssueStatus = 'OPEN' | 'IN_REMEDIATION' | 'RESOLVED';

export interface ComplianceIssue {
  id: string;
  tenantId: string;
  controlCode: string;
  resourceId: string;
  title: string;
  description: string;
  severity: IssueSeverity;
  status: IssueStatus;
  assignee: string;
  openedAt: string;
  slaDeadline: string; // e.g., 30-day policy deadline
  resolvedAt?: string;
  provider: IntegrationProvider;
  autoRemediationAvailable: boolean;
  autoRemediationAction?: string;
  evidenceSnapshotId?: string;
}

export interface WorkerJob {
  id: string;
  tenantId: string;
  name: string;
  provider: IntegrationProvider;
  controlCode: string;
  status: 'waiting' | 'active' | 'completed' | 'failed';
  startedAt?: string;
  completedAt?: string;
  durationMs?: number;
  logs: string[];
  findingsCount: number;
}

export interface WebhookEventLog {
  id: string;
  tenantId: string;
  provider: IntegrationProvider;
  event: string;
  receivedAt: string;
  payloadSummary: string;
  actionTaken: string;
  severity: 'INFO' | 'WARNING' | 'ALERT';
}

export interface SteampipeTableDef {
  name: string;
  description: string;
  provider: IntegrationProvider;
  queryExample: string;
  data: Record<string, unknown>[];
}

// -------------------------------------------------------------
// TRI-AUDITOR MULTI-AGENT CONSENSUS & CONTINUOUS AUDITING TYPES
// -------------------------------------------------------------

export type AgentAuditorId = 'chatgpt_control' | 'claude_adversarial' | 'gemini_technical';
export type AgentVerdict = 'PASS' | 'PARTIAL' | 'FAIL' | 'NOT_TESTABLE';
export type ConsensusStatus = 'CONFIRMED_PASS' | 'DISPUTED' | 'CONFIRMED_FAILURE' | 'PARTIAL' | 'NOT_TESTABLE';
export type FinalAssuranceStatus = 'READY_FOR_HUMAN_ASSURANCE' | 'HUMAN_ADJUDICATED' | 'REMEDIATION_REQUIRED' | 'INVESTIGATION_NEEDED';

export interface AgentFinding {
  id: string;
  controlId: string;
  agentId: AgentAuditorId;
  agentName: string;
  agentRole: string;
  requirement: string;
  evidenceExamined: string;
  testPerformed: string;
  result: AgentVerdict;
  severity: IssueSeverity;
  reason: string;
  remediation: string;
  evidenceNeeded: string;
  attackVector?: string;
  isRedTeamExploitConfirmed?: boolean;
  timestamp: string;
  codeSnippetTested?: string;
}

export interface EvidenceLineageRecord {
  evidenceId: string;
  controlId: string;
  source: string;
  timestamp: string;
  collectionMethod: string;
  sha256Hash: string;
  agent: string;
  testResult: AgentVerdict;
  reviewer: string;
  status: 'ACTIVE' | 'STALE' | 'REPLACED' | 'DISPUTED';
  rawPayloadPreview?: string;
}

export interface HumanAdjudicationRecord {
  id: string;
  reviewerName: string;
  reviewerEmail: string;
  reviewerRole: string;
  decision: 'ACCEPT_PASS' | 'UPHOLD_FAIL' | 'REQUIRE_REMEDIATION';
  notes: string;
  adjudicatedAt: string;
  digitalSignature: string;
}

export interface ControlConsensusState {
  controlId: string;
  controlCode: string;
  name: string;
  category: 'Security' | 'Availability' | 'Confidentiality' | 'Change Management';
  chatgptVerdict: AgentVerdict;
  claudeVerdict: AgentVerdict;
  geminiVerdict: AgentVerdict;
  consensusStatus: ConsensusStatus;
  finalAssuranceStatus: FinalAssuranceStatus;
  evidenceStatus: 'VERIFIED' | 'IN_MEMORY_ONLY' | 'UNVERIFIED' | 'SYNTHETIC';
  evidenceHashes: EvidenceLineageRecord[];
  findings: AgentFinding[];
  redTeamExploitTraces: string[];
  humanAdjudication?: HumanAdjudicationRecord;
}

export interface LiveDeploymentGateStep {
  id: string;
  name: string;
  stage: 'source' | 'build' | 'deploy' | 'live_endpoint' | 'security_tests' | 'evidence_collection' | 'tri_agent_review' | 'human_assurance';
  status: 'pending' | 'running' | 'success' | 'failed' | 'warning';
  details: string;
  latencyMs?: number;
  evidenceHash?: string;
  endpointUrl?: string;
  lastExecuted?: string;
  telemetry?: string;
}

export interface ContinuousAuditingCheck {
  id: string;
  name: string;
  category: 'RBAC' | 'Authentication' | 'Secrets' | 'Dependencies' | 'TLS_Headers' | 'Audit_Logs' | 'Database_Config' | 'Backups' | 'Evidence_Freshness';
  intervalSeconds: number;
  lastRunAt: string;
  status: 'HEALTHY' | 'WARNING' | 'ALERT';
  lastResult: string;
  consecutiveSuccesses: number;
  evidenceLineageId?: string;
}

