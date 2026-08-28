/**
 * Types for Controlled Correction & Remediation Capability (SOC 2 CC7.1, CC7.2, CC8.1)
 * Version: v1.0.1-rc1 (Append-Only Evidence Supersession & Maker-Checker Workflow)
 */

import { Role } from './soc2';

export type CorrectionType =
  | 'METADATA_CORRECTION'
  | 'EVIDENCE_SUPERSESSION'
  | 'CONTROL_REMEDIATION'
  | 'EMERGENCY_CORRECTION';

export type CorrectionStatus =
  | 'OPEN'
  | 'UNDER_REVIEW'
  | 'APPROVED'
  | 'REJECTED'
  | 'APPLIED'
  | 'VERIFIED'
  | 'CLOSED';

export interface CorrectionAuditEntry {
  transitionId: string;
  fromStatus: CorrectionStatus;
  toStatus: CorrectionStatus;
  actorId: string;
  actorEmail: string;
  actorRole: string;
  action: string;
  timestamp: string;
  reason?: string;
  auditLogEventId?: string;
  transitionHash: string;
}

export interface CorrectionRecord {
  id: string;
  tenantId: string;
  type: CorrectionType;
  status: CorrectionStatus;
  controlId: string;
  
  // Immutability & cryptographic lineage
  originalEvidenceId: string;
  originalEvidenceHash: string;
  supersedingEvidenceId?: string;
  supersedingEvidenceHash?: string;
  
  // Mandatory justification & supporting evidence
  reason: string;
  supportingEvidence?: string;
  proposedChanges: Record<string, unknown>;
  
  // Maker metadata (Requester)
  requestedByUserId: string;
  requestedByUserEmail: string;
  requestedByUserRole: Role;
  requestedAt: string;
  
  // Reviewer metadata
  reviewerUserId?: string;
  reviewerUserEmail?: string;
  reviewedAt?: string;
  
  // Checker metadata (Approver - must differ from Maker)
  approverUserId?: string;
  approverUserEmail?: string;
  approverRole?: string;
  approvedAt?: string;
  
  // Rejection metadata
  rejectionReason?: string;
  rejectedByUserId?: string;
  rejectedAt?: string;
  
  // Execution (Applier)
  appliedByUserId?: string;
  appliedAt?: string;
  
  // Verification metadata
  verifiedByUserId?: string;
  verifiedAt?: string;
  verificationNotes?: string;
  
  // Emergency Elevated Authorization
  isEmergency: boolean;
  emergencyJustification?: string;
  emergencyAuthorizedBy?: string;
  emergencyElevatedToken?: string;
  
  // Append-only audit trail and cumulative state transition hash
  auditTrail: CorrectionAuditEntry[];
  stateTransitionHash: string;
}

export interface CreateCorrectionInput {
  tenantId: string;
  type: CorrectionType;
  controlId: string;
  originalEvidenceId: string;
  reason: string;
  supportingEvidence?: string;
  proposedChanges: Record<string, unknown>;
  emergencyJustification?: string;
}

export interface ApproveCorrectionOptions {
  emergencyAuthorized?: boolean;
  emergencyElevatedToken?: string;
  notes?: string;
}
