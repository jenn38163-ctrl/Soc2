/**
 * Controlled Correction & Remediation Service (SOC 2 CC7.1, CC7.2, CC8.1)
 * Version: v1.0.1-rc1
 * 
 * Enforces:
 * 1. Maker/Checker Separation (no self-approval)
 * 2. Strict RBAC (Maker: write permission; Checker: admin; Emergency: elevated admin)
 * 3. Tenant Isolation
 * 4. Certified Evidence Immutability (WORM: no in-place UPDATE/DELETE)
 * 5. Append-Only Correction Ledger with SHA-256 state-transition chaining
 * 6. RFC 8785 canonical hash generation and parent-linkage on superseding records
 * 7. Enforced Workflow State Machine:
 *    OPEN -> UNDER_REVIEW -> APPROVED -> APPLIED -> VERIFIED -> CLOSED (or REJECTED)
 */

import { persistentStorage } from '../lib/persistentStorage';
import { auditLogStore } from '../lib/auditLogger';
import { createCanonicalEvidenceRecord, computeSha256Digest, canonicalizeJson } from '../lib/canonicalHasher';
import {
  CorrectionType,
  CorrectionStatus,
  CorrectionRecord,
  CorrectionAuditEntry,
  CreateCorrectionInput,
  ApproveCorrectionOptions,
  Role,
  CanonicalEvidenceRecord
} from '../types/soc2';

export class CorrectionService {
  /**
   * Helper to compute state transition cryptographic digest
   */
  private async computeTransitionHash(
    correctionId: string,
    fromStatus: CorrectionStatus,
    toStatus: CorrectionStatus,
    action: string,
    actorId: string,
    timestamp: string,
    previousTransitionHash: string
  ): Promise<string> {
    const input = `${previousTransitionHash}:${correctionId}:${fromStatus}:${toStatus}:${action}:${actorId}:${timestamp}`;
    return computeSha256Digest(input);
  }

  /**
   * Submits a new correction or remediation request (Maker role)
   */
  public async createCorrection(
    input: CreateCorrectionInput,
    actor: { id: string; email: string; role: Role }
  ): Promise<CorrectionRecord> {
    if (!input.tenantId || typeof input.tenantId !== 'string') {
      throw new Error('TENANT_REQUIRED: tenantId is mandatory for correction requests');
    }

    // 1. RBAC Check: Viewers are strictly forbidden
    if (actor.role === 'viewer') {
      throw new Error("RBAC_DENIED: Role 'viewer' is not authorized to create corrections. Requires write permission (editor or admin).");
    }

    // 2. Mandatory substantive justification (minimum 10 chars)
    if (!input.reason || typeof input.reason !== 'string' || input.reason.trim().length < 10) {
      throw new Error('CORRECTION_REASON_MANDATORY: A substantive correction reason (minimum 10 characters) is required.');
    }

    // 3. Mandatory supporting evidence for supersession, remediation, and emergency
    const requiresSupportingEvidence =
      input.type === 'EVIDENCE_SUPERSESSION' ||
      input.type === 'CONTROL_REMEDIATION' ||
      input.type === 'EMERGENCY_CORRECTION';

    if (requiresSupportingEvidence) {
      if (!input.supportingEvidence || typeof input.supportingEvidence !== 'string' || input.supportingEvidence.trim().length < 5) {
        throw new Error(`SUPPORTING_EVIDENCE_MANDATORY: Supporting evidence document reference or cryptographic digest is mandatory for ${input.type}.`);
      }
    }

    // 4. Emergency correction justification check
    if (input.type === 'EMERGENCY_CORRECTION') {
      if (!input.emergencyJustification || typeof input.emergencyJustification !== 'string' || input.emergencyJustification.trim().length < 15) {
        throw new Error('EMERGENCY_JUSTIFICATION_MANDATORY: Emergency corrections require detailed justification (minimum 15 characters).');
      }
    }

    // 5. Retrieve target original evidence and enforce Tenant Isolation
    const originalEvidence = persistentStorage.getEvidenceRecord(input.originalEvidenceId);
    if (!originalEvidence) {
      throw new Error(`ORIGINAL_EVIDENCE_NOT_FOUND: Target evidence ID '${input.originalEvidenceId}' does not exist in durable WORM storage.`);
    }

    if (originalEvidence.tenantId !== input.tenantId) {
      throw new Error(`TENANT_ISOLATION_VIOLATION: Original evidence belongs to tenant '${originalEvidence.tenantId}', mismatch with requested tenant '${input.tenantId}'.`);
    }

    const timestamp = new Date().toISOString();
    const correctionId = `corr_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 8)}`;
    const initialTransitionHash = await computeSha256Digest(
      `INIT:${correctionId}:${input.originalEvidenceId}:${originalEvidence.currentEvidenceHash}:${actor.id}:${timestamp}`
    );

    // 6. Record audit log into continuous SHA-256 hash chain
    const auditEvent = await auditLogStore.record({
      traceId: `trc_${correctionId}`,
      actorId: actor.id,
      action: 'correction.requested',
      resource: `evidence/${originalEvidence.evidenceId}`,
      ipAddress: '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        correctionId,
        tenantId: input.tenantId,
        controlId: input.controlId,
        correctionType: input.type,
        originalEvidenceHash: originalEvidence.currentEvidenceHash,
        reason: input.reason
      }
    });

    const initialAuditEntry: CorrectionAuditEntry = {
      transitionId: `tr_${Date.now().toString(36)}_0`,
      fromStatus: 'OPEN',
      toStatus: 'OPEN',
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      action: 'SUBMIT',
      timestamp,
      reason: input.reason,
      auditLogEventId: auditEvent?.eventId,
      transitionHash: initialTransitionHash
    };

    const record: CorrectionRecord = {
      id: correctionId,
      tenantId: input.tenantId,
      type: input.type,
      status: 'OPEN',
      controlId: input.controlId,
      originalEvidenceId: originalEvidence.evidenceId,
      originalEvidenceHash: originalEvidence.currentEvidenceHash,
      reason: input.reason,
      supportingEvidence: input.supportingEvidence,
      proposedChanges: input.proposedChanges || {},
      requestedByUserId: actor.id,
      requestedByUserEmail: actor.email,
      requestedByUserRole: actor.role,
      requestedAt: timestamp,
      isEmergency: input.type === 'EMERGENCY_CORRECTION',
      emergencyJustification: input.emergencyJustification,
      auditTrail: [initialAuditEntry],
      stateTransitionHash: initialTransitionHash
    };

    persistentStorage.saveCorrectionRecord(record);
    persistentStorage.appendCorrectionLedgerEntry(record, initialAuditEntry);

    return record;
  }

  /**
   * Moves a correction into review state
   */
  public async startReview(
    correctionId: string,
    actor: { id: string; email: string; role: Role },
    tenantId: string
  ): Promise<CorrectionRecord> {
    const correction = persistentStorage.getCorrectionRecord(correctionId);
    if (!correction) {
      throw new Error(`CORRECTION_NOT_FOUND: Correction ID '${correctionId}' not found.`);
    }

    if (correction.tenantId !== tenantId) {
      throw new Error(`TENANT_ISOLATION_VIOLATION: Cross-tenant correction review denied. Belonging tenant: '${correction.tenantId}', requested: '${tenantId}'.`);
    }

    if (actor.role === 'viewer') {
      throw new Error("RBAC_DENIED: Role 'viewer' cannot review corrections.");
    }

    if (correction.status !== 'OPEN') {
      throw new Error(`INVALID_WORKFLOW_TRANSITION: Cannot start review on correction with status '${correction.status}'. Must be in 'OPEN' state.`);
    }

    const timestamp = new Date().toISOString();
    const transitionHash = await this.computeTransitionHash(
      correction.id,
      'OPEN',
      'UNDER_REVIEW',
      'START_REVIEW',
      actor.id,
      timestamp,
      correction.stateTransitionHash
    );

    const auditEvent = await auditLogStore.record({
      traceId: `trc_${correction.id}`,
      actorId: actor.id,
      action: 'correction.under_review',
      resource: `correction/${correction.id}`,
      ipAddress: '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        correctionId: correction.id,
        tenantId: correction.tenantId,
        reviewer: actor.email
      }
    });

    const auditEntry: CorrectionAuditEntry = {
      transitionId: `tr_${Date.now().toString(36)}_${correction.auditTrail.length}`,
      fromStatus: 'OPEN',
      toStatus: 'UNDER_REVIEW',
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      action: 'START_REVIEW',
      timestamp,
      auditLogEventId: auditEvent?.eventId,
      transitionHash
    };

    correction.status = 'UNDER_REVIEW';
    correction.reviewerUserId = actor.id;
    correction.reviewerUserEmail = actor.email;
    correction.reviewedAt = timestamp;
    correction.auditTrail.push(auditEntry);
    correction.stateTransitionHash = transitionHash;

    persistentStorage.saveCorrectionRecord(correction);
    persistentStorage.appendCorrectionLedgerEntry(correction, auditEntry);

    return correction;
  }

  /**
   * Approves a correction (Checker role).
   * Enforces:
   * - Maker/Checker Separation (Requester cannot approve their own correction)
   * - Strict Admin role
   * - Elevated authorization for Emergency corrections
   * - Replay prevention
   */
  public async approveCorrection(
    correctionId: string,
    actor: { id: string; email: string; role: Role },
    tenantId: string,
    options?: ApproveCorrectionOptions
  ): Promise<CorrectionRecord> {
    const correction = persistentStorage.getCorrectionRecord(correctionId);
    if (!correction) {
      throw new Error(`CORRECTION_NOT_FOUND: Correction ID '${correctionId}' not found.`);
    }

    // 1. Tenant Isolation
    if (correction.tenantId !== tenantId) {
      throw new Error(`TENANT_ISOLATION_VIOLATION: Cross-tenant approval denied. Target tenant: '${correction.tenantId}', caller tenant: '${tenantId}'.`);
    }

    // 2. RBAC: Must be admin
    if (actor.role !== 'admin') {
      throw new Error(`RBAC_DENIED: Admin role required for correction approval. Role '${actor.role}' is insufficient.`);
    }

    // 3. Maker/Checker Segregation: Requester cannot approve own correction
    if (actor.id === correction.requestedByUserId || actor.email === correction.requestedByUserEmail) {
      throw new Error(`SELF_APPROVAL_FORBIDDEN: Maker-checker segregation violated. Requester '${actor.email}' cannot approve their own correction.`);
    }

    // 4. State & Replay Check
    if (correction.status === 'APPROVED') {
      throw new Error('APPROVAL_ALREADY_CONSUMED: Cannot re-approve an already approved correction (replay attack prevented).');
    }

    if (correction.status !== 'UNDER_REVIEW' && correction.status !== 'OPEN') {
      throw new Error(`INVALID_WORKFLOW_TRANSITION: Cannot approve correction in status '${correction.status}'. Must be 'OPEN' or 'UNDER_REVIEW'.`);
    }

    // 5. Emergency elevated authorization check
    if (correction.type === 'EMERGENCY_CORRECTION') {
      if (!options?.emergencyAuthorized || !options?.emergencyElevatedToken) {
        throw new Error('EMERGENCY_AUTHORIZATION_REQUIRED: Emergency corrections require explicit elevated multi-factor or CISO/Admin explicit authorization token.');
      }
    }

    const timestamp = new Date().toISOString();
    const transitionHash = await this.computeTransitionHash(
      correction.id,
      correction.status,
      'APPROVED',
      'APPROVE',
      actor.id,
      timestamp,
      correction.stateTransitionHash
    );

    const auditEvent = await auditLogStore.record({
      traceId: `trc_${correction.id}`,
      actorId: actor.id,
      action: 'correction.approved',
      resource: `correction/${correction.id}`,
      ipAddress: '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        correctionId: correction.id,
        tenantId: correction.tenantId,
        approver: actor.email,
        maker: correction.requestedByUserEmail,
        isEmergency: correction.isEmergency,
        notes: options?.notes
      }
    });

    const auditEntry: CorrectionAuditEntry = {
      transitionId: `tr_${Date.now().toString(36)}_${correction.auditTrail.length}`,
      fromStatus: correction.status,
      toStatus: 'APPROVED',
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      action: 'APPROVE',
      timestamp,
      reason: options?.notes || 'Correction approved after dual-control review.',
      auditLogEventId: auditEvent?.eventId,
      transitionHash
    };

    correction.status = 'APPROVED';
    correction.approverUserId = actor.id;
    correction.approverUserEmail = actor.email;
    correction.approverRole = actor.role;
    correction.approvedAt = timestamp;
    if (correction.isEmergency) {
      correction.emergencyAuthorizedBy = actor.email;
      correction.emergencyElevatedToken = options?.emergencyElevatedToken;
    }
    correction.auditTrail.push(auditEntry);
    correction.stateTransitionHash = transitionHash;

    persistentStorage.saveCorrectionRecord(correction);
    persistentStorage.appendCorrectionLedgerEntry(correction, auditEntry);

    return correction;
  }

  /**
   * Rejects a correction request
   */
  public async rejectCorrection(
    correctionId: string,
    actor: { id: string; email: string; role: Role },
    tenantId: string,
    rejectionReason: string
  ): Promise<CorrectionRecord> {
    const correction = persistentStorage.getCorrectionRecord(correctionId);
    if (!correction) {
      throw new Error(`CORRECTION_NOT_FOUND: Correction ID '${correctionId}' not found.`);
    }

    if (correction.tenantId !== tenantId) {
      throw new Error(`TENANT_ISOLATION_VIOLATION: Cross-tenant rejection denied.`);
    }

    if (actor.role !== 'admin' && actor.role !== 'editor') {
      throw new Error("RBAC_DENIED: Role 'viewer' cannot reject corrections.");
    }

    if (!rejectionReason || rejectionReason.trim().length < 5) {
      throw new Error('REJECTION_REASON_MANDATORY: Rejection reason must be provided (minimum 5 characters).');
    }

    if (correction.status === 'APPLIED' || correction.status === 'VERIFIED' || correction.status === 'CLOSED') {
      throw new Error(`INVALID_WORKFLOW_TRANSITION: Cannot reject correction that has already reached '${correction.status}'.`);
    }

    const timestamp = new Date().toISOString();
    const transitionHash = await this.computeTransitionHash(
      correction.id,
      correction.status,
      'REJECTED',
      'REJECT',
      actor.id,
      timestamp,
      correction.stateTransitionHash
    );

    const auditEvent = await auditLogStore.record({
      traceId: `trc_${correction.id}`,
      actorId: actor.id,
      action: 'correction.rejected',
      resource: `correction/${correction.id}`,
      ipAddress: '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        correctionId: correction.id,
        tenantId: correction.tenantId,
        rejectedBy: actor.email,
        rejectionReason
      }
    });

    const auditEntry: CorrectionAuditEntry = {
      transitionId: `tr_${Date.now().toString(36)}_${correction.auditTrail.length}`,
      fromStatus: correction.status,
      toStatus: 'REJECTED',
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      action: 'REJECT',
      timestamp,
      reason: rejectionReason,
      auditLogEventId: auditEvent?.eventId,
      transitionHash
    };

    correction.status = 'REJECTED';
    correction.rejectedByUserId = actor.id;
    correction.rejectedAt = timestamp;
    correction.rejectionReason = rejectionReason;
    correction.auditTrail.push(auditEntry);
    correction.stateTransitionHash = transitionHash;

    persistentStorage.saveCorrectionRecord(correction);
    persistentStorage.appendCorrectionLedgerEntry(correction, auditEntry);

    return correction;
  }

  /**
   * Applies an approved correction.
   * Generates a new RFC 8785 canonical superseding evidence record
   * linked to the original evidence hash, and appends to the immutable WORM ledger.
   * Certified original evidence remains 100% immutable!
   */
  public async applyCorrection(
    correctionId: string,
    actor: { id: string; email: string; role: Role },
    tenantId: string
  ): Promise<CorrectionRecord> {
    const correction = persistentStorage.getCorrectionRecord(correctionId);
    if (!correction) {
      throw new Error(`CORRECTION_NOT_FOUND: Correction ID '${correctionId}' not found.`);
    }

    if (correction.tenantId !== tenantId) {
      throw new Error(`TENANT_ISOLATION_VIOLATION: Cross-tenant apply denied.`);
    }

    if (actor.role === 'viewer') {
      throw new Error("RBAC_DENIED: Role 'viewer' cannot apply corrections.");
    }

    if (correction.status !== 'APPROVED') {
      throw new Error(`INVALID_WORKFLOW_TRANSITION: Correction must be in 'APPROVED' state before being applied. Current status: '${correction.status}'.`);
    }

    // Retrieve original evidence and verify it has not been tampered with
    const originalEvidence = persistentStorage.getEvidenceRecord(correction.originalEvidenceId);
    if (!originalEvidence) {
      throw new Error(`ORIGINAL_EVIDENCE_NOT_FOUND: Original evidence '${correction.originalEvidenceId}' not found.`);
    }

    if (originalEvidence.currentEvidenceHash !== correction.originalEvidenceHash) {
      throw new Error('ORIGINAL_EVIDENCE_INTEGRITY_COMPROMISED: Original evidence hash mismatch. Potential tampering detected.');
    }

    // Create superseding payload merging changes and adding backward cryptographic linkage
    const supersedingPayload = {
      ...(typeof originalEvidence.rawPayload === 'object' && !Array.isArray(originalEvidence.rawPayload) ? originalEvidence.rawPayload : {}),
      ...correction.proposedChanges,
      _supersessionLineage: {
        supersededEvidenceId: originalEvidence.evidenceId,
        parentEvidenceHash: originalEvidence.currentEvidenceHash,
        correctionId: correction.id,
        correctionType: correction.type,
        reason: correction.reason,
        supportingEvidence: correction.supportingEvidence,
        appliedBy: actor.email,
        appliedAt: new Date().toISOString()
      }
    };

    // Construct Canonical Evidence Record with deterministic JCS RFC 8785 hashing
    const supersedingRecord = await createCanonicalEvidenceRecord({
      tenantId: correction.tenantId,
      controlId: correction.controlId,
      sourceSystem: `${originalEvidence.sourceSystem} [SUPERSEDED via Correction ${correction.id}]`,
      rawPayload: supersedingPayload,
      previousEvidenceHash: originalEvidence.currentEvidenceHash,
      verificationStatus: 'VERIFIED',
      capturedByPrincipal: actor.email,
      reproducibilityNotes: `Supersedes ${originalEvidence.evidenceId} under Correction ID ${correction.id}`
    });

    // Append superseding record to WORM ledger (original remains immutable and untouched)
    persistentStorage.appendWormLedgerRecord(supersedingRecord);

    const timestamp = new Date().toISOString();
    const transitionHash = await this.computeTransitionHash(
      correction.id,
      'APPROVED',
      'APPLIED',
      'APPLY',
      actor.id,
      timestamp,
      correction.stateTransitionHash
    );

    const auditEvent = await auditLogStore.record({
      traceId: `trc_${correction.id}`,
      actorId: actor.id,
      action: 'correction.applied',
      resource: `evidence/${supersedingRecord.evidenceId}`,
      ipAddress: '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        correctionId: correction.id,
        tenantId: correction.tenantId,
        originalEvidenceId: originalEvidence.evidenceId,
        originalEvidenceHash: originalEvidence.currentEvidenceHash,
        supersedingEvidenceId: supersedingRecord.evidenceId,
        supersedingEvidenceHash: supersedingRecord.currentEvidenceHash
      }
    });

    const auditEntry: CorrectionAuditEntry = {
      transitionId: `tr_${Date.now().toString(36)}_${correction.auditTrail.length}`,
      fromStatus: 'APPROVED',
      toStatus: 'APPLIED',
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      action: 'APPLY',
      timestamp,
      auditLogEventId: auditEvent?.eventId,
      transitionHash
    };

    correction.status = 'APPLIED';
    correction.supersedingEvidenceId = supersedingRecord.evidenceId;
    correction.supersedingEvidenceHash = supersedingRecord.currentEvidenceHash;
    correction.appliedByUserId = actor.id;
    correction.appliedAt = timestamp;
    correction.auditTrail.push(auditEntry);
    correction.stateTransitionHash = transitionHash;

    persistentStorage.saveCorrectionRecord(correction);
    persistentStorage.appendCorrectionLedgerEntry(correction, auditEntry);

    return correction;
  }

  /**
   * Verifies an applied correction (Checker / Independent Auditor step).
   * Validates:
   * 1. Status is APPLIED (cannot skip directly to VERIFIED)
   * 2. Superseding record exists in WORM storage
   * 3. Back-link to original evidence hash is intact
   * 4. Canonical payload hash matches
   */
  public async verifyCorrection(
    correctionId: string,
    actor: { id: string; email: string; role: Role },
    tenantId: string,
    verificationNotes?: string
  ): Promise<CorrectionRecord> {
    const correction = persistentStorage.getCorrectionRecord(correctionId);
    if (!correction) {
      throw new Error(`CORRECTION_NOT_FOUND: Correction ID '${correctionId}' not found.`);
    }

    if (correction.tenantId !== tenantId) {
      throw new Error(`TENANT_ISOLATION_VIOLATION: Cross-tenant verification denied.`);
    }

    if (actor.role !== 'admin') {
      throw new Error(`RBAC_DENIED: Admin role required for verification.`);
    }

    if (correction.status !== 'APPLIED') {
      throw new Error(`INVALID_WORKFLOW_TRANSITION: Correction must be in 'APPLIED' state before verification. Current status: '${correction.status}'.`);
    }

    if (!correction.supersedingEvidenceId || !correction.supersedingEvidenceHash) {
      throw new Error('VERIFICATION_FAILED: Missing superseding evidence references on applied correction.');
    }

    const supersedingRecord = persistentStorage.getEvidenceRecord(correction.supersedingEvidenceId);
    if (!supersedingRecord) {
      throw new Error(`VERIFICATION_FAILED: Superseding evidence record '${correction.supersedingEvidenceId}' not found in WORM storage.`);
    }

    if (supersedingRecord.currentEvidenceHash !== correction.supersedingEvidenceHash) {
      throw new Error('VERIFICATION_FAILED: Superseding evidence hash mismatch with correction record.');
    }

    if (supersedingRecord.previousEvidenceHash !== correction.originalEvidenceHash) {
      throw new Error('VERIFICATION_FAILED: Cryptographic back-link broken: previousEvidenceHash does not equal originalEvidenceHash.');
    }

    // Verify canonical payload hash determinism
    const recalculatedPayloadDigest = await computeSha256Digest(canonicalizeJson(supersedingRecord.rawPayload));
    if (recalculatedPayloadDigest !== supersedingRecord.canonicalPayloadHash) {
      throw new Error('VERIFICATION_FAILED: Deterministic RFC 8785 payload hash validation failed.');
    }

    const timestamp = new Date().toISOString();
    const transitionHash = await this.computeTransitionHash(
      correction.id,
      'APPLIED',
      'VERIFIED',
      'VERIFY',
      actor.id,
      timestamp,
      correction.stateTransitionHash
    );

    const auditEvent = await auditLogStore.record({
      traceId: `trc_${correction.id}`,
      actorId: actor.id,
      action: 'correction.verified',
      resource: `correction/${correction.id}`,
      ipAddress: '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        correctionId: correction.id,
        tenantId: correction.tenantId,
        verifier: actor.email,
        verifiedEvidenceId: supersedingRecord.evidenceId,
        notes: verificationNotes
      }
    });

    const auditEntry: CorrectionAuditEntry = {
      transitionId: `tr_${Date.now().toString(36)}_${correction.auditTrail.length}`,
      fromStatus: 'APPLIED',
      toStatus: 'VERIFIED',
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      action: 'VERIFY',
      timestamp,
      reason: verificationNotes || 'Cryptographic back-link and canonical payload hash verified.',
      auditLogEventId: auditEvent?.eventId,
      transitionHash
    };

    correction.status = 'VERIFIED';
    correction.verifiedByUserId = actor.id;
    correction.verifiedAt = timestamp;
    correction.verificationNotes = verificationNotes || 'Cryptographically verified';
    correction.auditTrail.push(auditEntry);
    correction.stateTransitionHash = transitionHash;

    persistentStorage.saveCorrectionRecord(correction);
    persistentStorage.appendCorrectionLedgerEntry(correction, auditEntry);

    return correction;
  }

  /**
   * Closes a verified or rejected correction
   */
  public async closeCorrection(
    correctionId: string,
    actor: { id: string; email: string; role: Role },
    tenantId: string
  ): Promise<CorrectionRecord> {
    const correction = persistentStorage.getCorrectionRecord(correctionId);
    if (!correction) {
      throw new Error(`CORRECTION_NOT_FOUND: Correction ID '${correctionId}' not found.`);
    }

    if (correction.tenantId !== tenantId) {
      throw new Error(`TENANT_ISOLATION_VIOLATION: Cross-tenant close denied.`);
    }

    if (actor.role !== 'admin') {
      throw new Error("RBAC_DENIED: Admin role required to close correction.");
    }

    // Must be VERIFIED or REJECTED
    if (correction.status !== 'VERIFIED' && correction.status !== 'REJECTED') {
      throw new Error(`WORKFLOW_STATE_BYPASS: Cannot close correction before verification or rejection. Current status: '${correction.status}'.`);
    }

    const timestamp = new Date().toISOString();
    const transitionHash = await this.computeTransitionHash(
      correction.id,
      correction.status,
      'CLOSED',
      'CLOSE',
      actor.id,
      timestamp,
      correction.stateTransitionHash
    );

    const auditEvent = await auditLogStore.record({
      traceId: `trc_${correction.id}`,
      actorId: actor.id,
      action: 'correction.closed',
      resource: `correction/${correction.id}`,
      ipAddress: '127.0.0.1',
      status: 'SUCCESS',
      metadata: {
        correctionId: correction.id,
        tenantId: correction.tenantId,
        closedBy: actor.email
      }
    });

    const auditEntry: CorrectionAuditEntry = {
      transitionId: `tr_${Date.now().toString(36)}_${correction.auditTrail.length}`,
      fromStatus: correction.status,
      toStatus: 'CLOSED',
      actorId: actor.id,
      actorEmail: actor.email,
      actorRole: actor.role,
      action: 'CLOSE',
      timestamp,
      auditLogEventId: auditEvent?.eventId,
      transitionHash
    };

    correction.status = 'CLOSED';
    correction.auditTrail.push(auditEntry);
    correction.stateTransitionHash = transitionHash;

    persistentStorage.saveCorrectionRecord(correction);
    persistentStorage.appendCorrectionLedgerEntry(correction, auditEntry);

    return correction;
  }

  // --- Immutability Defense Guards (Direct Attacks) ---

  public deleteCorrection(id: string): never {
    return persistentStorage.deleteCorrectionRecord(id);
  }

  public modifyOriginalEvidence(evidenceId: string, updates?: any): never {
    return persistentStorage.modifyCertifiedEvidence(evidenceId, updates);
  }

  public modifySupersededEvidence(evidenceId: string, updates?: any): never {
    return persistentStorage.modifySupersededRecord(evidenceId, updates);
  }

  public getCorrection(id: string): CorrectionRecord | undefined {
    return persistentStorage.getCorrectionRecord(id);
  }

  public getCorrections(tenantId?: string): CorrectionRecord[] {
    return persistentStorage.getAllCorrectionRecords(tenantId);
  }

  /**
   * Verifies the cryptographic chain of transitions on a correction record
   */
  public async verifyCorrectionIntegrity(correctionId: string): Promise<{ valid: boolean; brokenAt?: number }> {
    const correction = persistentStorage.getCorrectionRecord(correctionId);
    if (!correction) return { valid: false };

    for (let i = 1; i < correction.auditTrail.length; i++) {
      const prev = correction.auditTrail[i - 1];
      const curr = correction.auditTrail[i];

      const expectedHash = await this.computeTransitionHash(
        correction.id,
        curr.fromStatus,
        curr.toStatus,
        curr.action,
        curr.actorId,
        curr.timestamp,
        prev.transitionHash
      );

      if (curr.transitionHash !== expectedHash) {
        return { valid: false, brokenAt: i };
      }
    }

    return { valid: true };
  }
}

export const correctionService = new CorrectionService();
