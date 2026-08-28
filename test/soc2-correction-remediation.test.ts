/**
 * SOC 2 Adversarial Test Suite: Controlled Correction & Remediation Module
 * Version: v1.0.1-rc1
 * 
 * Verifies all 14 mandatory attack vectors:
 * 1.  Original evidence mutation (WORM immutability)
 * 2.  Correction history deletion
 * 3.  Self-approval (Maker-checker segregation)
 * 4.  Forged actor identity
 * 5.  Forged role / RBAC bypass
 * 6.  Cross-tenant correction isolation
 * 7.  Missing correction reason
 * 8.  Missing supporting evidence
 * 9.  Replayed approval attack
 * 10. Modification of superseded evidence
 * 11. Workflow-state bypass
 * 12. Emergency authorization bypass
 * 13. Release-gate bypass prevention
 * 14. Audit-chain manipulation detection
 */

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { correctionService } from '../src/services/correctionService';
import { persistentStorage } from '../src/lib/persistentStorage';
import { createCanonicalEvidenceRecord } from '../src/lib/canonicalHasher';
import { releaseGateService } from '../src/services/releaseGateService';
import { Role, CanonicalEvidenceRecord } from '../src/types/soc2';

describe('SOC 2 Controlled Correction & Remediation Adversarial Suite (v1.0.1-rc1)', () => {
  let baselineEvidence: CanonicalEvidenceRecord;
  let tenantAlphaEvidence: CanonicalEvidenceRecord;

  const adminMaker = { id: 'usr_maker_1', email: 'maker@internal.soc2', role: 'admin' as Role };
  const adminChecker = { id: 'usr_checker_1', email: 'checker@internal.soc2', role: 'admin' as Role };
  const editorUser = { id: 'usr_editor_1', email: 'editor@internal.soc2', role: 'editor' as Role };
  const viewerUser = { id: 'usr_viewer_1', email: 'viewer@internal.soc2', role: 'viewer' as Role };

  before(async () => {
    // Seed test certified evidence in durable storage
    baselineEvidence = await createCanonicalEvidenceRecord({
      tenantId: 'tenant-internal',
      controlId: 'CC6.1',
      sourceSystem: 'KMS_CONFIG_ENGINE',
      rawPayload: { keyArn: 'arn:aws:kms:us-east-1:123456789012:key/test-key', rotationEnabled: true },
      previousEvidenceHash: '0000000000000000000000000000000000000000000000000000000000000000',
      verificationStatus: 'VERIFIED',
      capturedByPrincipal: 'secops@internal.soc2'
    });
    persistentStorage.saveEvidenceRecord(baselineEvidence);

    // Seed tenant-alpha evidence for cross-tenant testing
    tenantAlphaEvidence = await createCanonicalEvidenceRecord({
      tenantId: 'tenant-alpha',
      controlId: 'CC6.6',
      sourceSystem: 'S3_BUCKET_SCANNER',
      rawPayload: { bucketName: 'alpha-confidential-logs', encrypted: true },
      previousEvidenceHash: '0000000000000000000000000000000000000000000000000000000000000000',
      verificationStatus: 'VERIFIED',
      capturedByPrincipal: 'alpha-admin@client-alpha.com'
    });
    persistentStorage.saveEvidenceRecord(tenantAlphaEvidence);
  });

  // =========================================================================
  // Vector 1: Original Evidence Mutation Prevention (WORM Immutability)
  // =========================================================================
  describe('Vector C1: Original Evidence Mutation Prevention', () => {
    it('C1.1 should reject direct in-place modification of certified original evidence', () => {
      assert.throws(
        () => {
          persistentStorage.modifyCertifiedEvidence(baselineEvidence.evidenceId, { tampered: true });
        },
        /ORIGINAL_EVIDENCE_IMMUTABLE/,
        'Storage engine must strictly forbid mutating certified evidence in place'
      );
    });

    it('C1.2 should preserve original evidence byte-for-byte in WORM storage after correction applied', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Correcting typo in KMS key description metadata',
          proposedChanges: { descriptionNote: 'Updated KMS key description' }
        },
        editorUser
      );

      await correctionService.approveCorrection(correction.id, adminChecker, 'tenant-internal');
      await correctionService.applyCorrection(correction.id, editorUser, 'tenant-internal');

      // Verify original evidence is unchanged in persistent storage
      const fetchedOriginal = persistentStorage.getEvidenceRecord(baselineEvidence.evidenceId);
      assert.ok(fetchedOriginal, 'Original evidence must still exist');
      assert.equal(fetchedOriginal.currentEvidenceHash, baselineEvidence.currentEvidenceHash, 'Original evidence hash must remain identical');
      assert.equal(fetchedOriginal.canonicalPayloadHash, baselineEvidence.canonicalPayloadHash, 'Payload hash must not mutate');
    });
  });

  // =========================================================================
  // Vector 2: Correction History Deletion Prevention
  // =========================================================================
  describe('Vector C2: Correction History Deletion Prevention', () => {
    it('C2.1 should reject deletion of correction records from audit ledger', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Correction record created for deletion test',
          proposedChanges: { test: true }
        },
        editorUser
      );

      assert.throws(
        () => {
          correctionService.deleteCorrection(correction.id);
        },
        /CORRECTION_HISTORY_IMMUTABLE/,
        'Must forbid deleting historical correction records'
      );
    });
  });

  // =========================================================================
  // Vector 3: Maker-Checker Segregation / Self-Approval Prevention
  // =========================================================================
  describe('Vector C3: Maker-Checker Segregation (No Self-Approval)', () => {
    it('C3.1 should reject self-approval when requester attempts to approve their own correction', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Attempting self-approval under admin maker role',
          proposedChanges: { field: 'value' }
        },
        adminMaker
      );

      await assert.rejects(
        async () => {
          await correctionService.approveCorrection(correction.id, adminMaker, 'tenant-internal');
        },
        /SELF_APPROVAL_FORBIDDEN/,
        'Dual-control maker-checker policy must block self-approval'
      );
    });
  });

  // =========================================================================
  // Vector 4: Forged Actor Identity
  // =========================================================================
  describe('Vector C4: Forged Actor Identity & Audit Correlation', () => {
    it('C4.1 should correlate transition actor with authenticated session', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Actor correlation verification test',
          proposedChanges: { verified: true }
        },
        editorUser
      );

      assert.equal(correction.requestedByUserId, editorUser.id);
      assert.equal(correction.requestedByUserEmail, editorUser.email);
      assert.equal(correction.auditTrail[0].actorId, editorUser.id);
      assert.equal(correction.auditTrail[0].actorEmail, editorUser.email);
    });
  });

  // =========================================================================
  // Vector 5: Role Escalation / RBAC Bypass Prevention
  // =========================================================================
  describe('Vector C5: Role Escalation & RBAC Enforcement', () => {
    it('C5.1 should deny viewer role from creating correction requests', async () => {
      await assert.rejects(
        async () => {
          await correctionService.createCorrection(
            {
              tenantId: 'tenant-internal',
              type: 'METADATA_CORRECTION',
              controlId: 'CC6.1',
              originalEvidenceId: baselineEvidence.evidenceId,
              reason: 'Viewer attempting unauthorized correction creation',
              proposedChanges: { test: true }
            },
            viewerUser
          );
        },
        /RBAC_DENIED/,
        'Viewer must not be permitted to submit corrections'
      );
    });

    it('C5.2 should deny non-admin (editor) from approving corrections', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Testing approval role boundary enforcement',
          proposedChanges: { test: true }
        },
        adminMaker
      );

      await assert.rejects(
        async () => {
          await correctionService.approveCorrection(correction.id, editorUser, 'tenant-internal');
        },
        /RBAC_DENIED/,
        'Only admin checker role may approve corrections'
      );
    });
  });

  // =========================================================================
  // Vector 6: Cross-Tenant Isolation
  // =========================================================================
  describe('Vector C6: Cross-Tenant Correction Isolation', () => {
    it('C6.1 should reject correction submission when original evidence belongs to another tenant', async () => {
      await assert.rejects(
        async () => {
          // Tenant-internal user attempts to correct tenant-alpha evidence
          await correctionService.createCorrection(
            {
              tenantId: 'tenant-internal',
              type: 'METADATA_CORRECTION',
              controlId: 'CC6.6',
              originalEvidenceId: tenantAlphaEvidence.evidenceId,
              reason: 'Cross-tenant tampering attempt on external evidence',
              proposedChanges: { malicious: true }
            },
            editorUser
          );
        },
        /TENANT_ISOLATION_VIOLATION/,
        'Cross-tenant evidence correction must be blocked'
      );
    });

    it('C6.2 should reject cross-tenant approval', async () => {
      const alphaCorrection = await correctionService.createCorrection(
        {
          tenantId: 'tenant-alpha',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.6',
          originalEvidenceId: tenantAlphaEvidence.evidenceId,
          reason: 'Legitimate alpha tenant correction submission',
          proposedChanges: { tag: 'alpha' }
        },
        { id: 'alpha_maker', email: 'maker@alpha.com', role: 'admin' }
      );

      await assert.rejects(
        async () => {
          // Internal tenant admin attempts to approve alpha tenant correction
          await correctionService.approveCorrection(alphaCorrection.id, adminChecker, 'tenant-internal');
        },
        /TENANT_ISOLATION_VIOLATION/,
        'Approval across tenant boundaries must be strictly rejected'
      );
    });
  });

  // =========================================================================
  // Vector 7: Missing Correction Reason
  // =========================================================================
  describe('Vector C7: Mandatory Correction Reason Enforcement', () => {
    it('C7.1 should reject empty or missing correction reasons', async () => {
      await assert.rejects(
        async () => {
          await correctionService.createCorrection(
            {
              tenantId: 'tenant-internal',
              type: 'METADATA_CORRECTION',
              controlId: 'CC6.1',
              originalEvidenceId: baselineEvidence.evidenceId,
              reason: '',
              proposedChanges: {}
            },
            editorUser
          );
        },
        /CORRECTION_REASON_MANDATORY/,
        'Empty correction reason must be rejected'
      );
    });

    it('C7.2 should reject superficial correction reasons shorter than 10 characters', async () => {
      await assert.rejects(
        async () => {
          await correctionService.createCorrection(
            {
              tenantId: 'tenant-internal',
              type: 'METADATA_CORRECTION',
              controlId: 'CC6.1',
              originalEvidenceId: baselineEvidence.evidenceId,
              reason: 'fix bug',
              proposedChanges: {}
            },
            editorUser
          );
        },
        /CORRECTION_REASON_MANDATORY/,
        'Substantive reason with at least 10 characters required'
      );
    });
  });

  // =========================================================================
  // Vector 8: Missing Supporting Evidence
  // =========================================================================
  describe('Vector C8: Mandatory Supporting Evidence for Supersession', () => {
    it('C8.1 should reject EVIDENCE_SUPERSESSION without supporting evidence reference', async () => {
      await assert.rejects(
        async () => {
          await correctionService.createCorrection(
            {
              tenantId: 'tenant-internal',
              type: 'EVIDENCE_SUPERSESSION',
              controlId: 'CC6.1',
              originalEvidenceId: baselineEvidence.evidenceId,
              reason: 'Superseding old evidence without attaching supporting document',
              proposedChanges: { keyArn: 'arn:aws:kms:new' }
            },
            editorUser
          );
        },
        /SUPPORTING_EVIDENCE_MANDATORY/,
        'Supporting evidence is mandatory for evidence supersession'
      );
    });
  });

  // =========================================================================
  // Vector 9: Replayed Approval Attack Prevention
  // =========================================================================
  describe('Vector C9: Replayed Approval Attack Prevention', () => {
    it('C9.1 should reject duplicate approval calls on an already approved correction', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Valid correction for replay testing',
          proposedChanges: { note: 'replay test' }
        },
        editorUser
      );

      // First approval
      await correctionService.approveCorrection(correction.id, adminChecker, 'tenant-internal');

      // Replay attempt
      await assert.rejects(
        async () => {
          await correctionService.approveCorrection(correction.id, adminChecker, 'tenant-internal');
        },
        /APPROVAL_ALREADY_CONSUMED/,
        'Replay of approval call must be detected and rejected'
      );
    });
  });

  // =========================================================================
  // Vector 10: Modification of Superseded Evidence Prevention
  // =========================================================================
  describe('Vector C10: Superseded Evidence Immutability', () => {
    it('C10.1 should reject attempts to mutate superseded historical evidence records', async () => {
      assert.throws(
        () => {
          persistentStorage.modifySupersededRecord(baselineEvidence.evidenceId, { tampered: true });
        },
        /SUPERSEDED_EVIDENCE_IMMUTABLE/,
        'Superseded historical evidence must remain cryptographically sealed'
      );
    });
  });

  // =========================================================================
  // Vector 11: Workflow-State Bypass Prevention
  // =========================================================================
  describe('Vector C11: Workflow-State Bypass Prevention', () => {
    it('C11.1 should prevent applying a correction before it is APPROVED', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Testing apply without approval bypass',
          proposedChanges: { illegalApply: true }
        },
        editorUser
      );

      await assert.rejects(
        async () => {
          await correctionService.applyCorrection(correction.id, editorUser, 'tenant-internal');
        },
        /INVALID_WORKFLOW_TRANSITION/,
        'Must not apply unapproved corrections'
      );
    });

    it('C11.2 should prevent verifying a correction before it is APPLIED', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Testing verification bypass before application',
          proposedChanges: { test: true }
        },
        editorUser
      );

      await correctionService.approveCorrection(correction.id, adminChecker, 'tenant-internal');

      await assert.rejects(
        async () => {
          await correctionService.verifyCorrection(correction.id, adminChecker, 'tenant-internal');
        },
        /INVALID_WORKFLOW_TRANSITION/,
        'Must not verify corrections that have not been applied'
      );
    });

    it('C11.3 should prevent closing a correction before independent verification', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Testing closure without verification bypass',
          proposedChanges: { test: true }
        },
        editorUser
      );

      await assert.rejects(
        async () => {
          await correctionService.closeCorrection(correction.id, adminChecker, 'tenant-internal');
        },
        /WORKFLOW_STATE_BYPASS/,
        'Cannot close unverified correction'
      );
    });
  });

  // =========================================================================
  // Vector 12: Emergency Authorization Bypass Prevention
  // =========================================================================
  describe('Vector C12: Emergency Authorization Bypass Prevention', () => {
    it('C12.1 should reject EMERGENCY_CORRECTION without emergency justification', async () => {
      await assert.rejects(
        async () => {
          await correctionService.createCorrection(
            {
              tenantId: 'tenant-internal',
              type: 'EMERGENCY_CORRECTION',
              controlId: 'CC6.1',
              originalEvidenceId: baselineEvidence.evidenceId,
              reason: 'Emergency patch attempt without justification',
              supportingEvidence: 'DOC_HASH_991204',
              proposedChanges: { urgent: true }
            },
            editorUser
          );
        },
        /EMERGENCY_JUSTIFICATION_MANDATORY/,
        'Emergency corrections must have explicit emergency justification'
      );
    });

    it('C12.2 should reject emergency approval lacking elevated authorization credentials', async () => {
      const emergency = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'EMERGENCY_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Urgent certificate revocation remediation',
          supportingEvidence: 'CERT_REVOCATION_RECEIPT_1092',
          emergencyJustification: 'Critical zero-day vulnerability requires immediate control correction',
          proposedChanges: { revokedCert: 'cert_123' }
        },
        editorUser
      );

      // Attempt approval without elevated token
      await assert.rejects(
        async () => {
          await correctionService.approveCorrection(emergency.id, adminChecker, 'tenant-internal');
        },
        /EMERGENCY_AUTHORIZATION_REQUIRED/,
        'Emergency approval must require elevated multi-factor authorization'
      );
    });
  });

  // =========================================================================
  // Vector 13: Release-Gate Bypass Prevention
  // =========================================================================
  describe('Vector C13: Release-Gate Bypass Prevention', () => {
    it('C13.1 should evaluate gate-correction-remediation and block release if emergency corrections are unverified', async () => {
      const evaluation = await releaseGateService.evaluateReleaseGate('tenant-internal');
      const correctionGate = evaluation.gates.find((g) => g.gateId === 'gate-correction-remediation');
      assert.ok(correctionGate, 'Correction gate must be evaluated');

      // Since an emergency correction was created above and is pending/unverified:
      assert.equal(correctionGate.status, 'BLOCKED', 'Active unverified emergency correction must block release gate');
      assert.equal(evaluation.overallStatus, 'RELEASE_BLOCKED', 'Overall release must be BLOCKED');
      assert.equal(evaluation.humanOverrideRequired, true, 'Human review must be mandated');
    });
  });

  // =========================================================================
  // Vector 14: Audit-Chain Manipulation Detection
  // =========================================================================
  describe('Vector C14: Audit-Chain & Transition Hash Integrity', () => {
    it('C14.1 should detect tampered state transitions in correction audit trail', async () => {
      const correction = await correctionService.createCorrection(
        {
          tenantId: 'tenant-internal',
          type: 'METADATA_CORRECTION',
          controlId: 'CC6.1',
          originalEvidenceId: baselineEvidence.evidenceId,
          reason: 'Valid correction to test transition hash chain validation',
          proposedChanges: { test: true }
        },
        editorUser
      );

      await correctionService.startReview(correction.id, editorUser, 'tenant-internal');
      await correctionService.approveCorrection(correction.id, adminChecker, 'tenant-internal');

      // Verify chain is valid initially
      const initialCheck = await correctionService.verifyCorrectionIntegrity(correction.id);
      assert.equal(initialCheck.valid, true, 'Initial state transition chain must be valid');

      // Tamper with intermediate transition entry
      const fetched = persistentStorage.getCorrectionRecord(correction.id)!;
      fetched.auditTrail[1].action = 'MALICIOUS_ACTION_INJECTION';
      persistentStorage.saveCorrectionRecord(fetched);

      // Verify tamper detection
      const tamperedCheck = await correctionService.verifyCorrectionIntegrity(correction.id);
      assert.equal(tamperedCheck.valid, false, 'Tampered audit trail must fail verification');
      assert.equal(tamperedCheck.brokenAt, 1, 'Must pinpoint exact broken transition index');
    });
  });
});
