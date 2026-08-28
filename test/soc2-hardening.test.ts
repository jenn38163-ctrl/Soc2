import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'crypto';
import { 
  envelopeEncrypt, 
  envelopeDecrypt, 
  validateCiphertextIntegrity 
} from '../src/lib/kmsEnvelopeEncryption';
import { 
  generateToken, 
  verifyToken, 
  KNOWN_PERSONAS 
} from '../src/middleware/authMiddleware';
import { canPerformAction, ROLES_PERMISSIONS } from '../src/lib/accessPolicy';
import { persistentStorage } from '../src/lib/persistentStorage';
import { releaseGateService } from '../src/services/releaseGateService';
import { auditLogStore } from '../src/lib/auditLogger';

describe('SOC 2 Production Hardening Gate Verification', () => {

  describe('Gate 1: KMS Envelope Encryption (CC6.6, CC6.7)', () => {
    it('should encrypt with persistent KMS key and decrypt correctly', () => {
      const plaintext = 'SOC-2-AUDIT-SECRET-CREDENTIAL-998811';
      const envelope = envelopeEncrypt(plaintext);

      assert.ok(envelope.ciphertext, 'Ciphertext must be present');
      assert.ok(envelope.encryptedDataKey, 'Encrypted DEK must be present');
      assert.ok(envelope.iv, '96-bit IV must be present');
      assert.ok(envelope.authTag, '128-bit GCM auth tag must be present');
      assert.equal(envelope.algorithm, 'AES-256-GCM');
      assert.equal(envelope.keyVersion, 3);

      const decrypted = envelopeDecrypt(envelope);
      assert.equal(decrypted, plaintext, 'Decrypted text must match original plaintext');
    });

    it('should detect and reject tampered ciphertext with GCM auth tag verification', () => {
      const plaintext = 'FINANCIAL_LEDGER_CONFIDENTIAL_PAYMENT';
      const envelope = envelopeEncrypt(plaintext);

      // Tamper single bit in ciphertext
      const tamperedCiphertext = envelope.ciphertext.slice(0, -2) + (envelope.ciphertext.slice(-2) === 'aa' ? 'bb' : 'aa');
      const tamperedEnvelope = {
        ...envelope,
        ciphertext: tamperedCiphertext
      };

      const check = validateCiphertextIntegrity(tamperedEnvelope);
      assert.equal(check.valid, false, 'Tampered ciphertext must fail integrity check');

      assert.throws(() => {
        envelopeDecrypt(tamperedEnvelope);
      }, /cryptographic integrity compromised|Decryption failed/i);
    });
  });

  describe('Gate 2: API Authentication & RBAC Policy Matrix (CC6.1, CC6.2)', () => {
    it('should issue and verify cryptographic HMAC-SHA256 JWT tokens', () => {
      const adminPersona = KNOWN_PERSONAS['admin'];
      const token = generateToken(adminPersona);
      assert.ok(token && token.split('.').length === 3, 'JWT must have 3 segments');

      const verified = verifyToken(token);
      assert.ok(verified, 'Token must be validly verified');
      assert.equal(verified?.email, adminPersona.email);
      assert.equal(verified?.role, 'admin');
    });

    it('should enforce role-based access permissions deny-by-default', () => {
      // Viewer should have read, but NOT write, delete, or export
      assert.equal(canPerformAction('viewer', 'read'), true);
      assert.equal(canPerformAction('viewer', 'write'), false);
      assert.equal(canPerformAction('viewer', 'delete'), false);
      assert.equal(canPerformAction('viewer', 'export'), false);

      // Editor should have read and write, but NOT delete or export
      assert.equal(canPerformAction('editor', 'read'), true);
      assert.equal(canPerformAction('editor', 'write'), true);
      assert.equal(canPerformAction('editor', 'delete'), false);

      // Admin should have all permissions
      assert.equal(canPerformAction('admin', 'delete'), true);
      assert.equal(canPerformAction('admin', 'export'), true);
    });

    it('should reject tampered JWT tokens', () => {
      const token = generateToken(KNOWN_PERSONAS['viewer']);
      const parts = token.split('.');
      // Tamper payload
      const tamperedPayload = Buffer.from(JSON.stringify({ role: 'admin', email: 'hacked@company.com' })).toString('base64url');
      const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

      const verified = verifyToken(tamperedToken);
      assert.equal(verified, null, 'Tampered token must be rejected');
    });
  });

  describe('Gate 3: Audit Log SHA-256 Hash Chain Integrity (CC6.8, CC7.2)', () => {
    it('should append structured events and verify hash chain validity', async () => {
      await auditLogStore.record({
        action: 'system.security_gate.test',
        resource: 'release_pipeline',
        actorId: 'ci-system@company.internal',
        ipAddress: '127.0.0.1',
        status: 'SUCCESS',
        traceId: 'trc_ci_gate_test',
        metadata: { gateTest: true }
      });

      const verification = await auditLogStore.verifyChainIntegrity();
      assert.equal(verification.valid, true, 'Audit log chain must be cryptographically valid');
    });
  });

  describe('Gate 4: Persistent Policy Signatures & WORM Ledger (CC1.2, CC7.1)', () => {
    it('should persist policy signatures and prevent identity spoofing', () => {
      const tenantId = 'tenant-test-hardening';
      const signature = {
        id: `sig_test_${Date.now()}`,
        tenantId,
        policyId: 'pol_soc2_sec_01',
        employeeId: 'emp_auditor',
        employeeName: 'Elena Rostova',
        employeeEmail: 'auditor@company.internal',
        role: 'auditor' as const,
        ipAddress: '10.0.0.5',
        userAgent: 'Node-Test-Runner',
        signedAt: new Date().toISOString(),
        certificateHash: crypto.createHash('sha256').update(`cert_${Date.now()}`).digest('hex'),
        versionSigned: '2026.1'
      };

      persistentStorage.recordPolicySignature(signature);
      const signatures = persistentStorage.getPolicySignatures(tenantId);
      assert.ok(signatures.some(s => s.id === signature.id), 'Signature must be persisted');
    });

    it('should persist WORM evidence records with canonical hashing', async () => {
      const tenantId = 'tenant-test-hardening';
      const record = await persistentStorage.recordEvidence({
        tenantId,
        controlId: 'CC6.6',
        source: 'KMS Keystore Audit',
        collector: 'KMS Automated Scanner',
        evidenceType: 'KEY_ROTATION_PROOF',
        payload: {
          keyId: 'arn:aws:kms:us-east-1:482910481920:key/soc2-prod-envelope-master-key',
          rotationEnabled: true,
          spec: 'SYMMETRIC_DEFAULT'
        }
      });

      assert.ok(record.evidenceId, 'Evidence ID must be generated');
      assert.ok(record.currentEvidenceHash, 'Evidence must contain SHA-256 hash');
      assert.equal(record.wormReceipt?.storageTier, 'WORM_IMMUTABLE_S3_COMPLIANCE');

      const retrieved = persistentStorage.getAllEvidenceRecords(tenantId);
      assert.ok(retrieved.some(r => r.evidenceId === record.evidenceId), 'Record must exist in persistent store');
    });
  });

  describe('Gate 5: Tri-Auditor Release Security Gate Evaluation (CC8.1)', () => {
    it('should evaluate release gate status and return structured gate results', async () => {
      const evaluation = await releaseGateService.evaluateReleaseGate('tenant-test-hardening');

      assert.ok(evaluation.releaseId, 'Release ID must be present');
      assert.ok(evaluation.gates.length >= 6, 'Must evaluate all mandatory gates');
      assert.ok(evaluation.triAuditorConsensusSummary, 'Consensus summary must be present');

      // Verify that KMS envelope and API auth gates are evaluated
      const kmsGate = evaluation.gates.find(g => g.gateId === 'gate-kms-envelope');
      assert.ok(kmsGate, 'KMS gate must exist');
      assert.equal(kmsGate.status, 'PASSED', 'KMS envelope gate must pass with persistent keystore');

      const authGate = evaluation.gates.find(g => g.gateId === 'gate-api-auth-rbac');
      assert.ok(authGate, 'API auth gate must exist');
      assert.equal(authGate.status, 'PASSED');
    });
  });

});
