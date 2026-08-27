import { AuditLogPayload } from '../types/soc2';

// Sensitive keys to redact for PII/Secrets (SOC 2 CC6.8, CC7.2)
const SENSITIVE_KEYS = [
  'password',
  'token',
  'ssn',
  'creditcard',
  'secret',
  'apikey',
  'authheader',
  'privatekey',
  'cvv',
  'pin'
];

/**
 * Sanitizes metadata payload by redacting sensitive values
 */
export function sanitizePayloadMetadata(metadata?: Record<string, unknown>): Record<string, unknown> | undefined {
  if (!metadata) return undefined;
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(metadata)) {
    const isSensitive = SENSITIVE_KEYS.some((s) => key.toLowerCase().includes(s));
    if (isSensitive) {
      sanitized[key] = '[REDACTED]';
    } else if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
      sanitized[key] = sanitizePayloadMetadata(value as Record<string, unknown>);
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

/**
 * Computes a SHA-256 hash for immutable log chain verification (WORM emulation)
 */
export async function computeBlockHash(
  previousHash: string,
  eventId: string,
  timestamp: string,
  actorId: string,
  action: string,
  status: string
): Promise<string> {
  const content = `${previousHash}|${eventId}|${timestamp}|${actorId}|${action}|${status}`;
  
  // Use Web Crypto API or Node crypto
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const encoder = new TextEncoder();
    const data = encoder.encode(content);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
  }
  
  // Fallback simple hash for environments without WebCrypto
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const char = content.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0;
  }
  return Math.abs(hash).toString(16).padStart(64, '0');
}

// In-memory immutable log buffer with initial SOC 2 audit evidence seeds
const INITIAL_LOGS: AuditLogPayload[] = [
  {
    eventId: 'evt_01J8A9K1M2N3P4Q5R6S7T8U9V0',
    traceId: 'trc_99a8b7c6-d5e4-4321-8765-abcdef123456',
    actorId: 'usr_sec_auditor_01',
    action: 'policy.verify',
    resource: 'RBAC_Policy',
    ipAddress: '192.168.1.45',
    status: 'SUCCESS',
    timestamp: '2026-08-27T14:10:00.000Z',
    previousHash: '0000000000000000000000000000000000000000000000000000000000000000',
    currentHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    metadata: {
      policy: 'AccessControlPolicy_v2.1',
      reviewType: 'Quarterly_Access_Recertification',
      findings: 0
    }
  },
  {
    eventId: 'evt_01J8A9K2A3B4C5D6E7F8G9H0J1',
    traceId: 'trc_44b3c2d1-e6f5-4987-9876-123456abcdef',
    actorId: 'svc_ci_deployer',
    action: 'authorize.write',
    resource: 'prod_database_cluster',
    ipAddress: '10.0.4.12',
    status: 'SUCCESS',
    timestamp: '2026-08-27T14:35:12.000Z',
    previousHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    currentHash: '7a9c8f01b3d5e7a9c8f01b3d5e7a9c8f01b3d5e7a9c8f01b3d5e7a9c8f01b3d5',
    metadata: {
      role: 'admin',
      requestedAction: 'write',
      mfaVerified: true,
      idpProvider: 'Okta_SSO'
    }
  },
  {
    eventId: 'evt_01J8A9K3K4L5M6N7P8Q9R0S1T2',
    traceId: 'trc_77c8d9e0-f1a2-4567-8901-fedcba654321',
    actorId: 'usr_contractor_dev99',
    action: 'authorize.export',
    resource: 'customer_billing_vault',
    ipAddress: '203.0.113.88',
    status: 'DENIED',
    timestamp: '2026-08-27T15:02:44.000Z',
    previousHash: '7a9c8f01b3d5e7a9c8f01b3d5e7a9c8f01b3d5e7a9c8f01b3d5e7a9c8f01b3d5',
    currentHash: '4f8d2b1a9c3e5f7a4f8d2b1a9c3e5f7a4f8d2b1a9c3e5f7a4f8d2b1a9c3e5f7a',
    metadata: {
      role: 'viewer',
      requestedAction: 'export',
      reason: 'Least privilege violation: viewer cannot perform export',
      alertForwardedToSIEM: true
    }
  },
  {
    eventId: 'evt_01J8A9K4W5X6Y7Z8A9B0C1D2E3',
    traceId: 'trc_22f3a4b5-c6d7-4890-1234-987654321abc',
    actorId: 'usr_compliance_lead',
    action: 'data.encrypt',
    resource: 'customer_ssn_store',
    ipAddress: '192.168.1.102',
    status: 'SUCCESS',
    timestamp: '2026-08-27T15:20:10.000Z',
    previousHash: '4f8d2b1a9c3e5f7a4f8d2b1a9c3e5f7a4f8d2b1a9c3e5f7a4f8d2b1a9c3e5f7a',
    currentHash: '1c2b3a4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
    metadata: {
      algorithm: 'aes-256-gcm',
      keyId: 'kms-key-prod-soc2-v3',
      ssn: '[REDACTED]',
      creditCard: '[REDACTED]'
    }
  }
];

class ImmutableAuditLogStore {
  private logs: AuditLogPayload[] = [...INITIAL_LOGS];
  private subscribers: Array<(log: AuditLogPayload) => void> = [];

  public getLogs(): AuditLogPayload[] {
    return [...this.logs];
  }

  public async record(
    payload: Omit<AuditLogPayload, 'eventId' | 'timestamp' | 'previousHash' | 'currentHash'>
  ): Promise<AuditLogPayload> {
    const eventId = `evt_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
    const timestamp = new Date().toISOString();
    const previousLog = this.logs[this.logs.length - 1];
    const previousHash = previousLog ? (previousLog.currentHash || '0000000000000000000000000000000000000000000000000000000000000000') : '0000000000000000000000000000000000000000000000000000000000000000';
    
    // Sanitize metadata to redact PII/Secrets
    const sanitizedMeta = sanitizePayloadMetadata(payload.metadata);
    
    const currentHash = await computeBlockHash(
      previousHash,
      eventId,
      timestamp,
      payload.actorId,
      payload.action,
      payload.status
    );

    const logEntry: AuditLogPayload = {
      ...payload,
      eventId,
      timestamp,
      metadata: sanitizedMeta,
      previousHash,
      currentHash
    };

    this.logs.push(logEntry);
    this.notify(logEntry);
    return logEntry;
  }

  public subscribe(callback: (log: AuditLogPayload) => void): () => void {
    this.subscribers.push(callback);
    return () => {
      this.subscribers = this.subscribers.filter((cb) => cb !== callback);
    };
  }

  private notify(log: AuditLogPayload) {
    this.subscribers.forEach((cb) => {
      try {
        cb(log);
      } catch (err) {
        console.error('AuditLog subscriber error:', err);
      }
    });
  }

  public async verifyChainIntegrity(): Promise<{ valid: boolean; brokenAt?: number; totalChecked: number }> {
    for (let i = 0; i < this.logs.length; i++) {
      const current = this.logs[i];
      const prev = i > 0 ? this.logs[i - 1] : null;
      const expectedPrevHash = prev ? prev.currentHash : '0000000000000000000000000000000000000000000000000000000000000000';

      if (current.previousHash !== expectedPrevHash) {
        return { valid: false, brokenAt: i, totalChecked: this.logs.length };
      }

      const recalculatedHash = await computeBlockHash(
        current.previousHash || '',
        current.eventId,
        current.timestamp || '',
        current.actorId,
        current.action,
        current.status
      );

      // Verify consistency
      if (current.currentHash !== recalculatedHash) {
        return { valid: false, brokenAt: i, totalChecked: this.logs.length };
      }
    }

    return { valid: true, totalChecked: this.logs.length };
  }

  public clearTestLogs() {
    this.logs = [...INITIAL_LOGS];
  }
}

export const auditLogStore = new ImmutableAuditLogStore();
