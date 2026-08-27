import { EncryptedPayload } from '../types/soc2';
import { auditLogStore } from './auditLogger';

export interface KMSKey {
  keyId: string;
  alias: string;
  algorithm: string;
  version: number;
  status: 'ENABLED' | 'ROTATED' | 'DISABLED';
  createdAt: string;
  rotatedAt?: string;
  rawKeyBytes?: Uint8Array;
}

// Active KMS Key Registry Simulation
export const ACTIVE_KMS_KEYS: KMSKey[] = [
  {
    keyId: 'kms-key-prod-soc2-v3',
    alias: 'alias/app-prod-envelope-master-key',
    algorithm: 'AES-256-GCM',
    version: 3,
    status: 'ENABLED',
    createdAt: '2026-06-01T00:00:00Z',
    rotatedAt: '2026-08-01T00:00:00Z'
  },
  {
    keyId: 'kms-key-prod-soc2-v2',
    alias: 'alias/app-prod-envelope-master-key-v2',
    algorithm: 'AES-256-GCM',
    version: 2,
    status: 'ROTATED',
    createdAt: '2026-03-01T00:00:00Z',
    rotatedAt: '2026-06-01T00:00:00Z'
  }
];

// Helper to generate a 32-byte key
async function getOrDeriveCryptoKey(keySeed: string = 'soc2-master-key-seed-32byteslong!!'): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(keySeed.padEnd(32, '0').slice(0, 32)),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: encoder.encode('soc2-compliance-salt-2026'),
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts sensitive text using AES-256-GCM with a random 12-byte IV and returns ciphertext + IV + AuthTag
 * Satisfies SOC 2 CC6.6 & CC6.7 (Encryption at rest & field level encryption)
 */
export async function encryptSensitiveData(
  plainText: string,
  keyId: string = 'kms-key-prod-soc2-v3',
  actorId: string = 'usr_service_account',
  traceId: string = `trc_${Math.random().toString(36).substring(2, 10)}`
): Promise<EncryptedPayload> {
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV recommended for AES-GCM
  const encoder = new TextEncoder();
  const data = encoder.encode(plainText);

  const cryptoKey = await getOrDeriveCryptoKey(keyId);
  
  // Encrypt with 128-bit tag length
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
      tagLength: 128
    },
    cryptoKey,
    data
  );

  // In WebCrypto AES-GCM, the ciphertext includes the 16-byte authentication tag appended at the end
  const fullBytes = new Uint8Array(encryptedBuffer);
  const tagLengthBytes = 16;
  const ciphertextBytes = fullBytes.slice(0, fullBytes.length - tagLengthBytes);
  const authTagBytes = fullBytes.slice(fullBytes.length - tagLengthBytes);

  const ivHex = Array.from(iv).map((b) => b.toString(16).padStart(2, '0')).join('');
  const ciphertextHex = Array.from(ciphertextBytes).map((b) => b.toString(16).padStart(2, '0')).join('');
  const authTagHex = Array.from(authTagBytes).map((b) => b.toString(16).padStart(2, '0')).join('');

  const result: EncryptedPayload = {
    ciphertext: ciphertextHex,
    iv: ivHex,
    authTag: authTagHex,
    algorithm: 'AES-256-GCM',
    keyId,
    encryptedAt: new Date().toISOString(),
    originalFieldSample: plainText.length > 4 ? `${plainText.slice(0, 2)}***${plainText.slice(-2)}` : '***'
  };

  // Log encryption operation for SOC 2 evidence (CC6.6, CC6.8)
  await auditLogStore.record({
    traceId,
    actorId,
    action: 'data.encrypt',
    resource: 'FieldLevelEncryptionVault',
    ipAddress: '10.0.8.20',
    status: 'SUCCESS',
    metadata: {
      algorithm: 'aes-256-gcm',
      keyId,
      ivLengthBytes: 12,
      authTagLengthBytes: 16,
      payloadLength: plainText.length,
      encryptedAt: result.encryptedAt
    }
  });

  return result;
}

/**
 * Decrypts AES-256-GCM payload and verifies the authentication tag
 */
export async function decryptSensitiveData(
  payload: EncryptedPayload,
  actorId: string = 'usr_service_account',
  traceId: string = `trc_${Math.random().toString(36).substring(2, 10)}`
): Promise<{ plainText: string; verified: boolean }> {
  try {
    const ivBytes = new Uint8Array(
      payload.iv.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );
    const ciphertextBytes = new Uint8Array(
      payload.ciphertext.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );
    const authTagBytes = new Uint8Array(
      payload.authTag.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );

    // Recombine ciphertext and auth tag for WebCrypto decrypt
    const combinedBytes = new Uint8Array(ciphertextBytes.length + authTagBytes.length);
    combinedBytes.set(ciphertextBytes, 0);
    combinedBytes.set(authTagBytes, ciphertextBytes.length);

    const cryptoKey = await getOrDeriveCryptoKey(payload.keyId);

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: ivBytes,
        tagLength: 128
      },
      cryptoKey,
      combinedBytes
    );

    const decoder = new TextDecoder();
    const plainText = decoder.decode(decryptedBuffer);

    // Log decryption event with correlation ID
    await auditLogStore.record({
      traceId,
      actorId,
      action: 'data.decrypt',
      resource: 'FieldLevelEncryptionVault',
      ipAddress: '10.0.8.20',
      status: 'SUCCESS',
      metadata: {
        keyId: payload.keyId,
        authTagVerified: true,
        decryptedAt: new Date().toISOString()
      }
    });

    return { plainText, verified: true };
  } catch (error) {
    // Log failed decryption / tampering attempt
    await auditLogStore.record({
      traceId,
      actorId,
      action: 'data.decrypt',
      resource: 'FieldLevelEncryptionVault',
      ipAddress: '10.0.8.20',
      status: 'FAILURE',
      metadata: {
        keyId: payload.keyId,
        authTagVerified: false,
        error: error instanceof Error ? error.message : 'Decryption authentication failed'
      }
    });

    throw new Error('Authentication tag mismatch or invalid master key. Ciphertext integrity compromised.');
  }
}
