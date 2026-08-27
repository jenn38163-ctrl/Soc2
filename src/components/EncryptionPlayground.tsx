import React, { useState } from 'react';
import { Key, Lock, Unlock, ShieldCheck, AlertOctagon, RefreshCw, Copy, Check, CheckCircle2, ShieldAlert } from 'lucide-react';
import { motion } from 'motion/react';
import { ACTIVE_KMS_KEYS, encryptSensitiveData, decryptSensitiveData, KMSKey } from '../lib/encryption';
import { EncryptedPayload } from '../types/soc2';

interface EncryptionPlaygroundProps {
  onEncrypted: () => void;
}

export const EncryptionPlayground: React.FC<EncryptionPlaygroundProps> = ({ onEncrypted }) => {
  const [plainTextInput, setPlainTextInput] = useState('{"ssn": "987-65-4321", "creditCard": "4111-2222-3333-4444", "bankRouting": "121000358"}');
  const [selectedKeyId, setSelectedKeyId] = useState('kms-key-prod-soc2-v3');
  const [currentEncrypted, setCurrentEncrypted] = useState<EncryptedPayload | null>(null);
  const [decryptedOutput, setDecryptedOutput] = useState<string | null>(null);
  const [decryptionError, setDecryptionError] = useState<string | null>(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [isDecrypting, setIsDecrypting] = useState(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [kmsKeys, setKmsKeys] = useState<KMSKey[]>(ACTIVE_KMS_KEYS);

  // Field tampering state
  const [tamperedCiphertext, setTamperedCiphertext] = useState<string>('');

  const handleEncrypt = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsEncrypting(true);
    setDecryptedOutput(null);
    setDecryptionError(null);

    const payload = await encryptSensitiveData(
      plainTextInput,
      selectedKeyId,
      'usr_compliance_officer',
      `trc_enc_${Math.random().toString(36).substring(2, 10)}`
    );

    setCurrentEncrypted(payload);
    setTamperedCiphertext(payload.ciphertext);
    setIsEncrypting(false);
    onEncrypted();
  };

  const handleDecrypt = async (useTampered: boolean = false) => {
    if (!currentEncrypted) return;
    setIsDecrypting(true);
    setDecryptedOutput(null);
    setDecryptionError(null);

    try {
      const payloadToDecrypt: EncryptedPayload = {
        ...currentEncrypted,
        ciphertext: useTampered ? tamperedCiphertext : currentEncrypted.ciphertext
      };

      const result = await decryptSensitiveData(
        payloadToDecrypt,
        'usr_compliance_officer',
        `trc_dec_${Math.random().toString(36).substring(2, 10)}`
      );

      setDecryptedOutput(result.plainText);
      onEncrypted();
    } catch (err: any) {
      setDecryptionError(err.message || 'Decryption failed: Authentication tag verification failed');
      onEncrypted();
    } finally {
      setIsDecrypting(false);
    }
  };

  const handleRotateKey = () => {
    const nextVersion = kmsKeys.length + 1;
    const newKeyId = `kms-key-prod-soc2-v${nextVersion}`;
    const newKey: KMSKey = {
      keyId: newKeyId,
      alias: `alias/app-prod-envelope-master-key-v${nextVersion}`,
      algorithm: 'AES-256-GCM',
      version: nextVersion,
      status: 'ENABLED',
      createdAt: new Date().toISOString()
    };

    setKmsKeys((prev) => [
      newKey,
      ...prev.map((k) => (k.status === 'ENABLED' ? { ...k, status: 'ROTATED' as const, rotatedAt: new Date().toISOString() } : k))
    ]);
    setSelectedKeyId(newKeyId);
  };

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-amber-500/10 border border-amber-500/30 text-amber-400 rounded-lg">
              <Key className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Data Encryption at Rest & In Transit (CC6.6, CC6.7)</h2>
              <p className="text-xs text-slate-400">
                AES-256-GCM field-level encryption with 12-byte IVs, 128-bit AuthTags, and KMS Master Key lifecycle
              </p>
            </div>
          </div>

          <button
            onClick={handleRotateKey}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-amber-400" />
            <span>Simulate Annual KMS Key Rotation</span>
          </button>
        </div>
      </div>

      {/* KMS Keys Registry Status */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <h3 className="text-sm font-bold text-white mb-1">AWS KMS Customer-Managed Keys (CMK Registry)</h3>
        <p className="text-xs text-slate-400 mb-4">
          Hardware Security Module (HSM) backed master keys with automatic annual rotation policy (CC6.7)
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {kmsKeys.map((key) => {
            const isSelected = selectedKeyId === key.keyId;
            return (
              <div
                key={key.keyId}
                onClick={() => setSelectedKeyId(key.keyId)}
                className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-amber-950/40 border-amber-500 ring-1 ring-amber-500'
                    : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-mono text-xs font-bold text-slate-200">{key.keyId}</span>
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                      key.status === 'ENABLED'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {key.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono truncate">{key.alias}</div>
                <div className="mt-2 text-[10px] text-slate-500 flex justify-between">
                  <span>Algo: {key.algorithm}</span>
                  <span>v{key.version}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Live Encryption & Decryption Sandbox */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Plaintext Input & Encrypt Action */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-bold text-white">Sensitive Plaintext Input (Client / Service)</h3>
            </div>
            <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono">
              Algorithm: AES-256-GCM
            </span>
          </div>

          <form onSubmit={handleEncrypt} className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Customer Record / PII Payload to Encrypt
              </label>
              <textarea
                rows={4}
                value={plainTextInput}
                onChange={(e) => setPlainTextInput(e.target.value)}
                className="w-full p-3 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-cyan-300 focus:outline-none focus:border-amber-500"
                placeholder="Enter sensitive JSON, SSN, tokens..."
                required
              />
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Selected KMS Master Key</label>
              <input
                type="text"
                disabled
                value={selectedKeyId}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-400"
              />
            </div>

            <button
              type="submit"
              disabled={isEncrypting}
              className="w-full flex items-center justify-center gap-2 py-2.5 bg-amber-600 hover:bg-amber-500 text-white font-bold rounded-lg text-xs shadow-lg shadow-amber-600/20 transition-all"
            >
              <Lock className="w-4 h-4" />
              <span>Encrypt with AES-256-GCM & Emit Audit Log</span>
            </button>
          </form>
        </div>

        {/* Right: Ciphertext, IV, AuthTag & Decrypt Verification */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-white">Cryptographic Envelope & Verification</h3>
            </div>
            <span className="text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded font-mono">
              Tag: 128-bit GCM
            </span>
          </div>

          {currentEncrypted ? (
            <div className="space-y-3 text-xs">
              {/* Ciphertext */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-slate-400 font-medium">Ciphertext (Hex Encoded):</span>
                  <button
                    onClick={() => copyToClipboard(currentEncrypted.ciphertext, 'cipher')}
                    className="text-[10px] text-amber-400 hover:text-amber-300 flex items-center gap-1"
                  >
                    <Copy className="w-3 h-3" />
                    <span>{copiedField === 'cipher' ? 'Copied' : 'Copy'}</span>
                  </button>
                </div>
                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg font-mono text-amber-300 break-all text-[11px] max-h-20 overflow-y-auto">
                  {currentEncrypted.ciphertext}
                </div>
              </div>

              {/* IV & AuthTag */}
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-slate-400 font-medium block mb-1">Random IV (12-Bytes):</span>
                  <div className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-cyan-300 text-[10px] truncate">
                    {currentEncrypted.iv}
                  </div>
                </div>
                <div>
                  <span className="text-slate-400 font-medium block mb-1">Auth Tag (16-Bytes):</span>
                  <div className="p-2 bg-slate-950 border border-slate-800 rounded font-mono text-emerald-400 text-[10px] truncate">
                    {currentEncrypted.authTag}
                  </div>
                </div>
              </div>

              {/* Decrypt Actions */}
              <div className="pt-2 flex gap-2">
                <button
                  type="button"
                  onClick={() => handleDecrypt(false)}
                  disabled={isDecrypting}
                  className="flex-1 flex items-center justify-center gap-1.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-lg text-xs"
                >
                  <Unlock className="w-3.5 h-3.5" />
                  <span>Verify AuthTag & Decrypt</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    // Flip a character in ciphertext to test tamper rejection
                    const modified = tamperedCiphertext.slice(0, 4) === 'aaaa' ? 'ffff' + tamperedCiphertext.slice(4) : 'aaaa' + tamperedCiphertext.slice(4);
                    setTamperedCiphertext(modified);
                    handleDecrypt(true);
                  }}
                  className="px-3 py-2 bg-rose-950 hover:bg-rose-900 border border-rose-800 text-rose-300 font-bold rounded-lg text-xs flex items-center gap-1"
                >
                  <AlertOctagon className="w-3.5 h-3.5" />
                  <span>Test Tamper Attack</span>
                </button>
              </div>

              {/* Decrypted Output / Error */}
              {decryptedOutput && (
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-3 bg-emerald-950/40 border border-emerald-500/60 rounded-lg text-slate-200"
                >
                  <div className="flex items-center gap-1.5 text-emerald-400 font-bold text-xs mb-1">
                    <CheckCircle2 className="w-4 h-4" />
                    <span>Auth Tag Verified! Decrypted Plaintext:</span>
                  </div>
                  <pre className="font-mono text-[11px] text-emerald-300 overflow-x-auto">
                    {decryptedOutput}
                  </pre>
                </motion.div>
              )}

              {decryptionError && (
                <motion.div
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="p-3 bg-rose-950/60 border border-rose-500/60 rounded-lg text-rose-200"
                >
                  <div className="flex items-center gap-1.5 text-rose-400 font-bold text-xs mb-1">
                    <ShieldAlert className="w-4 h-4" />
                    <span>Tamper Detected! CC6.7 Security Gate Rejection</span>
                  </div>
                  <p className="text-[11px] text-rose-300">{decryptionError}</p>
                </motion.div>
              )}
            </div>
          ) : (
            <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 text-xs">
              Encrypt plaintext on the left to inspect the AES-256-GCM cryptographic envelope and test tamper rejection.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
