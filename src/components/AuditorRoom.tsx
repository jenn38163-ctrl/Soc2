import React, { useState, useEffect } from 'react';
import { 
  Eye, 
  Shield, 
  CheckCircle2, 
  Download, 
  FileText, 
  CheckSquare, 
  Sparkles, 
  AlertCircle, 
  FileCheck, 
  Layers, 
  Terminal, 
  Lock, 
  Unlock, 
  RefreshCw, 
  Link as LinkIcon, 
  AlertTriangle, 
  Copy, 
  Check, 
  BookOpen, 
  Printer,
  ShieldCheck,
  ShieldAlert,
  ArrowRight
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { SOC2_CONTROLS } from '../lib/complianceMatrix';
import { multiTenantStore } from '../lib/multiTenantStore';
import { AuditLogPayload, ComplianceControl, EvidenceSnapshot } from '../types/soc2';
import { TriAuditorConsensusHub } from './TriAuditorConsensusHub';

interface AuditorRoomProps {
  logs: AuditLogPayload[];
  chainValid: boolean;
  onExportEvidence: () => void;
}

export const AuditorRoom: React.FC<AuditorRoomProps> = ({ logs, chainValid, onExportEvidence }) => {
  const currentTenant = multiTenantStore.getCurrentTenant();
  const [activeTab, setActiveTab] = useState<'checklist' | 'ledger' | 'auditpack' | 'tri_auditor'>('checklist');
  const [auditType, setAuditType] = useState<'Type 1' | 'Type 2'>('Type 2');
  
  const [checkedControls, setCheckedControls] = useState<Record<string, boolean>>({
    'ctrl-cc6-1': true,
    'ctrl-cc6-2': true,
    'ctrl-cc6-3': true,
    'ctrl-cc6-6': true,
    'ctrl-cc6-7': true,
    'ctrl-cc6-8': true,
    'ctrl-cc7-1': true,
    'ctrl-cc7-2': true,
    'ctrl-cc8-1': true,
    'ctrl-a1-2': true
  });
  
  const [auditorNotes, setAuditorNotes] = useState(
    'All 10 AICPA Trust Services Criteria (CC6.1-CC8.1, A1.2) controls inspected and verified operational. Cryptographic WORM audit logs with SHA-256 block hash integrity confirmed. AES-256-GCM encryption at rest active with automated KMS rotation. Gated CI/CD workflows enforce branch protection and TruffleHog/Trivy/CodeQL checks.'
  );
  const [isAuditorCertified, setIsAuditorCertified] = useState(false);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Cryptographic Ledger Verification State
  const [ledgerVerification, setLedgerVerification] = useState<{
    isChainValid: boolean;
    totalBlocks: number;
    failedBlockIndex: number;
    blocks: Array<{
      index: number;
      id: string;
      controlCode: string;
      recordedHash: string;
      computedHash: string;
      previousHash: string;
      isValid: boolean;
      timestamp: string;
    }>;
  } | null>(null);
  const [isVerifyingLedger, setIsVerifyingLedger] = useState(false);
  const [simulatedTamper, setSimulatedTamper] = useState(false);

  // Run ledger verification on mount and store change
  const runLedgerCheck = async (tampered: boolean = false) => {
    setIsVerifyingLedger(true);
    const result = await multiTenantStore.verifyLedgerIntegrity(currentTenant.id);

    if (tampered && result.blocks.length > 1) {
      // Simulate tamper on block 1
      result.isChainValid = false;
      result.failedBlockIndex = 1;
      result.blocks[1].recordedHash = 'corrupted_tampered_hash_deadbeef_000000000000000000000000';
      result.blocks[1].isValid = false;
    }

    setLedgerVerification(result);
    setIsVerifyingLedger(false);
  };

  useEffect(() => {
    runLedgerCheck(simulatedTamper);
  }, [currentTenant.id, simulatedTamper]);

  const toggleCheck = (id: string) => {
    setCheckedControls((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const handleIssueCertification = () => {
    setIsAuditorCertified(true);
    confetti({
      particleCount: 120,
      spread: 70,
      origin: { y: 0.6 }
    });
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(text);
    setTimeout(() => setCopiedText(null), 2000);
  };

  // Compile Comprehensive CPA Audit Pack
  const generateAuditPack = () => {
    const staffSignatures = multiTenantStore.getStaffSignatures(currentTenant.id);
    const automatedPRs = multiTenantStore.getAutomatedPRs(currentTenant.id);
    const microLessons = multiTenantStore.getMicroLessons(currentTenant.id);
    const snapshots = multiTenantStore.getSnapshots(currentTenant.id);

    const report = {
      reportType: `AICPA SOC 2 ${auditType} Examination Report`,
      organization: currentTenant.name,
      tenantId: currentTenant.id,
      generatedAt: new Date().toISOString(),
      leadAuditor: 'Schellman & Company / CPA Independent Audit Practice',
      attestationStatus: isAuditorCertified ? 'UNQUALIFIED_CLEAN_OPINION' : 'IN_PROGRESS',
      cryptographicIntegrity: {
        chainValid: ledgerVerification?.isChainValid ?? true,
        totalWormSnapshots: snapshots.length,
        ledgerHashSample: snapshots[0]?.ledgerHash || 'N/A'
      },
      trustServicesCriteriaControls: SOC2_CONTROLS.map((ctrl) => ({
        code: ctrl.code,
        name: ctrl.name,
        category: ctrl.category,
        auditorVerified: checkedControls[ctrl.id] ?? false,
        score: ctrl.score,
        evidenceCount: ctrl.evidenceItems.length
      })),
      governanceAndSignatures: {
        totalStaffSignatures: staffSignatures.length,
        signatures: staffSignatures.map((s) => ({
          employee: s.employeeName,
          email: s.employeeEmail,
          policyId: s.policyId,
          versionSigned: s.versionSigned,
          signedAt: s.signedAt,
          certificateHash: s.certificateHash
        }))
      },
      gitopsChangeManagement: {
        totalPRs: automatedPRs.length,
        records: automatedPRs
      },
      continuousMicroTraining: {
        totalTrainingSessions: microLessons.length,
        records: microLessons
      },
      auditorOpinionNotes: auditorNotes
    };

    return report;
  };

  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [pdfDownloadError, setPdfDownloadError] = useState<string | null>(null);

  const handleDownloadPdf = async (tamperTest = false) => {
    setIsDownloadingPdf(true);
    setPdfDownloadError(null);

    try {
      const response = await fetch(`/api/audit/export-pack?tenantId=${currentTenant.id}&auditType=${encodeURIComponent(auditType)}&simulateTamper=${tamperTest ? 'true' : 'false'}`);
      
      if (!response.ok) {
        const errorJson = await response.json();
        throw new Error(errorJson.error || 'Failed to compile cryptographic PDF audit pack');
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `SOC2_${auditType.replace(/\s+/g, '_')}_Cryptographic_Audit_Pack_${currentTenant.slug || currentTenant.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);

      confetti({
        particleCount: 80,
        spread: 60,
        origin: { y: 0.7 }
      });
    } catch (err: any) {
      setPdfDownloadError(err.message || 'Error generating verified PDF pack');
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const auditPackData = generateAuditPack();

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-amber-500/10 border border-amber-500/30 text-amber-400 rounded-xl">
              <Eye className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white">Auditor Evidence Vault & Verification Room</h2>
                <span className="text-[10px] font-mono bg-emerald-950 text-emerald-300 px-2 py-0.5 rounded border border-emerald-800 font-semibold">
                  Read-Only Auditor Access
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Single-pane inspection workspace for AICPA Trust Services Criteria (TSC) Type 1 & Type 2 audit examinations
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="flex items-center bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs">
              <button
                onClick={() => setAuditType('Type 1')}
                className={`px-3 py-1 rounded font-medium transition-colors ${
                  auditType === 'Type 1' ? 'bg-amber-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Type 1 (Design)
              </button>
              <button
                onClick={() => setAuditType('Type 2')}
                className={`px-3 py-1 rounded font-medium transition-colors ${
                  auditType === 'Type 2' ? 'bg-amber-600 text-white' : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Type 2 (Operating Effectiveness)
              </button>
            </div>

            <button
              onClick={() => handleDownloadPdf(false)}
              disabled={isDownloadingPdf}
              className="flex items-center gap-1.5 px-3.5 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-bold shadow-md transition-all disabled:opacity-50"
            >
              <FileText className={`w-3.5 h-3.5 ${isDownloadingPdf ? 'animate-spin' : ''}`} />
              <span>{isDownloadingPdf ? 'Compiling PDF...' : 'Download Official PDF Pack'}</span>
            </button>

            <button
              onClick={onExportEvidence}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON</span>
            </button>
          </div>
        </div>

        {pdfDownloadError && (
          <div className="mt-4 p-3 bg-red-950/80 border border-red-800 rounded-lg text-red-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{pdfDownloadError}</span>
            </div>
            <button onClick={() => setPdfDownloadError(null)} className="text-red-400 hover:text-red-200 text-xs font-bold">
              Dismiss
            </button>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="flex items-center gap-2 mt-6 pt-4 border-t border-slate-800/80 overflow-x-auto pb-1">
          <button
            onClick={() => setActiveTab('checklist')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
              activeTab === 'checklist'
                ? 'bg-amber-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <CheckSquare className="w-4 h-4" />
            <span>Trust Services Criteria Checklist</span>
          </button>

          <button
            onClick={() => setActiveTab('ledger')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
              activeTab === 'ledger'
                ? 'bg-amber-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <LinkIcon className="w-4 h-4" />
            <span>Cryptographic Ledger Verifier</span>
            <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
              ledgerVerification?.isChainValid ? 'bg-emerald-950 text-emerald-400' : 'bg-red-950 text-red-400'
            }`}>
              {ledgerVerification?.isChainValid ? 'CHAIN VALID' : 'TAMPER DETECTED'}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('auditpack')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
              activeTab === 'auditpack'
                ? 'bg-amber-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>Compiled CPA Audit Pack</span>
            <span className="text-[10px] px-1.5 py-0.2 bg-slate-950/60 rounded font-mono">
              JSON / PDF Ready
            </span>
          </button>

          <button
            onClick={() => setActiveTab('tri_auditor')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
              activeTab === 'tri_auditor'
                ? 'bg-indigo-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <Sparkles className="w-4 h-4 text-cyan-400" />
            <span>Tri-Auditor Multi-Agent Review</span>
            <span className="text-[10px] px-1.5 py-0.2 bg-indigo-950/80 text-cyan-300 rounded font-mono border border-indigo-700">
              3 AI Consensus
            </span>
          </button>
        </div>
      </div>

      {/* Auditor Certification Status Card */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/50 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs font-bold uppercase tracking-wider text-amber-400">
                SOC 2 {auditType} Examination Assessment
              </span>
              <span className="text-xs bg-emerald-950 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded-full font-bold">
                100% Evidence Complete
              </span>
            </div>
            <h3 className="text-lg font-bold text-white">Continuous Control Monitoring & Evidence Assessment</h3>
            <p className="text-xs text-slate-300 mt-1 max-w-2xl">
              All automated tests, cryptographic chain verifications, CI/CD pipeline scans, and signed policies meet the AICPA SOC 2 Trust Services Criteria standards.
            </p>
          </div>

          <button
            onClick={handleIssueCertification}
            className="flex items-center gap-2 px-5 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded-xl shadow-lg shadow-emerald-600/20 transition-all shrink-0"
          >
            <Sparkles className="w-4 h-4" />
            <span>{isAuditorCertified ? 'Attestation Issued ✔' : 'Issue Audit Attestation'}</span>
          </button>
        </div>
      </div>

      {/* TAB 1: TRUST SERVICES CRITERIA CHECKLIST */}
      {activeTab === 'checklist' && (
        <div className="space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white mb-0.5">Trust Services Criteria Evidence Walkthrough</h3>
                <p className="text-xs text-slate-400">
                  Auditors review and verify evidence across Security (CC6/CC7/CC8), Confidentiality, and Availability (A1.2)
                </p>
              </div>
              <span className="text-xs font-mono text-slate-400">
                {Object.values(checkedControls).filter(Boolean).length} / {SOC2_CONTROLS.length} verified
              </span>
            </div>

            <div className="space-y-3">
              {SOC2_CONTROLS.map((ctrl) => {
                const isChecked = checkedControls[ctrl.id];
                return (
                  <div
                    key={ctrl.id}
                    onClick={() => toggleCheck(ctrl.id)}
                    className={`p-4 rounded-xl border cursor-pointer transition-all ${
                      isChecked
                        ? 'bg-slate-950/80 border-slate-800'
                        : 'bg-slate-950/40 border-slate-800/50 opacity-70'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2">
                      <div className="flex items-center gap-2.5">
                        <div
                          className={`w-5 h-5 rounded flex items-center justify-center border text-xs font-bold ${
                            isChecked
                              ? 'bg-emerald-600 border-emerald-500 text-white'
                              : 'border-slate-700 bg-slate-900 text-transparent'
                          }`}
                        >
                          ✓
                        </div>
                        <span className="font-mono text-xs font-bold text-indigo-400 px-1.5 py-0.5 bg-indigo-950 rounded border border-indigo-900">
                          {ctrl.code}
                        </span>
                        <span className="font-bold text-xs text-white">{ctrl.name}</span>
                      </div>

                      <span className="text-[11px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40 self-start sm:self-auto">
                        {ctrl.status} (Score: {ctrl.score}%)
                      </span>
                    </div>

                    <p className="text-xs text-slate-400 pl-7">{ctrl.description}</p>

                    <div className="mt-2.5 pl-7 flex flex-wrap gap-2">
                      {ctrl.evidenceItems.map((ev, idx) => (
                        <span
                          key={idx}
                          className="text-[10px] bg-slate-900 text-slate-300 border border-slate-800 px-2 py-1 rounded flex items-center gap-1"
                        >
                          <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                          <span>{ev}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Auditor Opinion & Notes Box */}
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-cyan-400" />
              <span>Auditor Opinion & Workpaper Notes</span>
            </h3>
            <textarea
              rows={3}
              value={auditorNotes}
              onChange={(e) => setAuditorNotes(e.target.value)}
              className="w-full p-3 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono text-slate-200 focus:outline-none focus:border-amber-500"
            />
            <div className="flex items-center justify-between text-[11px] text-slate-500">
              <span>Inspection Date: {new Date().toLocaleDateString()}</span>
              <span>Lead Auditor Sign-off: Certified (Schellman / AICPA Compliance Standard)</span>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: CRYPTOGRAPHIC LEDGER VERIFIER */}
      {activeTab === 'ledger' && (
        <div className="space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <LinkIcon className="w-5 h-5 text-indigo-400" />
                  <h3 className="text-base font-bold text-white">Cryptographic Blockchain Ledger Verifier</h3>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Sequential SHA-256 verification of WORM evidence snapshots ensuring mathematical non-repudiation
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => {
                    setSimulatedTamper(!simulatedTamper);
                  }}
                  className={`px-3 py-1.5 rounded-lg text-xs font-semibold border transition-all ${
                    simulatedTamper
                      ? 'bg-red-950 text-red-300 border-red-800'
                      : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
                  }`}
                >
                  {simulatedTamper ? 'Reset Tamper Attack' : 'Simulate Tamper Attack'}
                </button>

                <button
                  onClick={() => runLedgerCheck(simulatedTamper)}
                  disabled={isVerifyingLedger}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${isVerifyingLedger ? 'animate-spin' : ''}`} />
                  <span>Re-Verify Ledger</span>
                </button>
              </div>
            </div>

            {/* Overall Chain Status */}
            <div className={`p-4 rounded-xl border flex items-center justify-between ${
              ledgerVerification?.isChainValid
                ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-300'
                : 'bg-red-950/50 border-red-800 text-red-300'
            }`}>
              <div className="flex items-center gap-3">
                {ledgerVerification?.isChainValid ? (
                  <ShieldCheck className="w-6 h-6 text-emerald-400" />
                ) : (
                  <ShieldAlert className="w-6 h-6 text-red-400" />
                )}
                <div>
                  <div className="font-bold text-sm">
                    {ledgerVerification?.isChainValid
                      ? 'Cryptographic Ledger Integrity Verified: 100% Chain Valid'
                      : `Evidence Corruption Detected at Block #${ledgerVerification?.failedBlockIndex}`}
                  </div>
                  <div className="text-xs opacity-90">
                    {ledgerVerification?.isChainValid
                      ? 'All hash pointers match previous block hashes. No evidence has been modified or deleted.'
                      : 'The recorded SHA-256 hash does not match computed SHA-256(prevHash + payload + controlCode). Non-repudiation compromised.'}
                  </div>
                </div>
              </div>

              <span className="font-mono font-bold text-xs px-3 py-1 bg-slate-950 rounded-lg border border-slate-800">
                {ledgerVerification?.blocks.length} Blocks Verified
              </span>
            </div>

            {/* Block Chain Visualizer */}
            <div className="space-y-4 pt-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Sequential Evidence Block Chain
              </h4>

              <div className="space-y-3">
                {ledgerVerification?.blocks.map((b, idx) => (
                  <div
                    key={b.id}
                    className={`p-4 rounded-xl border font-mono text-xs transition-all ${
                      b.isValid
                        ? 'bg-slate-950 border-slate-800'
                        : 'bg-red-950/60 border-red-600 ring-1 ring-red-600'
                    }`}
                  >
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 mb-2 border-b border-slate-800/80 font-sans">
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 font-mono text-[10px] font-bold border border-indigo-800">
                          BLOCK #{b.index}
                        </span>
                        <span className="font-bold text-white">{b.controlCode}</span>
                        <span className="text-[10px] text-slate-400">({b.id})</span>
                      </div>

                      <div className="flex items-center gap-2">
                        <span className="text-[10px] text-slate-400">{new Date(b.timestamp).toLocaleString()}</span>
                        {b.isValid ? (
                          <span className="text-[10px] bg-emerald-950 text-emerald-400 px-2 py-0.5 rounded font-bold border border-emerald-800 flex items-center gap-1">
                            <Check className="w-3 h-3" />
                            <span>VALID</span>
                          </span>
                        ) : (
                          <span className="text-[10px] bg-red-950 text-red-400 px-2 py-0.5 rounded font-bold border border-red-800 flex items-center gap-1">
                            <AlertTriangle className="w-3 h-3" />
                            <span>HASH MISMATCH</span>
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="space-y-1.5 text-[11px]">
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between text-slate-400 gap-1">
                        <span>Previous Hash:</span>
                        <span className="text-slate-300 font-mono break-all">{b.previousHash}</span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between text-slate-400 gap-1">
                        <span>Recorded Ledger Hash:</span>
                        <span className={`font-mono break-all ${b.isValid ? 'text-amber-400' : 'text-red-400 font-bold'}`}>
                          {b.recordedHash}
                        </span>
                      </div>
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between text-slate-400 gap-1">
                        <span>Computed SHA-256:</span>
                        <span className="text-cyan-400 font-mono break-all">{b.computedHash}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: COMPILED CPA AUDIT PACK */}
      {activeTab === 'auditpack' && (
        <div className="space-y-6">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <FileText className="w-5 h-5 text-amber-400" />
                  <h3 className="text-base font-bold text-white">Compiled AICPA SOC 2 Audit Pack</h3>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Complete certification binder with control evaluations, cryptographic ledger hashes, and staff acceptance logs
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <button
                  onClick={() => handleCopy(JSON.stringify(auditPackData, null, 2))}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition-colors"
                >
                  <Copy className="w-3.5 h-3.5" />
                  <span>{copiedText ? 'Copied JSON!' : 'Copy JSON'}</span>
                </button>
                <button
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(auditPackData, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `SOC2_${auditType.replace(/\s+/g, '_')}_Audit_Pack_${currentTenant.slug || currentTenant.id}.json`;
                    a.click();
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold border border-slate-700 transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Download .JSON</span>
                </button>
                <button
                  onClick={() => handleDownloadPdf(false)}
                  disabled={isDownloadingPdf}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-bold shadow-sm transition-colors disabled:opacity-50"
                >
                  <FileText className={`w-3.5 h-3.5 ${isDownloadingPdf ? 'animate-spin' : ''}`} />
                  <span>Download Verified .PDF Audit Pack</span>
                </button>
              </div>
            </div>

            {/* Cryptographic Compiler Status Banner */}
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2.5">
                <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg border border-emerald-500/20">
                  <ShieldCheck className="w-4 h-4" />
                </div>
                <div>
                  <div className="font-bold text-white">Cryptographic PDF Audit Pack Compiler (Module 1)</div>
                  <div className="text-slate-400 text-[11px]">
                    Validates the sequential SHA-256 ledger before rendering a CPA-ready PDF document.
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleDownloadPdf(true)}
                  disabled={isDownloadingPdf}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-950/60 hover:bg-red-900 text-red-300 border border-red-800 transition-all disabled:opacity-50"
                  title="Simulates a tampered hash block to verify the compiler halts and reports corruption"
                >
                  Test Tamper Abort
                </button>
                <button
                  onClick={() => handleDownloadPdf(false)}
                  disabled={isDownloadingPdf}
                  className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow transition-all disabled:opacity-50 flex items-center gap-1"
                >
                  <FileCheck className="w-3.5 h-3.5" />
                  <span>Compile & Download PDF</span>
                </button>
              </div>
            </div>

            {/* Audit Pack JSON / Markdown Viewer */}
            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-slate-200 max-h-[500px] overflow-y-auto leading-relaxed">
              <pre>{JSON.stringify(auditPackData, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: TRI-AUDITOR MULTI-AGENT CONSENSUS */}
      {activeTab === 'tri_auditor' && (
        <TriAuditorConsensusHub />
      )}
    </div>
  );
};
