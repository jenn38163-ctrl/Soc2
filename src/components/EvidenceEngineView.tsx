import React, { useState } from 'react';
import { 
  Server, 
  Cpu, 
  Database, 
  ShieldCheck, 
  Lock, 
  Play, 
  CheckCircle2, 
  RefreshCw, 
  Download, 
  FileCode, 
  Search, 
  Layers, 
  Clock, 
  Copy, 
  Check, 
  ExternalLink,
  Sparkles,
  AlertTriangle
} from 'lucide-react';
import { multiTenantStore } from '../lib/multiTenantStore';
import { EvidenceSnapshot, WorkerJob } from '../types/soc2';

interface EvidenceEngineViewProps {
  onScanComplete?: () => void;
}

export const EvidenceEngineView: React.FC<EvidenceEngineViewProps> = ({ onScanComplete }) => {
  const currentTenant = multiTenantStore.getCurrentTenant();
  const snapshots = multiTenantStore.getSnapshots(currentTenant.id);
  const workerJobs = multiTenantStore.getWorkerJobs();

  const [isRunningScan, setIsRunningScan] = useState(false);
  const [selectedSnapshot, setSelectedSnapshot] = useState<EvidenceSnapshot | null>(snapshots[0] || null);
  const [activeTab, setActiveTab] = useState<'workers' | 'vault'>('workers');
  const [filterControl, setFilterControl] = useState<string>('ALL');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleTriggerWorkers = async () => {
    setIsRunningScan(true);
    await multiTenantStore.executeWorkerScan(currentTenant.id);
    setIsRunningScan(false);
    if (onScanComplete) onScanComplete();
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleExportSnapshotJson = (snp: EvidenceSnapshot) => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(snp, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `evidence-${snp.controlCode}-${snp.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const filteredSnapshots = snapshots.filter((s) => {
    if (filterControl === 'ALL') return true;
    return s.controlCode.startsWith(filterControl);
  });

  return (
    <div className="space-y-6" id="evidence-engine-container">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-emerald-400 bg-emerald-500/10 px-2.5 py-0.5 rounded-md border border-emerald-500/20">
              Evidence Engine
            </span>
            <span className="text-xs text-slate-400">
              Active Tenant: <strong className="text-white">{currentTenant.name}</strong>
            </span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight">BullMQ Worker Pool & WORM Evidence Vault</h2>
          <p className="text-sm text-slate-400">
            Background workers execute non-blocking cloud scans, evaluate controls, and archive immutable, SHA-256 hashed JSON snapshots for CPA auditors.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={handleTriggerWorkers}
            disabled={isRunningScan}
            className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRunningScan ? 'animate-spin' : ''}`} />
            <span>{isRunningScan ? 'Executing BullMQ Worker Jobs...' : 'Run BullMQ Scan Cycle'}</span>
          </button>
        </div>
      </div>

      {/* Navigation tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2">
        <button
          onClick={() => setActiveTab('workers')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all ${
            activeTab === 'workers'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Cpu className="w-4 h-4" />
          <span>BullMQ Worker Pool & Redis Queue</span>
          <span className="bg-emerald-500/20 text-emerald-300 text-[10px] px-1.5 py-0.5 rounded font-mono">
            {isRunningScan ? 'Active' : 'Idle'}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('vault')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all ${
            activeTab === 'vault'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Database className="w-4 h-4" />
          <span>Immutable Evidence Snapshots ({snapshots.length})</span>
          <span className="bg-indigo-500/20 text-indigo-300 text-[10px] px-1.5 py-0.5 rounded font-mono">WORM SHA-256</span>
        </button>
      </div>

      {/* TAB 1: WORKER POOL & REDIS QUEUE SIMULATOR */}
      {activeTab === 'workers' && (
        <div className="space-y-6">
          {/* Worker Pool Architecture Specs */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <span className="text-xs text-slate-400">Queue Backend</span>
              <div className="flex items-center justify-between mt-1">
                <span className="text-base font-bold text-white">Redis 7.2 (Cluster)</span>
                <Server className="w-4 h-4 text-rose-400" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">BullMQ multi-tenant worker pool</p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <span className="text-xs text-slate-400">Concurrency Limit</span>
              <div className="flex items-center justify-between mt-1">
                <span className="text-base font-bold text-white">10 Workers / Tenant</span>
                <Cpu className="w-4 h-4 text-indigo-400" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Rate-limit friendly with exponential backoff</p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <span className="text-xs text-slate-400">Credential Decryption</span>
              <div className="flex items-center justify-between mt-1">
                <span className="text-base font-bold text-emerald-400">AES-256-GCM</span>
                <Lock className="w-4 h-4 text-emerald-400" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Decrypted only in worker memory</p>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
              <span className="text-xs text-slate-400">WORM Evidence Storage</span>
              <div className="flex items-center justify-between mt-1">
                <span className="text-base font-bold text-indigo-300">SHA-256 Hashed</span>
                <ShieldCheck className="w-4 h-4 text-indigo-300" />
              </div>
              <p className="text-[11px] text-slate-400 mt-1">Append-only compliance table</p>
            </div>
          </div>

          {/* 5-Step Worker Lifecycle Visualization */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <h3 className="text-sm font-bold text-white mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-indigo-400" />
              <span>SOC 2 Continuous Evidence Collection Worker Pattern</span>
            </h3>
            
            <div className="grid grid-cols-1 md:grid-cols-5 gap-3 text-xs">
              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3 space-y-1.5">
                <div className="w-6 h-6 rounded bg-indigo-500/20 text-indigo-300 font-bold flex items-center justify-center text-[11px]">1</div>
                <div className="font-semibold text-white">Fetch & Decrypt</div>
                <p className="text-[11px] text-slate-400">Worker retrieves encrypted credentials from DB and uses AES-256-GCM to decrypt in memory.</p>
              </div>

              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3 space-y-1.5">
                <div className="w-6 h-6 rounded bg-indigo-500/20 text-indigo-300 font-bold flex items-center justify-center text-[11px]">2</div>
                <div className="font-semibold text-white">Dynamic SDK Init</div>
                <p className="text-[11px] text-slate-400">Instantiates STS AssumeRole or OAuth client scoped strictly to the target tenant's environment.</p>
              </div>

              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3 space-y-1.5">
                <div className="w-6 h-6 rounded bg-indigo-500/20 text-indigo-300 font-bold flex items-center justify-center text-[11px]">3</div>
                <div className="font-semibold text-white">Query Cloud APIs</div>
                <p className="text-[11px] text-slate-400">Calls AWS IAM/S3/RDS, GitHub Branch Protection, or Okta APIs to extract point-in-time state.</p>
              </div>

              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3 space-y-1.5">
                <div className="w-6 h-6 rounded bg-indigo-500/20 text-indigo-300 font-bold flex items-center justify-center text-[11px]">4</div>
                <div className="font-semibold text-white">Archive Evidence</div>
                <p className="text-[11px] text-slate-400">Stores immutable raw JSON payload with calculated SHA-256 WORM hash for CPA proof.</p>
              </div>

              <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-3 space-y-1.5">
                <div className="w-6 h-6 rounded bg-indigo-500/20 text-indigo-300 font-bold flex items-center justify-center text-[11px]">5</div>
                <div className="font-semibold text-white">Evaluate & Alert</div>
                <p className="text-[11px] text-slate-400">Checks AICPA Trust Criteria and automatically upserts open ComplianceIssues if failing.</p>
              </div>
            </div>
          </div>

          {/* Live Worker Execution Log Stream */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Cpu className="w-4 h-4 text-emerald-400" />
                <h3 className="text-xs font-mono font-bold text-white">BullMQ Worker Execution Activity & Logs</h3>
              </div>
              <span className="text-[11px] text-slate-400 font-mono">
                {workerJobs.length} jobs executed
              </span>
            </div>

            <div className="divide-y divide-slate-800">
              {workerJobs.length === 0 ? (
                <div className="p-8 text-center space-y-2 text-xs text-slate-400">
                  <p>No recent manual worker executions logged in this session.</p>
                  <button
                    onClick={handleTriggerWorkers}
                    className="text-indigo-400 font-semibold hover:text-indigo-300 cursor-pointer"
                  >
                    Click to trigger a full BullMQ background scan cycle →
                  </button>
                </div>
              ) : (
                workerJobs.map((job) => (
                  <div key={job.id} className="p-4 space-y-2 font-mono text-xs hover:bg-slate-800/20 transition-colors">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-white font-bold">{job.name}</span>
                        <span className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded">
                          {job.controlCode}
                        </span>
                        <span className="text-[10px] uppercase bg-indigo-500/20 text-indigo-300 px-1.5 py-0.5 rounded">
                          {job.provider}
                        </span>
                      </div>
                      <div className="flex items-center gap-2 text-[11px] text-slate-400">
                        {job.durationMs && <span>{job.durationMs}ms</span>}
                        <span className="text-emerald-400 font-semibold flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Completed
                        </span>
                      </div>
                    </div>

                    <div className="bg-slate-950 border border-slate-800/80 rounded-lg p-2.5 text-[11px] text-slate-300 space-y-1">
                      {job.logs.map((log, lIdx) => (
                        <div key={lIdx} className="leading-relaxed">
                          {log}
                        </div>
                      ))}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: IMMUTABLE EVIDENCE SNAPSHOT VAULT */}
      {activeTab === 'vault' && (
        <div className="space-y-4">
          {/* Filter Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-3">
            <div className="flex items-center gap-2 overflow-x-auto">
              <span className="text-xs text-slate-400 font-medium whitespace-nowrap">Filter Control:</span>
              {['ALL', 'CC6.1', 'CC6.6', 'CC6.7', 'CC8.1', 'CC7.1'].map((code) => (
                <button
                  key={code}
                  onClick={() => setFilterControl(code)}
                  className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                    filterControl === code
                      ? 'bg-indigo-600 text-white'
                      : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                  }`}
                >
                  {code}
                </button>
              ))}
            </div>

            <div className="text-xs text-slate-400 font-mono">
              Showing {filteredSnapshots.length} point-in-time evidence snapshots
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
            {/* Snapshot List (Left Col) */}
            <div className="lg:col-span-5 space-y-3">
              {filteredSnapshots.map((snp) => {
                const isSelected = selectedSnapshot?.id === snp.id;
                return (
                  <div
                    key={snp.id}
                    onClick={() => setSelectedSnapshot(snp)}
                    className={`bg-slate-900 border rounded-xl p-4 cursor-pointer transition-all ${
                      isSelected
                        ? 'border-indigo-500 ring-1 ring-indigo-500/50 bg-slate-850'
                        : 'border-slate-800 hover:border-slate-700 hover:bg-slate-850/50'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-2 mb-1.5">
                      <span className="text-xs font-mono font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded">
                        {snp.controlCode}
                      </span>
                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full flex items-center gap-1 ${
                        snp.isCompliant ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
                      }`}>
                        {snp.isCompliant ? <CheckCircle2 className="w-3 h-3" /> : <AlertTriangle className="w-3 h-3" />}
                        {snp.isCompliant ? 'Compliant' : 'Non-Compliant'}
                      </span>
                    </div>

                    <h4 className="text-sm font-bold text-white tracking-tight">{snp.title}</h4>
                    
                    <div className="mt-2 text-[11px] font-mono text-slate-400 truncate">
                      SHA: {snp.sha256Hash}
                    </div>

                    <div className="mt-3 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
                      <span>Provider: <strong className="text-slate-300 uppercase">{snp.provider}</strong></span>
                      <span>{new Date(snp.createdAt).toLocaleDateString()} {new Date(snp.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Snapshot Detail Viewer (Right Col) */}
            <div className="lg:col-span-7">
              {selectedSnapshot ? (
                <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm sticky top-24">
                  <div className="px-5 py-4 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded">
                          {selectedSnapshot.controlCode}
                        </span>
                        <h3 className="text-sm font-bold text-white">{selectedSnapshot.title}</h3>
                      </div>
                      <p className="text-xs text-slate-400 mt-0.5">
                        Recorded at {new Date(selectedSnapshot.createdAt).toLocaleString()} | {selectedSnapshot.recordCount} records
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => handleExportSnapshotJson(selectedSnapshot)}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors cursor-pointer"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Export JSON</span>
                      </button>
                    </div>
                  </div>

                  {/* Tamper-Proof SHA-256 WORM Hash Block */}
                  <div className="p-4 bg-slate-950/80 border-b border-slate-800 text-xs">
                    <div className="flex items-center justify-between text-[11px] mb-1">
                      <span className="text-slate-400 font-semibold flex items-center gap-1.5">
                        <ShieldCheck className="w-4 h-4 text-emerald-400" />
                        WORM SHA-256 Cryptographic Fingerprint (Audit Verified)
                      </span>
                      <button
                        onClick={() => handleCopy(selectedSnapshot.sha256Hash, selectedSnapshot.id)}
                        className="text-slate-400 hover:text-white flex items-center gap-1 cursor-pointer"
                      >
                        {copiedHash === selectedSnapshot.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>{copiedHash === selectedSnapshot.id ? 'Copied' : 'Copy Hash'}</span>
                      </button>
                    </div>
                    <div className="font-mono text-emerald-400 break-all bg-slate-900/90 border border-slate-800 p-2 rounded text-[11px]">
                      {selectedSnapshot.sha256Hash}
                    </div>
                  </div>

                  {/* Raw JSON Payload */}
                  <div className="p-4">
                    <div className="flex items-center justify-between text-xs text-slate-400 mb-2">
                      <span className="font-semibold text-slate-300">Raw Cloud Provider Response (Immutable Payload)</span>
                      <span className="font-mono text-[11px]">format: application/json</span>
                    </div>
                    <pre className="max-h-[380px] overflow-y-auto bg-slate-950 border border-slate-800/80 rounded-lg p-3.5 font-mono text-[11px] text-indigo-300 leading-relaxed">
                      {JSON.stringify(selectedSnapshot.rawPayload, null, 2)}
                    </pre>
                  </div>
                </div>
              ) : (
                <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center text-slate-400 text-xs">
                  Select an evidence snapshot to inspect raw provider payloads and WORM tamper hashes.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
