import React, { useState } from 'react';
import { Activity, Shield, CheckCircle2, AlertOctagon, Search, Filter, Download, Plus, Eye, EyeOff, Lock, CheckCircle, RefreshCw, Hash, Copy } from 'lucide-react';
import { motion } from 'motion/react';
import { AuditLogPayload } from '../types/soc2';
import { auditLogStore } from '../lib/auditLogger';

interface AuditLogViewerProps {
  logs: AuditLogPayload[];
  onNewLogAdded: () => void;
  chainIntegrityValid: boolean;
  onVerifyChain: () => Promise<void>;
  isVerifying: boolean;
}

export const AuditLogViewer: React.FC<AuditLogViewerProps> = ({
  logs,
  onNewLogAdded,
  chainIntegrityValid,
  onVerifyChain,
  isVerifying
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<'ALL' | 'SUCCESS' | 'FAILURE' | 'DENIED'>('ALL');
  const [showRawPII, setShowRawPII] = useState(false);
  const [selectedLog, setSelectedLog] = useState<AuditLogPayload | null>(null);
  const [showInjectModal, setShowInjectModal] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Injection Form State
  const [injectActor, setInjectActor] = useState('usr_developer_lead');
  const [injectAction, setInjectAction] = useState('user.delete');
  const [injectResource, setInjectResource] = useState('customer_account_998');
  const [injectStatus, setInjectStatus] = useState<'SUCCESS' | 'FAILURE' | 'DENIED'>('SUCCESS');
  const [injectIncludePII, setInjectIncludePII] = useState(true);

  const filteredLogs = logs.filter((log) => {
    const matchesSearch =
      log.eventId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.traceId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.actorId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.action.toLowerCase().includes(searchTerm.toLowerCase()) ||
      log.resource.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === 'ALL' || log.status === statusFilter;
    return matchesSearch && matchesStatus;
  });

  const handleInjectEvent = async (e: React.FormEvent) => {
    e.preventDefault();
    const traceId = `trc_${Math.random().toString(36).substring(2, 12)}`;
    
    const metadata: Record<string, unknown> = {
      initiatedVia: 'SOC2_Compliance_Module_Interactive_Tester',
      reason: 'Standard customer account lifecycle request'
    };

    if (injectIncludePII) {
      metadata.ssn = '123-45-6789';
      metadata.creditCard = '4532-1189-9876-5432';
      metadata.token = 'bearer_sec_tok_99182a8bf8c991e';
      metadata.password = 'super_secret_master_pw';
    }

    await auditLogStore.record({
      traceId,
      actorId: injectActor,
      action: injectAction,
      resource: injectResource,
      ipAddress: '192.168.1.140',
      status: injectStatus,
      metadata
    });

    onNewLogAdded();
    setShowInjectModal(false);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const downloadLogsJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `soc2-immutable-audit-logs-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & WORM Integrity Status */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2.5">
              <div className="p-2 bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 rounded-lg">
                <Activity className="w-5 h-5" />
              </div>
              <div>
                <h2 className="text-base font-bold text-white">Immutable Audit Logging (CC6.8, CC7.2)</h2>
                <p className="text-xs text-slate-400">
                  Cryptographically chained WORM (Write Once Read Many) log stream with automated PII redaction
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            {/* Hash Chain Integrity Status */}
            <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border ${
              chainIntegrityValid
                ? 'bg-emerald-950/60 border-emerald-800/60 text-emerald-300'
                : 'bg-rose-950/60 border-rose-800/60 text-rose-300'
            }`}>
              <Hash className="w-3.5 h-3.5" />
              <span>{chainIntegrityValid ? 'WORM Chain Verified (0 Tamper)' : 'Chain Verification Needed'}</span>
            </div>

            <button
              onClick={onVerifyChain}
              disabled={isVerifying}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition-colors"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isVerifying ? 'animate-spin' : ''}`} />
              <span>Verify SHA-256 Blocks</span>
            </button>

            <button
              onClick={() => setShowInjectModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-medium shadow-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Emit Test Audit Event</span>
            </button>

            <button
              onClick={downloadLogsJSON}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export SIEM JSON</span>
            </button>
          </div>
        </div>

        {/* Search, Filter & PII Redaction Controls */}
        <div className="mt-6 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 pt-4 border-t border-slate-800">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search eventId, traceId, actor, action, resource..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
            />
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            {/* Status Filter */}
            <div className="flex items-center bg-slate-950 rounded-lg border border-slate-800 p-1 text-xs">
              {(['ALL', 'SUCCESS', 'DENIED', 'FAILURE'] as const).map((status) => (
                <button
                  key={status}
                  onClick={() => setStatusFilter(status)}
                  className={`px-2.5 py-1 rounded transition-colors ${
                    statusFilter === status
                      ? status === 'DENIED'
                        ? 'bg-amber-600 text-white font-semibold'
                        : 'bg-indigo-600 text-white font-semibold'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {status}
                </button>
              ))}
            </div>

            {/* PII Sanitization Toggle Info */}
            <div className="flex items-center gap-1.5 bg-slate-950 px-2.5 py-1.5 rounded-lg border border-slate-800 text-xs text-slate-300">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>PII Redacted:</span>
              <span className="font-mono text-emerald-400 font-semibold">[REDACTED]</span>
            </div>
          </div>
        </div>
      </div>

      {/* Log Feed Table */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 bg-slate-950/60 border-b border-slate-800 flex items-center justify-between text-xs text-slate-400 font-medium">
          <span>Showing {filteredLogs.length} Immutable Log Entries</span>
          <span className="font-mono text-cyan-400">Target Storage: S3 Object Lock (COMPLIANCE)</span>
        </div>

        <div className="divide-y divide-slate-800/80 max-h-[600px] overflow-y-auto font-mono text-xs">
          {filteredLogs.length === 0 ? (
            <div className="p-8 text-center text-slate-500">
              No audit logs matched your query criteria.
            </div>
          ) : (
            filteredLogs.map((log) => {
              const isSelected = selectedLog?.eventId === log.eventId;
              return (
                <div
                  key={log.eventId}
                  onClick={() => setSelectedLog(isSelected ? null : log)}
                  className={`p-4 transition-colors cursor-pointer hover:bg-slate-800/50 ${
                    isSelected ? 'bg-slate-800/70 border-l-2 border-cyan-400' : ''
                  }`}
                >
                  <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-2">
                    <div className="flex items-center gap-2.5">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          log.status === 'SUCCESS'
                            ? 'bg-emerald-950 text-emerald-400 border border-emerald-800/60'
                            : log.status === 'DENIED'
                            ? 'bg-amber-950 text-amber-400 border border-amber-800/60'
                            : 'bg-rose-950 text-rose-400 border border-rose-800/60'
                        }`}
                      >
                        {log.status}
                      </span>
                      <span className="font-bold text-slate-200">{log.action}</span>
                      <span className="text-slate-500">on</span>
                      <span className="text-indigo-400 bg-indigo-950/40 px-1.5 py-0.5 rounded border border-indigo-900/40">
                        {log.resource}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 text-slate-400 text-[11px]">
                      <span>{log.actorId}</span>
                      <span className="text-slate-600">•</span>
                      <span>{log.ipAddress}</span>
                      <span className="text-slate-600">•</span>
                      <span className="text-slate-500">{log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : ''}</span>
                    </div>
                  </div>

                  {/* Hash & Correlation Row */}
                  <div className="mt-2 flex items-center gap-3 text-[10px] text-slate-500 flex-wrap">
                    <div className="flex items-center gap-1">
                      <span>EventID:</span>
                      <span className="text-slate-300 font-mono">{log.eventId}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span>TraceID:</span>
                      <span className="text-cyan-400 font-mono">{log.traceId}</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <span>SHA-256:</span>
                      <span className="text-slate-400 truncate max-w-xs">{log.currentHash?.slice(0, 16)}...</span>
                    </div>
                  </div>

                  {/* Expanded JSON Inspector */}
                  {isSelected && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: 'auto' }}
                      className="mt-3 p-3 bg-slate-950 rounded-lg border border-slate-800 text-[11px]"
                    >
                      <div className="flex items-center justify-between text-slate-400 pb-2 border-b border-slate-800 mb-2">
                        <span className="font-semibold text-slate-300">Winston Redacted Payload (Raw Evidence)</span>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            copyToClipboard(JSON.stringify(log, null, 2), log.eventId);
                          }}
                          className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300"
                        >
                          <Copy className="w-3 h-3" />
                          <span>{copiedId === log.eventId ? 'Copied JSON!' : 'Copy JSON'}</span>
                        </button>
                      </div>
                      <pre className="text-cyan-300 overflow-x-auto p-1 leading-relaxed">
                        {JSON.stringify(log, null, 2)}
                      </pre>
                    </motion.div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Emit Test Event Modal */}
      {showInjectModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-slate-900 border border-slate-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4"
          >
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Plus className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Emit Test SOC 2 Audit Event</h3>
              </div>
              <button
                onClick={() => setShowInjectModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleInjectEvent} className="space-y-3.5 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Actor ID (User or Service)</label>
                <input
                  type="text"
                  value={injectActor}
                  onChange={(e) => setInjectActor(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Action</label>
                <select
                  value={injectAction}
                  onChange={(e) => setInjectAction(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="user.delete">user.delete (CC6.1 / CC6.8)</option>
                  <option value="data.export">data.export (CC6.8 / CC7.2)</option>
                  <option value="policy.update">policy.update (CC8.1)</option>
                  <option value="emergency.break_glass">emergency.break_glass (CC6.1)</option>
                  <option value="db.snapshot.create">db.snapshot.create (A1.2)</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Target Resource</label>
                <input
                  type="text"
                  value={injectResource}
                  onChange={(e) => setInjectResource(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-cyan-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Status</label>
                <div className="grid grid-cols-3 gap-2">
                  {(['SUCCESS', 'DENIED', 'FAILURE'] as const).map((st) => (
                    <button
                      type="button"
                      key={st}
                      onClick={() => setInjectStatus(st)}
                      className={`py-1.5 rounded-lg border font-semibold ${
                        injectStatus === st
                          ? 'bg-cyan-600 border-cyan-500 text-white'
                          : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                      }`}
                    >
                      {st}
                    </button>
                  ))}
                </div>
              </div>

              <div className="flex items-center gap-2 p-3 bg-slate-950 rounded-lg border border-slate-800">
                <input
                  type="checkbox"
                  id="includePii"
                  checked={injectIncludePII}
                  onChange={(e) => setInjectIncludePII(e.target.checked)}
                  className="rounded border-slate-700 text-cyan-600 focus:ring-cyan-500"
                />
                <label htmlFor="includePii" className="text-slate-300">
                  Include raw PII & Secrets (SSN, creditCard, token) to test automated redaction
                </label>
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowInjectModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-lg"
                >
                  Emit & Chain Hash
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}
    </div>
  );
};
