import React, { useState } from 'react';
import { 
  AlertOctagon, 
  CheckCircle2, 
  Clock, 
  User, 
  Wrench, 
  ExternalLink, 
  Filter, 
  ShieldAlert, 
  ArrowRight, 
  Sparkles, 
  Check, 
  RefreshCw,
  Zap,
  Info
} from 'lucide-react';
import { multiTenantStore } from '../lib/multiTenantStore';
import { ComplianceIssue, IssueSeverity, IssueStatus } from '../types/soc2';

interface RemediationCenterProps {
  onIssueResolved?: () => void;
}

export const RemediationCenter: React.FC<RemediationCenterProps> = ({ onIssueResolved }) => {
  const currentTenant = multiTenantStore.getCurrentTenant();
  const issues = multiTenantStore.getIssues(currentTenant.id);

  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [remediatingId, setRemediatingId] = useState<string | null>(null);
  const [successBanner, setSuccessBanner] = useState<string | null>(null);

  const handleRemediate = async (issue: ComplianceIssue) => {
    setRemediatingId(issue.id);
    // Simulate auto-remediation API call (e.g., AWS SDK PutPublicAccessBlock or GitHub API call)
    await new Promise((r) => setTimeout(r, 600));

    await multiTenantStore.remediateIssue(currentTenant.id, issue.id);
    setRemediatingId(null);
    setSuccessBanner(`Remediated: "${issue.title}". Audit event recorded and compliance score updated.`);
    setTimeout(() => setSuccessBanner(null), 4000);

    if (onIssueResolved) onIssueResolved();
  };

  const filteredIssues = issues.filter((iss) => {
    if (severityFilter !== 'ALL' && iss.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && iss.status !== statusFilter) return false;
    return true;
  });

  const openCount = issues.filter((i) => i.status === 'OPEN').length;
  const criticalCount = issues.filter((i) => i.status === 'OPEN' && i.severity === 'CRITICAL').length;
  const highCount = issues.filter((i) => i.status === 'OPEN' && i.severity === 'HIGH').length;

  return (
    <div className="space-y-6" id="remediation-center-container">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-rose-400 bg-rose-500/10 px-2.5 py-0.5 rounded-md border border-rose-500/20">
              Task Center & Gaps
            </span>
            <span className="text-xs text-slate-400">
              Tenant: <strong className="text-white">{currentTenant.name}</strong>
            </span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight">Failing Controls & Remediation Task Center</h2>
          <p className="text-sm text-slate-400">
            Automatically surfaces gaps identified by background cloud worker scans, tracks 30-day resolution SLAs, and enables 1-click auto-remediations.
          </p>
        </div>

        {/* Severity Metrics Pill */}
        <div className="flex items-center gap-2">
          <div className="bg-slate-950 border border-slate-800 px-3.5 py-2 rounded-xl text-xs flex items-center gap-3">
            <div>
              <span className="text-slate-400 block text-[10px]">Open Issues</span>
              <span className="text-sm font-bold text-white">{openCount}</span>
            </div>
            <div className="h-6 w-px bg-slate-800" />
            <div>
              <span className="text-rose-400 block text-[10px]">Critical</span>
              <span className="text-sm font-bold text-rose-400">{criticalCount}</span>
            </div>
            <div className="h-6 w-px bg-slate-800" />
            <div>
              <span className="text-amber-400 block text-[10px]">High</span>
              <span className="text-sm font-bold text-amber-400">{highCount}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Success Notification Banner */}
      {successBanner && (
        <div className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 p-4 rounded-xl text-xs flex items-center gap-3 animate-fade-in shadow-lg">
          <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />
          <div className="flex-1 font-medium">{successBanner}</div>
        </div>
      )}

      {/* Filter and Switcher Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-slate-900 border border-slate-800 rounded-xl p-3">
        <div className="flex items-center gap-2 overflow-x-auto">
          <span className="text-xs text-slate-400 font-medium whitespace-nowrap">Filter Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                severityFilter === sev
                  ? 'bg-indigo-600 text-white'
                  : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400 font-medium">Status:</span>
          {['ALL', 'OPEN', 'RESOLVED'].map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                statusFilter === st
                  ? 'bg-slate-700 text-white'
                  : 'bg-slate-800/60 text-slate-400 hover:bg-slate-700'
              }`}
            >
              {st}
            </button>
          ))}
        </div>
      </div>

      {/* Issues List */}
      <div className="space-y-3">
        {filteredIssues.length === 0 ? (
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center space-y-3">
            <div className="w-12 h-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto">
              <CheckCircle2 className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white">All Clear! Zero Open Failing Controls</h3>
            <p className="text-xs text-slate-400 max-w-md mx-auto">
              All infrastructure checks for {currentTenant.name} conform to AICPA SOC 2 Trust Services Criteria. Compliance score is 100%.
            </p>
          </div>
        ) : (
          filteredIssues.map((issue) => {
            const isResolved = issue.status === 'RESOLVED';
            const isRemediating = remediatingId === issue.id;

            return (
              <div
                key={issue.id}
                className={`bg-slate-900 border rounded-xl p-5 transition-all shadow-sm ${
                  isResolved
                    ? 'border-slate-800/60 opacity-60 bg-slate-950/40'
                    : issue.severity === 'CRITICAL'
                    ? 'border-rose-500/40 hover:border-rose-500/60'
                    : 'border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                  {/* Left info */}
                  <div className="space-y-1.5 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded-full font-mono ${
                        issue.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : issue.severity === 'HIGH'
                          ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                          : 'bg-blue-500/20 text-blue-300 border border-blue-500/30'
                      }`}>
                        {issue.severity}
                      </span>

                      <span className="text-xs font-mono font-bold text-indigo-400 bg-indigo-500/10 px-2 py-0.5 rounded">
                        {issue.controlCode}
                      </span>

                      <span className="text-[11px] uppercase text-slate-400 font-mono">
                        {issue.provider}
                      </span>

                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded ${
                        isResolved ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-300'
                      }`}>
                        {issue.status}
                      </span>
                    </div>

                    <h4 className="text-base font-bold text-white">{issue.title}</h4>
                    <p className="text-xs text-slate-400 leading-relaxed">{issue.description}</p>

                    <div className="flex flex-wrap items-center gap-4 pt-1 text-[11px] text-slate-400">
                      <div className="flex items-center gap-1.5">
                        <User className="w-3.5 h-3.5 text-slate-400" />
                        <span>Assignee: <strong className="text-slate-300">{issue.assignee}</strong></span>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <Clock className="w-3.5 h-3.5 text-slate-400" />
                        <span>30-Day SLA Deadline: <strong className="text-slate-300">{new Date(issue.slaDeadline).toLocaleDateString()}</strong></span>
                      </div>
                    </div>
                  </div>

                  {/* Right Auto-Remediate Action */}
                  <div className="shrink-0 flex items-center justify-end">
                    {isResolved ? (
                      <div className="flex items-center gap-1.5 text-emerald-400 text-xs font-semibold bg-emerald-500/10 border border-emerald-500/20 px-3 py-1.5 rounded-lg">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Remediated & Verified</span>
                      </div>
                    ) : (
                      <button
                        onClick={() => handleRemediate(issue)}
                        disabled={isRemediating}
                        className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white rounded-lg text-xs font-semibold shadow-md transition-all cursor-pointer disabled:opacity-50"
                      >
                        {isRemediating ? (
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        ) : (
                          <Zap className="w-3.5 h-3.5 fill-current" />
                        )}
                        <span>{isRemediating ? 'Applying Fix...' : (issue.autoRemediationAction || 'Auto-Remediate Control')}</span>
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
