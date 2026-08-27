import React, { useState } from 'react';
import { 
  Shield, 
  CheckCircle,
  CheckCircle2, 
  AlertTriangle, 
  Activity, 
  Lock, 
  Users, 
  Terminal, 
  FileText, 
  ArrowUpRight, 
  RefreshCw, 
  Layers, 
  Key, 
  Check, 
  Database,
  Cloud,
  Cpu,
  Radio,
  AlertOctagon,
  Rocket,
  ArrowRight,
  Zap
} from 'lucide-react';
import { motion } from 'motion/react';
import { SOC2_CONTROLS } from '../lib/complianceMatrix';
import { ArchitectureDiagram } from './ArchitectureDiagram';
import { ComplianceControl, AuditLogPayload } from '../types/soc2';
import { multiTenantStore } from '../lib/multiTenantStore';

interface OverviewDashboardProps {
  onSelectTab: (tabId: string) => void;
  recentLogs: AuditLogPayload[];
  chainIntegrityValid: boolean;
  onRunAuditCheck: () => void;
  isVerifying: boolean;
}

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  onSelectTab,
  recentLogs,
  chainIntegrityValid,
  onRunAuditCheck,
  isVerifying
}) => {
  const [selectedCategory, setSelectedCategory] = useState<string>('All');
  const [selectedControl, setSelectedControl] = useState<ComplianceControl | null>(null);

  const currentTenant = multiTenantStore.getCurrentTenant();
  const integrations = multiTenantStore.getIntegrations(currentTenant.id);
  const snapshots = multiTenantStore.getSnapshots(currentTenant.id);
  const openIssues = multiTenantStore.getIssues(currentTenant.id).filter((i) => i.status === 'OPEN');

  const categories = ['All', 'Security', 'Confidentiality', 'Change Management', 'Availability'];

  const filteredControls = selectedCategory === 'All'
    ? SOC2_CONTROLS
    : SOC2_CONTROLS.filter((c) => c.category === selectedCategory);

  const compliantCount = SOC2_CONTROLS.filter((c) => c.status === 'Compliant').length;

  return (
    <div className="space-y-6">
      {/* Dogfooding / Tenant Callout Banner */}
      <div className="bg-gradient-to-r from-indigo-950/80 via-slate-900 to-slate-900 border border-indigo-500/30 rounded-2xl p-5 shadow-lg flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1.5">
            <span className="bg-indigo-500/20 border border-indigo-500/30 text-indigo-300 text-xs font-semibold px-2.5 py-0.5 rounded-full flex items-center gap-1.5">
              <Rocket className="w-3.5 h-3.5 text-indigo-400" />
              {currentTenant.mode === 'internal' ? 'Internal Dogfooding Mode Active' : 'Commercial SaaS Tenant Mode'}
            </span>
            <span className="text-xs text-slate-400">
              Tenant: <strong className="text-white">{currentTenant.name}</strong>
            </span>
          </div>
          <h2 className="text-lg font-bold text-white tracking-tight">
            Continuous SOC 2 Automated Compliance Platform
          </h2>
          <p className="text-xs text-slate-300 max-w-2xl mt-0.5 leading-relaxed">
            Real-time API ingestion from AWS & GitHub, BullMQ background worker scans, 30-day gap remediation SLAs, and immutable WORM audit snapshots.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => onSelectTab('dogfooding')}
            className="flex items-center gap-1.5 px-3.5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer"
          >
            <span>Dogfooding Roadmap</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
          <button
            onClick={() => onSelectTab('remediation')}
            className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer ${
              openIssues.length > 0
                ? 'bg-rose-600 hover:bg-rose-500 text-white animate-pulse'
                : 'bg-slate-800 hover:bg-slate-700 text-slate-200'
            }`}
          >
            <AlertOctagon className="w-3.5 h-3.5" />
            <span>{openIssues.length > 0 ? `${openIssues.length} Gaps to Remediate` : '0 Open Gaps'}</span>
          </button>
        </div>
      </div>

      {/* The 3 Core Pillars of Continuous SOC 2 */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Pillar 1 */}
        <div 
          onClick={() => onSelectTab('ingestion')}
          className="bg-slate-900/90 border border-slate-800 hover:border-indigo-500/50 rounded-xl p-5 cursor-pointer transition-all hover:bg-slate-850 flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center justify-between text-slate-400 mb-3">
              <span className="text-xs font-bold uppercase tracking-wider text-indigo-400">1. Ingestion Engine</span>
              <div className="p-2 bg-indigo-500/10 text-indigo-400 rounded-lg">
                <Cloud className="w-4 h-4" />
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-white">{integrations.length}</span>
              <span className="text-xs text-emerald-400 font-medium">Connectors Active</span>
            </div>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              AWS STS AssumeRole (ExternalId), GitHub OAuth, Google Workspace Directory & Steampipe SQL.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-indigo-400 font-semibold">
            <span>Manage Cloud Connectors</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </div>
        </div>

        {/* Pillar 2 */}
        <div 
          onClick={() => onSelectTab('evidence_engine')}
          className="bg-slate-900/90 border border-slate-800 hover:border-emerald-500/50 rounded-xl p-5 cursor-pointer transition-all hover:bg-slate-850 flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center justify-between text-slate-400 mb-3">
              <span className="text-xs font-bold uppercase tracking-wider text-emerald-400">2. Evidence Engine</span>
              <div className="p-2 bg-emerald-500/10 text-emerald-400 rounded-lg">
                <Cpu className="w-4 h-4" />
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-white">{snapshots.length}</span>
              <span className="text-xs text-emerald-400 font-medium">WORM Snapshots</span>
            </div>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Asynchronous BullMQ worker pool, Redis job queues, and immutable SHA-256 hashed API payloads.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-emerald-400 font-semibold">
            <span>Inspect Worker Pool & Vault</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </div>
        </div>

        {/* Pillar 3 */}
        <div 
          onClick={() => onSelectTab('remediation')}
          className="bg-slate-900/90 border border-slate-800 hover:border-amber-500/50 rounded-xl p-5 cursor-pointer transition-all hover:bg-slate-850 flex flex-col justify-between"
        >
          <div>
            <div className="flex items-center justify-between text-slate-400 mb-3">
              <span className="text-xs font-bold uppercase tracking-wider text-amber-400">3. Governance & Gaps</span>
              <div className="p-2 bg-amber-500/10 text-amber-400 rounded-lg">
                <AlertOctagon className="w-4 h-4" />
              </div>
            </div>
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-bold text-white">{currentTenant.complianceScore}%</span>
              <span className={`text-xs font-medium ${currentTenant.complianceScore >= 90 ? 'text-emerald-400' : 'text-amber-400'}`}>
                {openIssues.length === 0 ? 'Fully Compliant' : `${openIssues.length} Failing Controls`}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-2 leading-relaxed">
              Automated gap detection, 30-day SLA resolution countdown, 1-click auto-remediations & signed policies.
            </p>
          </div>
          <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-amber-400 font-semibold">
            <span>Open Remediation Task Center</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </div>
        </div>
      </div>

      {/* Architecture Visual Component */}
      <ArchitectureDiagram onSelectTab={onSelectTab} />

      {/* Trust Services Criteria Controls Grid */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-slate-800 gap-4">
          <div>
            <h2 className="text-base font-semibold text-white">AICPA Trust Services Criteria (TSC) Controls Matrix</h2>
            <p className="text-xs text-slate-400">Continuous monitoring of Security, Confidentiality, Change Management & Availability</p>
          </div>

          {/* Category Filter Pills */}
          <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800 text-xs overflow-x-auto max-w-full">
            {categories.map((cat) => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-2.5 py-1 rounded-md transition-colors whitespace-nowrap ${
                  selectedCategory === cat
                    ? 'bg-indigo-600 text-white font-medium shadow-sm'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Controls Table */}
        <div className="mt-4 divide-y divide-slate-800/60 overflow-hidden">
          {filteredControls.map((ctrl) => (
            <div
              key={ctrl.id}
              onClick={() => setSelectedControl(ctrl)}
              className="py-3.5 px-2 hover:bg-slate-800/40 rounded-lg transition-colors cursor-pointer flex flex-col md:flex-row items-start md:items-center justify-between gap-3"
            >
              <div className="flex items-start gap-3">
                <div className="p-1.5 bg-slate-800 border border-slate-700 text-indigo-400 rounded font-mono text-xs font-bold shrink-0">
                  {ctrl.code}
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-semibold text-slate-100">{ctrl.name}</span>
                    <span className="text-[10px] bg-slate-800 text-slate-400 px-1.5 py-0.5 rounded">
                      {ctrl.category}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 line-clamp-1 mt-0.5">{ctrl.description}</p>
                </div>
              </div>

              <div className="flex items-center gap-4 shrink-0 self-end md:self-auto text-xs">
                <div className="flex items-center gap-1.5 bg-emerald-950/60 border border-emerald-800/40 text-emerald-400 px-2.5 py-1 rounded-full">
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span className="font-medium">{ctrl.status}</span>
                </div>
                <div className="text-slate-400 text-right hidden sm:block">
                  <div className="text-[11px] font-mono text-slate-300">Score: {ctrl.score}%</div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Control Details Modal / Drawer */}
      {selectedControl && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-slate-900 border border-slate-700 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto"
          >
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <span className="px-2.5 py-1 bg-indigo-950 border border-indigo-700 text-indigo-300 font-mono text-sm font-bold rounded">
                  {selectedControl.code}
                </span>
                <h3 className="text-base font-bold text-white">{selectedControl.name}</h3>
              </div>
              <button
                onClick={() => setSelectedControl(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">AICPA TSC Requirement</h4>
              <p className="text-xs text-slate-200 bg-slate-950/60 p-3 rounded-lg border border-slate-800 leading-relaxed">
                {selectedControl.description}
              </p>
            </div>

            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Operational Control</h4>
              <p className="text-xs text-slate-300 bg-slate-800/40 p-3 rounded-lg border border-slate-700/60">
                {selectedControl.operationalControl}
              </p>
            </div>

            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-1">Technical Implementation</h4>
              <p className="text-xs font-mono text-cyan-300 bg-slate-950 p-3 rounded-lg border border-slate-800">
                {selectedControl.technicalImplementation}
              </p>
            </div>

            <div>
              <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-400 mb-2">Automated Audit Evidence</h4>
              <div className="space-y-1.5">
                {selectedControl.evidenceItems.map((item, idx) => (
                  <div key={idx} className="flex items-center gap-2 text-xs text-slate-300 bg-slate-800/60 px-3 py-2 rounded border border-slate-700/40">
                    <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end gap-2">
              <button
                onClick={() => setSelectedControl(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg cursor-pointer"
              >
                Close
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </div>
  );
};

