import React from 'react';
import { 
  Rocket, 
  CheckCircle2, 
  Circle, 
  ArrowRight, 
  ShieldCheck, 
  Cloud, 
  Cpu, 
  Lock, 
  Users, 
  FileCheck2, 
  Sparkles,
  Zap
} from 'lucide-react';
import { multiTenantStore } from '../lib/multiTenantStore';

interface DogfoodingGuideProps {
  onNavigateTab: (tabId: string) => void;
}

export const DogfoodingGuide: React.FC<DogfoodingGuideProps> = ({ onNavigateTab }) => {
  const currentTenant = multiTenantStore.getCurrentTenant();
  const integrations = multiTenantStore.getIntegrations(currentTenant.id);
  const openIssues = multiTenantStore.getIssues(currentTenant.id).filter((i) => i.status === 'OPEN');
  const snapshots = multiTenantStore.getSnapshots(currentTenant.id);

  const steps = [
    {
      step: 1,
      title: 'Spin Up Internal Dogfood Tenant & Connect Providers',
      description: 'Configure read-only AWS STS Cross-Account Role Assumption, GitHub OAuth/Webhooks, and Google Workspace Directory integration.',
      isDone: integrations.length >= 3,
      actionLabel: 'Open Ingestion Hub',
      tabTarget: 'ingestion'
    },
    {
      step: 2,
      title: 'Run Automated BullMQ Background Workers',
      description: 'Simulate the asynchronous worker queue that fetches encrypted credentials, queries provider APIs, and archives raw snapshots.',
      isDone: snapshots.length > 0,
      actionLabel: 'Open Worker Pool',
      tabTarget: 'evidence_engine'
    },
    {
      step: 3,
      title: 'Surface & Remediate Failing Security Controls',
      description: 'Resolve open gaps (e.g. enforce virtual MFA, apply S3 public access block, require peer reviews on main) within the 30-day SLA window.',
      isDone: openIssues.length === 0,
      actionLabel: 'Open Remediation Center',
      tabTarget: 'remediation'
    },
    {
      step: 4,
      title: 'Verify WORM Evidence Vault & Cryptographic Hashes',
      description: 'Audit the immutable point-in-time JSON payloads with SHA-256 tamper-proof verification for external CPA auditors.',
      isDone: snapshots.length >= 3,
      actionLabel: 'Inspect Evidence Vault',
      tabTarget: 'evidence_engine'
    },
    {
      step: 5,
      title: 'Scale to Commercial B2B Multi-Tenancy',
      description: 'Switch between internal dogfooding and commercial tenant instances (e.g. Acme FinTech, Nova Health) with strict data isolation.',
      isDone: true,
      actionLabel: 'Switch Tenants (Top Bar)',
      tabTarget: 'overview'
    }
  ];

  const completedCount = steps.filter((s) => s.isDone).length;
  const progressPercent = Math.round((completedCount / steps.length) * 100);

  return (
    <div className="space-y-6" id="dogfooding-guide-container">
      {/* Header Banner */}
      <div className="bg-gradient-to-br from-indigo-950/60 via-slate-900 to-slate-900 border border-indigo-500/30 rounded-2xl p-6 shadow-lg">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-2">
              <span className="bg-indigo-500/20 border border-indigo-500/40 text-indigo-300 text-xs font-semibold px-2.5 py-0.5 rounded-full flex items-center gap-1.5">
                <Rocket className="w-3.5 h-3.5 text-indigo-400" />
                Dogfooding Strategy to Commercial SaaS
              </span>
              <span className="text-xs text-slate-400">
                Tenant: <strong className="text-white">{currentTenant.name}</strong>
              </span>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">
              Internal Audit Readiness & B2B Launchpad
            </h2>
            <p className="text-xs text-slate-300 max-w-2xl mt-1 leading-relaxed">
              Before selling continuous compliance to external enterprises, "dogfood" the full software suite on your own organization. Complete all 5 milestones to achieve SOC 2 Type 2 certification.
            </p>
          </div>

          <div className="bg-slate-950/80 border border-slate-800 p-4 rounded-xl text-right shrink-0">
            <span className="text-xs text-slate-400 block mb-1">Audit Readiness Progress</span>
            <div className="flex items-center justify-end gap-2">
              <span className="text-2xl font-black text-indigo-400">{progressPercent}%</span>
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            </div>
            <span className="text-[11px] text-slate-400 font-mono mt-1 block">
              {completedCount} of {steps.length} Milestones Cleared
            </span>
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-slate-950/80 rounded-full h-2 mt-5 overflow-hidden border border-slate-800">
          <div
            className="bg-gradient-to-r from-indigo-500 to-emerald-400 h-2 rounded-full transition-all duration-500"
            style={{ width: `${progressPercent}%` }}
          />
        </div>
      </div>

      {/* 5-Step Milestone Cards */}
      <div className="space-y-4">
        {steps.map((st) => (
          <div
            key={st.step}
            className={`bg-slate-900 border rounded-xl p-5 transition-all shadow-sm flex flex-col md:flex-row md:items-center justify-between gap-4 ${
              st.isDone
                ? 'border-slate-800 hover:border-slate-700'
                : 'border-indigo-500/40 bg-slate-900/90 ring-1 ring-indigo-500/20'
            }`}
          >
            <div className="flex items-start gap-4">
              <div
                className={`w-9 h-9 rounded-xl flex items-center justify-center font-bold text-sm shrink-0 mt-0.5 ${
                  st.isDone
                    ? 'bg-emerald-500/10 border border-emerald-500/30 text-emerald-400'
                    : 'bg-indigo-500/20 border border-indigo-500/40 text-indigo-300'
                }`}
              >
                {st.isDone ? <CheckCircle2 className="w-5 h-5" /> : st.step}
              </div>

              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white tracking-tight">{st.title}</h3>
                  {st.isDone ? (
                    <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded-full font-semibold">
                      Completed
                    </span>
                  ) : (
                    <span className="text-[10px] bg-amber-500/10 text-amber-300 border border-amber-500/20 px-2 py-0.5 rounded-full font-semibold">
                      In Progress
                    </span>
                  )}
                </div>
                <p className="text-xs text-slate-400 mt-1 leading-relaxed">{st.description}</p>
              </div>
            </div>

            <div className="shrink-0 flex items-center justify-end">
              <button
                onClick={() => onNavigateTab(st.tabTarget)}
                className={`flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-semibold transition-all cursor-pointer ${
                  st.isDone
                    ? 'bg-slate-800 hover:bg-slate-700 text-slate-200'
                    : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow-sm'
                }`}
              >
                <span>{st.actionLabel}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
