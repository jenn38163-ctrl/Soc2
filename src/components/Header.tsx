import React, { useState } from 'react';
import { 
  Shield, 
  ShieldCheck,
  Lock, 
  FileText, 
  Terminal, 
  Key, 
  Users, 
  CheckCircle, 
  Download, 
  Eye, 
  Sparkles, 
  Layers, 
  Activity, 
  Cloud, 
  Cpu, 
  AlertOctagon, 
  Radio, 
  Rocket, 
  Building2,
  ChevronDown
} from 'lucide-react';
import { multiTenantStore } from '../lib/multiTenantStore';
import { Tenant } from '../types/soc2';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  auditorMode: boolean;
  setAuditorMode: (enabled: boolean) => void;
  onExportEvidence: () => void;
  onRunAuditCheck: () => void;
  overallScore: number;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  auditorMode,
  setAuditorMode,
  onExportEvidence,
  onRunAuditCheck,
  overallScore
}) => {
  const currentTenant = multiTenantStore.getCurrentTenant();
  const allTenants = multiTenantStore.getTenants();
  const [tenantDropdownOpen, setTenantDropdownOpen] = useState(false);

  const tabs = [
    { id: 'compliance_dashboard', label: 'Compliance Dashboard', icon: ShieldCheck },
    { id: 'overview', label: 'Overview', icon: Shield },
    { id: 'dogfooding', label: 'Dogfooding Roadmap', icon: Rocket },
    { id: 'ingestion', label: 'Ingestion Hub (APIs & SQL)', icon: Cloud },
    { id: 'evidence_engine', label: 'Evidence Engine & Workers', icon: Cpu },
    { id: 'remediation', label: 'Remediation Center (Gaps)', icon: AlertOctagon },
    { id: 'webhooks', label: 'Real-Time Webhooks', icon: Radio },
    { id: 'audit', label: 'Audit Logs (CC6.8)', icon: Activity },
    { id: 'rbac', label: 'RBAC Policy (CC6.1/6.2)', icon: Users },
    { id: 'encryption', label: 'Encryption & KMS (CC6.6/6.7)', icon: Key },
    { id: 'pipeline', label: 'CI/CD Pipeline (CC8.1/7.1)', icon: Terminal },
    { id: 'policies', label: 'Baseline Policies', icon: FileText },
    { id: 'iac', label: 'IaC & Isolation', icon: Layers },
    { id: 'auditor', label: 'Auditor Vault', icon: Eye }
  ];

  const handleSelectTenant = (t: Tenant) => {
    multiTenantStore.setCurrentTenant(t.id);
    setTenantDropdownOpen(false);
  };

  return (
    <header className="bg-slate-950/95 border-b border-slate-800 sticky top-0 z-40 backdrop-blur-md">
      {/* Top Banner Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          {/* Logo & Title */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-indigo-500 to-indigo-700 flex items-center justify-center text-white shadow-lg shadow-indigo-600/20 ring-1 ring-white/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-white tracking-tight">SOC 2 Compliance Engine</h1>
                <span className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-semibold px-2 py-0.5 rounded-full uppercase tracking-wider">
                  Type 2 Ready
                </span>
              </div>
              <p className="text-xs text-slate-400">Continuous Automated Cloud Ingestion, BullMQ Workers & WORM Evidence Vault</p>
            </div>
          </div>

          {/* Right Controls: Tenant Switcher & Quick Actions */}
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Multi-Tenant Switcher */}
            <div className="relative">
              <button
                onClick={() => setTenantDropdownOpen(!tenantDropdownOpen)}
                className="flex items-center gap-2 bg-slate-900 hover:bg-slate-850 border border-slate-800 hover:border-slate-700 px-3 py-1.5 rounded-lg text-xs font-medium text-white transition-all cursor-pointer"
              >
                <Building2 className="w-3.5 h-3.5 text-indigo-400" />
                <div className="text-left hidden sm:block">
                  <span className="text-[10px] text-slate-400 block uppercase font-mono leading-none">Tenant:</span>
                  <span className="text-xs font-semibold text-white">{currentTenant.name}</span>
                </div>
                <span className="text-xs font-semibold text-white sm:hidden">{currentTenant.slug}</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded font-mono ${
                  currentTenant.mode === 'internal' ? 'bg-indigo-500/20 text-indigo-300' : 'bg-emerald-500/20 text-emerald-300'
                }`}>
                  {currentTenant.mode === 'internal' ? 'Dogfood' : 'SaaS'}
                </span>
                <ChevronDown className="w-3.5 h-3.5 text-slate-400" />
              </button>

              {/* Dropdown Menu */}
              {tenantDropdownOpen && (
                <div className="absolute right-0 mt-2 w-72 bg-slate-900 border border-slate-800 rounded-xl shadow-2xl z-50 p-2 space-y-1 divide-y divide-slate-800/60">
                  <div className="px-2 py-1.5 text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                    Select SaaS Tenant
                  </div>
                  <div className="pt-1 space-y-1">
                    {allTenants.map((t) => (
                      <button
                        key={t.id}
                        onClick={() => handleSelectTenant(t)}
                        className={`w-full text-left p-2 rounded-lg text-xs transition-colors flex items-center justify-between cursor-pointer ${
                          t.id === currentTenant.id
                            ? 'bg-indigo-600/20 border border-indigo-500/40 text-white'
                            : 'hover:bg-slate-800 text-slate-300 hover:text-white'
                        }`}
                      >
                        <div>
                          <div className="font-semibold text-white flex items-center gap-1.5">
                            {t.name}
                            {t.id === currentTenant.id && <CheckCircle className="w-3 h-3 text-emerald-400" />}
                          </div>
                          <div className="text-[10px] text-slate-400 font-mono">
                            {t.mode === 'internal' ? 'Internal Dogfooding Mode' : 'Commercial Tenant Mode'}
                          </div>
                        </div>
                        <span className="text-xs font-bold text-emerald-400 font-mono">
                          {t.complianceScore}%
                        </span>
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Live Compliance Score */}
            <div className="hidden lg:flex items-center gap-2 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg">
              <span className="text-xs text-slate-400">Score:</span>
              <div className="flex items-center gap-1">
                <span className="text-sm font-bold text-emerald-400">{currentTenant.complianceScore}%</span>
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
              </div>
            </div>

            {/* Auditor Mode Toggle */}
            <button
              onClick={() => setAuditorMode(!auditorMode)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-all cursor-pointer ${
                auditorMode
                  ? 'bg-amber-500/20 border-amber-500/60 text-amber-300 ring-1 ring-amber-500/50'
                  : 'bg-slate-900 border-slate-800 text-slate-300 hover:text-white hover:border-slate-700'
              }`}
            >
              <Eye className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">{auditorMode ? 'Auditor View Active' : 'Auditor View'}</span>
            </button>

            {/* Export Evidence Pack */}
            <button
              onClick={onExportEvidence}
              className="hidden md:flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-medium shadow-sm transition-colors cursor-pointer"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Evidence</span>
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center gap-1 overflow-x-auto no-scrollbar py-2 border-t border-slate-800/80 text-xs">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg font-medium whitespace-nowrap transition-all cursor-pointer ${
                  isActive
                    ? 'bg-indigo-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};

