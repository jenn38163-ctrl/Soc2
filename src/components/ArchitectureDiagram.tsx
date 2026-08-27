import React, { useState } from 'react';
import { Shield, Lock, FileText, Server, Database, Key, Users, CheckCircle2, ArrowRight, Activity, Terminal } from 'lucide-react';
import { motion } from 'motion/react';

interface ArchitectureDiagramProps {
  onSelectTab: (tabId: string) => void;
}

export const ArchitectureDiagram: React.FC<ArchitectureDiagramProps> = ({ onSelectTab }) => {
  const [activeNode, setActiveNode] = useState<string | null>(null);

  const nodeDetails: Record<string, { title: string; criteria: string; description: string; tab: string }> = {
    app: {
      title: 'Application Layer',
      criteria: 'Business Logic & Services',
      description: 'Decoupled application layer executing user workloads without embedding hardcoded compliance controls.',
      tab: 'overview'
    },
    audit: {
      title: 'Audit & Access Logs Module',
      criteria: 'TSC CC6.1, CC6.8, CC7.2',
      description: 'Structured Winston audit logging with automated PII redaction, trace correlation IDs, and SHA-256 hash chaining.',
      tab: 'audit'
    },
    policy: {
      title: 'Policy Enforcer & Decision Engine',
      criteria: 'TSC CC6.1, CC6.3',
      description: 'Enforces the Principle of Least Privilege. Every authorization request is evaluated and emits an immutable policy decision log.',
      tab: 'rbac'
    },
    rbac: {
      title: 'Identity & RBAC Module',
      criteria: 'TSC CC6.1, CC6.2',
      description: 'Centralized role definitions (Admin, Editor, Viewer) integrated with SSO/MFA and automated 24-hr offboarding SLAs.',
      tab: 'rbac'
    },
    worm: {
      title: 'Immutable Log Store (WORM)',
      criteria: 'TSC CC6.8, CC7.2',
      description: 'Write-Once-Read-Many (WORM) storage via AWS S3 Object Lock in COMPLIANCE mode and continuous SIEM forwarders.',
      tab: 'audit'
    },
    kms: {
      title: 'KMS & Encryption Vault',
      criteria: 'TSC CC6.6, CC6.7',
      description: 'Hardware Security Module (HSM) backed AWS KMS Customer-Managed Keys (CMK) enforcing AES-256-GCM with automated annual rotation.',
      tab: 'encryption'
    },
    idp: {
      title: 'Identity Provider (IdP)',
      criteria: 'TSC CC6.1, CC6.2',
      description: 'Centralized Okta / Google Workspace SAML/OIDC with mandatory hardware TOTP/FIDO2 MFA (SMS prohibited).',
      tab: 'policies'
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 text-slate-100 shadow-xl backdrop-blur-sm">
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between pb-6 border-b border-slate-800 gap-4">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-indigo-500/10 border border-indigo-500/30 rounded-lg text-indigo-400">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-lg font-semibold tracking-tight text-white">SOC 2 Modular Technical Architecture</h2>
              <p className="text-xs text-slate-400">Decoupled security and compliance fabric satisfying AICPA Trust Services Criteria</p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs bg-slate-800/80 px-3 py-1.5 rounded-lg border border-slate-700/60">
          <span className="inline-block w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-slate-300 font-medium">Controls Live & Enforced</span>
        </div>
      </div>

      {/* Interactive Diagram Map */}
      <div className="py-8">
        {/* Tier 1: Application Layer */}
        <div className="flex justify-center mb-6">
          <motion.div
            whileHover={{ scale: 1.02 }}
            onClick={() => {
              setActiveNode('app');
            }}
            className={`w-full max-w-xl cursor-pointer p-4 rounded-xl border transition-all text-center ${
              activeNode === 'app'
                ? 'bg-indigo-950/60 border-indigo-500 shadow-lg shadow-indigo-500/10 ring-1 ring-indigo-500'
                : 'bg-slate-800/80 border-slate-700 hover:border-slate-600'
            }`}
          >
            <div className="flex items-center justify-center gap-2 text-sm font-medium text-slate-200">
              <Server className="w-4 h-4 text-indigo-400" />
              <span>Application Layer (REST APIs, Microservices & Core Logic)</span>
            </div>
            <p className="text-[11px] text-slate-400 mt-1">Decoupled from compliance internals via unified SOC 2 interceptors</p>
          </motion.div>
        </div>

        {/* Connector Line */}
        <div className="flex justify-center mb-6">
          <div className="flex flex-col items-center">
            <div className="w-px h-6 bg-indigo-500/40" />
            <div className="w-2 h-2 rounded-full bg-indigo-400" />
          </div>
        </div>

        {/* Tier 2: SOC 2 Module Container */}
        <div className="relative p-6 rounded-2xl border border-indigo-500/30 bg-gradient-to-b from-indigo-950/20 to-slate-900/40 mb-6">
          <div className="absolute -top-3 left-6 px-3 py-0.5 bg-indigo-600 text-[11px] font-semibold tracking-wide uppercase rounded-full text-white shadow">
            SOC 2 Production Module (Application Boundary)
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
            {/* Box A: Audit & Access Logs */}
            <motion.div
              whileHover={{ scale: 1.02 }}
              onClick={() => {
                setActiveNode('audit');
                onSelectTab('audit');
              }}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                activeNode === 'audit'
                  ? 'bg-cyan-950/50 border-cyan-400 ring-1 ring-cyan-400'
                  : 'bg-slate-800/90 border-slate-700 hover:border-cyan-500/50'
              }`}
            >
              <div className="flex items-center gap-2 text-cyan-400 font-medium text-sm mb-1.5">
                <Activity className="w-4 h-4" />
                <span>Audit & Access Logs</span>
              </div>
              <div className="text-[11px] font-mono text-cyan-300/80 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40 inline-block mb-2">
                CC6.1, CC6.8, CC7.2
              </div>
              <p className="text-xs text-slate-300 line-clamp-2">
                Structured Winston logger, automated PII sanitization, correlation trace IDs & hash chaining.
              </p>
            </motion.div>

            {/* Box B: Policy Enforcer */}
            <motion.div
              whileHover={{ scale: 1.02 }}
              onClick={() => {
                setActiveNode('policy');
                onSelectTab('rbac');
              }}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                activeNode === 'policy'
                  ? 'bg-amber-950/50 border-amber-400 ring-1 ring-amber-400'
                  : 'bg-slate-800/90 border-slate-700 hover:border-amber-500/50'
              }`}
            >
              <div className="flex items-center gap-2 text-amber-400 font-medium text-sm mb-1.5">
                <Shield className="w-4 h-4" />
                <span>Policy Enforcer</span>
              </div>
              <div className="text-[11px] font-mono text-amber-300/80 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/40 inline-block mb-2">
                CC6.1, CC6.3
              </div>
              <p className="text-xs text-slate-300 line-clamp-2">
                Principle of Least Privilege enforcer emitting explicit audit evidence on every decision.
              </p>
            </motion.div>

            {/* Box C: Identity & RBAC */}
            <motion.div
              whileHover={{ scale: 1.02 }}
              onClick={() => {
                setActiveNode('rbac');
                onSelectTab('rbac');
              }}
              className={`p-4 rounded-xl border cursor-pointer transition-all ${
                activeNode === 'rbac'
                  ? 'bg-emerald-950/50 border-emerald-400 ring-1 ring-emerald-400'
                  : 'bg-slate-800/90 border-slate-700 hover:border-emerald-500/50'
              }`}
            >
              <div className="flex items-center gap-2 text-emerald-400 font-medium text-sm mb-1.5">
                <Users className="w-4 h-4" />
                <span>Identity & RBAC</span>
              </div>
              <div className="text-[11px] font-mono text-emerald-300/80 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40 inline-block mb-2">
                CC6.1, CC6.2
              </div>
              <p className="text-xs text-slate-300 line-clamp-2">
                Granular role permissions (Admin, Editor, Viewer), least privilege matrix, and 24h offboarding.
              </p>
            </motion.div>
          </div>
        </div>

        {/* Connectors Downward */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4 text-center">
          <div className="flex justify-center"><div className="w-px h-6 bg-cyan-500/40" /></div>
          <div className="flex justify-center"><div className="w-px h-6 bg-amber-500/40" /></div>
          <div className="flex justify-center"><div className="w-px h-6 bg-emerald-500/40" /></div>
        </div>

        {/* Tier 3: Infrastructure & Cloud Persistence Layer */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Infra A: Immutable Log Store */}
          <motion.div
            whileHover={{ scale: 1.02 }}
            onClick={() => {
              setActiveNode('worm');
              onSelectTab('audit');
            }}
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              activeNode === 'worm'
                ? 'bg-cyan-950/70 border-cyan-400'
                : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center gap-2 text-slate-200 font-medium text-xs mb-1">
              <Database className="w-3.5 h-3.5 text-cyan-400" />
              <span>Immutable Log Store</span>
            </div>
            <p className="text-[11px] text-slate-400">AWS S3 Object Lock (COMPLIANCE mode) / SIEM</p>
          </motion.div>

          {/* Infra B: KMS / Vault */}
          <motion.div
            whileHover={{ scale: 1.02 }}
            onClick={() => {
              setActiveNode('kms');
              onSelectTab('encryption');
            }}
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              activeNode === 'kms'
                ? 'bg-amber-950/70 border-amber-400'
                : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center gap-2 text-slate-200 font-medium text-xs mb-1">
              <Key className="w-3.5 h-3.5 text-amber-400" />
              <span>KMS / Encryption Vault</span>
            </div>
            <p className="text-[11px] text-slate-400">AWS KMS / HashiCorp Vault (AES-256-GCM)</p>
          </motion.div>

          {/* Infra C: IdP */}
          <motion.div
            whileHover={{ scale: 1.02 }}
            onClick={() => {
              setActiveNode('idp');
              onSelectTab('policies');
            }}
            className={`p-4 rounded-xl border cursor-pointer transition-all ${
              activeNode === 'idp'
                ? 'bg-emerald-950/70 border-emerald-400'
                : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
            }`}
          >
            <div className="flex items-center gap-2 text-slate-200 font-medium text-xs mb-1">
              <Lock className="w-3.5 h-3.5 text-emerald-400" />
              <span>Identity Provider (IdP)</span>
            </div>
            <p className="text-[11px] text-slate-400">Okta / Google Workspace SSO / Mandatory MFA</p>
          </motion.div>
        </div>
      </div>

      {/* Selected Node Details Drawer */}
      {activeNode && nodeDetails[activeNode] && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          className="mt-4 p-4 rounded-xl bg-slate-800/90 border border-slate-700 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3"
        >
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-semibold text-white">{nodeDetails[activeNode].title}</span>
              <span className="text-xs px-2 py-0.5 rounded bg-indigo-950 border border-indigo-800/60 text-indigo-300 font-mono">
                {nodeDetails[activeNode].criteria}
              </span>
            </div>
            <p className="text-xs text-slate-300 mt-1">{nodeDetails[activeNode].description}</p>
          </div>
          <button
            onClick={() => onSelectTab(nodeDetails[activeNode].tab)}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium rounded-lg transition-colors shrink-0"
          >
            <span>Open Component Studio</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </motion.div>
      )}
    </div>
  );
};
