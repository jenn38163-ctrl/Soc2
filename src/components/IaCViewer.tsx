import React, { useState } from 'react';
import { Layers, Shield, CheckCircle2, Copy, Check, Server, Database, Lock, Terminal } from 'lucide-react';
import { IAC_RESOURCES, IaCResource } from '../lib/iacTemplates';

export const IaCViewer: React.FC = () => {
  const [resources] = useState<IaCResource[]>(IAC_RESOURCES);
  const [selectedResource, setSelectedResource] = useState<IaCResource>(IAC_RESOURCES[0]);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const copyCode = (code: string, id: string) => {
    navigator.clipboard.writeText(code);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 rounded-lg">
            <Layers className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">Infrastructure as Code & Environment Segregation (CC6.6, A1.2)</h2>
            <p className="text-xs text-slate-400">
              Reproducible Terraform modules for multi-account AWS isolation, S3 WORM Object Lock, and Aurora PITR backups
            </p>
          </div>
        </div>
      </div>

      {/* Main Grid: Resource Selector & Code Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Resource List (4 cols) */}
        <div className="lg:col-span-4 space-y-3">
          {resources.map((res) => {
            const isSelected = selectedResource.id === res.id;
            return (
              <div
                key={res.id}
                onClick={() => setSelectedResource(res)}
                className={`p-4 rounded-xl border cursor-pointer transition-all ${
                  isSelected
                    ? 'bg-indigo-950/50 border-indigo-500 ring-1 ring-indigo-500 shadow-lg'
                    : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-xs text-white">{res.name}</span>
                </div>

                <div className="flex items-center gap-1.5 mb-2 flex-wrap">
                  {res.soc2Criteria.map((c) => (
                    <span key={c} className="text-[10px] bg-indigo-900/40 text-indigo-300 px-1.5 py-0.5 rounded border border-indigo-700/40 font-mono">
                      {c}
                    </span>
                  ))}
                </div>

                <p className="text-[11px] text-slate-400 line-clamp-2">{res.description}</p>
                <div className="mt-2.5 text-[10px] font-mono text-cyan-400 truncate">{res.filename}</div>
              </div>
            );
          })}
        </div>

        {/* Right: Code Viewer & Verification Checklist (8 cols) */}
        <div className="lg:col-span-8 bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-5">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3 border-b border-slate-800 gap-2">
            <div>
              <h3 className="text-sm font-bold text-white">{selectedResource.name}</h3>
              <p className="text-xs font-mono text-slate-400">{selectedResource.filename}</p>
            </div>

            <button
              onClick={() => copyCode(selectedResource.code, selectedResource.id)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition-colors"
            >
              {copiedId === selectedResource.id ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedId === selectedResource.id ? 'Copied Terraform!' : 'Copy HCL Code'}</span>
            </button>
          </div>

          {/* Terraform / CloudFormation Code Viewer */}
          <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 overflow-x-auto max-h-96">
            <pre className="font-mono text-xs text-indigo-200 leading-relaxed">
              {selectedResource.code}
            </pre>
          </div>

          {/* Automated Posture Verification Checklist */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 mb-2">
              Automated SOC 2 Compliance Posture Verification
            </h4>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              {selectedResource.verificationChecks.map((check, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex items-start gap-2.5"
                >
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <div>
                    <div className="text-xs font-bold text-slate-200">{check.name}</div>
                    <div className="text-[11px] text-slate-400">{check.detail}</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
