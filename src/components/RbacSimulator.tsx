import React, { useState } from 'react';
import { Users, Shield, CheckCircle2, XCircle, AlertTriangle, ArrowRight, Play, Lock, FileCheck, Check, Clock, UserX } from 'lucide-react';
import { motion } from 'motion/react';
import { Action, RbacDecision, Role } from '../types/soc2';
import { authorize, DEFAULT_ROLE_PERMISSIONS, ROLE_DESCRIPTIONS, ACTION_DESCRIPTIONS } from '../lib/accessPolicy';

interface RbacSimulatorProps {
  onDecisionLogged: () => void;
}

export const RbacSimulator: React.FC<RbacSimulatorProps> = ({ onDecisionLogged }) => {
  const [selectedRole, setSelectedRole] = useState<Role>('viewer');
  const [selectedAction, setSelectedAction] = useState<Action>('export');
  const [actorId, setActorId] = useState('usr_contractor_alex99');
  const [resource, setResource] = useState('customer_billing_records');
  const [lastDecision, setLastDecision] = useState<RbacDecision | null>(null);
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [customMatrix, setCustomMatrix] = useState<Record<Role, Action[]>>(DEFAULT_ROLE_PERMISSIONS);

  // 24-Hour Offboarding SLA simulation state
  const [offboardingStatus, setOffboardingStatus] = useState<Array<{ name: string; email: string; role: string; departureTime: string; revokedWithinHours: number; status: string }>>([
    { name: 'David Miller', email: 'd.miller@legacycorp.com', role: 'Editor', departureTime: '2026-08-26 14:00', revokedWithinHours: 1.5, status: 'REVOKED (SLA Met)' },
    { name: 'Sarah Connor', email: 's.connor@vendor.io', role: 'Viewer', departureTime: '2026-08-25 09:30', revokedWithinHours: 0.8, status: 'REVOKED (SLA Met)' },
    { name: 'Marcus Vance', email: 'm.vance@contractor.net', role: 'Admin', departureTime: '2026-08-27 08:00', revokedWithinHours: 0.2, status: 'REVOKED (Immediate)' }
  ]);

  const handleEvaluate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsEvaluating(true);
    const traceId = `trc_rbac_${Math.random().toString(36).substring(2, 10)}`;

    const decision = await authorize(
      selectedRole,
      selectedAction,
      actorId,
      traceId,
      resource,
      '192.168.1.55',
      customMatrix
    );

    setLastDecision(decision);
    setIsEvaluating(false);
    onDecisionLogged();
  };

  const togglePermission = (role: Role, action: Action) => {
    setCustomMatrix((prev) => {
      const current = prev[role];
      const next = current.includes(action)
        ? current.filter((a) => a !== action)
        : [...current, action];
      return { ...prev, [role]: next };
    });
  };

  const roles: Role[] = ['admin', 'editor', 'viewer'];
  const actions: Action[] = ['read', 'write', 'delete', 'export'];

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 rounded-lg">
            <Users className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">Access Control & Role-Based Enforcement (CC6.1, CC6.2)</h2>
            <p className="text-xs text-slate-400">
              Least Privilege evaluation engine with explicit, correlated audit evidence for every permission check
            </p>
          </div>
        </div>
      </div>

      {/* Main Grid: Interactive Evaluator & Decision Result */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Authorization Testbed Form (7 cols) */}
        <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl">
          <h3 className="text-sm font-bold text-white mb-1 flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            <span>Interactive Policy Enforcer & Decision Simulator</span>
          </h3>
          <p className="text-xs text-slate-400 mb-5">
            Test policy decisions against the active RBAC matrix. Each evaluation emits a SOC 2 audit log with correlation traceId.
          </p>

          <form onSubmit={handleEvaluate} className="space-y-4 text-xs">
            {/* Actor ID */}
            <div>
              <label className="block text-slate-300 font-medium mb-1">Actor ID (User / Service Account)</label>
              <input
                type="text"
                value={actorId}
                onChange={(e) => setActorId(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
                required
              />
            </div>

            {/* Role Selector */}
            <div>
              <label className="block text-slate-300 font-medium mb-1.5">User Assigned Role</label>
              <div className="grid grid-cols-3 gap-2">
                {roles.map((r) => (
                  <button
                    type="button"
                    key={r}
                    onClick={() => setSelectedRole(r)}
                    className={`p-2.5 rounded-lg border text-left transition-all ${
                      selectedRole === r
                        ? 'bg-emerald-950/70 border-emerald-500 text-white ring-1 ring-emerald-500'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <div className="font-bold capitalize">{r}</div>
                    <div className="text-[10px] text-slate-400 line-clamp-1 mt-0.5">{ROLE_DESCRIPTIONS[r]}</div>
                  </button>
                ))}
              </div>
            </div>

            {/* Action Selector */}
            <div>
              <label className="block text-slate-300 font-medium mb-1.5">Requested Action</label>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {actions.map((act) => (
                  <button
                    type="button"
                    key={act}
                    onClick={() => setSelectedAction(act)}
                    className={`py-2 px-3 rounded-lg border font-semibold capitalize transition-all ${
                      selectedAction === act
                        ? act === 'delete' || act === 'export'
                          ? 'bg-amber-600 border-amber-500 text-white'
                          : 'bg-emerald-600 border-emerald-500 text-white'
                        : 'bg-slate-950 border-slate-800 text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    {act}
                  </button>
                ))}
              </div>
              <p className="text-[11px] text-slate-500 mt-1.5">
                Action detail: {ACTION_DESCRIPTIONS[selectedAction]}
              </p>
            </div>

            {/* Target Resource */}
            <div>
              <label className="block text-slate-300 font-medium mb-1">Target Resource</label>
              <input
                type="text"
                value={resource}
                onChange={(e) => setResource(e.target.value)}
                className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-emerald-500 font-mono"
                required
              />
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={isEvaluating}
                className="w-full flex items-center justify-center gap-2 py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-lg shadow-lg shadow-emerald-600/20 transition-all text-xs"
              >
                <Play className="w-4 h-4 fill-white" />
                <span>Evaluate Policy & Emit SOC 2 Log</span>
              </button>
            </div>
          </form>
        </div>

        {/* Right: Policy Decision Result Card (5 cols) */}
        <div className="lg:col-span-5 flex flex-col justify-between bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl">
          <div>
            <h3 className="text-sm font-bold text-white mb-1 flex items-center gap-2">
              <FileCheck className="w-4 h-4 text-cyan-400" />
              <span>Real-Time Policy Decision Evidence</span>
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Cryptographically verified decision recorded in the audit log.
            </p>

            {lastDecision ? (
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                className={`p-4 rounded-xl border ${
                  lastDecision.allowed
                    ? 'bg-emerald-950/50 border-emerald-500/60'
                    : 'bg-rose-950/50 border-rose-500/60'
                }`}
              >
                <div className="flex items-center gap-2.5 mb-3">
                  {lastDecision.allowed ? (
                    <div className="p-1.5 bg-emerald-500/20 rounded-full text-emerald-400">
                      <CheckCircle2 className="w-6 h-6" />
                    </div>
                  ) : (
                    <div className="p-1.5 bg-rose-500/20 rounded-full text-rose-400">
                      <XCircle className="w-6 h-6" />
                    </div>
                  )}
                  <div>
                    <div className="text-xs uppercase tracking-wider text-slate-400 font-semibold">
                      Authorization Result
                    </div>
                    <div className={`text-base font-bold ${lastDecision.allowed ? 'text-emerald-300' : 'text-rose-300'}`}>
                      {lastDecision.allowed ? 'ACCESS GRANTED (CC6.1)' : 'ACCESS DENIED (Least Privilege Violation)'}
                    </div>
                  </div>
                </div>

                <div className="text-xs space-y-2 text-slate-300 border-t border-slate-800/80 pt-3 font-mono">
                  <div className="flex justify-between">
                    <span className="text-slate-500">Role Evaluated:</span>
                    <span className="text-slate-200 font-bold capitalize">{lastDecision.role}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Action Requested:</span>
                    <span className="text-slate-200 font-bold capitalize">{lastDecision.action}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Trace ID:</span>
                    <span className="text-cyan-400">{lastDecision.traceId}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500">Resource:</span>
                    <span className="text-slate-200 truncate max-w-[180px]">{lastDecision.resource}</span>
                  </div>
                </div>

                <div className="mt-3 p-2.5 bg-slate-950/80 rounded-lg text-[11px] text-slate-300 border border-slate-800">
                  <span className="font-semibold text-slate-400 block mb-0.5">Policy Rationale:</span>
                  {lastDecision.policyReason}
                </div>
              </motion.div>
            ) : (
              <div className="p-8 border border-dashed border-slate-800 rounded-xl text-center text-slate-500 text-xs">
                Run an evaluation on the left to see the instant policy decision and audit evidence.
              </div>
            )}
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
            <Lock className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>Auditors verify that all authorization evaluations are recorded with correlation IDs.</span>
          </div>
        </div>
      </div>

      {/* Role-Permission Matrix (Principle of Least Privilege) */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-slate-800 gap-2">
          <div>
            <h3 className="text-sm font-bold text-white">Role-Based Permission Matrix (Least Privilege Enforcement)</h3>
            <p className="text-xs text-slate-400">Click checkboxes to customize or test policy modifications</p>
          </div>
          <button
            onClick={() => setCustomMatrix(DEFAULT_ROLE_PERMISSIONS)}
            className="text-xs text-indigo-400 hover:text-indigo-300 underline"
          >
            Reset to Baseline Matrix
          </button>
        </div>

        <div className="mt-4 overflow-x-auto">
          <table className="w-full text-xs text-left">
            <thead>
              <tr className="border-b border-slate-800 text-slate-400 uppercase text-[10px]">
                <th className="py-2.5 px-3">Role</th>
                <th className="py-2.5 px-3">Read</th>
                <th className="py-2.5 px-3">Write</th>
                <th className="py-2.5 px-3">Delete</th>
                <th className="py-2.5 px-3">Export</th>
                <th className="py-2.5 px-3">Least Privilege Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-medium">
              {roles.map((role) => (
                <tr key={role} className="hover:bg-slate-800/30">
                  <td className="py-3 px-3 capitalize font-bold text-white">{role}</td>
                  {actions.map((action) => {
                    const hasPerm = customMatrix[role]?.includes(action);
                    return (
                      <td key={action} className="py-3 px-3">
                        <button
                          type="button"
                          onClick={() => togglePermission(role, action)}
                          className={`w-6 h-6 rounded flex items-center justify-center border transition-all ${
                            hasPerm
                              ? 'bg-emerald-600 border-emerald-500 text-white'
                              : 'bg-slate-950 border-slate-700 text-slate-600 hover:border-slate-500'
                          }`}
                        >
                          {hasPerm ? <Check className="w-3.5 h-3.5" /> : null}
                        </button>
                      </td>
                    );
                  })}
                  <td className="py-3 px-3">
                    <span className="text-[11px] text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
                      {role === 'viewer' ? 'Strict Read-Only' : role === 'editor' ? 'No Delete/Export' : 'Full Admin (Audited)'}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* 24-Hour Offboarding SLA Ledger */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <UserX className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-bold text-white">24-Hour Automated Offboarding SLA Evidence (CC6.2 / CC6.3)</h3>
          </div>
          <span className="text-[11px] bg-emerald-950 text-emerald-400 px-2.5 py-0.5 rounded border border-emerald-800/40 font-semibold">
            100% SLA Met (&lt; 24h)
          </span>
        </div>

        <div className="mt-3 divide-y divide-slate-800/60 text-xs">
          {offboardingStatus.map((item, idx) => (
            <div key={idx} className="py-2.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <div className="font-semibold text-slate-200">{item.name} ({item.email})</div>
                <div className="text-[11px] text-slate-400">Departed: {item.departureTime} • Prior Role: {item.role}</div>
              </div>
              <div className="flex items-center gap-3">
                <span className="text-[11px] font-mono text-cyan-400">Revoked in {item.revokedWithinHours} hrs</span>
                <span className="bg-emerald-950 text-emerald-400 px-2 py-0.5 rounded border border-emerald-800/60 text-[10px] font-bold">
                  {item.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
