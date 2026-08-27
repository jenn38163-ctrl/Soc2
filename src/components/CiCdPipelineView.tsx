import React, { useState } from 'react';
import { Terminal, Shield, CheckCircle2, XCircle, Play, AlertTriangle, FileCode, GitBranch, GitPullRequest, Copy, RefreshCw, Check } from 'lucide-react';
import { motion } from 'motion/react';
import { executePipelineSimulation, INITIAL_PIPELINE_RUNS, SOC2_WORKFLOW_YAML } from '../lib/ciPipeline';
import { PipelineRun, PipelineStep } from '../types/soc2';

interface CiCdPipelineViewProps {
  onPipelineCompleted: () => void;
}

export const CiCdPipelineView: React.FC<CiCdPipelineViewProps> = ({ onPipelineCompleted }) => {
  const [pipelineRuns, setPipelineRuns] = useState<PipelineRun[]>(INITIAL_PIPELINE_RUNS);
  const [activeRun, setActiveRun] = useState<PipelineRun>(INITIAL_PIPELINE_RUNS[0]);
  const [isRunning, setIsRunning] = useState(false);
  const [showYaml, setShowYaml] = useState(false);
  const [copiedYaml, setCopiedYaml] = useState(false);
  const [scenario, setScenario] = useState<'clean' | 'secret_leak' | 'vulnerable_dep'>('clean');

  const handleRunPipeline = async () => {
    setIsRunning(true);

    const newRun = await executePipelineSimulation({
      injectSecret: scenario === 'secret_leak',
      injectVulnerableDep: scenario === 'vulnerable_dep',
      branch: scenario === 'clean' ? 'feat/rbac-least-privilege' : scenario === 'secret_leak' ? 'feat/aws-legacy-helper' : 'feat/upgrade-deps',
      actorId: 'jenngremicinc@gmail.com',
      onStepProgress: (step, run) => {
        setActiveRun({ ...run });
      }
    });

    setPipelineRuns((prev) => [newRun, ...prev]);
    setActiveRun(newRun);
    setIsRunning(false);
    onPipelineCompleted();
  };

  const copyYaml = () => {
    navigator.clipboard.writeText(SOC2_WORKFLOW_YAML);
    setCopiedYaml(true);
    setTimeout(() => setCopiedYaml(false), 2000);
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-indigo-500/10 border border-indigo-500/30 text-indigo-400 rounded-lg">
              <Terminal className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">SOC 2 CI/CD Security Pipeline (CC8.1, CC7.1, CC6.1)</h2>
              <p className="text-xs text-slate-400">
                Automated security gates: TruffleHog secret scanning, Trivy CVE audits, CodeQL SAST & build validation
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowYaml(!showYaml)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition-colors"
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>{showYaml ? 'Hide YAML' : 'View Workflow YAML'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* GitHub Actions YAML Preview (Collapsible) */}
      {showYaml && (
        <motion.div
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          className="bg-slate-950 border border-slate-800 rounded-xl p-5"
        >
          <div className="flex items-center justify-between pb-3 border-b border-slate-800 mb-3 text-xs">
            <span className="font-mono text-slate-300 font-semibold">.github/workflows/soc2-compliance.yml</span>
            <button
              onClick={copyYaml}
              className="flex items-center gap-1 text-cyan-400 hover:text-cyan-300 font-medium"
            >
              {copiedYaml ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedYaml ? 'Copied YAML!' : 'Copy Workflow'}</span>
            </button>
          </div>
          <pre className="text-[11px] font-mono text-slate-300 overflow-x-auto p-2 leading-relaxed bg-slate-900/60 rounded-lg border border-slate-800">
            {SOC2_WORKFLOW_YAML}
          </pre>
        </motion.div>
      )}

      {/* Pipeline Trigger & Scenario Runner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white">Execute Automated CI/CD Gate Simulation</h3>
            <p className="text-xs text-slate-400">Select a Pull Request scenario to verify automated gating enforcement</p>
          </div>

          <div className="flex items-center gap-2 flex-wrap text-xs">
            <select
              value={scenario}
              onChange={(e) => setScenario(e.target.value as any)}
              className="px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-indigo-500"
            >
              <option value="clean">Scenario 1: Clean Pull Request (Pass All Gates)</option>
              <option value="secret_leak">Scenario 2: Hardcoded Secret Injection (CC6.1 TruffleHog Failure)</option>
              <option value="vulnerable_dep">Scenario 3: High CVE Dependency (CC7.1 Trivy Scan Failure)</option>
            </select>

            <button
              onClick={handleRunPipeline}
              disabled={isRunning}
              className="flex items-center gap-1.5 px-4 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white font-bold rounded-lg shadow-sm transition-colors"
            >
              {isRunning ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-white" />}
              <span>{isRunning ? 'Running Security Gates...' : 'Trigger Pipeline'}</span>
            </button>
          </div>
        </div>

        {/* Branch Protection Rules Banner */}
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
          <div className="flex items-center gap-2 text-slate-300">
            <GitBranch className="w-4 h-4 text-emerald-400 shrink-0" />
            <span className="font-semibold text-white">Protected Branch: main</span>
            <span className="text-slate-500">•</span>
            <span className="text-slate-400">1+ Peer Approval Required</span>
            <span className="text-slate-500">•</span>
            <span className="text-slate-400">Force Push Disabled</span>
          </div>
          <div className="text-[11px] text-emerald-400 font-mono font-semibold">
            Status Checks Enforced (CC8.1)
          </div>
        </div>
      </div>

      {/* Active Run Terminal & Step Progress */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="p-4 bg-slate-950 border-b border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <GitPullRequest className="w-4 h-4 text-indigo-400" />
              <span className="text-xs font-bold text-white">{activeRun.branch}</span>
            </div>
            <span className="text-xs font-mono text-slate-400">Commit: {activeRun.commitHash}</span>
          </div>

          <div className="flex items-center gap-2">
            <span
              className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase ${
                activeRun.status === 'passed'
                  ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                  : activeRun.status === 'blocked'
                  ? 'bg-rose-950 text-rose-400 border border-rose-800'
                  : 'bg-indigo-950 text-indigo-400 border border-indigo-800 animate-pulse'
              }`}
            >
              Pipeline {activeRun.status}
            </span>
          </div>
        </div>

        {/* Steps Grid */}
        <div className="p-6 grid grid-cols-1 md:grid-cols-4 gap-4 bg-slate-900/50">
          {activeRun.steps.map((step, idx) => {
            const isSuccess = step.status === 'success';
            const isFailed = step.status === 'failed';
            const isRunningStep = step.status === 'running';

            return (
              <div
                key={step.id}
                className={`p-4 rounded-xl border transition-all ${
                  isSuccess
                    ? 'bg-slate-950 border-emerald-800/60'
                    : isFailed
                    ? 'bg-rose-950/40 border-rose-600 ring-1 ring-rose-500'
                    : isRunningStep
                    ? 'bg-indigo-950/40 border-indigo-500 animate-pulse'
                    : 'bg-slate-950/60 border-slate-800'
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-[10px] font-mono font-bold text-slate-400 uppercase">
                    Step {idx + 1}: {step.criteria}
                  </span>
                  {isSuccess && <CheckCircle2 className="w-4 h-4 text-emerald-400" />}
                  {isFailed && <XCircle className="w-4 h-4 text-rose-400" />}
                  {isRunningStep && <RefreshCw className="w-4 h-4 text-indigo-400 animate-spin" />}
                </div>

                <div className="text-xs font-bold text-white line-clamp-1">{step.name}</div>
                <div className="text-[10px] text-slate-400 mt-1 font-mono truncate">{step.tool}</div>

                {step.durationMs && (
                  <div className="mt-2 text-[10px] text-slate-500">
                    Duration: {(step.durationMs / 1000).toFixed(1)}s
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Terminal Execution Logs */}
        <div className="p-6 bg-slate-950 border-t border-slate-800 font-mono text-xs text-slate-300 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
            <span className="font-bold text-slate-400 flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-cyan-400" />
              <span>CI/CD Step Execution Terminal Stream</span>
            </span>
          </div>

          <div className="space-y-4 max-h-80 overflow-y-auto pr-2">
            {activeRun.steps.map((step) => (
              <div key={step.id} className="space-y-1">
                <div className="text-indigo-400 font-bold flex items-center gap-1.5 text-[11px]">
                  <span>▸ [{step.criteria}] {step.name}</span>
                </div>
                {step.logs.length === 0 ? (
                  <div className="text-slate-600 text-[11px] pl-4 italic">Waiting to execute...</div>
                ) : (
                  step.logs.map((log, lIdx) => (
                    <div
                      key={lIdx}
                      className={`pl-4 text-[11px] ${
                        log.includes('🚨') || log.includes('❌')
                          ? 'text-rose-400 font-bold'
                          : log.includes('✔')
                          ? 'text-emerald-400'
                          : 'text-slate-300'
                      }`}
                    >
                      {log}
                    </div>
                  ))
                )}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
