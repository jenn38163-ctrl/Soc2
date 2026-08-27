import React, { useState, useEffect } from 'react';
import {
  Users,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Flame,
  Key,
  Terminal,
  FileCode,
  Lock,
  Unlock,
  RefreshCw,
  Copy,
  Check,
  HelpCircle,
  Eye,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Sparkles,
  Activity,
  Cpu,
  Layers,
  ArrowRight,
  Filter,
  CheckSquare,
  Clock,
  Zap,
  Play
} from 'lucide-react';
import confetti from 'canvas-confetti';
import { 
  triAuditorEngine 
} from '../services/triAuditorEngine';
import { 
  ControlConsensusState, 
  AgentFinding, 
  EvidenceLineageRecord, 
  ContinuousAuditingCheck, 
  LiveDeploymentGateStep,
  AgentVerdict
} from '../types/soc2';

export const TriAuditorConsensusHub: React.FC = () => {
  const [consensusData, setConsensusData] = useState<ControlConsensusState[]>([]);
  const [evidenceLineage, setEvidenceLineage] = useState<EvidenceLineageRecord[]>([]);
  const [continuousChecks, setContinuousChecks] = useState<ContinuousAuditingCheck[]>([]);
  const [deploymentSteps, setDeploymentSteps] = useState<LiveDeploymentGateStep[]>([]);
  
  const [activeTab, setActiveTab] = useState<'matrix' | 'disagreements' | 'evidence_lineage' | 'continuous' | 'deployment_gate'>('matrix');
  const [selectedControl, setSelectedControl] = useState<ControlConsensusState | null>(null);
  const [filterCategory, setFilterCategory] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  
  // Re-evaluation state
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [evaluationStats, setEvaluationStats] = useState<string | null>(null);

  // Deployment gate state
  const [isRunningDeploymentGate, setIsRunningDeploymentGate] = useState<boolean>(false);

  // Human Adjudication Form State
  const [adjudicatingControlId, setAdjudicatingControlId] = useState<string | null>(null);
  const [reviewerName, setReviewerName] = useState<string>('Jennifer Gremi, CPA / CISA');
  const [reviewerEmail, setReviewerEmail] = useState<string>('jenngremicinc@gmail.com');
  const [adjudicationDecision, setAdjudicationDecision] = useState<'ACCEPT_PASS' | 'UPHOLD_FAIL' | 'REQUIRE_REMEDIATION'>('ACCEPT_PASS');
  const [adjudicationNotes, setAdjudicationNotes] = useState<string>('Verified cryptographic proof and confirmed remediation plan meets AICPA SOC 2 Type II operating effectiveness guidelines.');

  useEffect(() => {
    const update = () => {
      setConsensusData(triAuditorEngine.getConsensusData());
      setEvidenceLineage(triAuditorEngine.getEvidenceLineage());
      setContinuousChecks(triAuditorEngine.getContinuousChecks());
      setDeploymentSteps(triAuditorEngine.getDeploymentGateSteps());
    };

    update();
    const unsubscribe = triAuditorEngine.subscribe(update);
    return () => unsubscribe();
  }, []);

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const handleRunEvaluation = async () => {
    setIsEvaluating(true);
    setEvaluationStats(null);
    try {
      const stats = await triAuditorEngine.runTriAuditorEvaluation();
      setEvaluationStats(
        `Tri-Auditor Evaluation completed in ${stats.durationMs}ms: ${stats.confirmedPass} Confirmed Pass, ${stats.disputed} Disputed, ${stats.confirmedFail} Confirmed Fail.`
      );
      confetti({
        particleCount: 70,
        spread: 60,
        origin: { y: 0.6 }
      });
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleRunDeploymentGate = async () => {
    setIsRunningDeploymentGate(true);
    try {
      await triAuditorEngine.runDeploymentGate();
      confetti({
        particleCount: 90,
        spread: 70,
        origin: { y: 0.6 }
      });
    } finally {
      setIsRunningDeploymentGate(false);
    }
  };

  const handleAdjudicateSubmit = (controlId: string) => {
    triAuditorEngine.submitHumanAdjudication(
      controlId,
      reviewerName,
      reviewerEmail,
      adjudicationDecision,
      adjudicationNotes
    );
    setAdjudicatingControlId(null);
    confetti({
      particleCount: 60,
      spread: 50,
      origin: { y: 0.7 }
    });
  };

  // Filtered consensus data
  const filteredControls = consensusData.filter((ctrl) => {
    const matchesCat = filterCategory === 'ALL' || ctrl.category === filterCategory;
    const matchesSearch = 
      ctrl.controlCode.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ctrl.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      ctrl.category.toLowerCase().includes(searchQuery.toLowerCase());
    return matchesCat && matchesSearch;
  });

  const disagreementQueue = triAuditorEngine.getDisagreementQueue();

  const getVerdictBadge = (verdict: AgentVerdict) => {
    switch (verdict) {
      case 'PASS':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-800/80">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            PASS
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-amber-950/80 text-amber-300 border border-amber-800/80">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            PARTIAL
          </span>
        );
      case 'FAIL':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-rose-950/80 text-rose-300 border border-rose-800/80">
            <XCircle className="w-3 h-3 text-rose-400" />
            FAIL
          </span>
        );
      case 'NOT_TESTABLE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold bg-slate-800 text-slate-400 border border-slate-700">
            <HelpCircle className="w-3 h-3 text-slate-400" />
            NOT TESTABLE
          </span>
        );
    }
  };

  const getConsensusBadge = (status: ControlConsensusState['consensusStatus']) => {
    switch (status) {
      case 'CONFIRMED_PASS':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-extrabold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            CONFIRMED PASS
          </span>
        );
      case 'DISPUTED':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-extrabold bg-amber-500/10 text-amber-400 border border-amber-500/30 animate-pulse">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
            DISPUTED (SPLIT)
          </span>
        );
      case 'CONFIRMED_FAILURE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-extrabold bg-rose-500/10 text-rose-400 border border-rose-500/30">
            <Flame className="w-3.5 h-3.5 text-rose-400" />
            CONFIRMED FAILURE
          </span>
        );
      case 'PARTIAL':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-extrabold bg-purple-500/10 text-purple-400 border border-purple-500/30">
            <Clock className="w-3.5 h-3.5 text-purple-400" />
            PARTIAL IMPLEMENTATION
          </span>
        );
      case 'NOT_TESTABLE':
        return (
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-extrabold bg-slate-800 text-slate-400 border border-slate-700">
            <HelpCircle className="w-3.5 h-3.5 text-slate-400" />
            NOT TESTABLE
          </span>
        );
    }
  };

  const getAssuranceBadge = (status: ControlConsensusState['finalAssuranceStatus']) => {
    switch (status) {
      case 'READY_FOR_HUMAN_ASSURANCE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-cyan-950/70 text-cyan-300 border border-cyan-800">
            <Sparkles className="w-3 h-3 text-cyan-400" />
            READY FOR HUMAN ASSURANCE
          </span>
        );
      case 'HUMAN_ADJUDICATED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950/70 text-emerald-300 border border-emerald-700">
            <CheckSquare className="w-3 h-3 text-emerald-400" />
            CPA ADJUDICATED
          </span>
        );
      case 'INVESTIGATION_NEEDED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950/70 text-amber-300 border border-amber-800">
            <Search className="w-3 h-3 text-amber-400" />
            INVESTIGATION NEEDED
          </span>
        );
      case 'REMEDIATION_REQUIRED':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950/70 text-rose-300 border border-rose-800">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            REMEDIATION REQUIRED
          </span>
        );
    }
  };

  return (
    <div className="space-y-6" id="tri-auditor-consensus-hub">
      {/* Top Multi-Agent Architecture Header */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl relative overflow-hidden">
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div>
            <div className="flex items-center gap-2">
              <span className="px-2.5 py-1 rounded-full text-xs font-bold uppercase tracking-wider bg-indigo-500/10 text-indigo-400 border border-indigo-500/30 flex items-center gap-1.5">
                <Users className="w-3.5 h-3.5" />
                Tri-Auditor Multi-Agent Engine
              </span>
              <span className="px-2.5 py-1 rounded-full text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
                <ShieldCheck className="w-3 h-3" />
                Blind Independent Review Active
              </span>
            </div>
            <h1 className="text-xl sm:text-2xl font-bold text-white mt-2">
              SOC 2 Multi-Agent Consensus & Continuous Auditing Engine
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Three independent AI auditing agents evaluate the unified evidence corpus without prior knowledge of each other’s findings. Red-team exploit verification and cryptographic evidence hashing isolate disputes for human CPA assurance.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <button
              id="btn-run-tri-eval"
              onClick={handleRunEvaluation}
              disabled={isEvaluating}
              className="px-4 py-2.5 rounded-lg text-sm font-semibold bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white shadow-lg transition-all flex items-center gap-2 disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${isEvaluating ? 'animate-spin' : ''}`} />
              {isEvaluating ? 'Executing Blind Audits...' : 'Run Tri-Auditor Evaluation'}
            </button>

            <button
              id="btn-run-deploy-gate"
              onClick={handleRunDeploymentGate}
              disabled={isRunningDeploymentGate}
              className="px-4 py-2.5 rounded-lg text-sm font-semibold bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 shadow-lg transition-all flex items-center gap-2 disabled:opacity-50"
            >
              <Zap className="w-4 h-4 text-amber-400" />
              {isRunningDeploymentGate ? 'Probing Live Service...' : 'Live Deployment Gate'}
            </button>
          </div>
        </div>

        {evaluationStats && (
          <div className="mt-4 p-3 bg-indigo-950/60 border border-indigo-800/80 rounded-lg text-xs text-indigo-200 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400 flex-shrink-0" />
            <span>{evaluationStats}</span>
          </div>
        )}

        {/* Triad Agent Role Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6 pt-6 border-t border-slate-800/80">
          {/* Agent A */}
          <div className="bg-slate-950/70 border border-emerald-900/40 rounded-lg p-4 relative">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-950/80 px-2 py-0.5 rounded border border-emerald-800">
                AUDITOR A
              </span>
              <span className="text-[11px] text-slate-400">AICPA Standards</span>
            </div>
            <h3 className="text-sm font-bold text-slate-100 mt-2 flex items-center gap-1.5">
              ChatGPT (Control Auditor)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Evaluates controls line-by-line against AICPA SOC 2 Trust Services Criteria, policy documents, and governance sign-offs.
            </p>
            <div className="mt-3 flex items-center gap-2 text-[11px] text-emerald-400/90 font-mono">
              <span>● Status: PASS (6) | PARTIAL (2)</span>
            </div>
          </div>

          {/* Agent B */}
          <div className="bg-slate-950/70 border border-rose-900/40 rounded-lg p-4 relative">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-rose-400 bg-rose-950/80 px-2 py-0.5 rounded border border-rose-800">
                AUDITOR B
              </span>
              <span className="text-[11px] text-slate-400">Zero-Trust Red Team</span>
            </div>
            <h3 className="text-sm font-bold text-slate-100 mt-2 flex items-center gap-1.5">
              Claude (Adversarial Auditor)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Actively attempts to disprove PASS claims. Seeks bypasses, unauthenticated API mutations, hardcoded fallbacks, and in-memory traps.
            </p>
            <div className="mt-3 flex items-center gap-2 text-[11px] text-rose-400/90 font-mono">
              <span>● Disprovals: 1 FAIL | 3 PARTIAL</span>
            </div>
          </div>

          {/* Agent C */}
          <div className="bg-slate-950/70 border border-cyan-900/40 rounded-lg p-4 relative">
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800">
                AUDITOR C
              </span>
              <span className="text-[11px] text-slate-400">AST Code & Infra</span>
            </div>
            <h3 className="text-sm font-bold text-slate-100 mt-2 flex items-center gap-1.5">
              Gemini (Technical Auditor)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Inspects source code AST, Dockerfile, Railway config, GitHub Actions workflows, crypto keys, endpoint middlewares, and error handlers.
            </p>
            <div className="mt-3 flex items-center gap-2 text-[11px] text-cyan-400/90 font-mono">
              <span>● Status: PASS (5) | PARTIAL (3)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <button
            id="tab-tri-matrix"
            onClick={() => setActiveTab('matrix')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'matrix'
                ? 'bg-indigo-600 text-white shadow-md'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Consensus Matrix ({consensusData.length})
          </button>

          <button
            id="tab-tri-disagreements"
            onClick={() => setActiveTab('disagreements')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'disagreements'
                ? 'bg-amber-600 text-white shadow-md'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <AlertTriangle className="w-3.5 h-3.5 text-amber-300" />
            Disagreement Queue ({disagreementQueue.length})
          </button>

          <button
            id="tab-tri-evidence"
            onClick={() => setActiveTab('evidence_lineage')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'evidence_lineage'
                ? 'bg-cyan-600 text-white shadow-md'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <Key className="w-3.5 h-3.5" />
            Cryptographic Evidence Lineage ({evidenceLineage.length})
          </button>

          <button
            id="tab-tri-continuous"
            onClick={() => setActiveTab('continuous')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'continuous'
                ? 'bg-emerald-600 text-white shadow-md'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <Activity className="w-3.5 h-3.5 text-emerald-300" />
            Continuous Monitoring ({continuousChecks.length})
          </button>

          <button
            id="tab-tri-deploy-gate"
            onClick={() => setActiveTab('deployment_gate')}
            className={`px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2 ${
              activeTab === 'deployment_gate'
                ? 'bg-purple-600 text-white shadow-md'
                : 'bg-slate-900 text-slate-400 hover:text-white border border-slate-800'
            }`}
          >
            <Zap className="w-3.5 h-3.5 text-purple-300" />
            Live Deployment Gate ({deploymentSteps.length})
          </button>
        </div>

        {activeTab === 'matrix' && (
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Search controls..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 w-44 sm:w-56"
              />
            </div>
            <select
              value={filterCategory}
              onChange={(e) => setFilterCategory(e.target.value)}
              className="px-2.5 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Categories</option>
              <option value="Security">Security</option>
              <option value="Confidentiality">Confidentiality</option>
              <option value="Change Management">Change Management</option>
              <option value="Availability">Availability</option>
            </select>
          </div>
        )}
      </div>

      {/* TAB 1: CONSENSUS MATRIX */}
      {activeTab === 'matrix' && (
        <div className="space-y-4">
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-950/80 border-b border-slate-800 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                    <th className="py-3.5 px-4 font-semibold">Control ID & Requirement</th>
                    <th className="py-3.5 px-4 font-semibold text-center">ChatGPT (Auditor A)</th>
                    <th className="py-3.5 px-4 font-semibold text-center">Claude (Auditor B)</th>
                    <th className="py-3.5 px-4 font-semibold text-center">Gemini (Auditor C)</th>
                    <th className="py-3.5 px-4 font-semibold text-center">Consensus Verdict</th>
                    <th className="py-3.5 px-4 font-semibold">Assurance State</th>
                    <th className="py-3.5 px-4 font-semibold text-right">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-xs">
                  {filteredControls.map((ctrl) => (
                    <tr 
                      key={ctrl.controlId} 
                      className={`hover:bg-slate-800/40 transition-colors ${
                        ctrl.consensusStatus === 'DISPUTED' ? 'bg-amber-950/10' : ''
                      }`}
                    >
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-bold text-indigo-400 bg-indigo-950/80 px-2 py-0.5 rounded border border-indigo-800 text-xs">
                            {ctrl.controlCode}
                          </span>
                          <div>
                            <div className="font-bold text-slate-200">{ctrl.name}</div>
                            <div className="text-[11px] text-slate-400">{ctrl.category}</div>
                          </div>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 text-center">
                        {getVerdictBadge(ctrl.chatgptVerdict)}
                      </td>

                      <td className="py-3.5 px-4 text-center">
                        {getVerdictBadge(ctrl.claudeVerdict)}
                      </td>

                      <td className="py-3.5 px-4 text-center">
                        {getVerdictBadge(ctrl.geminiVerdict)}
                      </td>

                      <td className="py-3.5 px-4 text-center">
                        {getConsensusBadge(ctrl.consensusStatus)}
                      </td>

                      <td className="py-3.5 px-4">
                        {getAssuranceBadge(ctrl.finalAssuranceStatus)}
                      </td>

                      <td className="py-3.5 px-4 text-right">
                        <button
                          onClick={() => setSelectedControl(ctrl)}
                          className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white rounded text-xs font-medium border border-slate-700 transition-colors inline-flex items-center gap-1"
                        >
                          Inspect Findings
                          <ChevronRight className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: DISAGREEMENT QUEUE & RED-TEAM ADVERSARIAL INSPECTOR */}
      {activeTab === 'disagreements' && (
        <div className="space-y-6">
          <div className="p-4 bg-amber-950/40 border border-amber-800/60 rounded-xl text-xs text-amber-200 flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-sm text-amber-100">
                Disagreement Queue (Multi-Agent Contention Resolution)
              </div>
              <p className="mt-1 text-amber-200/90 leading-relaxed">
                When independent AI auditors reach split determinations (e.g., ChatGPT awards PASS based on policy structure, while Claude or Gemini disproves the control via red-team attack or missing middleware), the system classifies the control as <span className="font-mono font-bold text-amber-300">DISPUTED</span>. A qualified human CPA auditor must review the adversarial trace and submit an official adjudication.
              </p>
            </div>
          </div>

          <div className="space-y-4">
            {disagreementQueue.map((ctrl) => (
              <div 
                key={ctrl.controlId}
                className="bg-slate-900/90 border border-amber-900/50 rounded-xl p-5 shadow-xl space-y-4"
              >
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
                  <div className="flex items-center gap-3">
                    <span className="font-mono font-bold text-amber-400 bg-amber-950/80 px-2.5 py-1 rounded border border-amber-800 text-sm">
                      {ctrl.controlCode}
                    </span>
                    <div>
                      <h3 className="text-base font-bold text-slate-100">{ctrl.name}</h3>
                      <p className="text-xs text-slate-400">{ctrl.category} Criteria</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {getConsensusBadge(ctrl.consensusStatus)}
                    {ctrl.humanAdjudication ? (
                      <span className="px-2.5 py-1 rounded text-xs font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                        CPA Adjudicated: {ctrl.humanAdjudication.decision}
                      </span>
                    ) : (
                      <button
                        onClick={() => setAdjudicatingControlId(ctrl.controlId)}
                        className="px-3 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded text-xs font-bold transition-all shadow flex items-center gap-1.5"
                      >
                        <CheckSquare className="w-3.5 h-3.5" />
                        Human CPA Adjudicate
                      </button>
                    )}
                  </div>
                </div>

                {/* Side-by-Side Tri-Auditor Arguments */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                  {ctrl.findings.map((fnd) => (
                    <div 
                      key={fnd.id}
                      className={`p-3.5 rounded-lg border text-xs space-y-2 ${
                        fnd.agentId === 'chatgpt_control'
                          ? 'bg-slate-950/70 border-emerald-900/40'
                          : fnd.agentId === 'claude_adversarial'
                          ? 'bg-slate-950/70 border-rose-900/40'
                          : 'bg-slate-950/70 border-cyan-900/40'
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-slate-200">{fnd.agentName}</span>
                        {getVerdictBadge(fnd.result)}
                      </div>
                      <p className="text-slate-300 leading-relaxed">{fnd.reason}</p>
                      <div className="text-[11px] text-slate-400 font-mono pt-1 border-t border-slate-800">
                        <span className="text-slate-500">Evidence:</span> {fnd.evidenceExamined}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Red Team Exploit Traces */}
                {ctrl.redTeamExploitTraces.length > 0 && (
                  <div className="bg-rose-950/30 border border-rose-900/60 rounded-lg p-3 text-xs space-y-1.5">
                    <div className="font-bold text-rose-300 flex items-center gap-1.5">
                      <Flame className="w-4 h-4 text-rose-400" />
                      Adversarial Red-Team Attack Trace
                    </div>
                    <ul className="list-disc list-inside text-rose-200/90 space-y-1 font-mono text-[11px]">
                      {ctrl.redTeamExploitTraces.map((trace, i) => (
                        <li key={i}>{trace}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Adjudication Drawer / Modal */}
                {adjudicatingControlId === ctrl.controlId && (
                  <div className="bg-slate-950 border border-indigo-700/80 rounded-xl p-5 space-y-4 animate-in fade-in">
                    <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                      <div className="font-bold text-slate-100 flex items-center gap-2">
                        <CheckSquare className="w-4 h-4 text-indigo-400" />
                        Human Auditor Formal Adjudication & Attestation
                      </div>
                      <button
                        onClick={() => setAdjudicatingControlId(null)}
                        className="text-slate-400 hover:text-slate-200 text-xs"
                      >
                        Cancel
                      </button>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1">
                          Auditor Name & Certification
                        </label>
                        <input
                          type="text"
                          value={reviewerName}
                          onChange={(e) => setReviewerName(e.target.value)}
                          className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                        />
                      </div>

                      <div>
                        <label className="block text-xs font-semibold text-slate-300 mb-1">
                          Auditor Email
                        </label>
                        <input
                          type="email"
                          value={reviewerEmail}
                          onChange={(e) => setReviewerEmail(e.target.value)}
                          className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-indigo-500"
                        />
                      </div>
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        CPA Adjudication Determination
                      </label>
                      <div className="flex flex-wrap gap-3">
                        <label className="flex items-center gap-2 text-xs text-emerald-300 bg-emerald-950/40 px-3 py-2 rounded-lg border border-emerald-800/60 cursor-pointer">
                          <input
                            type="radio"
                            name="decision"
                            value="ACCEPT_PASS"
                            checked={adjudicationDecision === 'ACCEPT_PASS'}
                            onChange={() => setAdjudicationDecision('ACCEPT_PASS')}
                          />
                          Accept PASS (Compensating Controls Satisfied)
                        </label>

                        <label className="flex items-center gap-2 text-xs text-rose-300 bg-rose-950/40 px-3 py-2 rounded-lg border border-rose-800/60 cursor-pointer">
                          <input
                            type="radio"
                            name="decision"
                            value="UPHOLD_FAIL"
                            checked={adjudicationDecision === 'UPHOLD_FAIL'}
                            onChange={() => setAdjudicationDecision('UPHOLD_FAIL')}
                          />
                          Uphold FAIL (Defect Must Be Remediated)
                        </label>

                        <label className="flex items-center gap-2 text-xs text-amber-300 bg-amber-950/40 px-3 py-2 rounded-lg border border-amber-800/60 cursor-pointer">
                          <input
                            type="radio"
                            name="decision"
                            value="REQUIRE_REMEDIATION"
                            checked={adjudicationDecision === 'REQUIRE_REMEDIATION'}
                            onChange={() => setAdjudicationDecision('REQUIRE_REMEDIATION')}
                          />
                          Require Remediation & Re-test
                        </label>
                      </div>
                    </div>

                    <div>
                      <label className="block text-xs font-semibold text-slate-300 mb-1">
                        Auditor Working Paper Rationale & Digital Sign-off
                      </label>
                      <textarea
                        rows={3}
                        value={adjudicationNotes}
                        onChange={(e) => setAdjudicationNotes(e.target.value)}
                        className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-xs text-slate-100 focus:outline-none focus:border-indigo-500 font-mono"
                      />
                    </div>

                    <div className="flex items-center justify-end gap-3 pt-2">
                      <button
                        onClick={() => handleAdjudicateSubmit(ctrl.controlId)}
                        className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-cyan-600 hover:from-emerald-500 hover:to-cyan-500 text-white rounded-lg text-xs font-bold transition-all shadow flex items-center gap-1.5"
                      >
                        <Check className="w-4 h-4" />
                        Sign & Record Digital Attestation
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 3: CRYPTOGRAPHIC EVIDENCE LINEAGE */}
      {activeTab === 'evidence_lineage' && (
        <div className="space-y-4">
          <div className="p-4 bg-cyan-950/30 border border-cyan-800/60 rounded-xl text-xs text-cyan-200 flex items-start gap-3">
            <Key className="w-5 h-5 text-cyan-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-sm text-cyan-100">
                Cryptographic Evidence Lineage Vault (SHA-256 Provenance)
              </div>
              <p className="mt-1 text-cyan-200/90 leading-relaxed">
                Every piece of compliance evidence collected from AWS STS, GitHub Actions, Winston logging, and WebCrypto engines is assigned a globally unique Evidence ID and sealed with an immutable SHA-256 cryptographic digest.
              </p>
            </div>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-slate-950/80 border-b border-slate-800 text-[11px] font-mono uppercase tracking-wider text-slate-400">
                    <th className="py-3.5 px-4 font-semibold">Evidence ID & Control</th>
                    <th className="py-3.5 px-4 font-semibold">Source & Collection Method</th>
                    <th className="py-3.5 px-4 font-semibold">Collector Agent</th>
                    <th className="py-3.5 px-4 font-semibold">SHA-256 Digest</th>
                    <th className="py-3.5 px-4 font-semibold text-center">Result</th>
                    <th className="py-3.5 px-4 font-semibold text-right">Timestamp</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-xs font-mono">
                  {evidenceLineage.map((evd) => (
                    <tr key={evd.evidenceId} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3.5 px-4 font-sans">
                        <div className="font-mono font-bold text-cyan-400">{evd.evidenceId}</div>
                        <div className="text-[11px] text-slate-400">{evd.controlId}</div>
                      </td>

                      <td className="py-3.5 px-4 font-sans">
                        <div className="font-semibold text-slate-200">{evd.source}</div>
                        <div className="text-[11px] text-slate-400">{evd.collectionMethod}</div>
                      </td>

                      <td className="py-3.5 px-4 font-sans text-slate-300">
                        {evd.agent}
                      </td>

                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-1.5">
                          <span className="text-[11px] text-slate-300 bg-slate-950 px-2 py-1 rounded border border-slate-800 truncate max-w-[180px]">
                            {evd.sha256Hash}
                          </span>
                          <button
                            onClick={() => handleCopy(evd.sha256Hash)}
                            className="p-1 text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800 transition-colors"
                            title="Copy SHA-256 Hash"
                          >
                            {copiedHash === evd.sha256Hash ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </td>

                      <td className="py-3.5 px-4 text-center font-sans">
                        {getVerdictBadge(evd.testResult)}
                      </td>

                      <td className="py-3.5 px-4 text-right text-[11px] text-slate-400">
                        {new Date(evd.timestamp).toLocaleString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: CONTINUOUS MONITORING ENGINE */}
      {activeTab === 'continuous' && (
        <div className="space-y-6">
          <div className="p-4 bg-emerald-950/30 border border-emerald-800/60 rounded-xl text-xs text-emerald-200 flex items-start gap-3">
            <Activity className="w-5 h-5 text-emerald-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-sm text-emerald-100">
                Continuous Auditing & Autonomous Control Daemon
              </div>
              <p className="mt-1 text-emerald-200/90 leading-relaxed">
                Rather than treating SOC 2 as a static snapshot, the background engine executes automated re-tests across RBAC, encryption keys, secrets, audit log hash chains, security headers, and evidence freshness.
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {continuousChecks.map((chk) => (
              <div
                key={chk.id}
                className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-lg space-y-3"
              >
                <div className="flex items-center justify-between">
                  <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                    {chk.category}
                  </span>
                  <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-bold ${
                    chk.status === 'HEALTHY' 
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800' 
                      : 'bg-amber-950 text-amber-300 border border-amber-800'
                  }`}>
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />
                    {chk.status}
                  </span>
                </div>

                <div>
                  <h4 className="text-sm font-bold text-slate-100">{chk.name}</h4>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">{chk.lastResult}</p>
                </div>

                <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-[11px] text-slate-500 font-mono">
                  <span>Re-test: Every {chk.intervalSeconds}s</span>
                  <span className="text-emerald-400 font-bold">{chk.consecutiveSuccesses} Passing Cycles</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 5: LIVE DEPLOYMENT VERIFICATION GATE */}
      {activeTab === 'deployment_gate' && (
        <div className="space-y-6">
          <div className="p-4 bg-purple-950/30 border border-purple-800/60 rounded-xl text-xs text-purple-200 flex items-start gap-3">
            <Zap className="w-5 h-5 text-purple-400 flex-shrink-0 mt-0.5" />
            <div>
              <div className="font-bold text-sm text-purple-100">
                End-to-End Production Deployment Readiness Gate
              </div>
              <p className="mt-1 text-purple-200/90 leading-relaxed">
                Progression Pipeline: <span className="font-mono text-purple-300 font-bold">Source → Build → Deploy → Live Endpoint → Security Tests → Evidence Collection → Tri-Agent Blind Review → Human Assurance Queue</span>.
              </p>
            </div>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div>
                <h3 className="text-base font-bold text-slate-100">Pipeline Gate Execution Status</h3>
                <p className="text-xs text-slate-400">Live probing against Cloud Run container host at port 3000</p>
              </div>
              <button
                onClick={handleRunDeploymentGate}
                disabled={isRunningDeploymentGate}
                className="px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white rounded-lg text-xs font-bold transition-all shadow flex items-center gap-2 disabled:opacity-50"
              >
                <Play className="w-3.5 h-3.5" />
                {isRunningDeploymentGate ? 'Executing Gate Checks...' : 'Run Pipeline Gate Probing'}
              </button>
            </div>

            <div className="space-y-3">
              {deploymentSteps.map((step, idx) => (
                <div
                  key={step.id}
                  className={`p-4 rounded-xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 transition-all ${
                    step.status === 'success'
                      ? 'bg-slate-950/60 border-emerald-900/50'
                      : step.status === 'warning'
                      ? 'bg-slate-950/60 border-amber-900/50'
                      : step.status === 'running'
                      ? 'bg-slate-950/60 border-indigo-500/80 animate-pulse'
                      : 'bg-slate-950/40 border-slate-800'
                  }`}
                >
                  <div className="flex items-center gap-3.5">
                    <div className={`p-2 rounded-lg font-mono font-bold text-xs ${
                      step.status === 'success'
                        ? 'bg-emerald-950 text-emerald-400 border border-emerald-800'
                        : step.status === 'warning'
                        ? 'bg-amber-950 text-amber-400 border border-amber-800'
                        : step.status === 'running'
                        ? 'bg-indigo-950 text-indigo-400 border border-indigo-800'
                        : 'bg-slate-900 text-slate-500 border border-slate-800'
                    }`}>
                      {idx + 1}
                    </div>
                    <div>
                      <div className="text-sm font-bold text-slate-200">{step.name}</div>
                      <p className="text-xs text-slate-400 mt-0.5">{step.details}</p>
                    </div>
                  </div>

                  <div className="flex items-center gap-3">
                    {step.latencyMs ? (
                      <span className="text-[11px] font-mono text-slate-400">
                        {step.latencyMs}ms
                      </span>
                    ) : null}

                    {step.status === 'success' && (
                      <span className="px-2.5 py-1 rounded text-xs font-bold bg-emerald-950 text-emerald-300 border border-emerald-800 flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        PASSED
                      </span>
                    )}

                    {step.status === 'warning' && (
                      <span className="px-2.5 py-1 rounded text-xs font-bold bg-amber-950 text-amber-300 border border-amber-800 flex items-center gap-1">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        FLAGGED FOR CPA
                      </span>
                    )}

                    {step.status === 'running' && (
                      <span className="px-2.5 py-1 rounded text-xs font-bold bg-indigo-950 text-indigo-300 border border-indigo-800 flex items-center gap-1">
                        <RefreshCw className="w-3.5 h-3.5 text-indigo-400 animate-spin" />
                        PROBING...
                      </span>
                    )}

                    {step.status === 'pending' && (
                      <span className="px-2.5 py-1 rounded text-xs font-bold bg-slate-800 text-slate-400 border border-slate-700">
                        GATE PENDING
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Control Details Modal */}
      {selectedControl && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full max-h-[85vh] overflow-y-auto p-6 shadow-2xl space-y-5 animate-in fade-in">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-3">
                <span className="font-mono font-bold text-indigo-400 bg-indigo-950/80 px-2.5 py-1 rounded border border-indigo-800 text-sm">
                  {selectedControl.controlCode}
                </span>
                <div>
                  <h3 className="text-lg font-bold text-white">{selectedControl.name}</h3>
                  <p className="text-xs text-slate-400">{selectedControl.category} Criteria</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedControl(null)}
                className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-slate-800"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                <span className="text-slate-400 block mb-1">ChatGPT Verdict:</span>
                {getVerdictBadge(selectedControl.chatgptVerdict)}
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                <span className="text-slate-400 block mb-1">Claude Verdict:</span>
                {getVerdictBadge(selectedControl.claudeVerdict)}
              </div>
              <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs">
                <span className="text-slate-400 block mb-1">Gemini Verdict:</span>
                {getVerdictBadge(selectedControl.geminiVerdict)}
              </div>
            </div>

            {/* Findings */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                Independent Auditor Findings
              </h4>
              {selectedControl.findings.map((fnd) => (
                <div key={fnd.id} className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-slate-200">{fnd.agentName} ({fnd.agentRole})</span>
                    {getVerdictBadge(fnd.result)}
                  </div>
                  <p className="text-slate-300 leading-relaxed">{fnd.reason}</p>
                  <div className="p-2.5 bg-slate-900 rounded border border-slate-800/80 text-[11px] font-mono text-cyan-300">
                    <span className="text-slate-400">Remediation:</span> {fnd.remediation}
                  </div>
                </div>
              ))}
            </div>

            {selectedControl.redTeamExploitTraces.length > 0 && (
              <div className="p-4 bg-rose-950/30 border border-rose-900/60 rounded-xl text-xs space-y-2">
                <div className="font-bold text-rose-300 flex items-center gap-1.5">
                  <Flame className="w-4 h-4 text-rose-400" />
                  Red-Team Exploit Traces
                </div>
                <ul className="list-disc list-inside text-rose-200/90 space-y-1 font-mono text-[11px]">
                  {selectedControl.redTeamExploitTraces.map((trace, i) => (
                    <li key={i}>{trace}</li>
                  ))}
                </ul>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedControl(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-bold transition-colors"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
