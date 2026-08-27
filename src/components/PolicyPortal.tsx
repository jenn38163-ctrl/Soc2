import React, { useState, useEffect } from 'react';
import { 
  FileText, 
  Shield, 
  CheckCircle2, 
  Clock, 
  Award, 
  PenTool, 
  Check, 
  Copy, 
  Calendar, 
  UserCheck, 
  GitPullRequest, 
  GitBranch, 
  GitCommit, 
  Terminal, 
  ExternalLink, 
  MessageSquare, 
  AlertTriangle, 
  Users, 
  RefreshCw, 
  Sparkles, 
  BookOpen, 
  Send, 
  CheckCircle, 
  XCircle, 
  Plus, 
  Search,
  Lock,
  ArrowRight
} from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';
import { INITIAL_POLICIES, policyStore } from '../lib/policyDocuments';
import { multiTenantStore } from '../lib/multiTenantStore';
import { PolicyDocument, Employee, StaffPolicySignature, AutomatedPR, MicroLessonLog } from '../types/soc2';

interface PolicyPortalProps {
  onPolicySigned: () => void;
}

export const PolicyPortal: React.FC<PolicyPortalProps> = ({ onPolicySigned }) => {
  const currentTenant = multiTenantStore.getCurrentTenant();
  const [activeTab, setActiveTab] = useState<'policies' | 'roster' | 'gitops' | 'training'>('policies');
  
  const [policies, setPolicies] = useState<PolicyDocument[]>(policyStore.getPolicies());
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyDocument>(policies[0]);
  const [showSignModal, setShowSignModal] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Sign Form State
  const [signerName, setSignerName] = useState('Jennifer Gremic');
  const [signerEmail, setSignerEmail] = useState(currentTenant.contactEmail || 'jenngremicinc@gmail.com');
  const [signerRole, setSignerRole] = useState('Lead Security Officer');
  const [isSigning, setIsSigning] = useState(false);

  // Staff Roster & Signatures State
  const [employees, setEmployees] = useState<Employee[]>(multiTenantStore.getEmployees(currentTenant.id));
  const [staffSignatures, setStaffSignatures] = useState<StaffPolicySignature[]>(multiTenantStore.getStaffSignatures(currentTenant.id));
  const [selectedEmployeeEmail, setSelectedEmployeeEmail] = useState(currentTenant.contactEmail || 'jenngremicinc@gmail.com');

  // GitOps State
  const [automatedPRs, setAutomatedPRs] = useState<AutomatedPR[]>(multiTenantStore.getAutomatedPRs(currentTenant.id));
  const [targetRepo, setTargetRepo] = useState('compliance-control-center-api');
  const [policyTypeToDeploy, setPolicyTypeToDeploy] = useState('INFORMATION_SECURITY');
  const [isDeployingPR, setIsDeployingPR] = useState(false);
  const [generatedMarkdown, setGeneratedMarkdown] = useState('');

  // Micro-Lessons State
  const [microLessons, setMicroLessons] = useState<MicroLessonLog[]>(multiTenantStore.getMicroLessons(currentTenant.id));
  const [selectedTriggerRule, setSelectedTriggerRule] = useState<'OPEN_SSH_PORT' | 'BRANCH_PROTECTION_DROPPED' | 'SECRET_COMMITTED'>('OPEN_SSH_PORT');
  const [trainingTargetEmail, setTrainingTargetEmail] = useState(currentTenant.contactEmail || 'jenngremicinc@gmail.com');
  const [isTriggeringLesson, setIsTriggeringLesson] = useState(false);
  const [activeQuizId, setActiveQuizId] = useState<string | null>(null);
  const [selectedQuizOption, setSelectedQuizOption] = useState<number | null>(null);
  const [quizResult, setQuizResult] = useState<{ isCorrect: boolean; explanation: string } | null>(null);

  // Sync with store updates
  useEffect(() => {
    const unsub = multiTenantStore.subscribe(() => {
      setEmployees(multiTenantStore.getEmployees(currentTenant.id));
      setStaffSignatures(multiTenantStore.getStaffSignatures(currentTenant.id));
      setAutomatedPRs(multiTenantStore.getAutomatedPRs(currentTenant.id));
      setMicroLessons(multiTenantStore.getMicroLessons(currentTenant.id));
    });
    return unsub;
  }, [currentTenant.id]);

  const handleSign = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSigning(true);

    // Sign in core policy store
    await policyStore.signPolicy(selectedPolicy.id, signerName, signerEmail, signerRole);
    // Also record in multiTenant staff sign-off registry with IP & certificate
    await multiTenantStore.signPolicyAsEmployee(
      currentTenant.id,
      selectedPolicy.id,
      signerEmail,
      '192.168.1.100',
      navigator.userAgent || 'Mozilla/5.0 Compliance Agent Browser'
    );

    const updatedPolicies = policyStore.getPolicies();
    setPolicies(updatedPolicies);
    setSelectedPolicy(updatedPolicies.find((p) => p.id === selectedPolicy.id) || updatedPolicies[0]);
    setStaffSignatures(multiTenantStore.getStaffSignatures(currentTenant.id));

    setIsSigning(false);
    setShowSignModal(false);
    onPolicySigned();
  };

  const handleDeployGitOpsPR = async () => {
    setIsDeployingPR(true);
    const markdown = `# ${policyTypeToDeploy.replace(/_/g, ' ')} POLICY (SOC 2 COMPLIANCE)
**Tenant:** ${currentTenant.name}
**Version:** 2026.1
**Generated At:** ${new Date().toISOString()}

## 1. Objective & Scope
This policy establishes mandatory operational baseline controls to ensure compliance with AICPA Trust Services Criteria.

## 2. Mandatory Controls
- All team members must authenticate via Hardware/TOTP Multi-Factor Authentication (CC6.1).
- Direct git push to default branches is strictly forbidden. 1+ approving peer review required (CC8.1).
- All customer data at rest must be encrypted via AES-256 (CC6.7).
`;
    setGeneratedMarkdown(markdown);

    const pr = await multiTenantStore.deployAutomatedPolicyPR(
      currentTenant.id,
      targetRepo,
      policyTypeToDeploy,
      markdown
    );
    setAutomatedPRs(multiTenantStore.getAutomatedPRs(currentTenant.id));
    setIsDeployingPR(false);
  };

  const handleMergePR = async (prId: string) => {
    await multiTenantStore.mergeAutomatedPR(currentTenant.id, prId);
    setAutomatedPRs(multiTenantStore.getAutomatedPRs(currentTenant.id));
  };

  const handleTriggerMicroLesson = async () => {
    setIsTriggeringLesson(true);
    const lesson = await multiTenantStore.triggerMicroLesson(
      currentTenant.id,
      selectedTriggerRule,
      trainingTargetEmail
    );
    setMicroLessons(multiTenantStore.getMicroLessons(currentTenant.id));
    setActiveQuizId(lesson.id);
    setSelectedQuizOption(null);
    setQuizResult(null);
    setIsTriggeringLesson(false);
  };

  const handleSubmitQuiz = async (lessonId: string) => {
    if (selectedQuizOption === null) return;
    const result = await multiTenantStore.completeMicroLesson(currentTenant.id, lessonId, selectedQuizOption);
    setQuizResult(result);
    setMicroLessons(multiTenantStore.getMicroLessons(currentTenant.id));
  };

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Compute overall staff completion rate
  const activeStaff = employees.filter((e) => e.status === 'ACTIVE');
  const totalPossibleSigns = activeStaff.length * policies.length;
  const actualSigns = staffSignatures.length;
  const overallComplianceRate = totalPossibleSigns > 0 ? Math.min(100, Math.round((actualSigns / totalPossibleSigns) * 100)) : 100;

  return (
    <div className="space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl">
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-2.5 bg-amber-500/10 border border-amber-500/30 text-amber-400 rounded-xl">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-base font-bold text-white">SOC 2 Policy Governance & Active Training Portal</h2>
                <span className="text-[10px] font-mono bg-indigo-950 text-indigo-300 px-2 py-0.5 rounded border border-indigo-800">
                  CC1.2 / CC5.2 / CC8.1
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Versioned policy documents, staff acceptance ledger, GitOps Policy-as-Code automation, and event-driven micro-training
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <div className="px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs flex items-center gap-2">
              <span className="text-slate-400">Staff Acceptance:</span>
              <span className="font-bold text-amber-400">{overallComplianceRate}% Complete</span>
            </div>
            <span className="text-xs bg-emerald-950/80 border border-emerald-800/60 text-emerald-400 font-semibold px-3 py-1.5 rounded-lg flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>All 4 Baseline Policies Published</span>
            </span>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 mt-6 pt-4 border-t border-slate-800/80 overflow-x-auto pb-1">
          <button
            onClick={() => setActiveTab('policies')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
              activeTab === 'policies'
                ? 'bg-amber-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <BookOpen className="w-4 h-4" />
            <span>Policy Vault & Signature</span>
          </button>

          <button
            onClick={() => setActiveTab('roster')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
              activeTab === 'roster'
                ? 'bg-amber-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <Users className="w-4 h-4" />
            <span>Staff Acceptance Matrix</span>
            <span className="text-[10px] px-1.5 py-0.2 bg-slate-950/60 rounded font-mono">
              {staffSignatures.length} signed
            </span>
          </button>

          <button
            onClick={() => setActiveTab('gitops')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
              activeTab === 'gitops'
                ? 'bg-amber-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <GitPullRequest className="w-4 h-4" />
            <span>GitOps Policy PRs</span>
            <span className="text-[10px] px-1.5 py-0.2 bg-slate-950/60 rounded font-mono">
              {automatedPRs.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('training')}
            className={`px-3.5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition-all shrink-0 ${
              activeTab === 'training'
                ? 'bg-amber-600 text-white shadow-md'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}
          >
            <MessageSquare className="w-4 h-4" />
            <span>Slack Micro-Training</span>
            <span className="text-[10px] px-1.5 py-0.2 bg-slate-950/60 rounded font-mono">
              {microLessons.length}
            </span>
          </button>
        </div>
      </div>

      {/* TAB 1: POLICIES & DIGITAL SIGN-OFF VAULT */}
      {activeTab === 'policies' && (
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Left: Policy Selector (4 cols) */}
          <div className="lg:col-span-4 space-y-3">
            {policies.map((p) => {
              const isSelected = selectedPolicy.id === p.id;
              const completion = multiTenantStore.getPolicyCompletion(currentTenant.id, p.id);

              return (
                <div
                  key={p.id}
                  onClick={() => setSelectedPolicy(p)}
                  className={`p-4 rounded-xl border cursor-pointer transition-all ${
                    isSelected
                      ? 'bg-amber-950/40 border-amber-500 ring-1 ring-amber-500 shadow-lg'
                      : 'bg-slate-900/90 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-xs text-white">{p.title}</span>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-amber-300">
                      v{p.version}
                    </span>
                  </div>

                  <div className="flex items-center gap-1.5 mb-2 flex-wrap">
                    {p.tscCriteria.map((c) => (
                      <span key={c} className="text-[10px] bg-indigo-950/80 text-indigo-300 px-1.5 py-0.5 rounded border border-indigo-900/60 font-mono">
                        {c}
                      </span>
                    ))}
                  </div>

                  <p className="text-[11px] text-slate-400 line-clamp-2">{p.summary}</p>

                  <div className="mt-3 pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[10px] text-slate-400">
                    <div className="flex items-center gap-1">
                      <UserCheck className="w-3 h-3 text-emerald-400" />
                      <span>{completion.signedStaffCount}/{completion.totalActiveStaff} Staff Signed</span>
                    </div>
                    <div className="flex items-center gap-1">
                      <Calendar className="w-3 h-3 text-slate-500" />
                      <span>{p.reviewFrequency}</span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Right: Policy Document Content & Sign-off (8 cols) */}
          <div className="lg:col-span-8 bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-slate-800 gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">{selectedPolicy.title}</h3>
                  <span className="text-xs font-mono text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800">
                    v{selectedPolicy.version}
                  </span>
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Owner: {selectedPolicy.owner} • Next Review: {new Date(selectedPolicy.nextReviewDate).toLocaleDateString()}
                </p>
              </div>

              <button
                onClick={() => setShowSignModal(true)}
                className="flex items-center gap-1.5 px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white font-bold text-xs rounded-lg shadow-sm transition-colors shrink-0"
              >
                <PenTool className="w-3.5 h-3.5" />
                <span>Digital Policy Sign-off</span>
              </button>
            </div>

            {/* Policy Text Rendered */}
            <div className="p-5 bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-200 leading-relaxed max-h-96 overflow-y-auto font-sans whitespace-pre-wrap">
              {selectedPolicy.content}
            </div>

            {/* Digital Signatures Ledger */}
            <div className="pt-2">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                  <Award className="w-4 h-4 text-emerald-400" />
                  <span>Cryptographic Digital Signatures & Acknowledgements (CC1.2)</span>
                </h4>
                <span className="text-[11px] font-mono text-slate-400">
                  {selectedPolicy.signatures.length} verified signatures
                </span>
              </div>

              <div className="divide-y divide-slate-800/80 bg-slate-950 rounded-xl border border-slate-800 overflow-hidden text-xs">
                {selectedPolicy.signatures.length === 0 ? (
                  <div className="p-4 text-center text-slate-500">No active signatures recorded yet.</div>
                ) : (
                  selectedPolicy.signatures.map((sig) => (
                    <div key={sig.id} className="p-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-white">{sig.signerName}</span>
                          <span className="text-slate-400 font-mono">({sig.signerEmail})</span>
                          <span className="text-[10px] bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded">
                            {sig.signerRole}
                          </span>
                        </div>
                        <div className="text-[10px] text-slate-500 mt-0.5 flex items-center gap-2">
                          <span>Signed at: {new Date(sig.signedAt).toLocaleString()}</span>
                          <span>•</span>
                          <span>Version: v{sig.versionSigned}</span>
                          <span>•</span>
                          <span className="font-mono text-slate-400">IP: 192.168.1.100</span>
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => copyHash(sig.certificateHash)}
                          className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2 py-1 rounded flex items-center gap-1 hover:bg-cyan-900/60 transition-colors"
                        >
                          <Copy className="w-3 h-3" />
                          <span>{copiedHash === sig.certificateHash ? 'Copied' : sig.certificateHash.slice(0, 12) + '...'}</span>
                        </button>
                        <span className="text-[10px] bg-emerald-950 text-emerald-400 px-2 py-0.5 rounded font-bold border border-emerald-800 flex items-center gap-1">
                          <Check className="w-3 h-3" />
                          <span>VERIFIED</span>
                        </span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: STAFF ACCEPTANCE MATRIX (CC1.2 / CC5.2) */}
      {activeTab === 'roster' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Active Personnel Roster</div>
              <div className="text-2xl font-bold text-white mt-1">{activeStaff.length} Employees</div>
              <div className="text-[11px] text-slate-500 mt-1">Tenant: {currentTenant.name}</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Total Signed Acknowledgements</div>
              <div className="text-2xl font-bold text-amber-400 mt-1">{staffSignatures.length} Verified</div>
              <div className="text-[11px] text-slate-500 mt-1">Quarterly recertification cycle</div>
            </div>
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-xs text-slate-400 font-medium">Overall Acceptance Percentage</div>
              <div className="text-2xl font-bold text-emerald-400 mt-1">{overallComplianceRate}%</div>
              <div className="text-[11px] text-slate-500 mt-1">Auditor Threshold: &ge; 90%</div>
            </div>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div>
                <h3 className="text-sm font-bold text-white">Staff Policy Acceptance Matrix</h3>
                <p className="text-xs text-slate-400">
                  Individual employee sign-offs, timestamp logs, and certificate hashes per policy document
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="border-b border-slate-800 text-slate-400 bg-slate-950/60 font-semibold">
                    <th className="py-3 px-4">Employee</th>
                    <th className="py-3 px-4">Role & Dept</th>
                    {policies.map((p) => (
                      <th key={p.id} className="py-3 px-4 text-center">
                        <span className="font-mono text-[11px] block">{p.title.split(' ')[0]}</span>
                        <span className="text-[9px] text-slate-500 font-normal">v{p.version}</span>
                      </th>
                    ))}
                    <th className="py-3 px-4 text-right">Progress</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60 text-slate-300">
                  {employees.map((emp) => {
                    const empSignatures = staffSignatures.filter((s) => s.employeeEmail.toLowerCase() === emp.email.toLowerCase());
                    const progressPct = Math.round((empSignatures.length / policies.length) * 100);

                    return (
                      <tr key={emp.id} className="hover:bg-slate-800/40 transition-colors">
                        <td className="py-3 px-4">
                          <div className="font-bold text-white">{emp.name}</div>
                          <div className="text-[11px] text-slate-400 font-mono">{emp.email}</div>
                        </td>
                        <td className="py-3 px-4">
                          <div className="text-slate-200">{emp.role}</div>
                          <div className="text-[10px] text-slate-400">{emp.department}</div>
                        </td>
                        {policies.map((pol) => {
                          const isSigned = empSignatures.some((s) => s.policyId === pol.id);
                          const sig = empSignatures.find((s) => s.policyId === pol.id);

                          return (
                            <td key={pol.id} className="py-3 px-4 text-center">
                              {isSigned ? (
                                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/80 font-semibold text-[10px]">
                                  <Check className="w-3 h-3" />
                                  <span>Signed</span>
                                </span>
                              ) : (
                                <button
                                  onClick={async () => {
                                    await multiTenantStore.signPolicyAsEmployee(
                                      currentTenant.id,
                                      pol.id,
                                      emp.email,
                                      '192.168.1.100',
                                      'Mozilla/5.0 (Admin Signed)'
                                    );
                                  }}
                                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 hover:bg-amber-600 hover:text-white text-slate-400 border border-slate-700 font-semibold text-[10px] transition-colors"
                                >
                                  <PenTool className="w-3 h-3" />
                                  <span>Sign Now</span>
                                </button>
                              )}
                            </td>
                          );
                        })}
                        <td className="py-3 px-4 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <div className="w-16 bg-slate-800 rounded-full h-1.5 overflow-hidden">
                              <div
                                className={`h-full ${progressPct === 100 ? 'bg-emerald-500' : 'bg-amber-500'}`}
                                style={{ width: `${progressPct}%` }}
                              />
                            </div>
                            <span className="font-mono text-[11px] font-bold text-white">{progressPct}%</span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: GITOPS AUTOMATED PRS (CC8.1 CHANGE MANAGEMENT) */}
      {activeTab === 'gitops' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Deployer Panel */}
            <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
                <GitBranch className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Policy-as-Code GitOps PR Deployer</h3>
              </div>

              <p className="text-xs text-slate-300">
                Automatically generate version-controlled Markdown policies in your GitHub repositories with continuous branch reviews.
              </p>

              <div className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Target GitHub Repository</label>
                  <select
                    value={targetRepo}
                    onChange={(e) => setTargetRepo(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  >
                    <option value="compliance-control-center-api">compliance-control-center-api (Backend)</option>
                    <option value="compliance-frontend-portal">compliance-frontend-portal (UI)</option>
                    <option value="payment-gateway-service">payment-gateway-service (Core Service)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Policy Template</label>
                  <select
                    value={policyTypeToDeploy}
                    onChange={(e) => setPolicyTypeToDeploy(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  >
                    <option value="INFORMATION_SECURITY">Information Security Policy (CC6.1 / CC6.6)</option>
                    <option value="ACCESS_CONTROL">Access Control & MFA Policy (CC6.1)</option>
                    <option value="CHANGE_MANAGEMENT">Change Management & Peer Review Policy (CC8.1)</option>
                    <option value="DATA_PROTECTION">Data Protection & Cryptography Policy (CC6.7)</option>
                  </select>
                </div>

                <button
                  onClick={handleDeployGitOpsPR}
                  disabled={isDeployingPR}
                  className="w-full py-2.5 bg-gradient-to-r from-amber-600 to-amber-700 hover:from-amber-500 hover:to-amber-600 text-white font-bold rounded-lg flex items-center justify-center gap-2 shadow-lg transition-all"
                >
                  {isDeployingPR ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Deploying Pull Request to GitHub...</span>
                    </>
                  ) : (
                    <>
                      <GitPullRequest className="w-4 h-4" />
                      <span>Generate & Open GitHub PR</span>
                    </>
                  )}
                </button>
              </div>

              {generatedMarkdown && (
                <div className="pt-2">
                  <div className="text-[11px] font-mono text-slate-400 mb-1 flex items-center justify-between">
                    <span>Generated Markdown:</span>
                    <button
                      onClick={() => copyHash(generatedMarkdown)}
                      className="text-amber-400 hover:underline"
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-[10px] text-slate-300 max-h-36 overflow-y-auto font-mono">
                    {generatedMarkdown}
                  </pre>
                </div>
              )}
            </div>

            {/* PR History / Ledger */}
            <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <GitCommit className="w-4 h-4 text-emerald-400" />
                  <h3 className="text-sm font-bold text-white">Automated Compliance Pull Requests</h3>
                </div>
                <span className="text-xs text-slate-400 font-mono">{automatedPRs.length} total PRs</span>
              </div>

              <div className="space-y-3">
                {automatedPRs.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 text-xs">No automated PRs deployed yet.</div>
                ) : (
                  automatedPRs.map((pr) => (
                    <div
                      key={pr.id}
                      className="p-4 rounded-xl bg-slate-950 border border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3"
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-xs text-white">{pr.title}</span>
                          <span className="font-mono text-[10px] text-slate-400">#{pr.prNumber}</span>
                        </div>
                        <div className="flex items-center gap-2 text-[11px] text-slate-400 font-mono">
                          <span>Repo: {pr.repoName}</span>
                          <span>•</span>
                          <span>Branch: {pr.branchName}</span>
                        </div>
                        <div className="text-[10px] text-slate-500">
                          Created at: {new Date(pr.createdAt).toLocaleString()}
                        </div>
                      </div>

                      <div className="flex items-center gap-2 shrink-0">
                        {pr.status === 'MERGED' ? (
                          <span className="px-2.5 py-1 rounded bg-purple-950 text-purple-300 border border-purple-800 font-mono text-[11px] flex items-center gap-1 font-semibold">
                            <GitPullRequest className="w-3.5 h-3.5" />
                            <span>MERGED</span>
                          </span>
                        ) : (
                          <button
                            onClick={() => handleMergePR(pr.id)}
                            className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs flex items-center gap-1 shadow transition-colors"
                          >
                            <Check className="w-3.5 h-3.5" />
                            <span>Simulate Peer Approval & Merge</span>
                          </button>
                        )}
                        <a
                          href={pr.prUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="p-2 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
                          title="View on GitHub"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                        </a>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: SLACK MICRO-TRAINING (CC1.2 / CC5.2 CONTINUOUS COMPLIANCE) */}
      {activeTab === 'training' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* Trigger Panel */}
            <div className="lg:col-span-5 bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
              <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
                <MessageSquare className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-bold text-white">Trigger Slack Micro-Lesson (Drift Event)</h3>
              </div>

              <p className="text-xs text-slate-300 leading-relaxed">
                When security drift or non-compliant actions occur, dispatch a 60-second interactive educational quiz directly to the offending employee via Slack.
              </p>

              <div className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-300 font-medium mb-1">Target Personnel</label>
                  <select
                    value={trainingTargetEmail}
                    onChange={(e) => setTrainingTargetEmail(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  >
                    {employees.map((emp) => (
                      <option key={emp.id} value={emp.email}>
                        {emp.name} ({emp.email}) - {emp.department}
                      </option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-slate-300 font-medium mb-1">Drift Trigger Reason</label>
                  <select
                    value={selectedTriggerRule}
                    onChange={(e) => setSelectedTriggerRule(e.target.value as any)}
                    className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
                  >
                    <option value="OPEN_SSH_PORT">⚠️ Open SSH Port 22 Detected on AWS VPC</option>
                    <option value="BRANCH_PROTECTION_DROPPED">⚠️ GitHub Branch Protection Dropped on Main</option>
                    <option value="SECRET_COMMITTED">🚨 High-Entropy Secret Pushed in Commit</option>
                  </select>
                </div>

                <button
                  onClick={handleTriggerMicroLesson}
                  disabled={isTriggeringLesson}
                  className="w-full py-2.5 bg-gradient-to-r from-indigo-600 to-indigo-700 hover:from-indigo-500 hover:to-indigo-600 text-white font-bold rounded-lg flex items-center justify-center gap-2 shadow-lg transition-all"
                >
                  {isTriggeringLesson ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Sending Slack Webhook...</span>
                    </>
                  ) : (
                    <>
                      <Send className="w-4 h-4" />
                      <span>Dispatch Slack Micro-Lesson</span>
                    </>
                  )}
                </button>
              </div>

              {/* Active Quiz Preview / Simulator */}
              {activeQuizId && (
                <div className="mt-4 p-4 rounded-xl bg-slate-950 border border-indigo-900/60 space-y-3">
                  {(() => {
                    const lesson = microLessons.find((l) => l.id === activeQuizId);
                    if (!lesson) return null;

                    return (
                      <div className="space-y-3 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="text-[10px] font-mono font-bold text-indigo-400 uppercase bg-indigo-950 px-2 py-0.5 rounded border border-indigo-800">
                            Simulated Slack Dialog
                          </span>
                          <span className="text-[10px] text-slate-400 font-mono">{lesson.employeeName}</span>
                        </div>

                        <div className="font-bold text-white">{lesson.title}</div>
                        <p className="text-[11px] text-slate-300 leading-relaxed">{lesson.content}</p>

                        <div className="pt-2 border-t border-slate-800">
                          <div className="font-semibold text-amber-400 mb-2">{lesson.quizQuestion}</div>
                          <div className="space-y-2">
                            {lesson.quizOptions.map((opt, idx) => (
                              <button
                                key={idx}
                                disabled={lesson.completed}
                                onClick={() => setSelectedQuizOption(idx)}
                                className={`w-full text-left p-2.5 rounded-lg border text-xs transition-all ${
                                  selectedQuizOption === idx
                                    ? 'bg-indigo-950 border-indigo-500 text-white font-semibold'
                                    : 'bg-slate-900 border-slate-800 text-slate-300 hover:bg-slate-800'
                                }`}
                              >
                                {opt}
                              </button>
                            ))}
                          </div>

                          {!lesson.completed ? (
                            <button
                              onClick={() => handleSubmitQuiz(lesson.id)}
                              disabled={selectedQuizOption === null}
                              className="mt-3 w-full py-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white font-bold rounded-lg shadow"
                            >
                              Submit Answer & Record Credit
                            </button>
                          ) : (
                            <div className="mt-3 p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
                              <div className="flex items-center gap-1.5 font-bold text-xs text-emerald-400">
                                <CheckCircle className="w-4 h-4" />
                                <span>Training Credit Recorded for SOC 2 CC1.2</span>
                              </div>
                              <p className="text-[11px] text-slate-300">{lesson.explanation}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    );
                  })()}
                </div>
              )}
            </div>

            {/* Training History & Credits Ledger */}
            <div className="lg:col-span-7 bg-slate-900/90 border border-slate-800 rounded-xl p-6 shadow-xl space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <div className="flex items-center gap-2">
                  <Award className="w-4 h-4 text-amber-400" />
                  <h3 className="text-sm font-bold text-white">Employee Micro-Training Logs (SOC 2 CC1.2)</h3>
                </div>
                <span className="text-xs text-slate-400 font-mono">{microLessons.length} sessions</span>
              </div>

              <div className="space-y-3">
                {microLessons.length === 0 ? (
                  <div className="p-8 text-center text-slate-500 text-xs">No micro-training events dispatched yet.</div>
                ) : (
                  microLessons.map((l) => (
                    <div
                      key={l.id}
                      onClick={() => {
                        setActiveQuizId(l.id);
                        setSelectedQuizOption(l.userAnswerIndex ?? null);
                      }}
                      className="p-4 rounded-xl bg-slate-950 border border-slate-800 hover:border-slate-700 cursor-pointer transition-all space-y-2"
                    >
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <div className="font-bold text-xs text-white">{l.title}</div>
                          <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                            Assigned to: {l.employeeName} ({l.employeeEmail})
                          </div>
                        </div>

                        {l.completed ? (
                          <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 font-semibold text-[10px] flex items-center gap-1 shrink-0">
                            <Check className="w-3 h-3" />
                            <span>COMPLETED</span>
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-400 border border-amber-800 font-semibold text-[10px] flex items-center gap-1 shrink-0">
                            <Clock className="w-3 h-3" />
                            <span>PENDING RESPONSE</span>
                          </span>
                        )}
                      </div>

                      <p className="text-[11px] text-slate-400 line-clamp-1">{l.quizQuestion}</p>
                      
                      <div className="text-[10px] text-slate-500 flex items-center justify-between pt-1 border-t border-slate-900">
                        <span>Sent: {new Date(l.sentAt).toLocaleString()}</span>
                        {l.completedAt && <span>Completed: {new Date(l.completedAt).toLocaleString()}</span>}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Digital Sign Modal */}
      {showSignModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="bg-slate-900 border border-slate-700 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4"
          >
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <PenTool className="w-4 h-4 text-amber-400" />
                <h3 className="text-base font-bold text-white">Digital Policy Acknowledgement</h3>
              </div>
              <button
                onClick={() => setShowSignModal(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-300">
              By signing, you certify that you have reviewed <strong className="text-white">{selectedPolicy.title} (v{selectedPolicy.version})</strong> and agree to comply with all stated requirements.
            </p>

            <form onSubmit={handleSign} className="space-y-3 text-xs">
              <div>
                <label className="block text-slate-300 font-medium mb-1">Full Legal Name</label>
                <input
                  type="text"
                  value={signerName}
                  onChange={(e) => setSignerName(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-amber-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Corporate Email</label>
                <input
                  type="email"
                  value={signerEmail}
                  onChange={(e) => setSignerEmail(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-amber-500"
                  required
                />
              </div>

              <div>
                <label className="block text-slate-300 font-medium mb-1">Organizational Role</label>
                <input
                  type="text"
                  value={signerRole}
                  onChange={(e) => setSignerRole(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-slate-200 focus:outline-none focus:border-amber-500"
                  required
                />
              </div>

              <div className="pt-3 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowSignModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSigning}
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white font-bold rounded-lg shadow transition-colors"
                >
                  {isSigning ? 'Signing & Hashing...' : 'Sign & Record Evidence'}
                </button>
              </div>
            </form>
          </motion.div>
        </div>
      )}
    </div>
  );
};
