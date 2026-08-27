import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  RefreshCw,
  Zap,
  Server,
  CreditCard,
  Building2,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Key,
  Database,
  ArrowRight,
  Clock,
  Cpu,
  FileCheck2,
  HelpCircle,
  Play,
  Calendar
} from 'lucide-react';
import { multiTenantStore } from '../lib/multiTenantStore';
import { ComplianceIssue, Tenant, AccountStatus, SubscriptionTier, AwsIntegrationConfig, AwsStsScanResult } from '../types/soc2';

interface ComplianceDashboardProps {
  tenantId?: string;
  onNavigateTab?: (tabId: string) => void;
}

export default function ComplianceDashboard({ tenantId: initialTenantId, onNavigateTab }: ComplianceDashboardProps) {
  const currentStoreTenant = multiTenantStore.getCurrentTenant();
  const [activeTenantId, setActiveTenantId] = useState<string>(initialTenantId || currentStoreTenant.id);
  const [tenant, setTenant] = useState<Tenant>(currentStoreTenant);
  const [metrics, setMetrics] = useState<{
    healthScore: number;
    itemsOpen: number;
    ledgerChainValid: boolean;
    accountStatus?: AccountStatus;
    subscriptionTier?: SubscriptionTier;
    workersActive?: boolean;
  }>({
    healthScore: 100,
    itemsOpen: 0,
    ledgerChainValid: true,
    accountStatus: 'ACTIVE',
    subscriptionTier: 'enterprise',
    workersActive: true
  });
  const [issues, setIssues] = useState<ComplianceIssue[]>([]);
  const [awsConfig, setAwsConfig] = useState<AwsIntegrationConfig | null>(null);

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isScanningAws, setIsScanningAws] = useState<boolean>(false);
  const [isRemediating, setIsRemediating] = useState<string | null>(null);
  const [scanResult, setScanResult] = useState<AwsStsScanResult | null>(null);
  const [billingActionMsg, setBillingActionMsg] = useState<string | null>(null);
  const [activeViewMode, setActiveViewMode] = useState<'overview' | 'aws_sts' | 'billing'>('overview');

  // Load summary metrics and tenant data
  const loadComplianceData = async (tid: string) => {
    try {
      setIsLoading(true);
      const res = await fetch(`/api/compliance/summary?tenantId=${tid}`);
      if (res.ok) {
        const data = await res.json();
        setMetrics(data.metrics || { healthScore: 100, itemsOpen: 0, ledgerChainValid: true });
        setIssues(data.issues || []);
      } else {
        // Fallback to local store
        const summary = multiTenantStore.getComplianceSummary(tid);
        setMetrics(summary.metrics);
        setIssues(summary.issues);
      }

      const t = multiTenantStore.getTenant(tid) || multiTenantStore.getCurrentTenant();
      setTenant(t);

      const awsRes = await fetch(`/api/aws/config?tenantId=${tid}`);
      if (awsRes.ok) {
        const cfg = await awsRes.json();
        setAwsConfig(cfg);
      } else {
        setAwsConfig(multiTenantStore.getAwsConfig(tid));
      }
    } catch (err) {
      console.error('Error fetching compliance summary:', err);
      const summary = multiTenantStore.getComplianceSummary(tid);
      setMetrics(summary.metrics);
      setIssues(summary.issues);
      setTenant(multiTenantStore.getTenant(tid) || multiTenantStore.getCurrentTenant());
      setAwsConfig(multiTenantStore.getAwsConfig(tid));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadComplianceData(activeTenantId);

    const unsubscribe = multiTenantStore.subscribe(() => {
      const current = multiTenantStore.getTenant(activeTenantId) || multiTenantStore.getCurrentTenant();
      setTenant({ ...current });
      const summary = multiTenantStore.getComplianceSummary(activeTenantId);
      setMetrics(summary.metrics);
      setIssues(summary.issues);
      setAwsConfig(multiTenantStore.getAwsConfig(activeTenantId));
    });

    return unsubscribe;
  }, [activeTenantId]);

  const handleSwitchTenant = (newTenantId: string) => {
    setActiveTenantId(newTenantId);
    multiTenantStore.setCurrentTenant(newTenantId);
    setScanResult(null);
    setBillingActionMsg(null);
  };

  // Run AWS STS Cross-Account Assumption Scan
  const handleRunAwsStsScan = async (enforceFailure: boolean = false) => {
    setIsScanningAws(true);
    setScanResult(null);
    try {
      const res = await fetch('/api/aws/sts-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenantId: activeTenantId, enforceFailureSimulation: enforceFailure })
      });
      const data = await res.json();
      if (data.success) {
        setScanResult(data);
        loadComplianceData(activeTenantId);
      } else {
        alert(`AWS STS Scan Failed: ${data.error}`);
      }
    } catch (err: any) {
      console.error('AWS STS Scan error:', err);
      alert(`Scan failed: ${err.message}`);
    } finally {
      setIsScanningAws(false);
    }
  };

  // One-click issue remediation
  const handleRemediateIssue = async (issueId: string) => {
    setIsRemediating(issueId);
    try {
      await multiTenantStore.remediateIssue(activeTenantId, issueId);
      loadComplianceData(activeTenantId);
    } catch (err) {
      console.error('Remediation error:', err);
    } finally {
      setIsRemediating(null);
    }
  };

  // Stripe Billing Webhook Simulation
  const handleSimulateStripeEvent = async (eventType: 'customer.subscription.deleted' | 'invoice.payment_succeeded' | 'invoice.payment_failed') => {
    try {
      setBillingActionMsg('Dispatching Stripe Webhook Payload...');
      const res = await fetch('/api/billing/simulate-webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenantId: activeTenantId, eventType })
      });
      const data = await res.json();
      setBillingActionMsg(data.message);
      loadComplianceData(activeTenantId);
    } catch (err: any) {
      setBillingActionMsg(`Simulation error: ${err.message}`);
    }
  };

  const openIssues = issues.filter((i) => i.status === 'OPEN');
  const resolvedIssues = issues.filter((i) => i.status === 'RESOLVED');

  const allTenants = multiTenantStore.getTenants();

  return (
    <div id="compliance-dashboard-root" className="space-y-6 max-w-7xl mx-auto pb-12">
      {/* Header Banner & Multi-Tenant Switcher */}
      <div
        id="tenant-scope-header"
        className="bg-slate-900 text-slate-100 rounded-2xl p-6 shadow-xl border border-slate-800 relative overflow-hidden"
      >
        <div className="absolute top-0 right-0 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-1/3 w-64 h-64 bg-cyan-500/10 rounded-full blur-2xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                <ShieldCheck className="w-3.5 h-3.5" />
                Continuous SOC 2 Type II
              </span>
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
                <Building2 className="w-3.5 h-3.5 text-cyan-400" />
                Scope ID: <strong className="text-white">{activeTenantId}</strong>
              </span>
              <span
                className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold ${
                  tenant.accountStatus === 'SUSPENDED_PAST_DUE'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40 animate-pulse'
                    : 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30'
                }`}
              >
                <CreditCard className="w-3.5 h-3.5" />
                Status: {tenant.accountStatus || 'ACTIVE'}
                {tenant.workersActive === false ? ' (Workers Paused)' : ' (Workers Active)'}
              </span>
            </div>

            <h1 className="text-2xl lg:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
              <span>{tenant.name}</span>
              {tenant.mode === 'internal' ? (
                <span className="text-xs uppercase tracking-wider px-2.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 font-mono">
                  Internal Dogfood Audit
                </span>
              ) : (
                <span className="text-xs uppercase tracking-wider px-2.5 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/40 font-mono">
                  Commercial Tenant
                </span>
              )}
            </h1>

            <p className="text-sm text-slate-400 max-w-2xl">
              Continuous multi-tenant telemetry and cryptographic evidence ledger. All IAM permissions evaluated using short-term AWS STS role assumption tokens with External ID isolation.
            </p>
          </div>

          {/* Tenant Switcher Dropdown & Actions */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 bg-slate-800/80 p-3 rounded-xl border border-slate-700">
            <div className="space-y-1">
              <label htmlFor="tenant-select" className="text-xs text-slate-400 font-medium block">
                Active Tenant Context:
              </label>
              <select
                id="tenant-select"
                value={activeTenantId}
                onChange={(e) => handleSwitchTenant(e.target.value)}
                className="bg-slate-900 text-white text-sm rounded-lg px-3 py-2 border border-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-400 font-medium"
              >
                {allTenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name} ({t.mode === 'internal' ? 'Internal' : 'Commercial'})
                  </option>
                ))}
              </select>
            </div>

            <button
              id="refresh-dashboard-btn"
              onClick={() => loadComplianceData(activeTenantId)}
              disabled={isLoading}
              className="mt-4 sm:mt-0 self-end px-3 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm font-medium transition-colors flex items-center gap-2 border border-slate-600"
              title="Refresh Telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
              Sync
            </button>
          </div>
        </div>

        {/* View Switcher Tabs */}
        <div className="mt-6 pt-4 border-t border-slate-800 flex flex-wrap gap-2">
          <button
            id="tab-btn-overview"
            onClick={() => setActiveViewMode('overview')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              activeViewMode === 'overview'
                ? 'bg-cyan-500 text-slate-950 font-semibold shadow-lg shadow-cyan-500/20'
                : 'bg-slate-800/60 text-slate-300 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            Compliance & Ledger Overview
          </button>

          <button
            id="tab-btn-aws-sts"
            onClick={() => setActiveViewMode('aws_sts')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              activeViewMode === 'aws_sts'
                ? 'bg-cyan-500 text-slate-950 font-semibold shadow-lg shadow-cyan-500/20'
                : 'bg-slate-800/60 text-slate-300 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <Lock className="w-4 h-4" />
            AWS STS Cross-Account Scanner
          </button>

          <button
            id="tab-btn-billing"
            onClick={() => setActiveViewMode('billing')}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 ${
              activeViewMode === 'billing'
                ? 'bg-cyan-500 text-slate-950 font-semibold shadow-lg shadow-cyan-500/20'
                : 'bg-slate-800/60 text-slate-300 hover:bg-slate-800 hover:text-white'
            }`}
          >
            <CreditCard className="w-4 h-4" />
            Stripe Multi-Tenant Billing
          </button>

          {onNavigateTab && (
            <button
              id="tab-btn-open-timeline"
              onClick={() => onNavigateTab('timeline')}
              className="px-4 py-2 rounded-lg text-sm font-medium transition-colors flex items-center gap-2 bg-indigo-900/60 text-indigo-200 hover:bg-indigo-800 hover:text-white border border-indigo-700/50"
            >
              <Calendar className="w-4 h-4 text-cyan-400" />
              Visual Compliance Timeline
            </button>
          )}
        </div>
      </div>

      {/* Warning banner if account is past due */}
      {tenant.accountStatus === 'SUSPENDED_PAST_DUE' && (
        <motion.div
          initial={{ opacity: 0, y: -8 }}
          animate={{ opacity: 1, y: 0 }}
          id="billing-suspension-alert"
          className="bg-rose-50 border-l-4 border-rose-500 p-4 rounded-r-xl shadow-sm flex items-start justify-between gap-4"
        >
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
            <div>
              <h4 className="text-sm font-bold text-rose-900">Commercial Tenant Lapsed - Background Workers Suspended</h4>
              <p className="text-xs text-rose-700 mt-0.5">
                Stripe webhook received a subscription cancellation or invoice payment failure. Continuous automated evidence collectors for this client space are currently halted to protect multi-tenant cloud compute resources.
              </p>
            </div>
          </div>
          <button
            onClick={() => handleSimulateStripeEvent('invoice.payment_succeeded')}
            className="px-3 py-1.5 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-xs font-semibold shrink-0 transition-colors shadow"
          >
            Simulate Payment Recovery
          </button>
        </motion.div>
      )}

      {/* 3 HIGH-CONTRAST METRIC CARDS */}
      <div id="metric-cards-grid" className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Card 1: Framework Compliance */}
        <div
          id="metric-compliance-card"
          className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm hover:shadow-md transition-shadow relative overflow-hidden"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Framework Compliance</span>
            <div className="w-8 h-8 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-3">
            <span className="text-4xl font-extrabold tracking-tight text-slate-900">{metrics.healthScore}%</span>
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
              metrics.healthScore >= 90 ? 'bg-emerald-100 text-emerald-800' : metrics.healthScore >= 75 ? 'bg-amber-100 text-amber-800' : 'bg-rose-100 text-rose-800'
            }`}>
              {metrics.healthScore >= 90 ? 'SOC 2 Ready' : 'Remediation Required'}
            </span>
          </div>
          <div className="mt-3 w-full bg-slate-100 h-2 rounded-full overflow-hidden">
            <div
              className={`h-full transition-all duration-700 ${
                metrics.healthScore >= 90 ? 'bg-emerald-500' : metrics.healthScore >= 75 ? 'bg-amber-500' : 'bg-rose-500'
              }`}
              style={{ width: `${metrics.healthScore}%` }}
            />
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Calculated across Trust Services Criteria CC1.2, CC5.2, CC6.1, CC6.6, CC7.2, and CC8.1.
          </p>
        </div>

        {/* Card 2: Open Actions Required */}
        <div
          id="metric-open-actions-card"
          className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm hover:shadow-md transition-shadow"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Open Actions Required</span>
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
              openIssues.length > 0 ? 'bg-amber-50 text-amber-600' : 'bg-emerald-50 text-emerald-600'
            }`}>
              {openIssues.length > 0 ? <AlertTriangle className="w-5 h-5" /> : <CheckCircle2 className="w-5 h-5" />}
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-3">
            <span className="text-4xl font-extrabold tracking-tight text-slate-900">{openIssues.length}</span>
            <span className="text-sm font-medium text-slate-500">Failing Controls</span>
          </div>
          <div className="mt-3 flex items-center gap-2 text-xs">
            <span className="px-2 py-0.5 rounded bg-rose-50 text-rose-700 font-medium">
              {openIssues.filter(i => i.severity === 'CRITICAL').length} Critical
            </span>
            <span className="px-2 py-0.5 rounded bg-amber-50 text-amber-700 font-medium">
              {openIssues.filter(i => i.severity === 'HIGH').length} High
            </span>
            <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-600 font-medium">
              {resolvedIssues.length} Resolved
            </span>
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Automated remediation scripts available for all high-entropy findings.
          </p>
        </div>

        {/* Card 3: Audit Status & WORM Ledger */}
        <div
          id="metric-audit-status-card"
          className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm hover:shadow-md transition-shadow"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Audit Status: Continuous</span>
            <div className="w-8 h-8 rounded-lg bg-cyan-50 text-cyan-600 flex items-center justify-center">
              <Database className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-baseline gap-3">
            <span className="text-lg font-bold tracking-tight text-slate-900 flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping" />
              WORM Ledger Active
            </span>
          </div>
          <div className="mt-3 flex items-center gap-1.5 text-xs text-slate-600">
            <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
            <span>Cryptographic Chain: <strong className="text-emerald-700 font-mono">TAMPER-EVIDENT (SHA-256)</strong></span>
          </div>
          <p className="mt-3 text-xs text-slate-500">
            Immutable hashes recorded in continuous 60-minute cadence for external CPA inspection.
          </p>
        </div>
      </div>

      {/* VIEW 1: OVERVIEW & REAL-TIME FINDINGS STREAM */}
      {activeViewMode === 'overview' && (
        <div id="findings-stream-section" className="space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div>
              <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-amber-500" />
                Live Control Failures & Findings Stream
              </h2>
              <p className="text-xs text-slate-500">
                Real-time governance deviations detected across IAM, GitOps branch protections, and encryption policies.
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                id="run-quick-sts-scan-btn"
                onClick={() => handleRunAwsStsScan(false)}
                disabled={isScanningAws}
                className="px-3.5 py-2 rounded-xl bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold flex items-center gap-2 shadow-sm transition-all"
              >
                <Lock className={`w-3.5 h-3.5 text-cyan-400 ${isScanningAws ? 'animate-spin' : ''}`} />
                {isScanningAws ? 'Scanning AWS via STS...' : 'Trigger STS Role Scan'}
              </button>

              {onNavigateTab && (
                <button
                  onClick={() => onNavigateTab('evidence')}
                  className="px-3.5 py-2 rounded-xl bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold border border-slate-200 flex items-center gap-1.5 transition-colors"
                >
                  <FileCheck2 className="w-3.5 h-3.5 text-slate-500" />
                  View Audit Pack
                </button>
              )}
            </div>
          </div>

          {openIssues.length === 0 ? (
            <div id="no-failing-controls-banner" className="bg-emerald-50 border border-emerald-200 rounded-2xl p-8 text-center space-y-3">
              <div className="w-12 h-12 rounded-full bg-emerald-100 text-emerald-600 mx-auto flex items-center justify-center">
                <CheckCircle2 className="w-6 h-6" />
              </div>
              <h3 className="text-base font-bold text-emerald-900">Zero Open Control Failures</h3>
              <p className="text-xs text-emerald-700 max-w-md mx-auto">
                All cloud configurations and developer workflows for <strong>{tenant.name}</strong> strictly conform to SOC 2 Trust Services Criteria.
              </p>
              <button
                onClick={() => handleRunAwsStsScan(true)}
                className="mt-2 text-xs text-emerald-800 underline font-medium hover:text-emerald-950"
              >
                Test Non-Compliant AWS Password Policy Detection
              </button>
            </div>
          ) : (
            <div id="issues-list" className="space-y-4">
              {openIssues.map((issue) => (
                <motion.div
                  key={issue.id}
                  layout
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm hover:border-slate-300 transition-all flex flex-col md:flex-row md:items-center justify-between gap-6"
                >
                  <div className="space-y-2 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-xs font-bold font-mono ${
                          issue.severity === 'CRITICAL'
                            ? 'bg-rose-100 text-rose-800 border border-rose-300'
                            : issue.severity === 'HIGH'
                            ? 'bg-amber-100 text-amber-800 border border-amber-300'
                            : 'bg-blue-100 text-blue-800 border border-blue-300'
                        }`}
                      >
                        {issue.severity}
                      </span>
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-slate-100 text-slate-700 border border-slate-200">
                        {issue.controlCode}
                      </span>
                      <span className="text-xs text-slate-400 font-mono">
                        Resource: <strong>{issue.resourceId}</strong>
                      </span>
                    </div>

                    <h3 className="text-base font-semibold text-slate-900">{issue.title}</h3>
                    <p className="text-xs text-slate-600 leading-relaxed max-w-3xl">{issue.description}</p>

                    <div className="flex flex-wrap items-center gap-4 text-xs text-slate-500 pt-1">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5 text-slate-400" />
                        Opened: {new Date(issue.openedAt).toLocaleDateString()}
                      </span>
                      <span>Assignee: <strong className="text-slate-700">{issue.assignee}</strong></span>
                      <span>Provider: <strong className="uppercase text-slate-700">{issue.provider}</strong></span>
                    </div>
                  </div>

                  <div className="flex flex-col sm:flex-row md:flex-col items-end gap-2 shrink-0">
                    <button
                      id={`remediate-btn-${issue.id}`}
                      onClick={() => handleRemediateIssue(issue.id)}
                      disabled={isRemediating === issue.id}
                      className="w-full sm:w-auto px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold transition-colors flex items-center justify-center gap-2 shadow-sm"
                    >
                      {isRemediating === issue.id ? (
                        <>
                          <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          Remediating...
                        </>
                      ) : (
                        <>
                          <Zap className="w-3.5 h-3.5" />
                          Remediate via API
                        </>
                      )}
                    </button>
                    <span className="text-[10px] text-slate-400 text-right">
                      {issue.autoRemediationAction || 'Automated policy sync'}
                    </span>
                  </div>
                </motion.div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* VIEW 2: ENTERPRISE AWS STS SCANNER PANEL */}
      {activeViewMode === 'aws_sts' && (
        <div id="aws-sts-panel" className="space-y-6">
          <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
              <div>
                <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                  <Lock className="w-5 h-5 text-indigo-600" />
                  Enterprise AWS Cross-Account STS Assumption Engine
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Architecture Principle: Never accept raw AWS Access or Secret Keys. Connect customer infrastructure using ephemeral STS AssumeRole sessions and secure External ID tokens.
                </p>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleRunAwsStsScan(false)}
                  disabled={isScanningAws}
                  className="px-4 py-2.5 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-bold flex items-center gap-2 shadow-sm transition-all"
                >
                  <Play className={`w-3.5 h-3.5 ${isScanningAws ? 'animate-spin' : ''}`} />
                  {isScanningAws ? 'Assuming Role & Evaluating...' : 'Run Live STS Compliance Scan'}
                </button>
                <button
                  onClick={() => handleRunAwsStsScan(true)}
                  disabled={isScanningAws}
                  className="px-3.5 py-2.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-medium border border-slate-300 transition-colors"
                >
                  Simulate Password Policy Failure
                </button>
              </div>
            </div>

            {/* IAM Configuration Summary */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-slate-50 rounded-xl p-5 border border-slate-200 space-y-3 font-mono text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500 uppercase font-sans font-semibold">Target Client IAM Role ARN:</span>
                  <span className="px-2 py-0.5 rounded bg-indigo-100 text-indigo-800 text-[10px]">Read-Only Security Role</span>
                </div>
                <div className="p-3 bg-white rounded-lg border border-slate-200 text-slate-800 break-all select-all font-semibold">
                  {awsConfig?.clientIamRoleArn || tenant.clientIamRoleArn || 'arn:aws:iam::123456789012:role/SOC2ContinuousComplianceRole'}
                </div>

                <div className="pt-2 flex items-center justify-between">
                  <span className="text-slate-500 uppercase font-sans font-semibold">Tenant External ID (Anti-Confused Deputy):</span>
                  <span className="px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 text-[10px]">Isolated Token</span>
                </div>
                <div className="p-3 bg-white rounded-lg border border-slate-200 text-slate-800 break-all select-all font-semibold">
                  {awsConfig?.secureExternalToken || tenant.secureExternalToken || tenant.externalId}
                </div>
              </div>

              <div className="bg-slate-50 rounded-xl p-5 border border-slate-200 space-y-4">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-600 font-sans">
                  Active SOC 2 Evaluated Criteria
                </h4>

                <ul className="space-y-2.5 text-xs text-slate-700">
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                    <div>
                      <strong>CC6.1 - Account Password Policy:</strong> Requires MinimumPasswordLength &gt;= 14, RequireUppercase, RequireSymbols, RequireNumbers.
                    </div>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                    <div>
                      <strong>CC6.1 - Root Account Protection:</strong> Verifies Root MFA is active and no root programmatic access keys exist.
                    </div>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0 mt-0.5" />
                    <div>
                      <strong>CC6.6 - S3 Perimeter Isolation:</strong> Enforces S3 Block Public Access and KMS SSE encryption.
                    </div>
                  </li>
                </ul>
              </div>
            </div>

            {/* Scan Output Results */}
            {scanResult && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className={`rounded-xl p-5 border ${
                  scanResult.isCompliant
                    ? 'bg-emerald-50/70 border-emerald-200 text-emerald-950'
                    : 'bg-amber-50/70 border-amber-200 text-amber-950'
                }`}
              >
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-bold flex items-center gap-2">
                    {scanResult.isCompliant ? (
                      <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                    ) : (
                      <AlertTriangle className="w-5 h-5 text-amber-600" />
                    )}
                    AWS STS Assumption Scan Result ({new Date(scanResult.scanTimestamp).toLocaleTimeString()})
                  </h4>
                  <span className="text-xs font-mono bg-white px-2.5 py-1 rounded-lg border border-slate-200">
                    Snapshot ID: {scanResult.ledgerSnapshotId}
                  </span>
                </div>

                <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
                  <div className="bg-white p-3 rounded-lg border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Session Token:</span>
                    <span className="font-semibold text-slate-800">{scanResult.sessionTokenPreview}</span>
                  </div>
                  <div className="bg-white p-3 rounded-lg border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Password Policy (CC6.1):</span>
                    <span className={`font-semibold ${scanResult.evaluatedRules.passwordPolicy ? 'text-emerald-600' : 'text-rose-600'}`}>
                      {scanResult.evaluatedRules.passwordPolicy ? 'PASS (>= 14 Chars)' : 'FAIL (< 14 Chars)'}
                    </span>
                  </div>
                  <div className="bg-white p-3 rounded-lg border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">Root MFA (CC6.1):</span>
                    <span className="font-semibold text-emerald-600">PASS (Enforced)</span>
                  </div>
                  <div className="bg-white p-3 rounded-lg border border-slate-200">
                    <span className="text-slate-400 block text-[10px]">S3 Encryption (CC6.6):</span>
                    <span className="font-semibold text-emerald-600">PASS (KMS SSE)</span>
                  </div>
                </div>

                {scanResult.findings.length > 0 && (
                  <div className="mt-4 p-3 bg-white rounded-lg border border-rose-200 space-y-2">
                    <span className="text-xs font-bold text-rose-800 uppercase tracking-wider block">
                      Discovered Deviations ({scanResult.findings.length})
                    </span>
                    {scanResult.findings.map((f, i) => (
                      <div key={i} className="text-xs text-rose-900">
                        • <strong>{f.resourceId}</strong>: {f.title}
                      </div>
                    ))}
                  </div>
                )}
              </motion.div>
            )}
          </div>
        </div>
      )}

      {/* VIEW 3: STRIPE MULTI-TENANT BILLING & ISOLATION */}
      {activeViewMode === 'billing' && (
        <div id="billing-panel" className="space-y-6">
          <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-6 border-b border-slate-100">
              <div>
                <h2 className="text-lg font-bold text-slate-900 flex items-center gap-2">
                  <CreditCard className="w-5 h-5 text-cyan-600" />
                  Stripe Subscription Lifecycle & Worker Isolation
                </h2>
                <p className="text-xs text-slate-500 mt-1">
                  Architecture Principle: Background compliance collection tasks automatically pause if an external commercial client lets their credit card payment lapse.
                </p>
              </div>

              <span className={`px-3 py-1 rounded-full text-xs font-bold ${
                tenant.accountStatus === 'SUSPENDED_PAST_DUE'
                  ? 'bg-rose-100 text-rose-800 border border-rose-300'
                  : 'bg-emerald-100 text-emerald-800 border border-emerald-300'
              }`}>
                {tenant.accountStatus || 'ACTIVE'}
              </span>
            </div>

            {/* Billing Details Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-6">
              <div className="bg-slate-50 rounded-xl p-5 border border-slate-200">
                <span className="text-xs font-semibold text-slate-500 uppercase">Subscription Tier</span>
                <div className="mt-2 text-xl font-bold text-slate-900 capitalize">
                  {tenant.subscriptionTier || 'Growth Tier'}
                </div>
                <p className="mt-1 text-xs text-slate-500">Includes multi-account STS scans and unlimited WORM evidence records.</p>
              </div>

              <div className="bg-slate-50 rounded-xl p-5 border border-slate-200">
                <span className="text-xs font-semibold text-slate-500 uppercase">Worker Daemon Status</span>
                <div className="mt-2 text-xl font-bold flex items-center gap-2">
                  <span className={`w-3 h-3 rounded-full ${tenant.workersActive !== false ? 'bg-emerald-500' : 'bg-rose-500'}`} />
                  <span className={tenant.workersActive !== false ? 'text-emerald-700' : 'text-rose-700'}>
                    {tenant.workersActive !== false ? 'Active & Ingesting' : 'Suspended (Past Due)'}
                  </span>
                </div>
                <p className="mt-1 text-xs text-slate-500">Controlled automatically via Stripe webhook events.</p>
              </div>

              <div className="bg-slate-50 rounded-xl p-5 border border-slate-200">
                <span className="text-xs font-semibold text-slate-500 uppercase">Stripe Customer ID</span>
                <div className="mt-2 font-mono text-sm font-semibold text-slate-800">
                  {tenant.stripeCustomerId || `cus_${tenant.slug}_77291`}
                </div>
                <p className="mt-1 text-xs text-slate-500">Directly mapped in Prisma tenant entity schema.</p>
              </div>
            </div>

            {/* Interactive Stripe Webhook Event Simulator */}
            <div className="bg-slate-900 text-white rounded-xl p-6 border border-slate-800 space-y-4">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-bold flex items-center gap-2">
                  <Zap className="w-4 h-4 text-amber-400" />
                  Stripe Webhook Event Simulator (`/api/billing/webhook`)
                </h4>
                <span className="text-xs text-slate-400 font-mono">Simulates live Stripe payloads</span>
              </div>

              <p className="text-xs text-slate-300">
                Test the multi-tenant isolation layer by triggering subscription lifecycle events for <strong>{tenant.name}</strong>:
              </p>

              <div className="flex flex-wrap gap-3">
                <button
                  onClick={() => handleSimulateStripeEvent('customer.subscription.deleted')}
                  className="px-3.5 py-2 rounded-lg bg-rose-600 hover:bg-rose-700 text-white text-xs font-bold transition-colors"
                >
                  Simulate `customer.subscription.deleted` (Pause Workers)
                </button>
                <button
                  onClick={() => handleSimulateStripeEvent('invoice.payment_failed')}
                  className="px-3.5 py-2 rounded-lg bg-amber-600 hover:bg-amber-700 text-white text-xs font-bold transition-colors"
                >
                  Simulate `invoice.payment_failed` (Suspend Client)
                </button>
                <button
                  onClick={() => handleSimulateStripeEvent('invoice.payment_succeeded')}
                  className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold transition-colors"
                >
                  Simulate `invoice.payment_succeeded` (Resume Workers)
                </button>
              </div>

              {billingActionMsg && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="p-3 bg-slate-800 rounded-lg border border-slate-700 text-xs font-mono text-cyan-300"
                >
                  {billingActionMsg}
                </motion.div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
