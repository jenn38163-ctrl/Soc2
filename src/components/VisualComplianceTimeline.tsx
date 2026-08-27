import React, { useState, useEffect, useMemo, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Calendar,
  Clock,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  Lock,
  GitPullRequest,
  Zap,
  Activity,
  Filter,
  FileCheck2,
  Key,
  Database,
  Building2,
  RefreshCw,
  Search,
  ExternalLink,
  ChevronRight,
  ChevronLeft,
  X,
  Play,
  ArrowUpRight,
  Info,
  CalendarDays,
  FileText,
  Radio,
  Timer,
  Sparkles,
  Download
} from 'lucide-react';
import { multiTenantStore } from '../lib/multiTenantStore';
import { auditLogStore } from '../lib/auditLogger';
import {
  Tenant,
  EvidenceSnapshot,
  ComplianceIssue,
  AuditLogPayload,
  WebhookEventLog,
  AutomatedPR,
  IssueSeverity,
  IssueStatus
} from '../types/soc2';

export interface TimelineEventItem {
  id: string;
  type: 'audit_event' | 'evidence_snapshot' | 'remediation_deadline' | 'audit_milestone' | 'webhook_event' | 'pr_event';
  title: string;
  category: 'IAM & Access' | 'Change Management' | 'Encryption & KMS' | 'Vulnerability & SAST' | 'Audit Milestone' | 'Billing & Account';
  controlCode?: string;
  timestamp: string; // ISO 8601
  date: Date;
  status: 'COMPLIANT' | 'WARNING' | 'CRITICAL' | 'PENDING' | 'RESOLVED' | 'BREACHED';
  severity?: IssueSeverity;
  provider?: string;
  resourceId?: string;
  description: string;
  details?: Record<string, unknown>;
  sha256Hash?: string;
  slaDeadline?: string;
  isDeadline?: boolean;
  isPast?: boolean;
  issueRef?: ComplianceIssue;
}

interface VisualComplianceTimelineProps {
  tenantId?: string;
  onNavigateTab?: (tabId: string) => void;
}

export const VisualComplianceTimeline: React.FC<VisualComplianceTimelineProps> = ({
  tenantId: propTenantId,
  onNavigateTab
}) => {
  const currentStoreTenant = multiTenantStore.getCurrentTenant();
  const [activeTenantId, setActiveTenantId] = useState<string>(propTenantId || currentStoreTenant.id);
  const [tenant, setTenant] = useState<Tenant>(currentStoreTenant);

  // Filter and view controls
  const [categoryFilter, setCategoryFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [typeFilter, setTypeFilter] = useState<'ALL' | 'AUDIT_EVENTS' | 'DEADLINES_ONLY'>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedEvent, setSelectedEvent] = useState<TimelineEventItem | null>(null);
  const [zoomWindow, setZoomWindow] = useState<'all' | '60days' | '30days'>('all');
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [remediatingId, setRemediatingId] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);

  const timelineContainerRef = useRef<HTMLDivElement>(null);

  // Sync with multiTenantStore
  useEffect(() => {
    const unsub = multiTenantStore.subscribe(() => {
      const t = multiTenantStore.getTenant(activeTenantId) || multiTenantStore.getCurrentTenant();
      setTenant({ ...t });
    });
    return unsub;
  }, [activeTenantId]);

  const handleTenantChange = (newTid: string) => {
    setActiveTenantId(newTid);
    multiTenantStore.setCurrentTenant(newTid);
    setSelectedEvent(null);
  };

  // Compile unified timeline events
  const timelineEvents: TimelineEventItem[] = useMemo(() => {
    const events: TimelineEventItem[] = [];
    const now = new Date();

    // 1. Evidence Snapshots
    const snapshots = multiTenantStore.getSnapshots(activeTenantId);
    snapshots.forEach((s) => {
      const date = new Date(s.createdAt);
      events.push({
        id: `snp-${s.id}`,
        type: 'evidence_snapshot',
        title: `Evidence: ${s.title}`,
        category: s.controlCode.includes('MFA') || s.controlCode.includes('IAM')
          ? 'IAM & Access'
          : s.controlCode.includes('BRANCH')
          ? 'Change Management'
          : s.controlCode.includes('S3') || s.controlCode.includes('KMS')
          ? 'Encryption & KMS'
          : 'Vulnerability & SAST',
        controlCode: s.controlCode,
        timestamp: s.createdAt,
        date,
        status: s.isCompliant ? 'COMPLIANT' : 'CRITICAL',
        severity: s.isCompliant ? undefined : 'HIGH',
        provider: s.provider,
        resourceId: s.id,
        description: `WORM snapshot record with ${s.recordCount} validated resources. SHA-256 proof hash computed.`,
        sha256Hash: s.sha256Hash,
        details: Array.isArray(s.rawPayload) ? { records: s.rawPayload } : s.rawPayload,
        isPast: date <= now
      });
    });

    // 2. Compliance Issues & SLA Deadlines
    const issues = multiTenantStore.getIssues(activeTenantId);
    issues.forEach((iss) => {
      const openedDate = new Date(iss.openedAt);
      const deadlineDate = new Date(iss.slaDeadline);
      const isBreached = iss.status === 'OPEN' && deadlineDate < now;

      // Event when issue was discovered
      events.push({
        id: `iss-open-${iss.id}`,
        type: 'audit_event',
        title: `Finding Opened: ${iss.title}`,
        category: iss.controlCode.includes('MFA') || iss.controlCode.includes('OFFBOARDING')
          ? 'IAM & Access'
          : iss.controlCode.includes('BRANCH')
          ? 'Change Management'
          : iss.controlCode.includes('S3')
          ? 'Encryption & KMS'
          : 'Vulnerability & SAST',
        controlCode: iss.controlCode,
        timestamp: iss.openedAt,
        date: openedDate,
        status: iss.status === 'RESOLVED' ? 'RESOLVED' : iss.severity === 'CRITICAL' ? 'CRITICAL' : 'WARNING',
        severity: iss.severity,
        provider: iss.provider,
        resourceId: iss.resourceId,
        description: iss.description,
        slaDeadline: iss.slaDeadline,
        issueRef: iss,
        isPast: openedDate <= now
      });

      // Target SLA Remediation Deadline on time axis
      events.push({
        id: `iss-deadline-${iss.id}`,
        type: 'remediation_deadline',
        title: `SLA Deadline: ${iss.title}`,
        category: iss.controlCode.includes('MFA') || iss.controlCode.includes('OFFBOARDING')
          ? 'IAM & Access'
          : iss.controlCode.includes('BRANCH')
          ? 'Change Management'
          : iss.controlCode.includes('S3')
          ? 'Encryption & KMS'
          : 'Vulnerability & SAST',
        controlCode: iss.controlCode,
        timestamp: iss.slaDeadline,
        date: deadlineDate,
        status: iss.status === 'RESOLVED' ? 'RESOLVED' : isBreached ? 'BREACHED' : 'PENDING',
        severity: iss.severity,
        provider: iss.provider,
        resourceId: iss.resourceId,
        description: `Target SOC 2 compliance resolution deadline for ${iss.title}. SLA: ${
          iss.severity === 'CRITICAL' ? '24h / 7-day Critical SLA' : '30-day Remediation Window'
        }`,
        isDeadline: true,
        issueRef: iss,
        isPast: deadlineDate <= now
      });
    });

    // 3. Automated PRs
    const prs = multiTenantStore.getAutomatedPRs(activeTenantId);
    prs.forEach((pr) => {
      const date = new Date(pr.createdAt);
      events.push({
        id: `pr-${pr.id}`,
        type: 'pr_event',
        title: `Remediation PR #${pr.prNumber}: ${pr.title}`,
        category: 'Change Management',
        controlCode: 'CC8.1_CHANGE_MGMT',
        timestamp: pr.createdAt,
        date,
        status: pr.status === 'MERGED' ? 'COMPLIANT' : 'PENDING',
        provider: 'github',
        resourceId: `${pr.repoName}#${pr.prNumber}`,
        description: `Automated GitOps change management PR targeting branch ${pr.branchName}. Enforces peer review and automated security status checks.`,
        isPast: date <= now
      });
    });

    // 4. Webhook Alerts
    const webhooks = multiTenantStore.getWebhookLogs(activeTenantId);
    webhooks.forEach((wh) => {
      const date = new Date(wh.receivedAt);
      events.push({
        id: `wh-${wh.id}`,
        type: 'webhook_event',
        title: `Webhook: ${wh.event}`,
        category: wh.provider === 'github' ? 'Change Management' : 'IAM & Access',
        timestamp: wh.receivedAt,
        date,
        status: wh.severity === 'ALERT' ? 'CRITICAL' : wh.severity === 'WARNING' ? 'WARNING' : 'COMPLIANT',
        provider: wh.provider,
        resourceId: wh.event,
        description: `${wh.payloadSummary} -> Action taken: ${wh.actionTaken}`,
        isPast: date <= now
      });
    });

    // 5. Standard SOC 2 Observation Period Milestones
    const milestones = [
      {
        id: 'milestone-soc2-start',
        title: 'SOC 2 Type II Observation Window Start',
        timestamp: '2026-07-01T00:00:00Z',
        description: 'Beginning of continuous 3-month observation period for independent CPA auditor sampling.',
        controlCode: 'GOV_TYPE_II_START'
      },
      {
        id: 'milestone-mid-audit',
        title: 'Mid-Period Evidence Sampling & Vault Check',
        timestamp: '2026-08-15T12:00:00Z',
        description: 'Auditor inspection of WORM evidence snapshots and automated PR approval trails.',
        controlCode: 'CC1.2_AUDIT_SAMPLE'
      },
      {
        id: 'milestone-q3-close',
        title: 'Quarterly Access Review & Key Rotation Deadline',
        timestamp: '2026-09-15T18:00:00Z',
        description: 'Quarterly privileged IAM access re-certification and KMS key rotation cadence check.',
        controlCode: 'CC6.1_QUARTERLY_IAM'
      },
      {
        id: 'milestone-soc2-final',
        title: 'Final CPA SOC 2 Type II Report Attestation',
        timestamp: '2026-09-30T23:59:59Z',
        description: 'Final audit report generation and issuance of clean SOC 2 Type II attestation.',
        controlCode: 'CPA_TYPE_II_FINAL'
      }
    ];

    milestones.forEach((m) => {
      const date = new Date(m.timestamp);
      events.push({
        id: m.id,
        type: 'audit_milestone',
        title: m.title,
        category: 'Audit Milestone',
        controlCode: m.controlCode,
        timestamp: m.timestamp,
        date,
        status: date <= now ? 'COMPLIANT' : 'PENDING',
        description: m.description,
        isPast: date <= now
      });
    });

    // Sort by timestamp ascending
    return events.sort((a, b) => a.date.getTime() - b.date.getTime());
  }, [activeTenantId]);

  // Filtered Events
  const filteredEvents = useMemo(() => {
    return timelineEvents.filter((item) => {
      // Category filter
      if (categoryFilter !== 'ALL' && item.category !== categoryFilter) return false;

      // Severity filter
      if (severityFilter !== 'ALL') {
        if (severityFilter === 'CRITICAL' && item.status !== 'CRITICAL' && item.severity !== 'CRITICAL' && item.status !== 'BREACHED') return false;
        if (severityFilter === 'HIGH_PLUS' && item.severity !== 'CRITICAL' && item.severity !== 'HIGH' && item.status !== 'CRITICAL' && item.status !== 'BREACHED') return false;
        if (severityFilter === 'COMPLIANT' && item.status !== 'COMPLIANT' && item.status !== 'RESOLVED') return false;
      }

      // Type filter
      if (typeFilter === 'DEADLINES_ONLY' && item.type !== 'remediation_deadline') return false;
      if (typeFilter === 'AUDIT_EVENTS' && item.type === 'remediation_deadline') return false;

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTitle = item.title.toLowerCase().includes(q);
        const matchDesc = item.description.toLowerCase().includes(q);
        const matchCode = (item.controlCode || '').toLowerCase().includes(q);
        const matchResource = (item.resourceId || '').toLowerCase().includes(q);
        if (!matchTitle && !matchDesc && !matchCode && !matchResource) return false;
      }

      return true;
    });
  }, [timelineEvents, categoryFilter, severityFilter, typeFilter, searchQuery]);

  // Time boundaries for continuous axis plotting
  const { minTime, maxTime, nowTime } = useMemo(() => {
    const now = new Date('2026-08-27T16:16:00Z').getTime(); // Synchronized baseline
    let min = new Date('2026-07-01T00:00:00Z').getTime();
    let max = new Date('2026-10-01T00:00:00Z').getTime();

    if (zoomWindow === '30days') {
      min = now - 15 * 24 * 60 * 60 * 1000;
      max = now + 15 * 24 * 60 * 60 * 1000;
    } else if (zoomWindow === '60days') {
      min = now - 30 * 24 * 60 * 60 * 1000;
      max = now + 30 * 24 * 60 * 60 * 1000;
    }

    return { minTime: min, maxTime: max, nowTime: now };
  }, [zoomWindow]);

  // Helper to calculate X percentage position on time axis
  const getPercentPosition = (date: Date) => {
    const time = date.getTime();
    const clamped = Math.max(minTime, Math.min(maxTime, time));
    return ((clamped - minTime) / (maxTime - minTime)) * 100;
  };

  const nowPercent = getPercentPosition(new Date(nowTime));

  // SLA Stats Calculation
  const openDeadlines = timelineEvents.filter((e) => e.type === 'remediation_deadline' && e.status === 'PENDING');
  const breachedDeadlines = timelineEvents.filter((e) => e.type === 'remediation_deadline' && e.status === 'BREACHED');
  const totalAuditEvents = timelineEvents.filter((e) => e.type !== 'remediation_deadline').length;
  const imminentDeadlines = openDeadlines.filter((e) => {
    const diffHours = (e.date.getTime() - nowTime) / (1000 * 60 * 60);
    return diffHours > 0 && diffHours <= 24 * 7;
  });

  // Action: Remediate Issue
  const handleRemediate = async (issueId: string) => {
    setRemediatingId(issueId);
    try {
      await multiTenantStore.remediateIssue(activeTenantId, issueId);
      setStatusMessage('Control remediated successfully. WORM ledger record updated.');
      setTimeout(() => setStatusMessage(null), 4000);
      // Update selected event if open
      if (selectedEvent && selectedEvent.issueRef?.id === issueId) {
        setSelectedEvent(null);
      }
    } catch (err: any) {
      alert(`Remediation failed: ${err.message}`);
    } finally {
      setRemediatingId(null);
    }
  };

  // Action: Trigger Live STS Scan Simulation
  const handleSimulateScan = async () => {
    setIsSimulating(true);
    try {
      const res = await fetch('/api/aws/sts-scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tenantId: activeTenantId })
      });
      const data = await res.json();
      if (data.success) {
        setStatusMessage('Live AWS STS Scan completed and plotted onto timeline.');
        setTimeout(() => setStatusMessage(null), 4000);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setIsSimulating(false);
    }
  };

  // Export Timeline report
  const handleExportTimeline = () => {
    const reportData = {
      tenant: tenant.name,
      tenantId: activeTenantId,
      exportedAt: new Date().toISOString(),
      summary: {
        totalEvents: timelineEvents.length,
        openDeadlines: openDeadlines.length,
        breachedDeadlines: breachedDeadlines.length,
        auditWindow: '2026-07-01 to 2026-09-30 (Q3 SOC 2 Type II)'
      },
      events: filteredEvents.map((e) => ({
        id: e.id,
        title: e.title,
        type: e.type,
        category: e.category,
        controlCode: e.controlCode,
        timestamp: e.timestamp,
        status: e.status,
        severity: e.severity,
        sha256Hash: e.sha256Hash,
        description: e.description
      }))
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `compliance-timeline-${activeTenantId}-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Date marks on continuous axis
  const axisMarks = useMemo(() => {
    const marks: { date: Date; label: string; percent: number }[] = [];
    const step = zoomWindow === '30days' ? 5 : zoomWindow === '60days' ? 10 : 15; // days

    const start = new Date(minTime);
    start.setHours(0, 0, 0, 0);

    const curr = new Date(start);
    while (curr.getTime() <= maxTime) {
      if (curr.getTime() >= minTime) {
        marks.push({
          date: new Date(curr),
          label: curr.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
          percent: getPercentPosition(curr)
        });
      }
      curr.setDate(curr.getDate() + step);
    }
    return marks;
  }, [minTime, maxTime, zoomWindow]);

  const allTenants = multiTenantStore.getTenants();

  return (
    <div id="visual-compliance-timeline-root" className="space-y-6 max-w-7xl mx-auto pb-16">
      {/* Header Banner */}
      <div className="bg-slate-900 text-slate-100 rounded-2xl p-6 shadow-xl border border-slate-800 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-1/4 w-80 h-80 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 flex flex-col lg:flex-row lg:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                <Calendar className="w-3.5 h-3.5" />
                Time-Series Audit Timeline
              </span>
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-mono bg-slate-800 text-slate-300 border border-slate-700">
                <Building2 className="w-3.5 h-3.5 text-cyan-400" />
                Scope: <strong className="text-white">{tenant.name}</strong>
              </span>
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">
                <ShieldCheck className="w-3.5 h-3.5" />
                Observation Period: Q3 2026
              </span>
            </div>

            <h1 className="text-2xl lg:text-3xl font-bold tracking-tight text-white flex items-center gap-3">
              Visual Compliance & Remediation Timeline
            </h1>
            <p className="text-sm text-slate-400 max-w-3xl">
              Chronological time-series plotting critical security audit snapshots, WORM ledger evidence records, and active SLA remediation deadlines against SOC 2 Type II criteria.
            </p>
          </div>

          {/* Quick Actions & Tenant Selector */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="bg-slate-800/80 p-2 rounded-xl border border-slate-700 flex items-center gap-2">
              <label htmlFor="timeline-tenant-select" className="text-xs text-slate-400 font-medium pl-1">
                Tenant:
              </label>
              <select
                id="timeline-tenant-select"
                value={activeTenantId}
                onChange={(e) => handleTenantChange(e.target.value)}
                className="bg-slate-900 text-white text-xs rounded-lg px-2.5 py-1.5 border border-slate-600 focus:outline-none focus:ring-2 focus:ring-cyan-400 font-medium"
              >
                {allTenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>

            <button
              id="timeline-simulate-scan-btn"
              onClick={handleSimulateScan}
              disabled={isSimulating}
              className="px-3.5 py-2 rounded-xl bg-indigo-600 hover:bg-indigo-700 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-all"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
              {isSimulating ? 'Scanning...' : 'Trigger Live Scan'}
            </button>

            <button
              id="timeline-export-btn"
              onClick={handleExportTimeline}
              className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5 text-cyan-400" />
              Export Timeline
            </button>
          </div>
        </div>

        {/* Status Toast Banner */}
        <AnimatePresence>
          {statusMessage && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="mt-4 p-3 bg-emerald-500/20 border border-emerald-500/40 rounded-xl text-xs text-emerald-200 flex items-center gap-2"
            >
              <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
              <span>{statusMessage}</span>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* 4 HIGH-IMPACT SLA & AUDIT METRICS */}
      <div id="timeline-metrics-grid" className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1 */}
        <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Total Ingested Events</span>
            <div className="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-900">{totalAuditEvents}</span>
            <span className="text-xs font-medium text-emerald-600">Continuous Stream</span>
          </div>
          <p className="mt-2 text-xs text-slate-500">AWS STS, GitHub GitOps, & WORM snapshots</p>
        </div>

        {/* Metric 2 */}
        <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Active Remediation SLAs</span>
            <div className="w-8 h-8 rounded-lg bg-amber-50 text-amber-600 flex items-center justify-center">
              <Timer className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-slate-900">{openDeadlines.length}</span>
            <span className="text-xs font-medium text-slate-500">Pending Resolution</span>
          </div>
          <p className="mt-2 text-xs text-slate-500">
            {imminentDeadlines.length > 0 ? (
              <span className="text-rose-600 font-semibold">{imminentDeadlines.length} due within 7 days</span>
            ) : (
              'All SLAs currently healthy'
            )}
          </p>
        </div>

        {/* Metric 3 */}
        <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Breached Deadlines</span>
            <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${
              breachedDeadlines.length > 0 ? 'bg-rose-50 text-rose-600' : 'bg-emerald-50 text-emerald-600'
            }`}>
              {breachedDeadlines.length > 0 ? <AlertTriangle className="w-4 h-4" /> : <CheckCircle2 className="w-4 h-4" />}
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className={`text-3xl font-extrabold ${breachedDeadlines.length > 0 ? 'text-rose-600' : 'text-slate-900'}`}>
              {breachedDeadlines.length}
            </span>
            <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
              breachedDeadlines.length > 0 ? 'bg-rose-100 text-rose-800' : 'bg-emerald-100 text-emerald-800'
            }`}>
              {breachedDeadlines.length === 0 ? 'Zero Breaches' : 'Audit Exception'}
            </span>
          </div>
          <p className="mt-2 text-xs text-slate-500">SOC 2 Type II strict SLA conformance</p>
        </div>

        {/* Metric 4 */}
        <div className="bg-white rounded-2xl p-5 border border-slate-200 shadow-sm">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-500">Next Audit Milestone</span>
            <div className="w-8 h-8 rounded-lg bg-cyan-50 text-cyan-600 flex items-center justify-center">
              <FileCheck2 className="w-4 h-4" />
            </div>
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-lg font-bold text-slate-900 truncate">Sep 15, 2026</span>
          </div>
          <p className="mt-2 text-xs text-slate-500">Quarterly Privileged Access Review</p>
        </div>
      </div>

      {/* FILTER & TIME-WINDOW CONTROLS BAR */}
      <div id="timeline-filters-bar" className="bg-white rounded-2xl p-4 border border-slate-200 shadow-sm space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          {/* Search Input */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              id="timeline-search-input"
              type="text"
              placeholder="Search by control code, resource ID, or title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-2 text-xs bg-slate-50 border border-slate-200 rounded-xl focus:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Time Window Selector */}
          <div className="flex items-center gap-1.5 bg-slate-100 p-1 rounded-xl">
            <button
              id="zoom-30days-btn"
              onClick={() => setZoomWindow('30days')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                zoomWindow === '30days' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              ±15 Days Window
            </button>
            <button
              id="zoom-60days-btn"
              onClick={() => setZoomWindow('60days')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                zoomWindow === '60days' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              ±30 Days Window
            </button>
            <button
              id="zoom-all-btn"
              onClick={() => setZoomWindow('all')}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
                zoomWindow === 'all' ? 'bg-white text-slate-900 shadow-xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Full Q3 Audit Cycle
            </button>
          </div>
        </div>

        {/* Filter Pills */}
        <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-100 text-xs">
          <span className="text-slate-400 font-medium flex items-center gap-1">
            <Filter className="w-3.5 h-3.5" /> Filter:
          </span>

          {/* Category Filter */}
          <select
            id="timeline-category-filter"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1 text-slate-700 font-medium focus:outline-none"
          >
            <option value="ALL">All Categories</option>
            <option value="IAM & Access">IAM & Access (CC6.1/CC6.2)</option>
            <option value="Change Management">Change Management (CC8.1)</option>
            <option value="Encryption & KMS">Encryption & KMS (CC6.6/6.7)</option>
            <option value="Vulnerability & SAST">Vulnerability & SAST (CC7.1)</option>
            <option value="Audit Milestone">Audit Milestones</option>
          </select>

          {/* Severity Filter */}
          <select
            id="timeline-severity-filter"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-50 border border-slate-200 rounded-lg px-2.5 py-1 text-slate-700 font-medium focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical & Breached Only</option>
            <option value="HIGH_PLUS">High & Critical</option>
            <option value="COMPLIANT">Compliant / Resolved</option>
          </select>

          {/* Type Filter */}
          <div className="flex items-center gap-1 ml-auto">
            <button
              onClick={() => setTypeFilter('ALL')}
              className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
                typeFilter === 'ALL' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              All Tracks
            </button>
            <button
              onClick={() => setTypeFilter('AUDIT_EVENTS')}
              className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
                typeFilter === 'AUDIT_EVENTS' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Audit Events Only
            </button>
            <button
              onClick={() => setTypeFilter('DEADLINES_ONLY')}
              className={`px-2.5 py-1 rounded-lg font-medium transition-colors ${
                typeFilter === 'DEADLINES_ONLY' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
              }`}
            >
              Deadlines Only
            </button>
          </div>
        </div>
      </div>

      {/* INTERACTIVE TIME-SERIES VISUAL TRACK */}
      <div className="bg-white rounded-2xl p-6 border border-slate-200 shadow-sm space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h2 className="text-base font-bold text-slate-900 flex items-center gap-2">
              <Activity className="w-4 h-4 text-indigo-600" />
              Continuous Time-Series Axis
            </h2>
            <p className="text-xs text-slate-500">
              Interactive dual-track view. Upper lane displays ingested evidence & audit scans; lower lane tracks SLA resolution deadlines and CPA milestones.
            </p>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-indigo-500" />
              <span className="text-slate-600">Audit Scan / Evidence</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              <span className="text-slate-600">SLA Deadline</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
              <span className="text-slate-600">Critical / Breached</span>
            </div>
          </div>
        </div>

        {/* Visual Timeline Canvas Container */}
        <div
          ref={timelineContainerRef}
          id="timeline-visual-canvas"
          className="relative bg-slate-950 text-white rounded-xl p-6 border border-slate-800 overflow-x-auto min-h-[360px] select-none"
        >
          <div className="min-w-[760px] relative h-[280px]">
            {/* Top Lane Label */}
            <div className="absolute top-2 left-0 text-[10px] uppercase font-mono font-bold tracking-wider text-slate-400">
              ▲ Ingested Evidence & Audit Events
            </div>

            {/* Bottom Lane Label */}
            <div className="absolute bottom-2 left-0 text-[10px] uppercase font-mono font-bold tracking-wider text-slate-400">
              ▼ SLA Deadlines & Compliance Milestones
            </div>

            {/* Central Time Axis Line */}
            <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-slate-700 -translate-y-1/2" />

            {/* Axis Date Markers */}
            {axisMarks.map((mark, i) => (
              <div
                key={i}
                className="absolute top-1/2 -translate-y-1/2 flex flex-col items-center pointer-events-none"
                style={{ left: `${mark.percent}%` }}
              >
                <div className="w-0.5 h-4 bg-slate-600" />
                <span className="text-[10px] font-mono text-slate-400 mt-1 whitespace-nowrap">
                  {mark.label}
                </span>
              </div>
            ))}

            {/* "NOW" Real-Time Marker Cursor */}
            <div
              className="absolute top-0 bottom-0 z-20 flex flex-col items-center pointer-events-none"
              style={{ left: `${nowPercent}%` }}
            >
              <div className="px-2 py-0.5 rounded-full bg-cyan-500 text-slate-950 text-[10px] font-extrabold uppercase tracking-wider shadow-lg shadow-cyan-500/50 flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-slate-950 animate-ping" />
                NOW (Aug 27)
              </div>
              <div className="w-0.5 flex-1 bg-cyan-400 border-l border-dashed border-cyan-300 opacity-90 shadow-sm" />
            </div>

            {/* Render Top Track Events (Audit Events, Snapshots, PRs, Webhooks) */}
            {typeFilter !== 'DEADLINES_ONLY' &&
              filteredEvents
                .filter((e) => e.type !== 'remediation_deadline')
                .map((event, idx) => {
                  const percent = getPercentPosition(event.date);
                  const isSelected = selectedEvent?.id === event.id;
                  const isTopLane = true;
                  // Stagger Y position to avoid overlapping markers
                  const staggerY = 24 + ((idx % 3) * 32);

                  return (
                    <motion.button
                      key={event.id}
                      id={`timeline-node-${event.id}`}
                      onClick={() => setSelectedEvent(event)}
                      whileHover={{ scale: 1.2, zIndex: 30 }}
                      className={`absolute -translate-x-1/2 z-10 p-2 rounded-xl transition-all group flex flex-col items-center ${
                        isSelected
                          ? 'ring-2 ring-cyan-400 scale-110 shadow-lg'
                          : 'hover:ring-1 hover:ring-slate-400'
                      }`}
                      style={{
                        left: `${percent}%`,
                        top: `${staggerY}px`
                      }}
                      title={`${event.title} (${event.date.toLocaleDateString()})`}
                    >
                      <div
                        className={`w-7 h-7 rounded-lg flex items-center justify-center text-white shadow-md ${
                          event.status === 'CRITICAL'
                            ? 'bg-rose-600 shadow-rose-600/50'
                            : event.status === 'WARNING'
                            ? 'bg-amber-600 shadow-amber-600/50'
                            : event.type === 'audit_milestone'
                            ? 'bg-purple-600 shadow-purple-600/50'
                            : 'bg-indigo-600 shadow-indigo-600/50'
                        }`}
                      >
                        {event.type === 'pr_event' ? (
                          <GitPullRequest className="w-3.5 h-3.5" />
                        ) : event.type === 'audit_milestone' ? (
                          <CalendarDays className="w-3.5 h-3.5" />
                        ) : event.type === 'webhook_event' ? (
                          <Radio className="w-3.5 h-3.5" />
                        ) : (
                          <ShieldCheck className="w-3.5 h-3.5" />
                        )}
                      </div>

                      {/* Drop line to central axis */}
                      <div className="w-px h-6 bg-slate-700 mt-1 opacity-60" />

                      {/* Tooltip on hover */}
                      <div className="hidden group-hover:block absolute -top-8 bg-slate-900 text-white text-[10px] px-2 py-1 rounded-md border border-slate-700 whitespace-nowrap shadow-lg pointer-events-none">
                        {event.title}
                      </div>
                    </motion.button>
                  );
                })}

            {/* Render Bottom Track Events (SLA Deadlines, Remediations, Milestones) */}
            {typeFilter !== 'AUDIT_EVENTS' &&
              filteredEvents
                .filter((e) => e.type === 'remediation_deadline')
                .map((event, idx) => {
                  const percent = getPercentPosition(event.date);
                  const isSelected = selectedEvent?.id === event.id;
                  const staggerY = 160 + ((idx % 3) * 32);

                  return (
                    <motion.button
                      key={event.id}
                      id={`timeline-node-${event.id}`}
                      onClick={() => setSelectedEvent(event)}
                      whileHover={{ scale: 1.2, zIndex: 30 }}
                      className={`absolute -translate-x-1/2 z-10 p-2 rounded-xl transition-all group flex flex-col items-center ${
                        isSelected
                          ? 'ring-2 ring-amber-400 scale-110 shadow-lg'
                          : 'hover:ring-1 hover:ring-slate-400'
                      }`}
                      style={{
                        left: `${percent}%`,
                        top: `${staggerY}px`
                      }}
                      title={`${event.title} (${event.date.toLocaleDateString()})`}
                    >
                      {/* Drop line from central axis */}
                      <div className="w-px h-6 bg-slate-700 mb-1 opacity-60" />

                      <div
                        className={`w-7 h-7 rounded-lg flex items-center justify-center text-white shadow-md ${
                          event.status === 'BREACHED'
                            ? 'bg-rose-600 shadow-rose-600/50 animate-pulse'
                            : event.status === 'RESOLVED'
                            ? 'bg-emerald-600 shadow-emerald-600/50'
                            : event.severity === 'CRITICAL'
                            ? 'bg-rose-500 shadow-rose-500/50'
                            : 'bg-amber-600 shadow-amber-600/50'
                        }`}
                      >
                        {event.status === 'BREACHED' ? (
                          <AlertTriangle className="w-3.5 h-3.5" />
                        ) : event.status === 'RESOLVED' ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : (
                          <Clock className="w-3.5 h-3.5" />
                        )}
                      </div>

                      {/* Tooltip on hover */}
                      <div className="hidden group-hover:block absolute -bottom-8 bg-slate-900 text-white text-[10px] px-2 py-1 rounded-md border border-slate-700 whitespace-nowrap shadow-lg pointer-events-none">
                        {event.title}
                      </div>
                    </motion.button>
                  );
                })}
          </div>
        </div>
      </div>

      {/* SELECTED EVENT DETAIL DRAWER / MODAL */}
      <AnimatePresence>
        {selectedEvent && (
          <motion.div
            initial={{ opacity: 0, y: 15 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 15 }}
            id="timeline-event-detail-card"
            className="bg-white rounded-2xl p-6 border-2 border-indigo-200 shadow-md relative"
          >
            <button
              onClick={() => setSelectedEvent(null)}
              className="absolute top-4 right-4 text-slate-400 hover:text-slate-700 p-1 rounded-lg bg-slate-100"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex flex-col lg:flex-row lg:items-start justify-between gap-6">
              <div className="space-y-3 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className={`px-2.5 py-0.5 rounded-full text-xs font-bold font-mono ${
                      selectedEvent.status === 'CRITICAL' || selectedEvent.status === 'BREACHED'
                        ? 'bg-rose-100 text-rose-800 border border-rose-300'
                        : selectedEvent.status === 'WARNING'
                        ? 'bg-amber-100 text-amber-800 border border-amber-300'
                        : selectedEvent.status === 'RESOLVED' || selectedEvent.status === 'COMPLIANT'
                        ? 'bg-emerald-100 text-emerald-800 border border-emerald-300'
                        : 'bg-indigo-100 text-indigo-800 border border-indigo-300'
                    }`}
                  >
                    {selectedEvent.status}
                  </span>

                  <span className="px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700">
                    {selectedEvent.category}
                  </span>

                  {selectedEvent.controlCode && (
                    <span className="px-2.5 py-0.5 rounded-full text-xs font-mono bg-indigo-50 text-indigo-700 border border-indigo-200">
                      {selectedEvent.controlCode}
                    </span>
                  )}

                  <span className="text-xs text-slate-500 font-mono">
                    Timestamp: <strong>{new Date(selectedEvent.timestamp).toLocaleString()}</strong>
                  </span>
                </div>

                <h3 className="text-lg font-bold text-slate-900">{selectedEvent.title}</h3>
                <p className="text-sm text-slate-600 leading-relaxed max-w-4xl">{selectedEvent.description}</p>

                {/* Cryptographic SHA-256 Proof Hash */}
                {selectedEvent.sha256Hash && (
                  <div className="bg-slate-50 rounded-xl p-3 border border-slate-200 text-xs font-mono space-y-1">
                    <span className="text-slate-500 uppercase font-sans font-semibold block text-[10px]">
                      Cryptographic WORM SHA-256 Chain Proof:
                    </span>
                    <span className="text-indigo-900 break-all select-all font-semibold block">
                      {selectedEvent.sha256Hash}
                    </span>
                  </div>
                )}

                {/* Raw Details / JSON Inspection */}
                {selectedEvent.details && (
                  <details className="text-xs font-mono bg-slate-900 text-slate-200 p-3 rounded-xl">
                    <summary className="cursor-pointer font-sans font-semibold text-cyan-400">
                      Inspect Raw Payload & Metadata
                    </summary>
                    <pre className="mt-2 overflow-x-auto text-[11px] text-slate-300 max-h-48">
                      {JSON.stringify(selectedEvent.details, null, 2)}
                    </pre>
                  </details>
                )}
              </div>

              {/* Action Sidebar in Detail Card */}
              <div className="flex flex-col gap-2 shrink-0 lg:w-64 border-t lg:border-t-0 lg:border-l lg:pl-6 border-slate-200 pt-4 lg:pt-0">
                <span className="text-xs font-semibold text-slate-500 uppercase">Available Actions</span>

                {/* If issue has auto-remediation */}
                {selectedEvent.issueRef && selectedEvent.issueRef.status === 'OPEN' && (
                  <button
                    id={`remediate-issue-${selectedEvent.issueRef.id}`}
                    onClick={() => handleRemediate(selectedEvent.issueRef!.id)}
                    disabled={remediatingId === selectedEvent.issueRef.id}
                    className="w-full px-4 py-2.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white text-xs font-bold transition-colors flex items-center justify-center gap-2 shadow-sm"
                  >
                    {remediatingId === selectedEvent.issueRef.id ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        Remediating...
                      </>
                    ) : (
                      <>
                        <Zap className="w-3.5 h-3.5" />
                        Auto-Remediate Finding
                      </>
                    )}
                  </button>
                )}

                {onNavigateTab && (
                  <button
                    onClick={() => onNavigateTab('evidence')}
                    className="w-full px-4 py-2 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-semibold transition-colors flex items-center justify-center gap-1.5 border border-slate-300"
                  >
                    <FileCheck2 className="w-3.5 h-3.5 text-slate-500" />
                    Open Evidence Vault
                  </button>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* CHRONOLOGICAL EVENT STREAM TABLE */}
      <div className="bg-white rounded-2xl border border-slate-200 shadow-sm overflow-hidden">
        <div className="p-6 border-b border-slate-200 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h3 className="text-base font-bold text-slate-900">
              Chronological Audit & Deadline Stream ({filteredEvents.length} Records)
            </h3>
            <p className="text-xs text-slate-500">
              Sorted sequentially by event timestamp and target SLA resolution dates.
            </p>
          </div>

          <span className="text-xs font-mono bg-slate-100 text-slate-600 px-3 py-1 rounded-full">
            Scope: {tenant.id}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="bg-slate-50 text-slate-500 uppercase tracking-wider font-semibold border-b border-slate-200">
                <th className="py-3.5 px-4">Event Date</th>
                <th className="py-3.5 px-4">Type</th>
                <th className="py-3.5 px-4">Control Code</th>
                <th className="py-3.5 px-4">Event Title & Resource</th>
                <th className="py-3.5 px-4">Category</th>
                <th className="py-3.5 px-4">Status / SLA</th>
                <th className="py-3.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 font-medium">
              {filteredEvents.map((item) => {
                const isSelected = selectedEvent?.id === item.id;
                return (
                  <tr
                    key={item.id}
                    className={`hover:bg-slate-50/80 transition-colors cursor-pointer ${
                      isSelected ? 'bg-indigo-50/60' : ''
                    }`}
                    onClick={() => setSelectedEvent(item)}
                  >
                    <td className="py-3.5 px-4 whitespace-nowrap text-slate-700 font-mono">
                      {new Date(item.timestamp).toLocaleDateString()}{' '}
                      <span className="text-slate-400">{new Date(item.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-semibold ${
                          item.type === 'remediation_deadline'
                            ? 'bg-amber-100 text-amber-800'
                            : item.type === 'audit_milestone'
                            ? 'bg-purple-100 text-purple-800'
                            : item.type === 'pr_event'
                            ? 'bg-blue-100 text-blue-800'
                            : 'bg-indigo-100 text-indigo-800'
                        }`}
                      >
                        {item.type === 'remediation_deadline'
                          ? 'SLA Deadline'
                          : item.type === 'audit_milestone'
                          ? 'Milestone'
                          : item.type === 'pr_event'
                          ? 'GitOps PR'
                          : 'Audit Evidence'}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap font-mono text-indigo-700 font-semibold">
                      {item.controlCode || 'N/A'}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="font-semibold text-slate-900">{item.title}</div>
                      {item.resourceId && (
                        <div className="text-[11px] text-slate-400 font-mono truncate max-w-xs">
                          {item.resourceId}
                        </div>
                      )}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap text-slate-600">
                      {item.category}
                    </td>
                    <td className="py-3.5 px-4 whitespace-nowrap">
                      <span
                        className={`px-2.5 py-0.5 rounded-full text-[10px] font-bold font-mono ${
                          item.status === 'CRITICAL' || item.status === 'BREACHED'
                            ? 'bg-rose-100 text-rose-800 border border-rose-200'
                            : item.status === 'WARNING'
                            ? 'bg-amber-100 text-amber-800 border border-amber-200'
                            : item.status === 'RESOLVED' || item.status === 'COMPLIANT'
                            ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                            : 'bg-slate-100 text-slate-700 border border-slate-200'
                        }`}
                      >
                        {item.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedEvent(item);
                        }}
                        className="text-xs text-indigo-600 hover:text-indigo-900 font-semibold inline-flex items-center gap-1"
                      >
                        Inspect <ChevronRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default VisualComplianceTimeline;
