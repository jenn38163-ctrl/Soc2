import React, { useState, useEffect } from 'react';
import confetti from 'canvas-confetti';
import { Header } from './components/Header';
import ComplianceDashboard from './components/ComplianceDashboard';
import { VisualComplianceTimeline } from './components/VisualComplianceTimeline';
import { OverviewDashboard } from './components/OverviewDashboard';
import { DogfoodingGuide } from './components/DogfoodingGuide';
import { IngestionHub } from './components/IngestionHub';
import { EvidenceEngineView } from './components/EvidenceEngineView';
import { RemediationCenter } from './components/RemediationCenter';
import { CorrectionLifecycleView } from './components/CorrectionLifecycleView';
import { WebhookSimulator } from './components/WebhookSimulator';
import { AuditLogViewer } from './components/AuditLogViewer';
import { RbacSimulator } from './components/RbacSimulator';
import { EncryptionPlayground } from './components/EncryptionPlayground';
import { CiCdPipelineView } from './components/CiCdPipelineView';
import { PolicyPortal } from './components/PolicyPortal';
import { IaCViewer } from './components/IaCViewer';
import { AuditorRoom } from './components/AuditorRoom';
import { TriAuditorConsensusHub } from './components/TriAuditorConsensusHub';
import { auditLogStore } from './lib/auditLogger';
import { multiTenantStore } from './lib/multiTenantStore';
import { SOC2_CONTROLS } from './lib/complianceMatrix';
import { INITIAL_POLICIES } from './lib/policyDocuments';
import { IAC_RESOURCES } from './lib/iacTemplates';
import { AuditLogPayload } from './types/soc2';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [auditorMode, setAuditorMode] = useState<boolean>(false);
  const [logs, setLogs] = useState<AuditLogPayload[]>(auditLogStore.getLogs());
  const [chainIntegrityValid, setChainIntegrityValid] = useState<boolean>(true);
  const [isVerifying, setIsVerifying] = useState<boolean>(false);
  const [, setTenantTick] = useState(0);

  // Subscribe to audit logs
  useEffect(() => {
    const unsubscribeAudit = auditLogStore.subscribe(() => {
      setLogs(auditLogStore.getLogs());
    });
    const unsubscribeTenant = multiTenantStore.subscribe(() => {
      setTenantTick((prev) => prev + 1);
      setLogs(auditLogStore.getLogs());
    });
    return () => {
      unsubscribeAudit();
      unsubscribeTenant();
    };
  }, []);

  const handleVerifyChain = async () => {
    setIsVerifying(true);
    const result = await auditLogStore.verifyChainIntegrity();
    setChainIntegrityValid(result.valid);
    setIsVerifying(false);
  };

  const handleExportEvidence = () => {
    const currentTenant = multiTenantStore.getCurrentTenant();
    const evidenceBundle = {
      exportMetadata: {
        system: 'SOC 2 Automated Compliance Platform',
        tenant: currentTenant,
        generatedAt: new Date().toISOString(),
        framework: 'AICPA 2017 Trust Services Criteria (Security, Confidentiality, Availability, Change Management)',
        complianceScore: `${currentTenant.complianceScore}% Type 2 Ready`,
        auditorCertified: true
      },
      integrations: multiTenantStore.getIntegrations(currentTenant.id),
      evidenceSnapshots: multiTenantStore.getSnapshots(currentTenant.id),
      openComplianceIssues: multiTenantStore.getIssues(currentTenant.id),
      backgroundWorkerJobs: multiTenantStore.getWorkerJobs(),
      webhookEventLogs: multiTenantStore.getWebhookLogs(),
      trustServicesCriteriaControls: SOC2_CONTROLS,
      immutableAuditLogs: {
        totalRecords: logs.length,
        wormChainIntegrity: chainIntegrityValid ? 'VALID (0 Tamper)' : 'INVALID',
        targetStorage: 'AWS S3 Object Lock (COMPLIANCE mode, 7-year retention)',
        records: logs
      },
      policies: INITIAL_POLICIES.map((p) => ({
        id: p.id,
        title: p.title,
        version: p.version,
        tscCriteria: p.tscCriteria,
        lastUpdated: p.lastUpdated,
        owner: p.owner,
        signatures: p.signatures
      })),
      infrastructureAsCode: IAC_RESOURCES.map((r) => ({
        id: r.id,
        name: r.name,
        criteria: r.soc2Criteria,
        filename: r.filename,
        verificationChecks: r.verificationChecks
      })),
      cicdPipeline: {
        workflowFile: '.github/workflows/soc2-compliance.yml',
        enforcedGates: [
          'CC6.1 Secret Detection (TruffleHog)',
          'CC7.1 Dependency Audit & Vulnerability Check (Trivy + npm audit)',
          'CC7.1/CC8.1 Static Application Security Testing (CodeQL SAST)',
          'CC8.1 Automated Testing & Build Gate'
        ],
        branchProtection: {
          enforcedBranch: 'main',
          minimumPeerApprovals: 1,
          segregationOfDuties: true,
          forcePushDisabled: true
        }
      }
    };

    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(evidenceBundle, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `soc2-type2-${currentTenant.slug}-evidence-bundle-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();

    confetti({
      particleCount: 80,
      spread: 60,
      origin: { y: 0.8 }
    });
  };

  const currentTenant = multiTenantStore.getCurrentTenant();

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans selection:bg-indigo-500 selection:text-white pb-16">
      {/* Global Navigation Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        auditorMode={auditorMode}
        setAuditorMode={setAuditorMode}
        onExportEvidence={handleExportEvidence}
        onRunAuditCheck={handleVerifyChain}
        overallScore={currentTenant.complianceScore}
      />

      {/* Auditor Mode Banner Indicator */}
      {auditorMode && (
        <div className="bg-amber-950/80 border-b border-amber-800/80 px-4 py-2 text-center text-xs text-amber-300 font-medium flex items-center justify-center gap-2">
          <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
          <span>
            <strong>Auditor Mode Active:</strong> High-density evidence inspection view tailored for external SOC 2 Type 1 & Type 2 audit firms.
          </span>
        </div>
      )}

      {/* Main Content View Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-8">
        {activeTab === 'compliance_dashboard' && (
          <ComplianceDashboard
            tenantId={currentTenant.id}
            onNavigateTab={setActiveTab}
          />
        )}

        {activeTab === 'timeline' && (
          <VisualComplianceTimeline
            tenantId={currentTenant.id}
            onNavigateTab={setActiveTab}
          />
        )}

        {activeTab === 'tri_auditor' && (
          <TriAuditorConsensusHub />
        )}

        {activeTab === 'overview' && (
          <OverviewDashboard
            onSelectTab={setActiveTab}
            recentLogs={logs}
            chainIntegrityValid={chainIntegrityValid}
            onRunAuditCheck={handleVerifyChain}
            isVerifying={isVerifying}
          />
        )}

        {activeTab === 'dogfooding' && (
          <DogfoodingGuide onNavigateTab={setActiveTab} />
        )}

        {activeTab === 'ingestion' && (
          <IngestionHub onRefreshData={() => setLogs(auditLogStore.getLogs())} />
        )}

        {activeTab === 'evidence_engine' && (
          <EvidenceEngineView onRefreshData={() => setLogs(auditLogStore.getLogs())} />
        )}

        {activeTab === 'remediation' && (
          <RemediationCenter onIssueResolved={() => setLogs(auditLogStore.getLogs())} />
        )}

        {activeTab === 'corrections' && (
          <CorrectionLifecycleView />
        )}

        {activeTab === 'webhooks' && (
          <WebhookSimulator onWebhookFired={() => setLogs(auditLogStore.getLogs())} />
        )}

        {activeTab === 'audit' && (
          <AuditLogViewer
            logs={logs}
            onNewLogAdded={() => setLogs(auditLogStore.getLogs())}
            chainIntegrityValid={chainIntegrityValid}
            onVerifyChain={handleVerifyChain}
            isVerifying={isVerifying}
          />
        )}

        {activeTab === 'rbac' && (
          <RbacSimulator onDecisionLogged={() => setLogs(auditLogStore.getLogs())} />
        )}

        {activeTab === 'encryption' && (
          <EncryptionPlayground onEncrypted={() => setLogs(auditLogStore.getLogs())} />
        )}

        {activeTab === 'pipeline' && (
          <CiCdPipelineView onPipelineCompleted={() => setLogs(auditLogStore.getLogs())} />
        )}

        {activeTab === 'policies' && (
          <PolicyPortal onPolicySigned={() => setLogs(auditLogStore.getLogs())} />
        )}

        {activeTab === 'iac' && (
          <IaCViewer />
        )}

        {activeTab === 'auditor' && (
          <AuditorRoom
            logs={logs}
            chainValid={chainIntegrityValid}
            onExportEvidence={handleExportEvidence}
          />
        )}
      </main>
    </div>
  );
}

