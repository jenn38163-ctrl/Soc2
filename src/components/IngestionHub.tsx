import React, { useState } from 'react';
import { 
  Cloud, 
  GitBranch, 
  Users, 
  ShieldAlert, 
  Database, 
  Terminal, 
  CheckCircle2, 
  AlertCircle, 
  ExternalLink, 
  Copy, 
  Check, 
  RefreshCw, 
  Play, 
  Code2, 
  Server, 
  KeyRound, 
  Lock, 
  Cpu, 
  Radio, 
  Search,
  Sparkles
} from 'lucide-react';
import { multiTenantStore, STEAMPIPE_TABLES } from '../lib/multiTenantStore';
import { Integration, IntegrationProvider } from '../types/soc2';

interface IngestionHubProps {
  onTriggerScan: () => void;
  onOpenIssueRemediation?: () => void;
}

export const IngestionHub: React.FC<IngestionHubProps> = ({ onTriggerScan, onOpenIssueRemediation }) => {
  const currentTenant = multiTenantStore.getCurrentTenant();
  const integrations = multiTenantStore.getIntegrations(currentTenant.id);

  const [activeSubTab, setActiveSubTab] = useState<'integrations' | 'steampipe' | 'prowler' | 'custodian'>('integrations');
  const [selectedProviderModal, setSelectedProviderModal] = useState<IntegrationProvider | null>(null);
  const [copiedText, setCopiedText] = useState<string | null>(null);

  // Steampipe state
  const [selectedTable, setSelectedTable] = useState<string>(STEAMPIPE_TABLES[0].name);
  const [sqlQuery, setSqlQuery] = useState<string>(STEAMPIPE_TABLES[0].queryExample);
  const [steampipeResults, setSteampipeResults] = useState<{ columns: string[]; rows: Array<Record<string, unknown>> } | null>(
    () => multiTenantStore.runSteampipeQuery(STEAMPIPE_TABLES[0].queryExample)
  );
  const [isExecutingSql, setIsExecutingSql] = useState(false);

  // Cloud Custodian state
  const [custodianYaml, setCustodianYaml] = useState<string>(`policies:
  - name: s3-enforce-soc2-public-block
    resource: aws.s3
    description: "SOC 2 CC6.6: Automatically detect and remediate buckets without public access block"
    filters:
      - type: missing-public-access-block
    actions:
      - type: set-public-access-block
        block_public_acls: true
        ignore_public_acls: true
        block_public_policy: true
        restrict_public_buckets: true
      - type: post-finding
        severity: CRITICAL
        compliance_criteria: ["CC6.6", "CC6.7"]`);

  const [custodianOutput, setCustodianOutput] = useState<string | null>(null);

  // Connection form state
  const [awsRoleArn, setAwsRoleArn] = useState<string>(`arn:aws:iam::${currentTenant.awsAccountId || '482910481920'}:role/SOC2ContinuousComplianceRole`);
  const [awsExternalId, setAwsExternalId] = useState<string>(currentTenant.externalId || 'soc2-ext-dogfood-prod-994821');
  const [awsRegion, setAwsRegion] = useState<string>('us-east-1');
  const [connectingProvider, setConnectingProvider] = useState<string | null>(null);
  const [connectionSuccess, setConnectionSuccess] = useState<boolean>(false);

  const handleCopy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(label);
    setTimeout(() => setCopiedText(null), 2000);
  };

  const handleRunSql = () => {
    setIsExecutingSql(true);
    setTimeout(() => {
      const results = multiTenantStore.runSteampipeQuery(sqlQuery);
      setSteampipeResults(results);
      setIsExecutingSql(false);
    }, 250);
  };

  const handleTableSelect = (tableName: string) => {
    setSelectedTable(tableName);
    const tableDef = STEAMPIPE_TABLES.find((t) => t.name === tableName);
    if (tableDef) {
      setSqlQuery(tableDef.queryExample);
      const results = multiTenantStore.runSteampipeQuery(tableDef.queryExample);
      setSteampipeResults(results);
    }
  };

  const handleRunCustodian = () => {
    setCustodianOutput('Running Cloud Custodian policy evaluation against live tenant AWS inventory...');
    setTimeout(() => {
      setCustodianOutput(`[Cloud Custodian v0.9.32] Executing Policy: s3-enforce-soc2-public-block
Resource Type: aws.s3 | Region: us-east-1
--------------------------------------------------------------------------------
[MATCH] Bucket 'soc2-prod-immutable-audit-logs-worm' -> COMPLIANT (PublicBlock=TRUE, SSE=aws:kms)
[MATCH] Bucket 'soc2-prod-customer-attachments-vault' -> COMPLIANT (PublicBlock=TRUE, SSE=aws:kms)
--------------------------------------------------------------------------------
Policy Evaluation Result: 0 non-compliant resources found. SOC 2 CC6.6 criteria satisfied.`);
    }, 450);
  };

  const handleSaveIntegration = async (provider: IntegrationProvider) => {
    setConnectingProvider(provider);
    
    // Simulate testing STS AssumeRole or OAuth
    await new Promise((r) => setTimeout(r, 600));

    multiTenantStore.addOrUpdateIntegration(currentTenant.id, {
      provider,
      name: provider === 'aws' ? `AWS Cloud (${awsRegion})` : `${provider.toUpperCase()} Integration`,
      authMethod: provider === 'aws' ? 'sts_role' : 'oauth_token',
      roleArn: provider === 'aws' ? awsRoleArn : undefined,
      externalId: provider === 'aws' ? awsExternalId : undefined,
      region: provider === 'aws' ? awsRegion : undefined,
      status: 'connected',
      activeChecks: provider === 'aws' 
        ? ['IAM MFA & Keys', 'S3 Public Block', 'RDS Encryption', 'Security Group Ingress']
        : ['Branch Protection', 'CodeQL SAST', 'Webhook Event Stream']
    });

    setConnectingProvider(null);
    setConnectionSuccess(true);
    setTimeout(() => {
      setConnectionSuccess(false);
      setSelectedProviderModal(null);
    }, 1200);
  };

  const awsTrustPolicyTemplate = JSON.stringify({
    Version: "2012-10-17",
    Statement: [
      {
        Effect: "Allow",
        Principal: {
          AWS: "arn:aws:iam::104829104829:root" // SOC 2 Scanner SaaS Engine Root
        },
        Action: "sts:AssumeRole",
        Condition: {
          StringEquals: {
            "sts:ExternalId": awsExternalId
          }
        }
      }
    ]
  }, null, 2);

  return (
    <div className="space-y-6" id="ingestion-hub-container">
      {/* Header with Tenant Badge */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400 bg-indigo-500/10 px-2.5 py-0.5 rounded-md border border-indigo-500/20">
              API Ingestion Layer
            </span>
            <span className="text-xs text-slate-400">
              Tenant: <strong className="text-white">{currentTenant.name}</strong> ({currentTenant.mode === 'internal' ? 'Dogfooding' : 'Commercial'})
            </span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight">Cloud & Developer API Ingestion Hub</h2>
          <p className="text-sm text-slate-400">
            Securely connect AWS (Cross-Account STS IAM Role Assumption), GitHub, Okta, and vulnerability feeds for continuous, non-blocking evidence collection.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={onTriggerScan}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Trigger Automated Scan Cycle</span>
          </button>
        </div>
      </div>

      {/* Sub Navigation Bar */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 overflow-x-auto">
        <button
          onClick={() => setActiveSubTab('integrations')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all ${
            activeSubTab === 'integrations'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Cloud className="w-4 h-4" />
          <span>Connected Providers ({integrations.length})</span>
        </button>

        <button
          onClick={() => setActiveSubTab('steampipe')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all ${
            activeSubTab === 'steampipe'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Database className="w-4 h-4" />
          <span>Steampipe SQL Query Runner</span>
          <span className="bg-emerald-500/20 text-emerald-300 text-[10px] px-1.5 py-0.5 rounded font-mono">Live</span>
        </button>

        <button
          onClick={() => setActiveSubTab('custodian')}
          className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-all ${
            activeSubTab === 'custodian'
              ? 'bg-indigo-600 text-white shadow-sm'
              : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
          }`}
        >
          <Code2 className="w-4 h-4" />
          <span>Cloud Custodian YAML Engine</span>
        </button>
      </div>

      {/* SUBTAB 1: INTEGRATIONS */}
      {activeSubTab === 'integrations' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* AWS Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between hover:border-slate-700 transition-all">
              <div>
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
                    <Cloud className="w-5 h-5" />
                  </div>
                  <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-semibold px-2 py-0.5 rounded-full flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Connected
                  </span>
                </div>
                <h3 className="text-base font-bold text-white">Amazon Web Services</h3>
                <p className="text-xs text-slate-400 mt-1">
                  STS Cross-Account IAM Role Assumption with External ID. Non-destructive read-only security audit.
                </p>
                <div className="mt-4 space-y-1.5 text-xs text-slate-300">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>IAM MFA Enforcement (CC6.1)</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>S3 Public Block & KMS (CC6.6)</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>RDS Encryption & PITR (CC6.7)</span>
                  </div>
                </div>
              </div>
              <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-400">AES-256 Encrypted</span>
                <button
                  onClick={() => setSelectedProviderModal('aws')}
                  className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 cursor-pointer"
                >
                  Configure Role
                </button>
              </div>
            </div>

            {/* GitHub Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between hover:border-slate-700 transition-all">
              <div>
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 rounded-lg bg-slate-800 border border-slate-700 flex items-center justify-center text-white">
                    <GitBranch className="w-5 h-5" />
                  </div>
                  <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-semibold px-2 py-0.5 rounded-full flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Connected
                  </span>
                </div>
                <h3 className="text-base font-bold text-white">GitHub Enterprise / Org</h3>
                <p className="text-xs text-slate-400 mt-1">
                  OAuth App & Real-time Webhooks. Verifies branch protections, peer reviews, and automated CI scans.
                </p>
                <div className="mt-4 space-y-1.5 text-xs text-slate-300">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Branch Protection on main (CC8.1)</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>1+ Approving Reviews Required</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Webhooks Receiver Active</span>
                  </div>
                </div>
              </div>
              <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-400">Webhook Sync: 30m</span>
                <button
                  onClick={() => setSelectedProviderModal('github')}
                  className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 cursor-pointer"
                >
                  Manage App
                </button>
              </div>
            </div>

            {/* Google Workspace / Okta Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between hover:border-slate-700 transition-all">
              <div>
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 rounded-lg bg-blue-500/10 border border-blue-500/30 flex items-center justify-center text-blue-400">
                    <Users className="w-5 h-5" />
                  </div>
                  <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-semibold px-2 py-0.5 rounded-full flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Connected
                  </span>
                </div>
                <h3 className="text-base font-bold text-white">Google Workspace / Okta</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Directory API synchronization. Enforces company-wide MFA and offboarded staff credential revocation.
                </p>
                <div className="mt-4 space-y-1.5 text-xs text-slate-300">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>MFA Adoption 100% (CC6.1)</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Deactivated 0 Active Keys (CC6.2)</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>24h Deprovisioning SLA</span>
                  </div>
                </div>
              </div>
              <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-400">Directory Sync</span>
                <button
                  onClick={() => setSelectedProviderModal('okta')}
                  className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 cursor-pointer"
                >
                  Configure SSO
                </button>
              </div>
            </div>

            {/* Snyk & Dependabot Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between hover:border-slate-700 transition-all">
              <div>
                <div className="flex items-start justify-between mb-3">
                  <div className="w-10 h-10 rounded-lg bg-purple-500/10 border border-purple-500/30 flex items-center justify-center text-purple-400">
                    <ShieldAlert className="w-5 h-5" />
                  </div>
                  <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[10px] font-semibold px-2 py-0.5 rounded-full flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" /> Connected
                  </span>
                </div>
                <h3 className="text-base font-bold text-white">Snyk & Dependabot</h3>
                <p className="text-xs text-slate-400 mt-1">
                  Continuous vulnerability intelligence. Tracks open CVE severity and enforces 30-day patch SLA.
                </p>
                <div className="mt-4 space-y-1.5 text-xs text-slate-300">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>High/Critical CVE Scans (CC7.1)</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>30-Day Patch SLA Enforcement</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                    <span>0 Unaddressed Criticals</span>
                  </div>
                </div>
              </div>
              <div className="mt-5 pt-3 border-t border-slate-800 flex items-center justify-between">
                <span className="text-[11px] text-slate-400">Daily Sync</span>
                <button
                  onClick={() => setSelectedProviderModal('snyk')}
                  className="text-xs font-semibold text-indigo-400 hover:text-indigo-300 cursor-pointer"
                >
                  Configure API
                </button>
              </div>
            </div>
          </div>

          {/* Active Integration Table Details */}
          <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
            <div className="px-5 py-4 border-b border-slate-800 flex items-center justify-between">
              <div>
                <h3 className="text-sm font-bold text-white">Configured Ingestion Connectors (Tenant: {currentTenant.name})</h3>
                <p className="text-xs text-slate-400">All credentials stored with AES-256-GCM encryption and KMS key envelope protection</p>
              </div>
              <span className="text-xs font-mono bg-slate-800 text-slate-300 px-2.5 py-1 rounded-md">
                KMS Envelope: kms-key-prod-soc2-v3
              </span>
            </div>

            <div className="divide-y divide-slate-800">
              {integrations.map((int) => (
                <div key={int.id} className="p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-slate-800/30 transition-colors">
                  <div className="flex items-start gap-3">
                    <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center text-indigo-400 shrink-0 mt-0.5">
                      {int.provider === 'aws' && <Cloud className="w-4 h-4" />}
                      {int.provider === 'github' && <GitBranch className="w-4 h-4" />}
                      {int.provider === 'google_workspace' && <Users className="w-4 h-4" />}
                      {int.provider === 'okta' && <Users className="w-4 h-4" />}
                      {int.provider === 'snyk' && <ShieldAlert className="w-4 h-4" />}
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-bold text-white">{int.name}</span>
                        <span className="text-[10px] font-mono uppercase bg-slate-800 text-slate-400 px-2 py-0.5 rounded">
                          {int.authMethod.replace('_', ' ')}
                        </span>
                      </div>
                      <p className="text-xs text-slate-400 font-mono mt-0.5">{int.credentialsMasked}</p>
                      <div className="flex flex-wrap items-center gap-2 mt-2">
                        {int.activeChecks.map((chk, i) => (
                          <span key={i} className="text-[11px] bg-slate-800/80 border border-slate-700/60 text-slate-300 px-2 py-0.5 rounded">
                            ✓ {chk}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="flex sm:flex-col items-center sm:items-end justify-between gap-1 text-right shrink-0">
                    <span className="text-xs text-emerald-400 font-semibold flex items-center gap-1">
                      <CheckCircle2 className="w-3.5 h-3.5" /> Healthy
                    </span>
                    <span className="text-[11px] text-slate-400">
                      Synced {new Date(int.lastSyncAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* SUBTAB 2: STEAMPIPE SQL QUERY RUNNER */}
      {activeSubTab === 'steampipe' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="text-base font-bold text-white">Steampipe Open-Source SQL Cloud Inventory</h3>
                  <span className="bg-indigo-500/20 text-indigo-300 text-[10px] font-mono px-2 py-0.5 rounded">PostgreSQL Engine</span>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Query live AWS, GitHub, and Okta infrastructure using standard SQL to audit compliance controls instantly.
                </p>
              </div>

              {/* Table quick selector */}
              <div className="flex items-center gap-2 overflow-x-auto">
                <span className="text-xs text-slate-400 whitespace-nowrap">Sample Tables:</span>
                {STEAMPIPE_TABLES.map((table) => (
                  <button
                    key={table.name}
                    onClick={() => handleTableSelect(table.name)}
                    className={`px-2.5 py-1 rounded text-xs font-mono transition-colors whitespace-nowrap ${
                      selectedTable === table.name
                        ? 'bg-indigo-600 text-white'
                        : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                    }`}
                  >
                    {table.name}
                  </button>
                ))}
              </div>
            </div>

            {/* SQL Input Area */}
            <div className="space-y-2">
              <div className="relative">
                <textarea
                  value={sqlQuery}
                  onChange={(e) => setSqlQuery(e.target.value)}
                  rows={3}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-400 focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                  placeholder="SELECT * FROM aws_iam_user WHERE mfa_enabled = false;"
                />
              </div>

              <div className="flex items-center justify-between">
                <div className="text-[11px] text-slate-400">
                  Tip: Query <code className="text-slate-300">aws_iam_user</code>, <code className="text-slate-300">aws_s3_bucket</code>, or <code className="text-slate-300">github_branch_protection</code>
                </div>
                <button
                  onClick={handleRunSql}
                  disabled={isExecutingSql}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer"
                >
                  {isExecutingSql ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                  <span>Execute SQL Query</span>
                </button>
              </div>
            </div>
          </div>

          {/* Steampipe Results Table */}
          {steampipeResults && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
              <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs font-mono font-bold text-white">Query Output</span>
                  <span className="text-[10px] font-mono bg-slate-800 text-slate-300 px-2 py-0.5 rounded">
                    {steampipeResults.rows.length} rows returned (0.042s)
                  </span>
                </div>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 font-mono border-b border-slate-800">
                    <tr>
                      {steampipeResults.columns.map((col) => (
                        <th key={col} className="px-4 py-2.5 font-semibold">
                          {col}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                    {steampipeResults.rows.map((row, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                        {steampipeResults.columns.map((col) => {
                          const val = row[col];
                          const isBool = typeof val === 'boolean';
                          return (
                            <td key={col} className="px-4 py-2.5 whitespace-nowrap">
                              {isBool ? (
                                <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${val ? 'bg-emerald-500/20 text-emerald-300' : 'bg-rose-500/20 text-rose-300'}`}>
                                  {val ? 'TRUE' : 'FALSE'}
                                </span>
                              ) : (
                                String(val ?? '')
                              )}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* SUBTAB 3: CLOUD CUSTODIAN */}
      {activeSubTab === 'custodian' && (
        <div className="space-y-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            <div>
              <h3 className="text-base font-bold text-white">Cloud Custodian Declarative Governance Policy Engine</h3>
              <p className="text-xs text-slate-400 mt-1">
                Define lightweight YAML policies to automatically validate infrastructure against SOC 2 Trust Services Criteria.
              </p>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Policy Definition (YAML)
                </label>
                <textarea
                  value={custodianYaml}
                  onChange={(e) => setCustodianYaml(e.target.value)}
                  rows={12}
                  className="w-full bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-indigo-300 focus:outline-none focus:border-indigo-500"
                />
                <button
                  onClick={handleRunCustodian}
                  className="mt-3 flex items-center gap-1.5 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer"
                >
                  <Play className="w-3.5 h-3.5 fill-current" />
                  <span>Evaluate Custodian Policy</span>
                </button>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Execution Output & Evaluation Log
                </label>
                <div className="h-[285px] bg-slate-950 border border-slate-800 rounded-lg p-3 text-xs font-mono text-emerald-400 overflow-y-auto whitespace-pre-wrap">
                  {custodianOutput || '// Click "Evaluate Custodian Policy" to simulate live policy check against tenant resources.'}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* AWS SETUP MODAL (STS Cross-Account Role Assumption) */}
      {selectedProviderModal === 'aws' && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 space-y-5 shadow-2xl overflow-y-auto max-h-[90vh]">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400">
                  <Cloud className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white">AWS Cross-Account IAM Role Setup</h3>
                  <p className="text-xs text-slate-400">Secure, zero-credential STS AssumeRole configuration (SOC 2 CC6.1, CC6.6)</p>
                </div>
              </div>
              <button
                onClick={() => setSelectedProviderModal(null)}
                className="text-slate-400 hover:text-white text-xs font-mono bg-slate-800 px-2 py-1 rounded"
              >
                ✕ Close
              </button>
            </div>

            {connectionSuccess ? (
              <div className="p-8 text-center space-y-3">
                <div className="w-12 h-12 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center mx-auto">
                  <CheckCircle2 className="w-6 h-6" />
                </div>
                <h4 className="text-base font-bold text-white">AWS Connection Verified & Encrypted!</h4>
                <p className="text-xs text-slate-400">
                  STS AssumeRole credentials validated. Background workers will now automatically collect SOC 2 evidence snapshots on a 60-minute interval.
                </p>
              </div>
            ) : (
              <div className="space-y-4 text-xs">
                <div>
                  <h4 className="font-semibold text-white mb-1">Step 1: Trust Policy for AWS IAM Role</h4>
                  <p className="text-slate-400 mb-2">
                    Create an IAM role in your AWS account and attach the following Trust Relationship with your tenant External ID:
                  </p>
                  <div className="relative bg-slate-950 border border-slate-800 rounded-lg p-3 font-mono text-[11px] text-amber-300">
                    <button
                      onClick={() => handleCopy(awsTrustPolicyTemplate, 'trust')}
                      className="absolute top-2 right-2 flex items-center gap-1 bg-slate-800 text-slate-300 hover:text-white px-2 py-1 rounded text-[10px]"
                    >
                      {copiedText === 'trust' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedText === 'trust' ? 'Copied' : 'Copy JSON'}</span>
                    </button>
                    <pre className="overflow-x-auto">{awsTrustPolicyTemplate}</pre>
                  </div>
                </div>

                <div className="space-y-3 pt-2">
                  <h4 className="font-semibold text-white">Step 2: Enter Assumed Role Details</h4>
                  
                  <div>
                    <label className="block text-slate-300 font-medium mb-1">Assumed Role ARN</label>
                    <input
                      type="text"
                      value={awsRoleArn}
                      onChange={(e) => setAwsRoleArn(e.target.value)}
                      className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-indigo-500"
                      placeholder="arn:aws:iam::123456789012:role/SOC2ComplianceAssumedRole"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-300 font-medium mb-1">Generated External ID</label>
                      <input
                        type="text"
                        value={awsExternalId}
                        onChange={(e) => setAwsExternalId(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-slate-300 focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                    <div>
                      <label className="block text-slate-300 font-medium mb-1">Primary Region</label>
                      <input
                        type="text"
                        value={awsRegion}
                        onChange={(e) => setAwsRegion(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs font-mono text-white focus:outline-none focus:border-indigo-500"
                      />
                    </div>
                  </div>
                </div>

                <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                  <button
                    onClick={() => setSelectedProviderModal(null)}
                    className="px-3.5 py-2 text-slate-400 hover:text-white rounded-lg"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleSaveIntegration('aws')}
                    disabled={connectingProvider === 'aws'}
                    className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg font-semibold shadow-sm cursor-pointer"
                  >
                    {connectingProvider === 'aws' ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <CheckCircle2 className="w-3.5 h-3.5" />
                    )}
                    <span>Test STS AssumeRole & Save</span>
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* GITHUB SETUP MODAL */}
      {selectedProviderModal === 'github' && (
        <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-lg w-full p-6 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <GitBranch className="w-5 h-5 text-white" />
                <h3 className="text-base font-bold text-white">GitHub Integration & Webhook Setup</h3>
              </div>
              <button
                onClick={() => setSelectedProviderModal(null)}
                className="text-slate-400 hover:text-white text-xs font-mono bg-slate-800 px-2 py-1 rounded"
              >
                ✕
              </button>
            </div>

            <p className="text-xs text-slate-300">
              Configure OAuth and GitHub App webhooks to verify automated branch protection (CC8.1) and code review gates.
            </p>

            <div className="space-y-2 text-xs">
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                <span className="text-slate-400 font-mono text-[11px]">Webhook Delivery URL:</span>
                <p className="font-mono text-emerald-400 break-all text-[11px]">https://soc2-api.company.internal/api/webhooks/github</p>
              </div>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg space-y-1">
                <span className="text-slate-400 font-mono text-[11px]">Subscribed Events:</span>
                <p className="text-slate-300 text-[11px]"><code>branch_protection_rule</code>, <code>pull_request</code>, <code>repository</code>, <code>push</code></p>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-2">
              <button
                onClick={() => setSelectedProviderModal(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Close
              </button>
              <button
                onClick={() => handleSaveIntegration('github')}
                className="px-3.5 py-1.5 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold cursor-pointer"
              >
                Save & Register Webhooks
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
