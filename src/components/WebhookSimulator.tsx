import React, { useState } from 'react';
import { 
  Radio, 
  Zap, 
  GitBranch, 
  Cloud, 
  Users, 
  AlertTriangle, 
  CheckCircle2, 
  Activity, 
  Clock, 
  Copy, 
  Check, 
  RefreshCw,
  Terminal,
  MessageSquare,
  Send,
  ShieldCheck,
  ExternalLink
} from 'lucide-react';
import { multiTenantStore } from '../lib/multiTenantStore';
import { WebhookEventLog } from '../types/soc2';

interface WebhookSimulatorProps {
  onWebhookFired?: () => void;
}

export const WebhookSimulator: React.FC<WebhookSimulatorProps> = ({ onWebhookFired }) => {
  const currentTenant = multiTenantStore.getCurrentTenant();
  const webhookLogs = multiTenantStore.getWebhookLogs();

  const [simulatingEvent, setSimulatingEvent] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Slack Micro-Lessons Interactive API Receiver State (Module 2)
  const [slackViolationType, setSlackViolationType] = useState<string>('OPEN_SSH_PORT');
  const [slackEmployeeEmail, setSlackEmployeeEmail] = useState<string>(currentTenant.contactEmail || 'alex.devops@company.internal');
  const [isDispatchingSlack, setIsDispatchingSlack] = useState(false);
  const [activeSlackPayload, setActiveSlackPayload] = useState<any | null>({
    title: '⚠️ Security Drift Alert: Open SSH Port 22 on AWS Security Group',
    content: 'An AWS Security Group rule was modified to permit inbound SSH traffic (port 22) from 0.0.0.0/0. SOC 2 Criteria CC6.6 requires network perimeter boundary isolation. Bastion hosts or public SSH exposure introduce severe brute-force and credential stuffing risks.',
    violationType: 'OPEN_SSH_PORT',
    employeeEmail: currentTenant.contactEmail || 'alex.devops@company.internal'
  });
  const [slackActionResponse, setSlackActionResponse] = useState<any | null>(null);
  const [isProcessingSlackAction, setIsProcessingSlackAction] = useState(false);

  const handleSimulateWebhook = async (
    provider: 'github' | 'aws' | 'okta',
    event: string,
    payloadSummary: string,
    actionTaken: string,
    severity: 'INFO' | 'WARNING' | 'ALERT'
  ) => {
    setSimulatingEvent(event);
    await new Promise((r) => setTimeout(r, 450));

    await multiTenantStore.receiveWebhook(
      currentTenant.id,
      provider,
      event,
      payloadSummary,
      actionTaken,
      severity
    );

    setSimulatingEvent(null);
    if (onWebhookFired) onWebhookFired();
  };

  const handleDispatchSlackLesson = async () => {
    setIsDispatchingSlack(true);
    setSlackActionResponse(null);

    try {
      const res = await fetch('/api/slack/trigger-micro-lesson', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tenantId: currentTenant.id,
          employeeEmail: slackEmployeeEmail,
          violationType: slackViolationType
        })
      });

      const data = await res.json();
      setActiveSlackPayload({
        ...data.lesson,
        violationType: slackViolationType,
        employeeEmail: slackEmployeeEmail,
        slackBlocks: data.slackBlocks
      });
      if (onWebhookFired) onWebhookFired();
    } catch (err: any) {
      console.error(err);
    } finally {
      setIsDispatchingSlack(false);
    }
  };

  const handleSlackInteractiveAction = async (actionId: string, violationType: string) => {
    setIsProcessingSlackAction(true);

    try {
      // Send URL-encoded payload as Slack production servers do
      const slackPayloadObj = {
        type: 'block_actions',
        user: {
          id: 'U_DEV_SIMULATOR',
          username: slackEmployeeEmail.split('@')[0],
          email: slackEmployeeEmail
        },
        actions: [
          {
            action_id: actionId,
            block_id: `block_ack_${violationType}`,
            value: JSON.stringify({
              tenantId: currentTenant.id,
              employeeEmail: slackEmployeeEmail,
              violationType,
              lessonId: activeSlackPayload?.id
            })
          }
        ]
      };

      const params = new URLSearchParams();
      params.append('payload', JSON.stringify(slackPayloadObj));

      const res = await fetch('/api/slack/actions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params.toString()
      });

      const data = await res.json();
      setSlackActionResponse(data);
      if (onWebhookFired) onWebhookFired();
    } catch (err: any) {
      console.error(err);
    } finally {
      setIsProcessingSlackAction(false);
    }
  };

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6" id="webhook-simulator-container">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold uppercase tracking-wider text-amber-400 bg-amber-500/10 px-2.5 py-0.5 rounded-md border border-amber-500/20 flex items-center gap-1">
              <Radio className="w-3 h-3 text-amber-400 animate-pulse" />
              Event-Driven Webhook Layer
            </span>
            <span className="text-xs text-slate-400">
              Tenant: <strong className="text-white">{currentTenant.name}</strong>
            </span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight">Real-Time Continuous Webhook Ingestion</h2>
          <p className="text-sm text-slate-400">
            Rather than waiting for hourly cron jobs, ingest real-time webhooks from GitHub, AWS EventBridge, and Okta to catch and remediate security drift in seconds.
          </p>
        </div>
      </div>

      {/* Webhook Test Scenarios */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <h3 className="text-sm font-bold text-white flex items-center gap-2">
          <Zap className="w-4 h-4 text-amber-400" />
          <span>Interactive Webhook Drift & Alert Simulator</span>
        </h3>
        <p className="text-xs text-slate-400">
          Trigger simulated real-world webhook events to observe immediate compliance status shifts, automatic issue creation, and WORM audit log updates:
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Test Scenario 1 */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3">
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs font-bold text-white">
                  <GitBranch className="w-4 h-4 text-rose-400" />
                  <span>Branch Protection Dropped</span>
                </div>
                <span className="text-[10px] font-mono uppercase bg-rose-500/20 text-rose-300 px-1.5 py-0.5 rounded">
                  Alert
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Simulates an engineer removing required PR approval reviews or allowing force pushes on <code>main</code> branch.
              </p>
            </div>
            <button
              onClick={() =>
                handleSimulateWebhook(
                  'github',
                  'branch_protection_rule.deleted',
                  'Branch protection disabled on repo: payment-gateway-service (branch: main). Direct force pushes allowed.',
                  'Triggered CRITICAL CC8.1 issue & notified engineering leads',
                  'ALERT'
                )
              }
              disabled={simulatingEvent === 'branch_protection_rule.deleted'}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer disabled:opacity-50"
            >
              {simulatingEvent === 'branch_protection_rule.deleted' ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Zap className="w-3.5 h-3.5" />
              )}
              <span>Simulate Protection Dropped</span>
            </button>
          </div>

          {/* Test Scenario 2 */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3">
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs font-bold text-white">
                  <Cloud className="w-4 h-4 text-amber-400" />
                  <span>AWS Security Group SSH Ingress</span>
                </div>
                <span className="text-[10px] font-mono uppercase bg-amber-500/20 text-amber-300 px-1.5 py-0.5 rounded">
                  Warning
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Simulates an AWS Admin opening Port 22 (SSH) to <code>0.0.0.0/0</code> on production database security group.
              </p>
            </div>
            <button
              onClick={() =>
                handleSimulateWebhook(
                  'aws',
                  'AuthorizeSecurityGroupIngress',
                  'Ingress rule added: TCP port 22 open to 0.0.0.0/0 on sg-0918239019231-prod-db',
                  'Logged security drift event & queued automated revocation bot',
                  'ALERT'
                )
              }
              disabled={simulatingEvent === 'AuthorizeSecurityGroupIngress'}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer disabled:opacity-50"
            >
              {simulatingEvent === 'AuthorizeSecurityGroupIngress' ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Zap className="w-3.5 h-3.5" />
              )}
              <span>Simulate SSH Ingress Open</span>
            </button>
          </div>

          {/* Test Scenario 3 */}
          <div className="bg-slate-950 border border-slate-800 rounded-xl p-4 flex flex-col justify-between space-y-3">
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs font-bold text-white">
                  <Users className="w-4 h-4 text-blue-400" />
                  <span>Okta Offboarded User Sync</span>
                </div>
                <span className="text-[10px] font-mono uppercase bg-blue-500/20 text-blue-300 px-1.5 py-0.5 rounded">
                  Info
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Simulates employee deprovisioning in Okta, initiating automated verification of cloud API key revocations.
              </p>
            </div>
            <button
              onClick={() =>
                handleSimulateWebhook(
                  'okta',
                  'user.lifecycle.deactivate',
                  'User sarah.contractor@legacy.io status changed to DEACTIVATED. Checked AWS IAM: 0 active keys found.',
                  'CC6.2 Offboarding SLA verified (24-hour compliance target met)',
                  'INFO'
                )
              }
              disabled={simulatingEvent === 'user.lifecycle.deactivate'}
              className="w-full flex items-center justify-center gap-1.5 px-3 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow-sm transition-all cursor-pointer disabled:opacity-50"
            >
              {simulatingEvent === 'user.lifecycle.deactivate' ? (
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              ) : (
                <Zap className="w-3.5 h-3.5" />
              )}
              <span>Simulate Staff Deprovision</span>
            </button>
          </div>
        </div>
      </div>

      {/* 🌟 MODULE 2: SLACK MICRO-LESSONS API RECEIVER & BLOCK KIT TEST HARNESS */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <MessageSquare className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-bold text-white">Slack Interactive Micro-Lessons API Receiver (Module 2)</h3>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Simulate and test real Slack interactive button selections hitting the live <code>POST /api/slack/actions</code> webhook endpoint.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 px-2 py-0.5 rounded font-bold">
              POST /api/slack/actions
            </span>
          </div>
        </div>

        {/* Dispatch Controls */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <div>
            <label className="block text-[11px] font-medium text-slate-300 mb-1">Violation Trigger Rule</label>
            <select
              value={slackViolationType}
              onChange={(e) => setSlackViolationType(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
            >
              <option value="OPEN_SSH_PORT">OPEN_SSH_PORT (CC6.6)</option>
              <option value="BYPASS_PR_REVIEW">BYPASS_PR_REVIEW (CC8.1)</option>
              <option value="SECRET_COMMITTED">SECRET_COMMITTED (CC6.7)</option>
              <option value="MFA_DISABLED">MFA_DISABLED (CC6.1)</option>
            </select>
          </div>

          <div>
            <label className="block text-[11px] font-medium text-slate-300 mb-1">Target Developer Email</label>
            <input
              type="email"
              value={slackEmployeeEmail}
              onChange={(e) => setSlackEmployeeEmail(e.target.value)}
              className="w-full px-3 py-2 bg-slate-950 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-amber-500 font-mono"
            />
          </div>

          <div className="flex items-end">
            <button
              onClick={handleDispatchSlackLesson}
              disabled={isDispatchingSlack}
              className="w-full flex items-center justify-center gap-1.5 px-3.5 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold shadow-sm transition-all disabled:opacity-50"
            >
              <Send className={`w-3.5 h-3.5 ${isDispatchingSlack ? 'animate-spin' : ''}`} />
              <span>Dispatch Micro-Lesson</span>
            </button>
          </div>
        </div>

        {/* Interactive Slack Message Simulation Card */}
        {activeSlackPayload && (
          <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3 font-sans">
            <div className="flex items-center justify-between pb-2 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 bg-slate-800 text-slate-300 rounded">
                  Slack Block Kit Preview
                </span>
                <span className="text-xs text-slate-400">
                  Channel: <strong className="text-slate-300">#security-drifts</strong>
                </span>
              </div>
              <span className="text-[10px] text-slate-500 font-mono">SOC 2 Bot • Just now</span>
            </div>

            <div className="space-y-2 text-xs">
              <h4 className="font-bold text-sm text-white">{activeSlackPayload.title}</h4>
              <p className="text-slate-300 leading-relaxed">{activeSlackPayload.content}</p>
              
              <div className="text-[11px] text-slate-400 font-mono">
                Target: {slackEmployeeEmail} | Rule: {slackViolationType}
              </div>
            </div>

            {/* Interactive Slack Action Buttons */}
            <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center gap-3">
              <button
                onClick={() => handleSlackInteractiveAction(`acknowledge_${slackViolationType}`, slackViolationType)}
                disabled={isProcessingSlackAction}
                className="flex items-center gap-1.5 px-3.5 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs rounded-lg shadow transition-all disabled:opacity-50 cursor-pointer"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>
                  {isProcessingSlackAction ? 'POSTing to /api/slack/actions...' : '✅ I Acknowledge and Fixed It'}
                </span>
              </button>

              <button
                onClick={() => handleSlackInteractiveAction('view_policy_doc', slackViolationType)}
                disabled={isProcessingSlackAction}
                className="flex items-center gap-1.5 px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold text-xs rounded-lg border border-slate-700 transition-all cursor-pointer"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                <span>📖 Open Policy Documentation</span>
              </button>
            </div>

            {/* Server Response Display */}
            {slackActionResponse && (
              <div className="mt-3 p-3 bg-emerald-950/70 border border-emerald-800 rounded-lg space-y-1">
                <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-300">
                  <ShieldCheck className="w-4 h-4" />
                  <span>Slack Action Endpoint (200 OK) Response:</span>
                </div>
                <p className="text-xs text-emerald-200 font-mono leading-relaxed">
                  {slackActionResponse.text}
                </p>
                <div className="text-[10px] text-emerald-400/80">
                  Status: Evidence captured in WORM ledger & training log updated in real time.
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Live Webhook Event Stream Log */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-indigo-400" />
            <h3 className="text-xs font-mono font-bold text-white">Live Ingested Webhook Stream</h3>
          </div>
          <span className="text-[11px] font-mono text-slate-400">{webhookLogs.length} events received</span>
        </div>

        <div className="divide-y divide-slate-800">
          {webhookLogs.map((log) => (
            <div key={log.id} className="p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-800/30 transition-colors text-xs font-mono">
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded ${
                    log.severity === 'ALERT'
                      ? 'bg-rose-500/20 text-rose-300'
                      : log.severity === 'WARNING'
                      ? 'bg-amber-500/20 text-amber-300'
                      : 'bg-indigo-500/20 text-indigo-300'
                  }`}>
                    {log.severity}
                  </span>
                  <span className="text-white font-bold">{log.event}</span>
                  <span className="text-slate-400 uppercase text-[10px] bg-slate-800 px-1.5 py-0.5 rounded">
                    {log.provider}
                  </span>
                </div>

                <p className="text-slate-300 font-sans text-xs leading-relaxed">{log.payloadSummary}</p>
                <div className="text-indigo-400 text-[11px] font-sans">
                  Action: {log.actionTaken}
                </div>
              </div>

              <div className="text-slate-400 text-[11px] shrink-0 text-right">
                {new Date(log.receivedAt).toLocaleTimeString()}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
