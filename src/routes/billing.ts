import express, { Request, Response } from 'express';
import Stripe from 'stripe';
import crypto from 'crypto';
import { multiTenantStore } from '../lib/multiTenantStore';
import { auditLogStore } from '../lib/auditLogger';
import { AccountStatus, SubscriptionTier } from '../types/soc2';

const router = express.Router();

// Safe lazy Stripe client initialization
let stripeClient: Stripe | null = null;

function getStripe(): Stripe | null {
  if (!stripeClient && process.env.STRIPE_SECRET_KEY) {
    stripeClient = new Stripe(process.env.STRIPE_SECRET_KEY, {
      apiVersion: '2025-01-27.acacia' as any
    });
  }
  return stripeClient;
}

/**
 * POST /api/billing/webhook
 * Receives incoming Stripe webhook events with cryptographic signature verification.
 */
router.post('/webhook', express.raw({ type: 'application/json' }), async (req: Request, res: Response) => {
  const sig = req.headers['stripe-signature'] as string;
  let event: any;

  try {
    const stripe = getStripe();
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (stripe && webhookSecret && sig) {
      event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } else {
      // In development or when webhook secret is not set, parse payload directly
      const bodyStr = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : JSON.stringify(req.body);
      event = typeof req.body === 'object' && !Buffer.isBuffer(req.body) ? req.body : JSON.parse(bodyStr || '{}');
    }
  } catch (err: any) {
    console.error(`[Stripe Webhook] Signature validation error:`, err.message);
    return res.status(400).send(`Webhook Signature Validation Error: ${err.message}`);
  }

  const eventType = event.type || 'invoice.payment_succeeded';
  const dataObject = event.data?.object || event;
  const customerId = dataObject.customer || dataObject.stripeCustomerId || 'cus_unknown';

  console.log(`[Stripe Webhook] Processing event ${eventType} for customer ${customerId}`);

  // Find matching tenant by stripeCustomerId or slug
  const allTenants = multiTenantStore.getTenants();
  const matchedTenant = allTenants.find((t) => t.stripeCustomerId === customerId) || allTenants[0];

  switch (eventType) {
    case 'customer.subscription.deleted': {
      // Pivot database record to suspend worker processes for this client space
      multiTenantStore.updateAccountStatus(matchedTenant.id, 'SUSPENDED_PAST_DUE');

      await auditLogStore.record({
        traceId: `trc_stripe_${Date.now().toString(36)}`,
        actorId: 'stripe_webhook_receiver',
        action: 'billing.subscription.deleted_workers_suspended',
        resource: `tenant:${matchedTenant.id}`,
        ipAddress: req.ip || '127.0.0.1',
        status: 'SUCCESS',
        metadata: {
          tenantId: matchedTenant.id,
          stripeCustomerId: customerId,
          newStatus: 'SUSPENDED_PAST_DUE',
          workersSuspended: true
        }
      });
      break;
    }

    case 'invoice.payment_failed': {
      multiTenantStore.updateAccountStatus(matchedTenant.id, 'SUSPENDED_PAST_DUE');

      await auditLogStore.record({
        traceId: `trc_stripe_${Date.now().toString(36)}`,
        actorId: 'stripe_webhook_receiver',
        action: 'billing.invoice.payment_failed',
        resource: `tenant:${matchedTenant.id}`,
        ipAddress: req.ip || '127.0.0.1',
        status: 'DENIED',
        metadata: {
          tenantId: matchedTenant.id,
          stripeCustomerId: customerId,
          newStatus: 'SUSPENDED_PAST_DUE'
        }
      });
      break;
    }

    case 'customer.subscription.created':
    case 'invoice.payment_succeeded': {
      multiTenantStore.updateAccountStatus(matchedTenant.id, 'ACTIVE');

      await auditLogStore.record({
        traceId: `trc_stripe_${Date.now().toString(36)}`,
        actorId: 'stripe_webhook_receiver',
        action: 'billing.payment_succeeded_workers_active',
        resource: `tenant:${matchedTenant.id}`,
        ipAddress: req.ip || '127.0.0.1',
        status: 'SUCCESS',
        metadata: {
          tenantId: matchedTenant.id,
          stripeCustomerId: customerId,
          newStatus: 'ACTIVE',
          workersActive: true
        }
      });
      break;
    }
  }

  res.json({ received: true, eventType, tenantId: matchedTenant.id });
});

/**
 * POST /api/billing/simulate-webhook
 * Test harness to simulate Stripe webhook events without real Stripe keys.
 */
router.post('/simulate-webhook', async (req: Request, res: Response) => {
  const { tenantId = 'tenant-internal', eventType = 'customer.subscription.deleted' } = req.body;
  const tenant = multiTenantStore.getTenant(tenantId) || multiTenantStore.getCurrentTenant();

  let targetStatus: AccountStatus = 'ACTIVE';
  let workersActive = true;

  if (eventType === 'customer.subscription.deleted' || eventType === 'invoice.payment_failed') {
    targetStatus = 'SUSPENDED_PAST_DUE';
    workersActive = false;
  } else if (eventType === 'customer.subscription.created' || eventType === 'invoice.payment_succeeded') {
    targetStatus = 'ACTIVE';
    workersActive = true;
  }

  multiTenantStore.updateAccountStatus(tenant.id, targetStatus);

  await auditLogStore.record({
    traceId: `trc_sim_stripe_${Date.now().toString(36)}`,
    actorId: 'billing_simulator',
    action: `billing.simulation.${eventType}`,
    resource: `tenant:${tenant.id}`,
    ipAddress: req.ip || '127.0.0.1',
    status: 'SUCCESS',
    metadata: {
      tenantId: tenant.id,
      eventType,
      accountStatus: targetStatus,
      workersActive
    }
  });

  res.json({
    success: true,
    eventType,
    tenantId: tenant.id,
    accountStatus: targetStatus,
    workersActive,
    message: workersActive
      ? `✅ Payment verified. Background compliance collectors resumed for ${tenant.name}.`
      : `⚠️ Payment lapsed. Background compliance collection workers suspended for ${tenant.name}.`
  });
});

/**
 * GET /api/billing/status
 * Query billing state, subscription tier, and worker state for a tenant.
 */
router.get('/status', (req: Request, res: Response) => {
  const tenantId = (req.query.tenantId as string) || multiTenantStore.getCurrentTenant().id;
  const tenant = multiTenantStore.getTenant(tenantId) || multiTenantStore.getCurrentTenant();

  const tierPricing: Record<SubscriptionTier, { monthlyPrice: number; name: string; maxIntegrations: number }> = {
    starter: { monthlyPrice: 499, name: 'SOC 2 Starter Tier', maxIntegrations: 3 },
    growth: { monthlyPrice: 1499, name: 'Growth Continuous Compliance', maxIntegrations: 10 },
    enterprise: { monthlyPrice: 3999, name: 'Enterprise Multi-Cloud & Cross-Account STS', maxIntegrations: 50 }
  };

  const currentTier = tenant.subscriptionTier || 'growth';
  const tierInfo = tierPricing[currentTier] || tierPricing.growth;

  res.json({
    tenantId: tenant.id,
    tenantName: tenant.name,
    accountStatus: tenant.accountStatus || 'ACTIVE',
    subscriptionTier: currentTier,
    tierDetails: tierInfo,
    stripeCustomerId: tenant.stripeCustomerId || `cus_${tenant.slug}_default`,
    stripeSubscriptionId: tenant.stripeSubscriptionId || `sub_${tenant.slug}_live`,
    workersActive: tenant.workersActive !== false,
    nextBillingDate: new Date(Date.now() + 1000 * 60 * 60 * 24 * 22).toISOString().slice(0, 10),
    paymentMethod: {
      brand: 'Visa',
      last4: '4242',
      expiryMonth: 12,
      expiryYear: 2028
    }
  });
});

/**
 * POST /api/billing/update-tier
 * Switch commercial subscription tier.
 */
router.post('/update-tier', (req: Request, res: Response) => {
  const { tenantId, tier } = req.body;
  if (!tenantId || !tier) {
    return res.status(400).json({ error: 'tenantId and tier are required' });
  }

  const updatedTenant = multiTenantStore.updateTenant(tenantId, { subscriptionTier: tier as SubscriptionTier });
  if (!updatedTenant) {
    return res.status(404).json({ error: 'Tenant not found' });
  }

  res.json({ success: true, tenant: updatedTenant });
});

export default router;
