import { Action, RbacDecision, Role } from '../types/soc2';
import { auditLogStore } from './auditLogger';

// Core Role-Based Access Control Matrix (Principle of Least Privilege - CC6.1, CC6.2)
export const DEFAULT_ROLE_PERMISSIONS: Record<Role, Action[]> = {
  admin: ['read', 'write', 'delete', 'export'],
  editor: ['read', 'write'],
  viewer: ['read']
};

export const ROLES_PERMISSIONS = DEFAULT_ROLE_PERMISSIONS;

export function canPerformAction(role: Role, action: Action, customMatrix?: Record<Role, Action[]>): boolean {
  const permissions = customMatrix || DEFAULT_ROLE_PERMISSIONS;
  return permissions[role]?.includes(action) ?? false;
}

export const ACTION_DESCRIPTIONS: Record<Action, string> = {
  read: 'Query and view resources & sensitive data',
  write: 'Create or update records & configuration settings',
  delete: 'Remove production records & infrastructure components',
  export: 'Download bulk datasets & decrypt bulk customer records'
};

export const ROLE_DESCRIPTIONS: Record<Role, string> = {
  admin: 'Full administrative access for system configurations and emergency operations',
  editor: 'Operational access for content updates and day-to-day workflow changes',
  viewer: 'Read-only access strictly conforming to least privilege principles'
};

/**
 * Authorizes a role to perform an action and generates an explicit SOC 2 policy decision log
 */
export async function authorize(
  role: Role,
  action: Action,
  actorId: string,
  traceId: string,
  resource: string = 'RBAC_Policy',
  ipAddress: string = '127.0.0.1',
  customMatrix?: Record<Role, Action[]>
): Promise<RbacDecision> {
  const permissions = customMatrix || DEFAULT_ROLE_PERMISSIONS;
  const allowed = permissions[role]?.includes(action) ?? false;
  const timestamp = new Date().toISOString();

  const policyReason = allowed
    ? `Access granted: Role '${role}' has explicit permission for action '${action}' under Principle of Least Privilege.`
    : `Access DENIED: Role '${role}' lacks entitlement for action '${action}'. Policy violation logged for SOC 2 CC6.1 audit.`;

  // Emit an explicit policy decision log for SOC 2 evidence (CC6.1, CC6.8, CC7.2)
  await auditLogStore.record({
    traceId,
    actorId,
    action: `authorize.${action}`,
    resource,
    ipAddress,
    status: allowed ? 'SUCCESS' : 'DENIED',
    metadata: {
      role,
      requestedAction: action,
      evaluatedResource: resource,
      reason: policyReason,
      leastPrivilegeChecked: true
    }
  });

  return {
    allowed,
    role,
    action,
    actorId,
    traceId,
    resource,
    timestamp,
    policyReason
  };
}
