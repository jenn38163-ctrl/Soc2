# Policy 1: Access Control Policy (Trust Services Criteria CC6.1, CC6.2, CC6.3)

## 1. Purpose & Scope
This policy defines the rules for provisioning, managing, and revoking access to internal systems, customer data, and production infrastructure. It applies to all employees, contractors, and automated service accounts.

## 2. Principle of Least Privilege
Access to systems, infrastructure, databases, and third-party tools is granted strictly based on role necessity (Least Privilege). Default access for any new account is zero/denied.

## 3. Identity & Authentication Requirements
* **Centralized IdP:** All user access must be authenticated through the company’s centralized Identity Provider (e.g., Okta, Google Workspace).
* **Multi-Factor Authentication (MFA):** MFA is mandatory for all user accounts across all platforms. Acceptable authentication methods include hardware keys (FIDO2) and TOTP authenticator apps. SMS-based MFA is prohibited.
* **Password Standards:** Passwords must be at least 16 characters in length and evaluated against common breach databases.

## 4. Access Provisioning & Offboarding
* **Provisioning:** Access requires explicit written approval from the team manager and system owner via a tracked ticket (e.g., Jira/GitHub Issue).
* **Immediate Offboarding:** Upon employee or contractor termination, HR notifies IT/Security. Access across all systems must be revoked within 24 hours of departure (immediately for involuntary terminations).

## 5. User Access Reviews
* Formal access reviews are conducted quarterly.
* System owners review current permission sets for all active users to identify and remove stale or excessive access. Signed evidence of completed reviews is retained for audit inspection.
