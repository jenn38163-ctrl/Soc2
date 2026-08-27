# Policy 2: Software Change Management Policy (Trust Services Criteria CC8.1)

## 1. Purpose & Scope
This policy ensures all changes to production software, infrastructure, and databases are tested, reviewed, authorized, and logged prior to deployment.

## 2. Source Code Management & Branch Protection
* **Version Control:** All application code and Infrastructure as Code (IaC) must reside in the centralized version control repository (GitHub/GitLab).
* **Branch Protection:** Direct commits to `main` / `production` branches are strictly disabled.

## 3. Peer Review & Approval Controls
* **Peer Reviews:** Every code change requires at least one independent code review and explicit approval from a qualified engineer prior to merging.
* **Segregation of Duties:** Authors cannot approve their own pull requests.
* **Automated CI Gating:** Pull requests cannot be merged unless all automated checks (unit tests, security scans, vulnerability audits) pass cleanly.

## 4. Environment Separation
* **Isolation:** Development, Staging, and Production environments are physically and logically segregated.
* **Data Handling:** Production customer data is strictly prohibited in Non-Production environments.

## 5. Emergency Hotfix Procedure
In the event of a critical security incident or operational outage requiring an expedited fix:
* The emergency fix may be applied directly after verbal approval from the Engineering Lead/CTO.
* A post-deployment code review and retro-documentation (PR creation and incident log update) must occur within 24 hours of the emergency release.
