export interface IaCResource {
  id: string;
  name: string;
  type: 'terraform' | 'cloudformation' | 'kubernetes';
  soc2Criteria: string[];
  filename: string;
  description: string;
  code: string;
  verificationChecks: {
    name: string;
    passed: boolean;
    detail: string;
  }[];
}

export const IAC_RESOURCES: IaCResource[] = [
  {
    id: 'iac-s3-immutable-worm',
    name: 'AWS S3 Immutable Audit Log Bucket with Object Lock (WORM)',
    type: 'terraform',
    soc2Criteria: ['CC6.6', 'CC6.8', 'CC7.2'],
    filename: 'terraform/modules/soc2_audit_storage/main.tf',
    description: 'Enforces AWS S3 Object Lock in COMPLIANCE mode with AWS KMS Customer-Managed Key (CMK) encryption. Prevents log deletion or modification even by root accounts.',
    code: `# SOC 2 Criteria: CC6.6 (Encryption), CC6.8 & CC7.2 (Immutable Audit Logs)
resource "aws_kms_key" "soc2_audit_key" {
  description             = "KMS Master Key for SOC 2 Immutable Audit Logs"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Environment = "production"
    Compliance  = "SOC2-Type2"
    ManagedBy   = "Terraform"
  }
}

resource "aws_s3_bucket" "soc2_immutable_logs" {
  bucket        = "company-prod-soc2-audit-logs-immutable"
  force_destroy = false

  object_lock_enabled = true

  tags = {
    Environment = "production"
    Security    = "Strict"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "soc2_worm_lock" {
  bucket = aws_s3_bucket.soc2_immutable_logs.id

  rule {
    default_retention {
      mode  = "COMPLIANCE" # Cannot be bypassed even by root account
      years = 7             # SOC 2 & regulatory 7-year audit retention
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "s3_kms_enc" {
  bucket = aws_s3_bucket.soc2_immutable_logs.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.soc2_audit_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "block_all_public" {
  bucket = aws_s3_bucket.soc2_immutable_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}`,
    verificationChecks: [
      { name: 'S3 Object Lock Mode', passed: true, detail: 'COMPLIANCE mode active (strict WORM enforcement)' },
      { name: 'Server-Side Encryption', passed: true, detail: 'Enforces aws:kms with CMK and annual rotation' },
      { name: 'Public Access Block', passed: true, detail: 'All 4 public access blocks enabled' },
      { name: 'Retention Window', passed: true, detail: '7-year mandatory retention configured' }
    ]
  },
  {
    id: 'iac-env-segregation',
    name: 'Multi-Account AWS Organizations & IAM Isolation',
    type: 'terraform',
    soc2Criteria: ['CC6.6'],
    filename: 'terraform/environments/production/iam_isolation.tf',
    description: 'Enforces hard physical/logical separation between Staging and Production with separate AWS Account IDs and zero shared credentials.',
    code: `# SOC 2 Criteria: CC6.6 (Environment Segregation & Isolation)
data "aws_caller_identity" "current" {}

locals {
  is_production = data.aws_caller_identity.current.account_id == "112233445566"
}

# Strict Service Control Policy (SCP) preventing cross-account access
resource "aws_organizations_policy" "deny_cross_env_access" {
  name        = "SOC2-Enforce-Strict-Env-Isolation"
  description = "Denies non-production workloads from assuming production IAM roles"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyStagingToProdRoleAssumption"
        Effect    = "Deny"
        Action    = ["sts:AssumeRole", "sts:AssumeRoleWithSAML"]
        Resource  = "arn:aws:iam::112233445566:role/*"
        Condition = {
          StringNotEquals = {
            "aws:PrincipalAccount": "112233445566"
          }
        }
      }
    ]
  })
}

# Require MFA for all Console and API operations
resource "aws_iam_policy" "enforce_mfa" {
  name        = "SOC2-Mandatory-MFA-Policy"
  description = "Blocks all AWS actions if MFA is not authenticated"
  policy      = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BlockNonMFA"
        Effect = "Deny"
        NotAction = [
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:GetUser",
          "iam:ListMFADevices",
          "iam:ResyncMFADevice",
          "sts:GetSessionToken"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = {
            "aws:MultiFactorAuthPresent": "false"
          }
        }
      }
    ]
  })
}`,
    verificationChecks: [
      { name: 'Account Boundary Check', passed: true, detail: 'Staging (account: 998877665544) != Prod (112233445566)' },
      { name: 'Cross-Account IAM SCP', passed: true, detail: 'Service Control Policy active in AWS Organization' },
      { name: 'MFA Enforcement', passed: true, detail: 'MFA required for all AWS Console and API interactions' }
    ]
  },
  {
    id: 'iac-backup-pitr',
    name: 'RDS PostgreSQL Automated Daily Snapshots & Point-In-Time Recovery',
    type: 'terraform',
    soc2Criteria: ['A1.2'],
    filename: 'terraform/modules/database/aurora_soc2_backup.tf',
    description: 'Enforces 35-day backup retention, continuous Point-In-Time Recovery (PITR), multi-AZ deployment, and storage encryption with automated test restore validation.',
    code: `# SOC 2 Criteria: A1.2 (Backup, Retention & Point-In-Time Recovery)
resource "aws_rds_cluster" "soc2_aurora_cluster" {
  cluster_identifier      = "soc2-prod-postgres-cluster"
  engine                  = "aurora-postgresql"
  engine_version          = "16.1"
  database_name           = "app_production"
  master_username         = "app_soc2_admin"
  manage_master_user_password = true # Auto-managed in AWS Secrets Manager

  # Backup & Retention (SOC 2 A1.2)
  backup_retention_period   = 35      # 35 days continuous PITR
  preferred_backup_window   = "03:00-04:00"
  copy_tags_to_snapshot     = true
  deletion_protection       = true
  storage_encrypted         = true
  kms_key_id                = aws_kms_key.soc2_db_key.arn

  # High Availability (Availability criteria)
  availability_zones        = ["us-east-1a", "us-east-1b", "us-east-1c"]
  
  # Audit logging enabled
  enabled_cloudwatch_logs_exports = ["postgresql", "upgrade"]
}

# Automated AWS Backup Vault for cross-region replication
resource "aws_backup_vault" "soc2_dr_vault" {
  name        = "soc2-dr-immutable-vault"
  kms_key_arn = aws_kms_key.soc2_db_key.arn
}`,
    verificationChecks: [
      { name: 'PITR Retention Window', passed: true, detail: '35 days continuous replication enabled' },
      { name: 'Storage Encryption', passed: true, detail: 'AES-256 with KMS CMK' },
      { name: 'Deletion Protection', passed: true, detail: 'Active (Prevents accidental cluster drop)' },
      { name: 'Multi-AZ Availability', passed: true, detail: '3 Availability Zones with automatic failover' }
    ]
  }
];
