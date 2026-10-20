# ground-truth.json is the facts-only answer key: each scenario's condition, FSBP coverage, and
# published FSBP control severities. Every database starts from the module's hardened default
# (private, PostgreSQL, customer-managed KMS, TLS enforced, IAM and Secrets Manager authentication,
# 7-day backups, log exports) and lists only what differs. Deletion protection is off everywhere for
# easy teardown. rds-07 is the RDS Proxy in proxy.tf.
#
# controlled: one setting changed per database from that default.
# realistic:  a proxy and its target database, a public BI database, and a legacy MySQL database.
locals {
  all_scenarios = {
    # ---------- controlled ----------

    # Private instance with unencrypted storage.
    "rds-01" = {
      tier      = "controlled"
      name      = "analytics-db"
      encrypted = false
    }
    # Private instance with rds.force_ssl 0, so TLS is optional.
    "rds-02" = {
      tier      = "controlled"
      name      = "billing-db"
      force_ssl = false
    }
    # Private instance with an associated s3Export role that allows s3:PutObject on the exports bucket.
    "rds-03" = {
      tier = "controlled"
      name = "events-db"
      associated_role = {
        feature = "s3Export"
        statements = [{
          actions   = ["s3:PutObject", "s3:AbortMultipartUpload"]
          resources = ["${aws_s3_bucket.exports.arn}/*"]
        }]
      }
    }
    # Public instance in an Internet-routed subnet; TCP 5432 from 0.0.0.0/0.
    "rds-04" = {
      tier    = "controlled"
      name    = "crm-db"
      public  = true
      ingress = { cidrs = ["0.0.0.0/0"], description = "Remote access" }
    }
    # Unencrypted pre-migration manual snapshot of an unencrypted instance, shared with all AWS accounts.
    "rds-05" = {
      tier      = "controlled"
      name      = "staging-db"
      encrypted = false
      snapshot  = { name = "pre-migration", shared_accounts = ["all"] }
    }

    # ---------- realistic ----------

    # Orders database; TCP 5432 only from the proxy security group.
    "rds-06" = {
      tier    = "realistic"
      name    = "orders-db"
      ingress = { security_group_ids = [local.proxy_security_group_id], description = "From orders DB proxy" }
    }
    # The orders database's proxy, with debug logging on and require_tls false.
    "rds-07" = {
      tier = "realistic"
      name = "orders-db-proxy"
      type = "PROXY"
    }
    # Public BI database; TCP 5432 only from one office /32 address.
    "rds-08" = {
      tier    = "realistic"
      name    = "bi-reporting-db"
      public  = true
      ingress = { cidrs = ["${cidrhost(var.office_cidr, 10)}/32"], description = "Office BI tool" }
    }
    # Legacy MySQL with TCP 3306 from 10.0.0.0/8, require_secure_transport off, a static master
    # password, no IAM authentication, 1-day backups, and no log exports.
    "rds-09" = {
      tier             = "realistic"
      name             = "legacy-inventory-db"
      engine           = "mysql"
      ingress          = { cidrs = ["10.0.0.0/8"], description = "Corporate network" }
      force_ssl        = false
      iam_auth         = false
      managed_password = false
      backup_retention = 1
      log_exports      = false
    }
  }
}
