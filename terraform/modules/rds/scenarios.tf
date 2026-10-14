# Expected ratings are in ground-truth.json. Every database starts hardened (private, PostgreSQL,
# customer-managed KMS, TLS enforced, IAM and Secrets Manager authentication, 7-day backups, log
# exports) and lists only what differs. Deletion protection is off everywhere for easy teardown. rds-07 is the RDS Proxy in proxy.tf.
#
# controlled: the single-flaw severity ladder.
# realistic:  expected, ambiguous, and messy cases, including a proxy and a legacy MySQL database.
locals {
  all_scenarios = {
    # ---------- controlled ----------

    # LOW: private, but the storage is unencrypted.
    "rds-01" = {
      tier      = "controlled"
      name      = "analytics-db"
      encrypted = false
    }
    # MEDIUM: private, but TLS is optional because rds.force_ssl is 0.
    "rds-02" = {
      tier      = "controlled"
      name      = "billing-db"
      force_ssl = false
    }
    # MEDIUM: private instance with an associated role that can write to the exports bucket.
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
    # HIGH: public instance in an Internet-routed subnet with the database port open to the world.
    "rds-04" = {
      tier    = "controlled"
      name    = "crm-db"
      public  = true
      ingress = { cidrs = ["0.0.0.0/0"], description = "Remote access" }
    }
    # CRITICAL: unencrypted manual snapshot, taken before a migration, shared with every AWS account.
    "rds-05" = {
      tier      = "controlled"
      name      = "staging-db"
      encrypted = false
      snapshot  = { name = "pre-migration", shared_accounts = ["all"] }
    }

    # ---------- realistic ----------

    # EXPECTED: hardened orders database, reachable only through its proxy.
    "rds-06" = {
      tier    = "realistic"
      name    = "orders-db"
      ingress = { security_group_ids = [local.proxy_security_group_id], description = "From orders DB proxy" }
    }
    # MEDIUM: the orders database's proxy, with debug logging left on and TLS optional.
    "rds-07" = {
      tier = "realistic"
      name = "orders-db-proxy"
      type = "PROXY"
    }
    # AMBIGUOUS: public BI database, but 5432 is open to a single office IP.
    "rds-08" = {
      tier    = "realistic"
      name    = "bi-reporting-db"
      public  = true
      ingress = { cidrs = ["${cidrhost(var.office_cidr, 10)}/32"], description = "Office BI tool" }
    }
    # MEDIUM: legacy MySQL open to all of 10.0.0.0/8, with TLS optional, a static master password,
    # no IAM authentication, 1-day backups, and no log exports.
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
