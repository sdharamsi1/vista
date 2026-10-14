output "scenario_resources" {
  description = "Scenario ID -> instance, snapshot, or proxy identifier that Vista cites in its findings."
  value = merge(
    { for id, scenario in module.scenario : id => scenario.identifier },
    local.proxy_enabled ? { "rds-07" = aws_db_proxy.orders[0].name } : {},
  )
}
