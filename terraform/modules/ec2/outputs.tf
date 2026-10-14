output "scenario_resources" {
  description = "Scenario ID -> instance ID that Vista cites in its findings."
  value       = { for id, scenario in module.scenario : id => scenario.instance_id }
}
