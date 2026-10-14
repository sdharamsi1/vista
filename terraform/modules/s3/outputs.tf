output "scenario_resources" {
  description = "Scenario ID -> bucket name that Vista cites in its findings."
  value       = { for id, scenario in module.scenario : id => scenario.bucket_name }
}
