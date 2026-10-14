output "scenario_resources" {
  description = "Scenario ID -> the identifier Vista cites in its findings, for scoring."
  value = merge(
    try(module.ec2[0].scenario_resources, {}),
    try(module.s3[0].scenario_resources, {}),
    try(module.apigateway[0].scenario_resources, {}),
    try(module.rds[0].scenario_resources, {}),
  )
}
