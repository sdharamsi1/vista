output "scenario_resources" {
  description = "Scenario ID -> API ID that Vista cites in its findings."
  value = merge(
    { for id, scenario in module.scenario : id => scenario.api_id },
    local.http_enabled ? { "apigw-09" = aws_apigatewayv2_api.webhooks[0].id } : {},
  )
}
