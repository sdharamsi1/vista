# API Gateway facts payload

REST APIs (`apigateway`) and HTTP/WebSocket APIs (`apigatewayv2`) are reshaped into one common
format. Identical REST resource policies are de-duplicated into `shared.policies` and referenced by
`policy_ref`. Region-wide context (account logging role and throttle, usage plans, VPC links, and
custom domains) is listed once per region, and only for regions that contain an API. Stage variable
values are never collected, only their names.

```json
{
  "scan": { "account_id": "...", "regions": ["..."], "collection_errors_by_region": null },
  "shared": { "policies": { "pol-<hash>": { "Statement": [] } } },
  "account_settings": [ { "region": "...", "cloudwatch_role_arn": "...", "throttle": { "burstLimit": 5000, "rateLimit": 10000.0 } } ],
  "usage_plans": [ { "id": "...", "region": "...", "throttle": null, "quota": null, "api_stages": [ { "api_id": "...", "stage": "prod" } ], "api_key_count": 3 } ],
  "vpc_links": [ { "id": "...", "region": "...", "target_arns": ["arn:...:loadbalancer/net/..."] } ],
  "domain_names": [ { "domain_name": "api.example.com", "security_policy": "TLS_1_2", "mappings": [ { "base_path": "(none)", "api_id": "...", "stage": "prod" } ] } ],
  "apis": [
    {
      "api_id": "...",
      "name": "...",
      "type": "REST",
      "region": "...",
      "endpoint_types": ["REGIONAL"],
      "disable_execute_api_endpoint": false,
      "policy_ref": "pol-<hash>",
      "authorizers": { "<id>": { "type": "COGNITO_USER_POOLS", "identity_source": "..." } },
      "request_validators": { "<id>": { "validate_request_body": true } },
      "routes": [ { "route_key": "GET /orders", "authorization_type": "NONE", "api_key_required": true, "integration": { "type": "AWS_PROXY", "uri": "..." } } ],
      "stages": [ { "stage_name": "prod", "web_acl_arn": null, "access_log_destination": "...", "method_settings": {}, "variable_names": [] } ],
      "collection_errors": null
    }
  ]
}
```

- **routes[]** — every route with the authorization it enforces. REST routes carry their
  integration inline; HTTP/WebSocket routes reference `integrations[integration_id]` on the same API.
  Integrations record TLS verification settings and any `credentials_arn` they execute with.
- **stages[]** — WAF (REST only), access log destination, tracing, method/route settings (logging
  level, data tracing, throttling, caching), and stage variable names.
- **usage_plans[]** — throttle and quota per plan and per API stage, plus the number of API keys.

A full populated example is in
[`vista/apigateway/examples/sample-payload.json`](../../vista/apigateway/examples/sample-payload.json).
