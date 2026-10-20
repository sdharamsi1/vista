# IAM permissions

The scanning identity needs read-only access plus Bedrock invoke. Common to every scan:

- `sts:GetCallerIdentity`, `ec2:DescribeRegions`
- `bedrock:InvokeModel` on the chosen model/inference profile

For **EC2**:

- `ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`, `ec2:DescribeSubnets`,
  `ec2:DescribeRouteTables`, `ec2:DescribeNetworkAcls`, `ec2:DescribeVolumes`
- `iam:GetInstanceProfile`, `iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`,
  `iam:GetRolePolicy`, `iam:GetPolicy`, `iam:GetPolicyVersion`
- `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeListeners`,
  `elasticloadbalancing:DescribeTargetHealth`

For **S3**:

- `s3:ListAllMyBuckets`, `s3:GetBucketLocation`
- `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicy`, `s3:GetBucketPolicyStatus`,
  `s3:GetBucketAcl`, `s3:GetBucketOwnershipControls`, `s3:GetBucketWebsite`,
  `s3:GetEncryptionConfiguration`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`,
  `s3:GetReplicationConfiguration`, `s3:GetBucketObjectLockConfiguration`, `s3:GetBucketCORS`,
  `s3:GetBucketTagging`
- `s3:GetAccountPublicAccessBlock`, `s3:ListAccessPoints`, `s3:GetAccessPointPolicyStatus`

For **API Gateway**:

- `apigateway:GET` (covers every REST and HTTP/WebSocket read: APIs, resources, routes,
  integrations, authorizers, request validators, stages, account settings, usage plans and keys,
  VPC links, domain names, and API mappings)

For **RDS**:

- `rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `rds:DescribeDBProxies`,
  `rds:DescribeDBSubnetGroups`, `rds:DescribeDBSnapshots`, `rds:DescribeDBSnapshotAttributes`,
  `rds:DescribeDBClusterSnapshots`, `rds:DescribeDBClusterSnapshotAttributes`,
  `rds:DescribeDBParameters`, `rds:DescribeDBClusterParameters`
- `ec2:DescribeSecurityGroups`, `ec2:DescribeSubnets`, `ec2:DescribeRouteTables`,
  `ec2:DescribeNetworkAcls`
- `kms:DescribeKey` (to tell AWS-managed `aws/rds` keys from customer-managed keys)

Anything denied is recorded per resource under `collection_errors` rather than aborting the scan.
