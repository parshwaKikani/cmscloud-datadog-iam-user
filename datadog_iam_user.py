import boto3
import sys
import json

def getKeys(account):
    print("\nPlease set AWS environment variables for the " + account  + " account")
    key_id = access_key = token = None
    for key in sys.stdin:
        if "AWS_ACCESS_KEY_ID" in key:
            key_id = key.split("=")[1].rstrip()
        elif "AWS_SECRET_ACCESS_KEY" in key:
            access_key = key.split("=")[1].rstrip()
        elif "AWS_SESSION_TOKEN" in key:
            token = key.split("=")[1].rstrip()
            break
        else:
            print("\nInvalid access keys. Retrieve valid credentials and rerun the script.\n")
            break
    return key_id, access_key, token

def createSession(account):
    key_id, access_key, token = getKeys(account)
    region = "us-east-1"  # Set the region to us-east-1 by default as IAM is global
    session = boto3.session.Session(
        aws_access_key_id=key_id,
        aws_secret_access_key=access_key,
        aws_session_token=token,
        region_name=region
    )
    account_number = session.client('sts').get_caller_identity().get('Account')
    return session, region, account_number

def createIAMUserAndGroup(session, account_number):
    iam = session.client('iam')
    secretsmanager = session.client('secretsmanager')

    user_name = "datadog_user"
    group_name = "datadog_group"

    # Create IAM user
    iam.create_user(UserName=user_name)
    # Create access keys for the user
    keys_response = iam.create_access_key(UserName=user_name)
    # Store the keys in AWS Secrets Manager
    access_key_id = keys_response['AccessKey']['AccessKeyId']
    secret_access_key = keys_response['AccessKey']['SecretAccessKey']
    secret_string = json.dumps({
        'AccessKeyId': access_key_id,
        'SecretAccessKey': secret_access_key
    })
    secretsmanager.create_secret(Name="cms-cloud-datadog9", SecretString=secret_string)
    
    # Create IAM group
    iam.create_group(GroupName=group_name)
    # Attach policies to the group
    policies = ['PowerUserAccess', 'CMSApprovedAWSServices', 'CMSCloudApprovedRegions', 'ADO-Restriction-Policy']
    for policy in policies:
        if policy == "PowerUserAccess":
            iam.attach_group_policy(GroupName=group_name, PolicyArn=f'arn:aws:iam::aws:policy/{policy}')
        else:
            iam.attach_group_policy(GroupName=group_name, PolicyArn=f'arn:aws:iam::{account_number}:policy/{policy}')
    # Add user to the group
    iam.add_user_to_group(GroupName=group_name, UserName=user_name)

    # Attach permissions boundary to the user
    iam.put_user_permissions_boundary(UserName=user_name, PermissionsBoundary=f'arn:aws:iam::{account_number}:policy/cms-cloud-admin/ct-ado-poweruser-permissions-boundary-policy')

    # Create and attach the new policy to the group
    createAndAttachPolicy(iam, group_name)

def createAndAttachPolicy(iam, group_name):
    # AWS Integration IAM Policy (https://docs.datadoghq.com/integrations/guide/aws-manual-setup/?tab=accesskeysgovcloudorchinaonly)
    datadog_aws_integration_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": [
                    "apigateway:GET",
                    "autoscaling:Describe*",
                    "backup:List*",
                    "budgets:ViewBudget",
                    "cloudfront:GetDistributionConfig",
                    "cloudfront:ListDistributions",
                    "cloudtrail:DescribeTrails",
                    "cloudtrail:GetTrailStatus",
                    "cloudtrail:LookupEvents",
                    "cloudwatch:Describe*",
                    "cloudwatch:Get*",
                    "cloudwatch:List*",
                    "codedeploy:List*",
                    "codedeploy:BatchGet*",
                    "directconnect:Describe*",
                    "dynamodb:List*",
                    "dynamodb:Describe*",
                    "ec2:Describe*",
                    "ec2:GetTransitGatewayPrefixListReferences",
                    "ec2:SearchTransitGatewayRoutes",
                    "ecs:Describe*",
                    "ecs:List*",
                    "elasticache:Describe*",
                    "elasticache:List*",
                    "elasticfilesystem:DescribeFileSystems",
                    "elasticfilesystem:DescribeTags",
                    "elasticfilesystem:DescribeAccessPoints",
                    "elasticloadbalancing:Describe*",
                    "elasticmapreduce:List*",
                    "elasticmapreduce:Describe*",
                    "es:ListTags",
                    "es:ListDomainNames",
                    "es:DescribeElasticsearchDomains",
                    "events:CreateEventBus",
                    "fsx:DescribeFileSystems",
                    "fsx:ListTagsForResource",
                    "health:DescribeEvents",
                    "health:DescribeEventDetails",
                    "health:DescribeAffectedEntities",
                    "kinesis:List*",
                    "kinesis:Describe*",
                    "lambda:GetPolicy",
                    "lambda:List*",
                    "logs:DeleteSubscriptionFilter",
                    "logs:DescribeLogGroups",
                    "logs:DescribeLogStreams",
                    "logs:DescribeSubscriptionFilters",
                    "logs:FilterLogEvents",
                    "logs:PutSubscriptionFilter",
                    "logs:TestMetricFilter",
                    "organizations:Describe*",
                    "organizations:List*",
                    "rds:Describe*",
                    "rds:List*",
                    "redshift:DescribeClusters",
                    "redshift:DescribeLoggingStatus",
                    "route53:List*",
                    "s3:GetBucketLogging",
                    "s3:GetBucketLocation",
                    "s3:GetBucketNotification",
                    "s3:GetBucketTagging",
                    "s3:ListAllMyBuckets",
                    "s3:PutBucketNotification",
                    "ses:Get*",
                    "sns:List*",
                    "sns:Publish",
                    "sqs:ListQueues",
                    "states:ListStateMachines",
                    "states:DescribeStateMachine",
                    "support:DescribeTrustedAdvisor*",
                    "support:RefreshTrustedAdvisorCheck",
                    "tag:GetResources",
                    "tag:GetTagKeys",
                    "tag:GetTagValues",
                    "xray:BatchGetTraces",
                    "xray:GetTraceSummaries"
                ],
                "Effect": "Allow",
                "Resource": "*"
            }
        ]
    }
    # Create a policy
    response = iam.create_policy(
        PolicyName='datadog_aws_integration_policy',
        PolicyDocument=json.dumps(datadog_aws_integration_policy)
    )
    # Get the ARN of the newly created policy
    policy_arn = response['Policy']['Arn']

    # Attach the policy to the previously created group
    iam.attach_group_policy(
        GroupName=group_name,
        PolicyArn=policy_arn
    )

if __name__ == '__main__':
    account_session, region, account_number = createSession("AWS")
    createIAMUserAndGroup(account_session, account_number)
