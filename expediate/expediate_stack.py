import cdk_nag

from aws_cdk import (
    Aspects,
    Duration,
    RemovalPolicy,
    Stack,
    aws_events as _events,
    aws_events_targets as _targets,
    aws_iam as _iam,
    aws_lambda as _lambda,
    aws_logs as _logs,
    aws_logs_destinations as _destinations
)

from constructs import Construct

class ExpediateStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        account = Stack.of(self).account
        region = Stack.of(self).region

        Aspects.of(self).add(
            cdk_nag.AwsSolutionsChecks(
                log_ignores = True,
                verbose = True
            )
        )

        cdk_nag.NagSuppressions.add_stack_suppressions(
            self, suppressions = [
                {'id': 'AwsSolutions-IAM4','reason': 'GitHub Issue'}
            ]
        )

        layer = _lambda.LayerVersion.from_layer_version_arn(
            self, 'layer',
            layer_version_arn = 'arn:aws:lambda:'+region+':070176467818:layer:getpublicip:3'
        )

### ERROR ###

        error = _lambda.Function.from_function_arn(
            self, 'error',
            'arn:aws:lambda:'+region+':'+account+':function:shipit-error'
        )

        timeout = _lambda.Function.from_function_arn(
            self, 'timeout',
            'arn:aws:lambda:'+region+':'+account+':function:shipit-timeout'
        )

### IAM ###

        role = _iam.Role(
            self, 'role', 
            assumed_by = _iam.ServicePrincipal(
                'lambda.amazonaws.com'
            )
        )

        role.add_managed_policy(
            _iam.ManagedPolicy.from_aws_managed_policy_name(
                'service-role/AWSLambdaBasicExecutionRole'
            )
        )

        role.add_to_policy(
            _iam.PolicyStatement(
                actions = [
                    'securityhub:BatchImportFindings'
                ],
                resources = [
                    'arn:aws:securityhub:'+region+':'+account+':product/'+account+'/default'
                ]
            )
        )

### ALERT ###

        alert = _lambda.Function(
            self, 'alert',
            function_name = 'alert',
            handler = 'alert.handler',
            code = _lambda.Code.from_asset('alert'),
            architecture = _lambda.Architecture.ARM_64,
            runtime = _lambda.Runtime.PYTHON_3_9,
            timeout = Duration.seconds(900),
            environment = dict(
                ACCOUNT = account,
                REGION = region
            ),
            memory_size = 256,
            role = role,
            layers = [
                layer
            ]
        )

        alertlogs = _logs.LogGroup(
            self, 'alertlogs',
            log_group_name = '/aws/lambda/'+alert.function_name,
            retention = _logs.RetentionDays.ONE_DAY,
            removal_policy = RemovalPolicy.DESTROY
        )

        alertsub = _logs.SubscriptionFilter(
            self, 'alertsub',
            log_group = alertlogs,
            destination = _destinations.LambdaDestination(error),
            filter_pattern = _logs.FilterPattern.all_terms('ERROR')
        )

        alerttime= _logs.SubscriptionFilter(
            self, 'alerttime',
            log_group = alertlogs,
            destination = _destinations.LambdaDestination(error),
            filter_pattern = _logs.FilterPattern.all_terms('Task','timed','out')
        )

### RULES ###

        cloudshell = _events.Rule(
            self, 'cloudshell',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.cloudshell'],
                detail = {
                    "eventSource": [
                        "cloudshell.amazonaws.com"
                    ],
                    "eventName": [
                        "CreateEnvironment",
                        "CreateSession",
                        "DeleteEnvironment",
                        "GetEnvironmentStatus",
                        "GetFileDownloadUrls",
                        "GetFileUploadUrls",
                        "PutCredentials",
                        "StartEnvironment",
                        "StopEnvironment"
                    ]
                }
            )
        )

        cloudshell.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        cloudtrail = _events.Rule(
            self, 'cloudtrail',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.cloudtrail'],
                detail = {
                    "eventSource": [
                        "cloudtrail.amazonaws.com"
                    ],
                    "eventName": [
                        "DeleteEventDataStore",
                        "DeleteTrail",
                        "PutEventSelectors",
                        "StopLogging",
                        "UpdateEventDataStore",
                        "UpdateTrail"
                    ]
                }
            )
        )

        cloudtrail.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        config = _events.Rule(
            self, 'config',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.config'],
                detail = {
                    "eventSource": [
                        "config.amazonaws.com"
                    ],
                    "eventName": [
                        "DeleteDeliveryChannel",
                        "StopConfigurationRecorder"
                    ]
                }
            )
        )

        config.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        connect = _events.Rule(
            self, 'connect',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.connect'],
                detail = {
                    "eventSource": [
                        "connect.amazonaws.com"
                    ],
                    "eventName": [
                        "CreateInstance"
                    ]
                }
            )
        )

        connect.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        ec2 = _events.Rule(
            self, 'ec2',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.ec2'],
                detail = {
                    "eventSource": [
                        "ec2.amazonaws.com"
                    ],
                    "eventName": [
                        "CreateDefaultVpc",
                        "CreateImage",
                        "CreateInstanceExportTask",
                        "CreateKeyPair",
                        "DeleteFlowLogs",
                        "DeleteVpc",
                        "DescribeInstanceAttribute",
                        "DisableEbsEncryptionByDefault",
                        "GetPasswordData",
                        "ModifyInstanceAttribute",
                        "ModifySnapshotAttribute",
                        "SharedSnapshotCopyInitiated",
                        "SharedSnapshotVolumeCreated"
                    ]
                }
            )
        )

        ec2.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        ecr = _events.Rule(
            self, 'ecr',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.ecr'],
                detail = {
                    "eventSource": [
                        "ecr.amazonaws.com"
                    ],
                    "eventName": [
                        "CreateRepository",
                        "GetAuthorizationToken"
                    ]
                }
            )
        )

        ecr.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        ecs = _events.Rule(
            self, 'ecs',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.ecs'],
                detail = {
                    "eventSource": [
                        "ecs.amazonaws.com"
                    ],
                    "eventName": [
                        "RegisterTaskDefinition",
                        "RunTask"
                    ]
                }
            )
        )

        ecs.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        eks = _events.Rule(
            self, 'eks',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.eks'],
                detail = {
                    "eventSource": [
                        "eks.amazonaws.com"
                    ],
                    "eventName": [
                        "CreateCluster",
                        "DeleteCluster"
                    ]
                }
            )
        )

        eks.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        elasticache = _events.Rule(
            self, 'elasticache',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.elasticache'],
                detail = {
                    "eventSource": [
                        "elasticache.amazonaws.com"
                    ],
                    "eventName": [
                        "AuthorizeCacheSecurityGroupEgress",
                        "AuthorizeCacheSecurityGroupIngress",
                        "CreateCacheSecurityGroup",
                        "DeleteCacheSecurityGroup",
                        "RevokeCacheSecurityGroupEgress",
                        "RevokeCacheSecurityGroupIngress"
                    ]
                }
            )
        )

        elasticache.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        elasticfilesystem = _events.Rule(
            self, 'elasticfilesystem',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.elasticfilesystem'],
                detail = {
                    "eventSource": [
                        "elasticfilesystem.amazonaws.com"
                    ],
                    "eventName": [
                        "DeleteFileSystem",
                        "DeleteMountTarget"
                    ]
                }
            )
        )

        elasticfilesystem.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        glue = _events.Rule(
            self, 'glue',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.glue'],
                detail = {
                    "eventSource": [
                        "glue.amazonaws.com"
                    ],
                    "eventName": [
                        "CreateDevEndpoint",
                        "DeleteDevEndpoint",
                        "UpdateDevEndpoint"
                    ]
                }
            )
        )

        glue.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        guardduty = _events.Rule(
            self, 'guardduty',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.guardduty'],
                detail = {
                    "eventSource": [
                        "guardduty.amazonaws.com"
                    ],
                    "eventName": [
                        "CreateIPSet"
                    ]
                }
            )
        )

        guardduty.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        iam = _events.Rule(
            self, 'iam',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.iam'],
                detail = {
                    "eventSource": [
                        "iam.amazonaws.com"
                    ],
                    "eventName": [
                        "AddUserToGroup",
                        "AttachGroupPolicy",
                        "AttachUserPolicy",
                        "ChangePassword",
                        "CreateAccessKey",
                        "CreateLoginProfile",
                        "CreateUser",
                        "CreateVirtualMFADevice",
                        "DeactivateMFADevice",
                        "DeleteAccessKey",
                        "DeleteUser",
                        "DeleteUserPolicy",
                        "DeleteVirtualMFADevice",
                        "DetachGroupPolicy",
                        "DetachUserPolicy",
                        "EnableMFADevice",
                        "PutUserPolicy",
                        "ResyncMFADevice",
                        "UpdateAccessKey",
                        "UpdateGroup",
                        "UpdateLoginProfile",
                        "UpdateSAMLProvider",
                        "UpdateUser"
                    ]
                }
            )
        )

        iam.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        kms = _events.Rule(
            self, 'kms',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.kms'],
                detail = {
                    "eventSource": [
                        "kms.amazonaws.com"
                    ],
                    "eventName": [
                        "DisableKey",
                        "ScheduleKeyDeletion"
                    ]
                }
            )
        )

        kms.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        lambdaX = _events.Rule(
            self, 'lambda',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.lambda'],
                detail = {
                    "eventSource": [
                        "lambda.amazonaws.com"
                    ],
                    "eventName": [
                        "AddLayerVersionPermission",
                        "CreateFunction",
                        "GetLayerVersionPolicy",
                        "PublishLayerVersion",
                        "UpdateFunctionConfiguration"
                    ]
                }
            )
        )

        lambdaX.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        macie = _events.Rule(
            self, 'macie',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.macie'],
                detail = {
                    "eventSource": [
                        "macie.amazonaws.com"
                    ],
                    "eventName": [
                        "DisableMacie"
                    ]
                }
            )
        )

        macie.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        macie2 = _events.Rule(
            self, 'macie2',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.macie2'],
                detail = {
                    "eventSource": [
                        "macie2.amazonaws.com"
                    ],
                    "eventName": [
                        "DisableMacie"
                    ]
                }
            )
        )

        macie2.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        organizations = _events.Rule(
            self, 'organizations',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.organizations'],
                detail = {
                    "eventSource": [
                        "organizations.amazonaws.com"
                    ],
                    "eventName": [
                        "LeaveOrganization"
                    ]
                }
            )
        )

        organizations.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        rds = _events.Rule(
            self, 'rds',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.rds'],
                detail = {
                    "eventSource": [
                        "rds.amazonaws.com"
                    ],
                    "eventName": [
                        "ModifyDBInstance",
                        "RestoreDBInstanceFromDBSnapshot"
                    ]
                }
            )
        )

        rds.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        rolesanywhere = _events.Rule(
            self, 'rolesanywhere',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.rolesanywhere'],
                detail = {
                    "eventSource": [
                        "rolesanywhere.amazonaws.com"
                    ],
                    "eventName": [
                        "CreateProfile",
                        "CreateTrustAnchor"
                    ]
                }
            )
        )

        rolesanywhere.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        route53 = _events.Rule(
            self, 'route53',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.route53'],
                detail = {
                    "eventSource": [
                        "route53.amazonaws.com"
                    ],
                    "eventName": [
                        "DisableDomainTransferLock",
                        "TransferDomainToAnotherAwsAccount"
                    ]
                }
            )
        )

        route53.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        s3 = _events.Rule(
            self, 's3',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.s3'],
                detail = {
                    "eventSource": [
                        "s3.amazonaws.com"
                    ],
                    "eventName": [
                        "PutBucketLogging",
                        "PutBucketWebsite",
                        "PutEncryptionConfiguration",
                        "PutLifecycleConfiguration",
                        "PutReplicationConfiguration",
                        "ReplicateObject",
                        "RestoreObject"
                    ]
                }
            )
        )

        s3.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        securityhub = _events.Rule(
            self, 'securityhub',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.securityhub'],
                detail = {
                    "eventSource": [
                        "securityhub.amazonaws.com"
                    ],
                    "eventName": [
                        "BatchUpdateFindings",
                        "DeleteInsight",
                        "UpdateFindings",
                        "UpdateInsight"
                    ]
                }
            )
        )

        securityhub.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        sso = _events.Rule(
            self, 'sso',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.sso'],
                detail = {
                    "eventSource": [
                        "sso.amazonaws.com"
                    ],
                    "eventName": [
                        "AttachCustomerManagedPolicyReferenceToPermissionSet",
                        "AttachManagedPolicyToPermissionSet",
                        "CreateAccountAssignment",
                        "CreateInstanceAccessControlAttributeConfiguration",
                        "CreatePermissionSet",
                        "DeleteAccountAssignment",
                        "DeleteInlinePolicyFromPermissionSet",
                        "DeleteInstanceAccessControlAttributeConfiguration",
                        "DeletePermissionsBoundaryFromPermissionSet",
                        "DeletePermissionSet",
                        "DetachCustomerManagedPolicyReferenceFromPermissionSet",
                        "DetachManagedPolicyFromPermissionSet",
                        "ProvisionPermissionSet",
                        "PutInlinePolicyToPermissionSet",
                        "PutPermissionsBoundaryToPermissionSet",
                        "UpdateInstanceAccessControlAttributeConfiguration",
                        "UpdatePermissionSet"
                    ]
                }
            )
        )

        sso.add_target(
            _targets.LambdaFunction(
                alert
            )
        )

        sts = _events.Rule(
            self, 'sts',
            event_pattern = _events.EventPattern(
                detail_type = ['AWS API Call via CloudTrail'],
                source = ['aws.sts'],
                detail = {
                    "eventSource": [
                        "sts.amazonaws.com"
                    ],
                    "eventName": [
                        "GetFederationToken",
                        "GetSessionToken"
                    ]
                }
            )
        )

        sts.add_target(
            _targets.LambdaFunction(
                alert
            )
        )
