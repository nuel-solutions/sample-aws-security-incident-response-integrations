from os import path
from aws_cdk import (
    CfnOutput,
    CfnParameter,
    Duration,
    RemovalPolicy,
    Stack,
    aws_events,
    aws_events_targets,
    aws_iam,
    aws_lambda,
    aws_lambda_python_alpha as py_lambda,
    aws_dynamodb as dynamodb,
    aws_events as events,
    aws_logs,
    aws_ssm,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
)
from .event_bus_logger_construct import EventBusLoggerConstruct
from cdk_nag import NagSuppressions
from constructs import Construct
from .constants import JIRA_AWS_ACCOUNT_ID, JIRA_EVENT_SOURCE, SECURITY_IR_EVENT_SOURCE

class AwsSecurityIncidentResponseSampleIntegrationsStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        """
        cdk for global resources used across all lambdas
        """
        table = dynamodb.Table(
            self,
            "IncidentsTable",
            partition_key=dynamodb.Attribute(
                name="PK", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(name="SK", type=dynamodb.AttributeType.STRING),
            removal_policy=RemovalPolicy.DESTROY,
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            point_in_time_recovery=True,
        )
        
        # Create a custom event bus for security incident events
        event_bus = events.EventBus(
            self,
            "SecurityIncidentEventBus",
            event_bus_name="security-incident-event-bus",
        )
        
        # Create an EventBusLogger to log all events from the event bus to CloudWatch Logs
        event_bus_logger = EventBusLoggerConstruct(
            self,
            "SecurityIncidentEventBusLogger",
            event_bus=event_bus,
            log_group_name=f"/aws/events/{event_bus.event_bus_name}",
            log_retention=aws_logs.RetentionDays.ONE_WEEK
        )
        
        """
        cdk for adding python package layers for shared files between lambdas
        """
        # Create a domain layer for shared domain models with correct directory structure
        domain_layer = aws_lambda.LayerVersion(
            self,
            "DomainLayer",
            code=aws_lambda.Code.from_asset(
                path.join(path.dirname(__file__), "..", "assets/domain"),
            ),
            compatible_runtimes=[aws_lambda.Runtime.PYTHON_3_13],
            description="Layer containing domain models for security incident response",
        )

        # Create a mappers layer for shared field mappers with correct directory structure
        mappers_layer = aws_lambda.LayerVersion(
            self,
            "MappersLayer",
            code=aws_lambda.Code.from_asset(
                path.join(path.dirname(__file__), "..", "assets/mappers"),
            ),
            compatible_runtimes=[aws_lambda.Runtime.PYTHON_3_13],
            description="Layer containing field mappers for security incident response",
        )
        
        # Create a mappers layer for shared client wrappers with correct directory structure
        wrappers_layer = aws_lambda.LayerVersion(
            self,
            "WrappersLayer",
            code=aws_lambda.Code.from_asset(
                path.join(path.dirname(__file__), "..", "assets/wrappers"),
            ),
            compatible_runtimes=[aws_lambda.Runtime.PYTHON_3_13],
            description="Layer containing field mappers for security incident response",
        )
        
        """
        cdk for setting log level
        """
        # Create log level parameter
        log_level_param = CfnParameter(
            self,
            "logLevel",
            type="String",
            description="The log level for Lambda functions (info or debug). Error logs are always enabled.",
            allowed_values=["info", "debug", "error"],
            default="error"
        )
        
        """
        cdk for setting Jira Client parameters
        """
        # Create Jira client parameters
        jira_email_param = CfnParameter(
            self,
            "jiraEmail",
            type="String",
            description="The email address that will be used with the Jira API.",
            no_echo=True,
        )

        # Store Jira URL CFN parameter
        jira_url_param = CfnParameter(
            self, "jiraUrl", type="String", description="The URL of the Jira API."
        )

        # Store Jira token CFN parameter
        jira_token_param = CfnParameter(
            self,
            "jiraToken",
            type="String",
            description="The API token that will be used with the Jira API.",
            no_echo=True,
        )
        
        jira_token_ssm_param = aws_ssm.StringParameter(
            self,
            "JiraTokenSecret",
            string_value=jira_token_param.value_as_string,
        )

        aws_ssm.StringParameter(
            self,
            "jiraEmailSSM",
            parameter_name="/SecurityIncidentResponse/jiraEmail",
            string_value=jira_email_param.value_as_string,
            description="Jira email",
        )

        aws_ssm.StringParameter(
            self,
            "jiraUrlSSM",
            parameter_name="/SecurityIncidentResponse/jiraUrl",
            string_value=jira_url_param.value_as_string,
            description="Jira URL",
        )
        
        """
        cdk for assets/jira_notifications_handler
        """
        # Create a custom role for the Lambda function with specific permissions
        jira_notifications_handler_role = aws_iam.Role(
            self,
            "JiraNotificationsHandlerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Jira Notifications Handler Lambda function"
        )
        
        # Add custom policy for CloudWatch Logs permissions (replacing AWSLambdaBasicExecutionRole)
        jira_notifications_handler_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ]
            )
        )
        
        # Create Lambda function for Jira Notifications handler with custom role
        jira_notifications_handler = py_lambda.PythonFunction(
            self,
            "JiraNotificationsHandler",
            entry=path.join(path.dirname(__file__), "..", "assets/jira_notifications_handler"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            layers=[domain_layer, mappers_layer, wrappers_layer],
            environment={
                "EVENT_BUS_NAME": event_bus.event_bus_name,
                "JIRA_EMAIL": "/SecurityIncidentResponse/jiraEmail",
                "JIRA_URL": "/SecurityIncidentResponse/jiraUrl",
                "INCIDENTS_TABLE_NAME": table.table_name,
                "JIRA_TOKEN_PARAM": jira_token_ssm_param.parameter_name,
                "EVENT_SOURCE": JIRA_EVENT_SOURCE,
                "LOG_LEVEL": log_level_param.value_as_string
            },
            role=jira_notifications_handler_role  # Use the custom role instead of default
        )

        # Create SNS topic for JIRA notifications
        jira_notifications_topic = sns.Topic(
            self,
            "JiraNotificationsTopic",
            display_name="Jira Notifications Topic"
        )

        # Add Lambda subscription to the JIRA notifications SNS topic
        jira_notifications_topic.add_subscription(
            subscriptions.LambdaSubscription(
                jira_notifications_handler
            )
        )

        # Create a topic policy for the JIRA notifications SNS topic
        jira_notifications_topic_policy = sns.TopicPolicy(
            self,
            "JiraNotificationsTopicPolicy",
            topics=[jira_notifications_topic],
        )

        # Add policy statements to the JIRA notifications SNS topic
        jira_notifications_topic_policy.document.add_statements(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                principals=[aws_iam.ServicePrincipal("events.amazonaws.com")],
                actions=["sns:Publish"],
                resources=[jira_notifications_topic.topic_arn],
                conditions={
                    "StringEquals": {
                        "AWS:SourceAccount": self.account
                    }
                }
            )
        )

        # Add policy to let JIRA IAM principal publish events to SNS topic
        jira_notifications_topic_policy.document.add_statements(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                principals=[aws_iam.AccountPrincipal(JIRA_AWS_ACCOUNT_ID)],
                actions=["SNS:Publish"],
                resources=[jira_notifications_topic.topic_arn]
            )
        )

        # Grant the SNS topic permission to invoke the Lambda function
        jira_notifications_handler.grant_invoke(
            aws_iam.ServicePrincipal("sns.amazonaws.com")
        )

        jira_notifications_handler.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    # Replace security-ir:* with specific permissions
                    "security-ir:GetCase",
                    "security-ir:UpdateCase",
                    "security-ir:ListCases",
                    "security-ir:CreateCase",
                    "security-ir:ListComments",
                    # Replace events:* with specific permissions
                    "events:PutEvents",
                    "events:DescribeRule",
                    "events:ListRules",
                    "lambda:GetFunctionConfiguration",
                    "lambda:UpdateFunctionConfiguration",
                ],
                resources=["*"]
            )
        )
        
        # Add specific permission for the custom event bus
        jira_notifications_handler.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["events:PutEvents"],
                resources=[event_bus.event_bus_arn],
            )
        )
        
        # allow adding SSM values
        jira_notifications_handler.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["ssm:GetParameter", "ssm:PutParameter"],
                resources=["*"],
            )
        )
        
        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            jira_notifications_handler,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir, events, lambda, and SSM actions",
                    "applies_to": ["Resource::*"]
                }
            ],
            True
        )
        
        # Add a specific rule for Jira notification events
        jira_notifications_rule = aws_events.Rule(
            self,
            "JiraNotificationsRule",
            description="Rule to capture events from Jira notifications handler",
            event_pattern=events.EventPattern(
                source=[JIRA_EVENT_SOURCE]
            ),
            event_bus=event_bus,
        )

        # Use the same log group as the event bus logger
        jira_notifications_rule.add_target(
            aws_events_targets.CloudWatchLogGroup(
                log_group=event_bus_logger.log_group
            )
        )

        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(jira_notifications_handler)

        """
        cdk for assets/security_ir_poller
        """
        # Create a custom role for the poller Lambda function
        poller_role = aws_iam.Role(
            self,
            "SecurityIncidentResponsePollerRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Poller Lambda function"
        )
        
        # Add custom policy for CloudWatch Logs permissions (replacing AWSLambdaBasicExecutionRole)
        poller_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ]
            )
        )
        
        # Create lambda function for Security Incident Response poller with custom role
        poller = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponsePoller",
            entry=path.join(path.dirname(__file__), "..", "assets/security_ir_poller"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.millis(30000),  # 30 seconds timeout
            layers=[domain_layer],  # Add the domain layer
            environment={
                "INCIDENTS_TABLE_NAME": table.table_name,
                "EVENT_BUS_NAME": event_bus.event_bus_name,
                "EVENT_SOURCE": SECURITY_IR_EVENT_SOURCE,
                "LOG_LEVEL": log_level_param.value_as_string
            },
            role=poller_role  # Use the custom role instead of default
        )

        aws_events.Rule(
            self,
            "SecurityIncidentResponsePollerRule",
            schedule=aws_events.Schedule.rate(duration=Duration.minutes(1)),
            targets=[aws_events_targets.LambdaFunction(poller)],
        )

        poller.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    # Replace security-ir:* with specific permissions
                    "security-ir:GetCase",
                    "security-ir:UpdateCase",
                    "security-ir:ListCases",
                    "security-ir:CreateCase",
                    "security-ir:ListComments",
                    # Replace events:* with specific permissions
                    "events:PutEvents",
                    "events:DescribeRule",
                    "events:ListRules",
                    "events:PutRule",
                    "lambda:GetFunctionConfiguration",
                    "lambda:UpdateFunctionConfiguration",
                ],
                resources=["*"],
            )
        )

        # Add specific permission for the custom event bus
        poller.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["events:PutEvents"],
                resources=[event_bus.event_bus_arn],
            )
        )

        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(poller)
        
        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            poller,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir, events, and lambda actions",
                    "applies_to": ["Resource::*"]
                }
            ],
            True
        )

        """
        cdk for assets/jira_client
        """
        # Create a custom role for the Jira Client Lambda function
        jira_client_role = aws_iam.Role(
            self,
            "SecurityIncidentResponseJiraClientRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Jira Client Lambda function"
        )
        
        # Add custom policy for CloudWatch Logs permissions (replacing AWSLambdaBasicExecutionRole)
        jira_client_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ]
            )
        )
        
        # create Lambda function for Jira with custom role
        jira_client = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponseJiraClient",
            entry=path.join(path.dirname(__file__), "..", "assets/jira_client"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.seconds(30),
            layers=[domain_layer, mappers_layer, wrappers_layer],
            environment={
                "JIRA_EMAIL": "/SecurityIncidentResponse/jiraEmail",
                "JIRA_URL": "/SecurityIncidentResponse/jiraUrl",
                "INCIDENTS_TABLE_NAME": table.table_name,
                "JIRA_TOKEN_PARAM": jira_token_ssm_param.parameter_name,
                "EVENT_SOURCE": SECURITY_IR_EVENT_SOURCE,
                "LOG_LEVEL": log_level_param.value_as_string
            },
            role=jira_client_role  # Use the custom role instead of default
        )

        # create Event Bridge rule for Jira Client Lambda function
        jira_client_rule = aws_events.Rule(
            self,
            "jira-client-rule",
            description="Rule to send all events from {event_bus.event_bus_name} to Jira Lambda function",
            event_pattern=events.EventPattern(source=[SECURITY_IR_EVENT_SOURCE]),
            event_bus=event_bus,
        )
        jira_client_rule.add_target(aws_events_targets.LambdaFunction(jira_client))
        
        # grant permissions to DynamoDB table and security-ir
        jira_client.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "security-ir:GetCaseAttachmentDownloadUrl",
                    "security-ir:ListComments"
                ],
                resources=["*"],
            )
        )

        # allow adding SSM values
        jira_client.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["ssm:GetParameter", "ssm:PutParameter"],
                resources=["*"],
            )
        )

        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(jira_client)
        
        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            jira_client,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir and SSM actions",
                    "applies_to": ["Resource::*"]
                }
            ],
            True
        )
        
        """
        cdk for assets/security_ir_client
        """
        # Create a custom role for the Security IR Client Lambda function
        security_ir_client_role = aws_iam.Role(
            self,
            "SecurityIncidentResponseClientRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Client Lambda function"
        )
        
        # Add custom policy for CloudWatch Logs permissions (replacing AWSLambdaBasicExecutionRole)
        security_ir_client_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ]
            )
        )
        
        security_ir_client = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponseClient",
            entry=path.join(path.dirname(__file__), "..", "assets/security_ir_client"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.seconds(30),
            layers=[domain_layer, mappers_layer, wrappers_layer],
            environment={
                "EVENT_SOURCE": JIRA_EVENT_SOURCE,
                "INCIDENTS_TABLE_NAME": table.table_name
            },
            role=security_ir_client_role  # Use the custom role instead of default
        )
        
        # create Event Bridge rule for Security Incident Response Client Lambda function
        security_ir_client_rule = aws_events.Rule(
            self,
            "security-ir-client-rule",
            description="Rule to send all events from {event_bus.event_bus_name} to Security Incident Response Client lambda function",
            event_pattern=events.EventPattern(source=[JIRA_EVENT_SOURCE]),
            event_bus=event_bus,
        )
        security_ir_client_rule.add_target(aws_events_targets.LambdaFunction(security_ir_client))
        
        # Add permissions for Security IR API
        security_ir_client.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "dynamodb:PutItem", 
                    "dynamodb:GetItem", 
                    "dynamodb:UpdateItem",
                    "security-ir:UpdateCase",
                    "security-ir:CreateCaseComment",
                    "security-ir:UpdateCaseComment",
                    "security-ir:UpdateCaseStatus",
                    "security-ir:ListComments",
                    "security-ir:GetCase",
                    "security-ir:CreateCase",
                    "security-ir:CloseCase",
                    "security-ir:GetCaseAttachmentUploadUrl"
                ],
                resources=["*"],
            )
        )
        
        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(security_ir_client)
        
        """
        cdk for setting Service Now Client parameters
        """
        # Create Service Now Client parameters
        service_now_instance_id_param = CfnParameter(
            self,
            "serviceNowInstanceId",
            type="String",
            description="The instance id that will be used with the Service Now API.",
            no_echo=True,
        )

        # Store Service Now User parameter
        service_now_user_param = CfnParameter(
            self,
            "serviceNowUser",
            type="String",
            description="The user for the Jira API."
        )

        # Store Service Now User Password parameter
        service_now_password_param = CfnParameter(
            self,
            "serviceNowPassword",
            type="String",
            description="The user password that will be used with the Service Now API.",
            no_echo=True,
        )
        
        service_now_password_ssm_param = aws_ssm.StringParameter(
            self,
            "serviceNowPasswordSSM",
            string_value=service_now_password_param.value_as_string,
            description="Service Now password",
        )

        aws_ssm.StringParameter(
            self,
            "serviceNowUserSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowUser",
            string_value=service_now_user_param.value_as_string,
            description="Service Now user",
        )

        aws_ssm.StringParameter(
            self,
            "serviceNowInstanceIdSSM",
            parameter_name="/SecurityIncidentResponse/serviceNowInstanceId",
            string_value=service_now_instance_id_param.value_as_string,
            description="Service Now instance id",
        )
        
        """
        cdk for assets/service_now_client
        """
        # Create a custom role for the ServiceNow Client Lambda function
        service_now_client_role = aws_iam.Role(
            self,
            "SecurityIncidentResponseServiceNowClientRole",
            assumed_by=aws_iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Custom role for Security Incident Response Service Now Client Lambda function"
        )
        
        # Add custom policy for CloudWatch Logs permissions (replacing AWSLambdaBasicExecutionRole)
        service_now_client_role.add_to_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents"
                ],
                resources=[
                    f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/*"
                ]
            )
        )
        
        # create Lambda function for Service Now with custom role
        service_now_client = py_lambda.PythonFunction(
            self,
            "SecurityIncidentResponseServiceNowClient",
            entry=path.join(path.dirname(__file__), "..", "assets/service_now_client"),
            runtime=aws_lambda.Runtime.PYTHON_3_13,
            timeout=Duration.seconds(30),
            layers=[domain_layer, mappers_layer, wrappers_layer],
            environment={
                "SERVICE_NOW_INSTANCE_ID": "/SecurityIncidentResponse/serviceNowInstanceId",
                "SERVICE_NOW_USER": "/SecurityIncidentResponse/serviceNowUser",
                "INCIDENTS_TABLE_NAME": table.table_name,
                "SERVICE_NOW_PASSWORD_PARAM": service_now_password_ssm_param.parameter_name,
                "EVENT_SOURCE": SECURITY_IR_EVENT_SOURCE,
                "LOG_LEVEL": log_level_param.value_as_string
            },
            role=service_now_client_role  # Use the custom role instead of default
        )

        # create Event Bridge rule for Service Now Client Lambda function
        service_now_client_rule = aws_events.Rule(
            self,
            "service-now-client-rule",
            description="Rule to send all events from {event_bus.event_bus_name} to Service Now Lambda function",
            event_pattern=events.EventPattern(source=[SECURITY_IR_EVENT_SOURCE]),
            event_bus=event_bus,
        )
        service_now_client_rule.add_target(aws_events_targets.LambdaFunction(service_now_client))
        
        # grant permissions to DynamoDB table and security-ir
        service_now_client.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=[
                    "security-ir:GetCaseAttachmentDownloadUrl",
                    "security-ir:ListComments"
                ],
                resources=["*"],
            )
        )

        # allow adding SSM values
        service_now_client.add_to_role_policy(
            aws_iam.PolicyStatement(
                effect=aws_iam.Effect.ALLOW,
                actions=["ssm:GetParameter", "ssm:PutParameter"],
                resources=["*"],
            )
        )

        # Grant specific DynamoDB permissions instead of full access
        table.grant_read_write_data(service_now_client)
        
        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            service_now_client,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for security-ir and SSM actions",
                    "applies_to": ["Resource::*"]
                }
            ],
            True
        )
        
        """
        cdk for adding NagSuppressions (if applicable)
        """        
        # Add suppressions for IAM5 findings related to wildcard resources
        NagSuppressions.add_resource_suppressions(
            security_ir_client,
            [
                {
                    "id": "AwsSolutions-IAM5",
                    "reason": "Wildcard resources are required for DynamoDB actions",
                    "applies_to": ["Resource::*"]
                }
            ],
            True
        )

        """
        cdk to output the generated name of CFN resources 
        """
        # Output the generated table name
        CfnOutput(
            self,
            "TableName",
            value=table.table_name,
            description="IncidentsTable DynamoDB Table Name",
            export_name=f"{construct_id}-table-name",
        )

        # Output the CloudWatch Logs information/description for the Poller lambda function
        CfnOutput(
            self,
            "SecurityIRPollerLambdaLogGroupName",
            value=poller.log_group.log_group_name,
            description="Lambda CloudWatch Logs Group Name",
        )

        # Output the CloudWatch Logs URL for the Poller lambda function
        CfnOutput(
            self,
            "SecurityIRPollerLambdaLogGroupUrl",
            value=f"https://console.aws.amazon.com/cloudwatch/home?region={Stack.of(self).region}#logsV2:log-groups/log-group/{poller.log_group.log_group_name}",
            description="Lambda CloudWatch Logs URL",
        )

        # Output the Poller lambda function ARN
        CfnOutput(
            self,
            "SecurityIRPollerLambdaArn",
            value=poller.function_arn,
            description="Poller Lambda Function ARN",
        )
        
        CfnOutput(
            self,
            "JiraClientLambdaArn",
            value=jira_client.function_arn,
            description="Jira Client Lambda Function ARN",
        )
        
        CfnOutput(
            self,
            "SecurityIRClientLambdaArn",
            value=security_ir_client.function_arn,
            description="Security Incident Response Client Lambda Function ARN",
        )
        
        # Output the CloudWatch Logs information/description for the jira-notifications-handler lambda function
        CfnOutput(
            self,
            "JiraNotificationsHandlerLambdaLogGroup",
            value=jira_notifications_handler.log_group.log_group_name,
            description="Jira Notifications Handler Lambda CloudWatch Logs Group Name"
        )

        # Output the CloudWatch Logs URL for the jira-notifications-handler lambda function
        CfnOutput(
            self,
            "JiraNotificationsHandlerLambdaLogGroupUrl",
            value=f"https://console.aws.amazon.com/cloudwatch/home?region={Stack.of(self).region}#logsV2:log-groups/log-group/{jira_notifications_handler.log_group.log_group_name}",
            description="Jira Notifications Handler Lambda CloudWatch Logs URL"
        )

        """
        Add suppressions for AWS Lambda functions
        """

        # Define constants for suppressions
        IAM4_SUPPRESSION = {
            "id": "AwsSolutions-IAM4",
            "reason": "Built-in LogRetention Lambda role requires AWSLambdaBasicExecutionRole managed policy",
            "applies_to": [
                "Policy::arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
            ],
        }

        IAM5_APPLIES_TO = [
            "Resource::arn:aws:logs:*:*:log-group:*",
            "Action::logs:DeleteLogGroup",
            "Action::logs:PutRetentionPolicy",
            "Action::logs:DeleteRetentionPolicy",
            "Action::logs:DescribeLogGroups",
        ]

        IAM5_SUPPRESSION = {
            "id": "AwsSolutions-IAM5",
            "reason": "Built-in LogRetention Lambda needs these permissions to manage log retention",
            "applies_to": IAM5_APPLIES_TO,
        }

        SQS3_SUPPRESSION = {
            "id": "AwsSolutions-SQS3",
            "reason": "SQS is used as DLQ",
        }
        
        SNS3_SUPPRESSION = {
            "id": "AwsSolutions-SNS3",
            "reason": "Jira Notifications SNS Topic requires encryption disabled, see Jira documentation - https://support.atlassian.com/cloud-automation/docs/configure-aws-sns-for-jira-automation/",
        }
        
        patterns = [
            f"/{construct_id}/Custom::LogRetention*",
            f"/{construct_id}/LogRetention*",
            "Custom::LogRetention*",
            "LogRetention*",
        ]

        NagSuppressions.add_resource_suppressions(
            poller,
            [
                # IAM4 suppression removed
                # {
                #     "id": "AwsSolutions-IAM4",
                #     "reason": "Poller uses Managed Lambda policy as part of execution.  This is best practice",
                # },
                # IAM5 suppression removed
                # {
                #     "id": "AwsSolutions-IAM5",
                #     "reason": "Poller needs complete access to Security Incident Response",
                # },
                {
                    "id": "AwsSolutions-L1",
                    "reason": "Using the latest available runtime for Python (3.13)",
                },
            ],
            True,
        )

        for pattern in patterns:
            try:
                NagSuppressions.add_resource_suppressions_by_path(
                    self,
                    [pattern],
                    [IAM4_SUPPRESSION, IAM5_SUPPRESSION],  # Add back suppressions for LogRetention Lambda
                    True,
                )
            except RuntimeError:
                continue

        # Add stack-level suppression as fallback
        NagSuppressions.add_stack_suppressions(
            self, [
                IAM4_SUPPRESSION,
                IAM5_SUPPRESSION,
                SQS3_SUPPRESSION,
                SNS3_SUPPRESSION,
                {
                    "id": "AwsSolutions-L1",
                    "reason": "CDK-generated Lambda functions may use older runtimes which we cannot directly control"
                }
            ]  # Add back IAM4 for LogRetention
        )
        
        # Output the event bus name
        CfnOutput(
            self,
            "EventBusName",
            value=event_bus.event_bus_name,
            description="Security Incident Event Bus Name",
            export_name=f"{construct_id}-event-bus-name",
        )

        # Output the log group name
        CfnOutput(
            self,
            "EventBusLogGroupName",
            value=event_bus_logger.log_group.log_group_name,
            description="Security Incident Event Bus Log Group Name",
            export_name=f"{construct_id}-log-group-name",
        )

        # Store references for other stacks
        self.table = table
        self.event_bus = event_bus
        self.event_bus_logger = event_bus_logger
        
        # Add node-level suppressions
        for child in self.node.find_all():
            if any(pattern.replace("*", "") in child.node.id for pattern in patterns):
                try:
                    NagSuppressions.add_resource_suppressions(
                        child, [], True  # IAM4_SUPPRESSION and IAM5_SUPPRESSION removed
                    )
                except ValueError:
                    # Handle specific ValueError exceptions that might occur during suppression
                    continue
                except TypeError:
                    # Handle specific TypeError exceptions that might occur during suppression
                    continue
