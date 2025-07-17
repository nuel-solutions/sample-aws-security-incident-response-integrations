# AWS Security Incident Response Jira Integration

This document provides an overview of the AWS Security Incident Response Jira integration, including its architecture, resources, parameters, and outputs.

## Quick Start

```bash
# Deploy the integration with a single command
deploy-integrations-solution jira \
  --email <your-jira-email> \
  --url <your-jira-url> \
  --token <your-jira-api-token> \
  --log-level info
```

After deployment, create a test case in AWS Security Incident Response and verify it appears in Jira.

## Table of Contents

- [Architecture](#architecture)
- [Resources](#resources)
  - [AWS Resources](#aws-resources)
  - [Jira Resources](#jira-resources)
- [Parameters](#parameters)
  - [Preparing for Deployment](#preparing-for-deployment)
- [Setup and Configuration](#setup-and-configuration)
  - [Deployment Steps](#deployment-steps)
- [Outputs and Validation](#outputs-and-validation)
- [Troubleshooting](#troubleshooting)
  - [Common Issues and Solutions](#common-issues-and-solutions)
  - [Diagnostic Steps](#diagnostic-steps)
- [Security Considerations](#security-considerations)
- [Frequently Asked Questions](#frequently-asked-questions)
- [Related Resources](#related-resources)

## Architecture

The Jira integration for AWS Security Incident Response enables bidirectional communication between AWS Security Incident Response and Jira. This allows security incidents to be synchronized between both systems in real-time.

### Integration Overview

```
┌─────────────────┐                  ┌────────────────┐                  ┌─────────────┐
│                 │                  │                │                  │             │
│  AWS Security   │◄─── Updates ────►│   EventBridge  │◄─── Updates ────►│  Jira      │
│  Incident       │                  │   Event Bus    │                  │  Instance   │
│  Response       │                  │                │                  │             │
│                 │                  │                │                  │             │
└─────────────────┘                  └────────────────┘                  └─────────────┘
        ▲                                    ▲                                 ▲
        │                                    │                                 │
        │                                    │                                 │
        ▼                                    ▼                                 ▼
┌─────────────────┐                  ┌────────────────┐                  ┌─────────────┐
│                 │                  │                │                  │             │
│  Security IR    │                  │  Jira          │                  │  Jira SNS   │
│  Client Lambda  │                  │  Client Lambda │                  │  Topic      │
│                 │                  │                │                  │             │
│                 │                  │                │                  │             │
└─────────────────┘                  └────────────────┘                  └─────────────┘
```

The integration consists of two main flows:

### Flow 1: AWS Security Incident Response to Jira

1. The Security IR Poller Lambda polls for incidents from AWS Security Incident Response
2. Events are published to EventBridge
3. The Jira Client Lambda processes these events
4. The Jira Client Lambda creates or updates issues in Jira via the Jira API

### Flow 2: Jira to AWS Security Incident Response

1. Jira publishes events to the SNS topic when issues are created, updated, or deleted
2. The SNS topic triggers the Jira Notifications Handler Lambda
3. The Jira Notifications Handler Lambda processes the events and publishes them to EventBridge
4. The Security IR Client Lambda subscribes to these events and performs the appropriate operations in AWS Security Incident Response

## Resources

### AWS Resources

The Jira integration stack creates the following AWS resources:

#### Lambda Functions

1. **Jira Client Lambda** (`SecurityIncidentResponseJiraClient`)
   - Processes events from AWS Security Incident Response
   - Creates or updates issues in Jira
   - Timeout: 15 minutes

2. **Jira Notifications Handler Lambda** (`JiraNotificationsHandler`)
   - Processes events from Jira via SNS
   - Publishes events to EventBridge

#### SNS Topic

- **Jira Notifications Topic** (`JiraNotificationsTopic`)
  - Receives events from Jira
  - Triggers the Jira Notifications Handler Lambda
  - Configured with appropriate permissions for Jira's AWS account

#### EventBridge Rules

1. **Jira Client Rule** (`jira-client-rule`)
   - Captures events from AWS Security Incident Response
   - Triggers the Jira Client Lambda

2. **Jira Notifications Rule** (`JiraNotificationsRule`)
   - Captures events from Jira
   - Logs events to CloudWatch

#### SSM Parameters

- `/SecurityIncidentResponse/jiraEmail`
- `/SecurityIncidentResponse/jiraUrl`
- `/SecurityIncidentResponse/jiraProjectKey`
- Jira token parameter (auto-generated name)

#### IAM Roles

- Custom roles for each Lambda function with least privilege permissions

#### DynamoDB Table

- Uses a shared table from the common stack to store issue mapping information

### Jira Resources

To use this integration, you'll need to configure the following in your Jira instance:

1. **Jira Automation Rule**:
   - Create automation rules in Jira to send events to the SNS topic when issues are created, updated, or deleted
   - Configure the AWS SNS trigger in Jira automation

2. **Jira Project**:
   - A project where security incident issues will be created
   - The project key is required for deployment

## Parameters

The Jira integration stack requires the following parameters during deployment:

| Parameter | Description | Type | Required | Example |
|-----------|-------------|------|----------|---------|
| `jiraEmail` | The email address associated with your Jira account | String | Yes | `user@example.com` |
| `jiraUrl` | The URL of your Jira instance | String | Yes | `https://your-company.atlassian.net` |
| `jiraToken` | The API token for Jira API access | String | Yes | `********` |
| `jiraProjectKey` | The key of the Jira project where issues will be created | String | Yes | `SEC` |

### Preparing for Deployment

#### Step 1: Create a Jira API Token

1. Log in to your Atlassian account at https://id.atlassian.com/manage-profile/security/api-tokens
2. Click "Create API token"
3. Enter a label for your token (e.g., "AWS Security IR Integration")
4. Click "Create"
5. Copy the generated token (you won't be able to see it again)

#### Step 2: Identify Your Jira URL

1. Log in to your Jira instance
2. The URL in your browser's address bar is your Jira URL
3. For Jira Cloud, it typically looks like `https://your-company.atlassian.net`

#### Step 3: Set Up Your Jira Project

1. Create a dedicated project for security incidents if you don't have one
2. Note the project key (e.g., "SEC" or "SECURITY")
3. Ensure you have appropriate permissions in this project

#### Step 4: Configure Jira Automation

1. In your Jira project, go to Project settings > Automation
2. Create rules to send events to AWS when issues are created, updated, or deleted
3. Use the AWS SNS trigger in Jira automation
4. Configure the SNS topic ARN (this will be available after deployment)

## Setup and Configuration

### Deployment Steps

1. **Prepare Jira**:
   - Create an API token as described above
   - Identify your Jira URL and project key

2. **Deploy the Stack**:
   ```bash
   # Using the deploy-integrations-solution script
   deploy-integrations-solution jira \
     --email <your-jira-email> \
     --url <your-jira-url> \
     --token <your-jira-api-token> \
     --project-key <your-jira-project-key>
   ```

3. **Configure Jira Automation**:
   - Use the SNS topic ARN from the CloudFormation outputs
   - Set up automation rules in Jira to send events to the SNS topic

4. **Verify the Setup**:
   - Check CloudFormation outputs for the Lambda ARNs and log group URLs
   - Create a test case in AWS Security Incident Response
   - Verify that an issue is created in your Jira project

5. **Test the Integration**:
   - Update the issue in Jira and verify the changes appear in AWS Security Incident Response
   - Update the case in AWS Security Incident Response and verify the changes appear in Jira

## Outputs and Validation

After deploying the stack, you'll receive CloudFormation outputs that can be used to validate and troubleshoot the integration.

### Using CloudFormation Outputs

#### JiraClientLambdaArn

This output provides the ARN of the Jira Client Lambda function.

**How to use it for validation:**

1. **Verify Lambda Function Existence:**
   ```bash
   aws lambda get-function --function-name <JiraClientLambdaArn>
   ```

2. **Check Lambda Logs:**
   ```bash
   # Get the function name from the ARN
   FUNCTION_NAME=$(echo <JiraClientLambdaArn> | cut -d':' -f7)
   aws logs filter-log-events --log-group-name "/aws/lambda/$FUNCTION_NAME" --limit 10
   ```

3. **Monitor Function Invocations:**
   - Navigate to the Lambda console
   - Search for the function using the ARN
   - Check the monitoring tab to see invocation metrics

#### JiraNotificationsHandlerLambdaLogGroup

This output provides the name of the CloudWatch Logs group for the Jira Notifications Handler Lambda.

**How to use it for validation:**

1. **Check Lambda Logs:**
   ```bash
   aws logs filter-log-events --log-group-name <JiraNotificationsHandlerLambdaLogGroup> --limit 10
   ```

2. **Set Up Log Metrics:**
   ```bash
   aws logs put-metric-filter \
     --log-group-name <JiraNotificationsHandlerLambdaLogGroup> \
     --filter-name "ErrorCount" \
     --filter-pattern "ERROR" \
     --metric-transformations \
       metricName=ErrorCount,metricNamespace=JiraIntegration,metricValue=1
   ```

#### JiraNotificationsHandlerLambdaLogGroupUrl

This output provides a direct URL to the CloudWatch Logs for the Jira Notifications Handler Lambda.

**How to use it for validation:**

1. Open the URL in your browser to directly access the logs
2. Filter logs by time range or search for specific terms like "ERROR" or "SUCCESS"
3. Use this URL for quick troubleshooting when issues occur

### Validating Jira Configuration

To validate the Jira automation configuration:

1. **Verify Automation Rules:**
   - Navigate to your Jira project
   - Go to Project settings > Automation
   - Check that your rules for creating, updating, and deleting issues are active
   - Verify that the AWS SNS trigger is configured with the correct SNS topic ARN

2. **Test Issue Creation:**
   - Create a test issue in your Jira project
   - Check the Jira Notifications Handler Lambda logs to verify it received the event
   - Verify that a corresponding case was created in AWS Security Incident Response

3. **Test Issue Updates:**
   - Update a test issue in Jira
   - Check the logs to verify the update was processed
   - Verify that the changes appear in AWS Security Incident Response

## Troubleshooting

### Common Issues and Solutions

1. **Jira API Token Issues**:
   - Check that the API token is valid and not expired
   - Verify the email address matches the one used to create the token
   - Try creating a new token if necessary

2. **Events Not Flowing from Jira to AWS**:
   - Verify the Jira automation rules are correctly configured
   - Check the SNS topic policy allows the Jira AWS account to publish
   - Examine CloudWatch Logs for the Jira Notifications Handler Lambda
   - Verify the SNS topic ARN in Jira automation matches the deployed topic

3. **Events Not Flowing from AWS to Jira**:
   - Check CloudWatch Logs for the Jira Client Lambda
   - Verify the Jira API is accessible from AWS
   - Ensure the Jira credentials are still valid
   - Check EventBridge for event delivery status

4. **Issue Mapping Issues**:
   - Examine the DynamoDB table for issue mapping information
   - Verify that issue IDs are being correctly stored and retrieved
   - Check for duplicate entries or missing mappings

### Diagnostic Steps

1. Create a test case in AWS Security Incident Response and monitor the logs
2. Create a test issue in Jira and monitor the logs
3. Verify EventBridge events are being properly routed
4. Examine DynamoDB for proper issue mapping

## Security Considerations

- All credentials are stored securely in SSM Parameter Store
- IAM roles follow the principle of least privilege
- SNS topic is configured with appropriate access policies
- CloudWatch logging is enabled for all Lambda functions
- Jira API token should be rotated regularly

## Frequently Asked Questions

### General Questions

**Q: How long does it take for changes to sync between systems?**  
A: Changes typically sync within seconds. The integration uses event-driven architecture to ensure near real-time updates.

**Q: Can I customize which issues are synchronized?**  
A: Yes, you can modify the Jira automation rules to filter issues based on criteria like project, issue type, or labels.

**Q: What happens if the integration fails?**  
A: The integration includes error handling and dead-letter queues. Failed events are stored and can be reprocessed. CloudWatch alarms will notify you of failures.

**Q: Does this integration support custom fields?**  
A: The base integration supports standard Jira issue fields. For custom fields, you'll need to modify the Lambda functions.

**Q: Can I use this with Jira Server/Data Center?**  
A: This integration is designed for Jira Cloud. For Jira Server/Data Center, you'll need to modify the authentication mechanism and API endpoints.

### Technical Questions

**Q: What permissions are required in Jira?**  
A: The integration user needs permissions to create and update issues in the specified project.

**Q: How are credentials stored?**  
A: Jira credentials are stored in AWS Systems Manager Parameter Store with secure string parameters.

**Q: Can I deploy multiple integrations to different Jira instances?**  
A: Yes, you can deploy the stack multiple times with different parameters to connect to different Jira instances.

## Related Resources

- [AWS Security Incident Response Documentation](https://docs.aws.amazon.com/security-incident-response/)
- [Jira API Documentation](https://developer.atlassian.com/cloud/jira/platform/rest/v3/intro/)
- [Jira Automation Documentation](https://support.atlassian.com/jira-cloud-administration/docs/automate-your-jira-cloud-processes-and-workflows/)
- [AWS SNS Documentation](https://docs.aws.amazon.com/sns/)
- [Atlassian API Token Documentation](https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/)