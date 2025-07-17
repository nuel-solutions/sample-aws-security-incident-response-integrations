# AWS Security Incident Response ServiceNow Integration

This document provides an overview of the AWS Security Incident Response ServiceNow integration, including its architecture, resources, parameters, and outputs.

## Quick Start

```bash
# Deploy the integration with a single command
deploy-integrations-solution service-now \
  --instance <your-servicenow-instance-id> \
  --username <your-servicenow-username> \
  --password <your-servicenow-password> \
  --log-level info
```

After deployment, create a test incident in ServiceNow and verify it appears in AWS Security Incident Response.

## Table of Contents

- [Architecture](#architecture)
- [Resources](#resources)
  - [AWS Resources](#aws-resources)
  - [ServiceNow Resources](#servicenow-resources)
- [Parameters](#parameters)
  - [Preparing for Deployment](#preparing-for-deployment)
- [Setup and Configuration](#setup-and-configuration)
  - [Deployment Steps](#deployment-steps)
- [Outputs and Validation](#outputs-and-validation)
- [Troubleshooting](#troubleshooting)
  - [Common Issues and Solutions](#common-issues-and-solutions)
  - [Diagnostic Steps](#diagnostic-steps)
- [Security Considerations](#security-considerations)
- [Related Resources](#related-resources)

## Architecture

The ServiceNow integration for AWS Security Incident Response enables bidirectional communication between AWS Security Incident Response and ServiceNow. This allows security incidents to be synchronized between both systems in real-time.

### Integration Overview

```
┌─────────────────┐                  ┌────────────────┐                  ┌─────────────┐
│                 │                  │                │                  │             │
│  AWS Security   │◄─── Updates ────►│   EventBridge  │◄─── Updates ────►│  ServiceNow │
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
│  Security IR    │                  │  ServiceNow    │                  │  ServiceNow │
│  Client Lambda  │                  │  Client Lambda │                  │  Webhook    │
│                 │                  │                │                  │  (API GW)   │
│                 │                  │                │                  │             │
└─────────────────┘                  └────────────────┘                  └─────────────┘
```

The integration consists of two main flows:

### Flow 1: AWS Security Incident Response to ServiceNow

1. The Security IR Poller Lambda polls for incidents from AWS Security Incident Response
2. Events are published to EventBridge
3. The ServiceNow Client Lambda processes these events
4. The ServiceNow Client Lambda creates or updates incidents in ServiceNow via the ServiceNow API

### Flow 2: ServiceNow to AWS Security Incident Response

1. ServiceNow publishes events to the API Gateway webhook when incidents are created, updated, or closed
2. The API Gateway triggers the ServiceNow Notifications Handler Lambda
3. The ServiceNow Notifications Handler Lambda processes the events and publishes them to EventBridge
4. The Security IR Client Lambda subscribes to these events and performs the appropriate operations in AWS Security Incident Response

## Resources

### AWS Resources

The ServiceNow integration stack creates the following AWS resources:

### Lambda Functions

1. **ServiceNow Client Lambda** (`SecurityIncidentResponseServiceNowClient`)
   - Processes events from AWS Security Incident Response
   - Creates or updates incidents in ServiceNow
   - Timeout: 15 minutes

2. **ServiceNow Notifications Handler Lambda** (`ServiceNowNotificationsHandler`)
   - Processes webhook events from ServiceNow
   - Publishes events to EventBridge

3. **ServiceNow Resource Setup Lambda** (`ServiceNowResourceSetupLambda`)
   - Sets up required resources in ServiceNow during deployment:
     - **Business Rules**: Creates or updates business rules in ServiceNow that trigger when incidents are created, updated, or deleted
     - **Outbound REST Messages**: Configures REST messages that send incident data to the API Gateway webhook
   - Automatically configures the webhook URL in ServiceNow to point to the API Gateway endpoint
   - Runs as a Custom Resource during CloudFormation deployment
   - Timeout: 5 minutes
   - Uses the ServiceNow API to create these components programmatically

### API Gateway

- **ServiceNow Webhook API** (`ServiceNowWebhookApi`)
  - Provides an endpoint for ServiceNow to send events
  - Supports POST and OPTIONS methods
  - Integrates with the ServiceNow Notifications Handler Lambda
  - Configured with CORS support

### EventBridge Rules

1. **Service Now Client Rule** (`service-now-client-rule`)
   - Captures events from AWS Security Incident Response
   - Triggers the ServiceNow Client Lambda

2. **ServiceNow Notifications Rule** (`ServiceNowNotificationsRule`)
   - Captures events from ServiceNow
   - Logs events to CloudWatch

### SSM Parameters

- `/SecurityIncidentResponse/serviceNowInstanceId`
- `/SecurityIncidentResponse/serviceNowUser`
- ServiceNow password parameter (auto-generated name)

### IAM Roles

- Custom roles for each Lambda function with least privilege permissions

### DynamoDB Table

- Uses a shared table from the common stack to store incident mapping information

### ServiceNow Resources

The ServiceNow Resource Setup Lambda creates the following components in your ServiceNow instance:

1. **Business Rules**:
   - **Incident Created Rule**: Triggers when a new incident is created in ServiceNow
   - **Incident Updated Rule**: Triggers when an incident is updated in ServiceNow
   - **Incident Deleted Rule**: Triggers when an incident is deleted in ServiceNow
   - Each rule is configured to send incident data to AWS via the outbound REST message
   - Rules are prefixed with the Lambda function name for easy identification

2. **Outbound REST Messages**:
   - **AWS Security IR Integration Message**: Configured to send incident data to the API Gateway webhook URL
   - Includes authentication and proper formatting of the payload
   - Automatically updated if the webhook URL changes during redeployment

3. **Script Includes**:
   - Helper scripts to format incident data for transmission to AWS
   - Handles error conditions and logging

All these components work together to ensure real-time synchronization between ServiceNow incidents and AWS Security Incident Response cases.

## Parameters

The ServiceNow integration stack requires the following parameters during deployment:

| Parameter | Description | Type | Required | Example |
|-----------|-------------|------|----------|--------|
| `serviceNowInstanceId` | The ServiceNow instance ID (subdomain of your ServiceNow URL) | String | Yes | `dev12345` (from dev12345.service-now.com) |
| `serviceNowUser` | The username for ServiceNow API access (must have admin privileges to create business rules) | String | Yes | `admin` or `integration_user` |
| `serviceNowPassword` | The password for ServiceNow API access | String | Yes | `********` |

### Preparing for Deployment

#### Step 1: Identify Your ServiceNow Instance ID

1. Open your ServiceNow instance in a web browser
2. Look at the URL in your browser's address bar
3. The instance ID is the subdomain part of the URL

**Example:**
- URL: `https://dev12345.service-now.com`
- Instance ID: `dev12345`

#### Step 2: Create a ServiceNow Integration User

1. Log in to your ServiceNow instance as an administrator
2. Navigate to User Administration > Users
3. Click "New" to create a new user
4. Fill in the required fields:
   - User ID: `aws_integration` (recommended)
   - First Name: `AWS`
   - Last Name: `Integration`
   - Password: Create a secure password
5. Assign the following roles:
   - `admin` (or a custom role with permissions to create business rules)
   - `incident_manager`

**Best Practice:** Create a dedicated service account rather than using a personal account.

#### Step 3: Secure Your Credentials

1. Store your ServiceNow credentials securely
2. For production environments, consider using:
   - AWS Secrets Manager
   - ServiceNow API keys instead of passwords
3. Rotate credentials regularly according to your security policies

## Outputs

The stack provides the following outputs that can be used for integration:

| Output | Description | Usage |
|--------|-------------|-------|
| `ServiceNowClientLambdaArn` | ARN of the ServiceNow Client Lambda function | Reference for other AWS resources |
| `ServiceNowWebhookUrl` | URL of the API Gateway webhook endpoint | Configure in ServiceNow to send events to AWS |

## Setup and Configuration

### Deployment Steps

1. **Prepare ServiceNow**:
   - Ensure you have a ServiceNow instance with admin access
   - Create a dedicated service account for the integration if needed

2. **Deploy the Stack**:
   ```bash
   # Using the deploy-integrations-solution script
   deploy-integrations-solution service-now --instance <your-instance-id> --username <your-username> --password <your-password>
   ```

3. **Automatic Configuration**:
   - The ServiceNow Resource Setup Lambda will automatically:
     - Create business rules in ServiceNow to detect incident changes
     - Configure outbound REST messages to send data to the API Gateway
     - Set up the webhook URL in ServiceNow

4. **Verify the Setup**:
   - Check CloudFormation outputs for the webhook URL
   - Verify in ServiceNow that the business rules and outbound REST messages were created
   - The business rules will be prefixed with the Lambda function name for easy identification

5. **Test the Integration**:
   - Create a test incident in ServiceNow
   - Verify that the incident appears in AWS Security Incident Response
   - Update the incident in AWS and verify the changes appear in ServiceNow

## Outputs and Validation

After deploying the stack, you'll receive CloudFormation outputs that can be used to validate and troubleshoot the integration.

### Using CloudFormation Outputs

#### ServiceNowClientLambdaArn

This output provides the ARN of the ServiceNow Client Lambda function.

**How to use it for validation:**

1. **Verify Lambda Function Existence:**
   ```bash
   aws lambda get-function --function-name <ServiceNowClientLambdaArn>
   ```

2. **Check Lambda Logs:**
   ```bash
   # Get the function name from the ARN
   FUNCTION_NAME=$(echo <ServiceNowClientLambdaArn> | cut -d':' -f7)
   aws logs filter-log-events --log-group-name "/aws/lambda/$FUNCTION_NAME" --limit 10
   ```

3. **Monitor Function Invocations:**
   - Navigate to the Lambda console
   - Search for the function using the ARN
   - Check the monitoring tab to see invocation metrics

#### ServiceNowWebhookUrl

This output provides the URL of the API Gateway webhook endpoint that ServiceNow uses to send events to AWS.

**How to use it for validation:**

1. **Verify API Gateway Configuration:**
   - Extract the API ID from the URL: `https://<api-id>.execute-api.<region>.amazonaws.com/prod/webhook`
   - Check the API Gateway using AWS CLI:
     ```bash
     aws apigateway get-rest-api --rest-api-id <api-id>
     ```

2. **Verify ServiceNow Configuration:**
   - Log in to your ServiceNow instance
   - Navigate to System Web Services > Outbound > REST Messages
   - Find the outbound REST message created by the integration
   - Confirm that the endpoint URL matches the ServiceNowWebhookUrl output

3. **Test the Webhook:**
   - You can send a test request to the webhook URL:
     ```bash
     curl -X POST <ServiceNowWebhookUrl> \
       -H "Content-Type: application/json" \
       -d '{"event_type":"test","incident_number":"INC0010001","short_description":"Test incident"}'
     ```
   - Check the CloudWatch logs for the ServiceNow Notifications Handler Lambda to verify it received the request

### Validating ServiceNow Resources

To validate the resources created in ServiceNow:

1. **Business Rules:**
   - Navigate to System Definition > Business Rules
   - Search for rules with names containing the ServiceNow Notifications Handler Lambda function name
   - Verify that the following rules exist:
     - Rule for incident creation
     - Rule for incident updates
     - Rule for incident deletion

2. **Outbound REST Messages:**
   - Navigate to System Web Services > Outbound > REST Messages
   - Verify that the REST message is configured with the correct webhook URL
   - Check that the HTTP method is set to POST

3. **Script Includes:**
   - Navigate to System Definition > Script Includes
   - Look for script includes related to the AWS integration
   - Verify they contain the correct formatting logic for incident data

## Security Considerations

- All credentials are stored securely in SSM Parameter Store
- IAM roles follow the principle of least privilege
- API Gateway is configured with CORS to control access
- CloudWatch logging is enabled for all Lambda functions

## Troubleshooting

### Common Issues and Solutions

1. **ServiceNow Resource Setup Fails**:
   - Check CloudWatch Logs for the ServiceNow Resource Setup Lambda
   - Verify the ServiceNow credentials are correct
   - Ensure the ServiceNow user has sufficient permissions to create business rules
   - Try manually creating the business rules using the scripts in `assets/service_now_scripts`

2. **Events Not Flowing from ServiceNow to AWS**:
   - Verify the business rules were created in ServiceNow
   - Check the outbound REST message configuration in ServiceNow
   - Examine ServiceNow system logs for errors in the business rules
   - Verify the API Gateway endpoint is accessible from ServiceNow
   - Check CloudWatch Logs for the ServiceNow Notifications Handler Lambda

3. **Events Not Flowing from AWS to ServiceNow**:
   - Check CloudWatch Logs for the ServiceNow Client Lambda
   - Verify the ServiceNow API is accessible from AWS
   - Ensure the ServiceNow credentials are still valid
   - Check EventBridge for event delivery status

4. **Incident Mapping Issues**:
   - Examine the DynamoDB table for incident mapping information
   - Verify that incident IDs are being correctly stored and retrieved
   - Check for duplicate entries or missing mappings

### Diagnostic Steps

1. Create a test incident in ServiceNow and monitor the logs
2. Check API Gateway access logs for incoming requests
3. Verify EventBridge events are being properly routed
4. Examine DynamoDB for proper incident mapping

## Frequently Asked Questions

### General Questions

**Q: How long does it take for changes to sync between systems?**  
A: Changes typically sync within seconds. The integration uses event-driven architecture to ensure near real-time updates.

**Q: Can I customize which incidents are synchronized?**  
A: Yes, you can modify the ServiceNow business rules created by the integration to filter incidents based on criteria like priority or assignment group.

**Q: What happens if the integration fails?**  
A: The integration includes error handling and dead-letter queues. Failed events are stored and can be reprocessed. CloudWatch alarms will notify you of failures.

**Q: Does this integration support custom fields?**  
A: The base integration supports standard ServiceNow incident fields. For custom fields, you'll need to modify the Lambda functions and ServiceNow scripts.

**Q: Can I use this with ServiceNow's Security Incident Response module?**  
A: Yes, the integration can be adapted to work with ServiceNow's Security Incident Response module by modifying the business rules to target security incidents instead of standard incidents.

### Technical Questions

**Q: What permissions are required in ServiceNow?**  
A: The integration user needs admin access to create business rules and REST messages, plus access to incident records.

**Q: How are credentials stored?**  
A: ServiceNow credentials are stored in AWS Systems Manager Parameter Store with secure string parameters.

**Q: Can I deploy multiple integrations to different ServiceNow instances?**  
A: Yes, you can deploy the stack multiple times with different parameters to connect to different ServiceNow instances.

## Related Resources

- [AWS Security Incident Response Documentation](https://docs.aws.amazon.com/security-incident-response/)
- [ServiceNow API Documentation](https://developer.servicenow.com/dev.do)
- [ServiceNow Business Rules Documentation](https://docs.servicenow.com/bundle/tokyo-application-development/page/script/business-rules/concept/c_BusinessRules.html)
- [AWS EventBridge Documentation](https://docs.aws.amazon.com/eventbridge/)