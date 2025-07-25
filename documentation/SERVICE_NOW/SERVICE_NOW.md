# ServiceNow Integration is not released yet

This document will provide, when its ready, an overview of the AWS Security Incident Response ServiceNow integration, including its architecture, resources, parameters, and outputs.

## Deployment

```bash
# Deploy the integration with a single command
./deploy-integrations-solution.py service-now \
  --instance <your-servicenow-instance-id> \
  --username <your-servicenow-username> \
  --password <your-servicenow-password> \
  --log-level info
```
See the section below for instructions on how to obtain your ServiceNow instance id, username and password

## Prerequisites

### Identify Your ServiceNow Instance ID

1. Open your ServiceNow instance in a web browser
2. Look at the URL in your browser's address bar
3. The instance ID is the subdomain part of the URL

**Example:**
- URL: `https://dev12345.service-now.com`
- Instance ID: `dev12345`

### Create a ServiceNow Integration User

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

### Secure Your Credentials (Optional)

1. Store your ServiceNow credentials securely
2. For production environments, consider using:
   - AWS Secrets Manager
   - ServiceNow API keys instead of passwords
3. Rotate credentials regularly according to your security policies

## Parameters

The ServiceNow integration stack requires the following parameters during deployment:

| Parameter | Description | Type | Required | Example |
|-----------|-------------|------|----------|--------|
| `serviceNowInstanceId` | The ServiceNow instance ID (subdomain of your ServiceNow URL) | String | Yes | `dev12345` (from dev12345.service-now.com) |
| `serviceNowUser` | The username for ServiceNow API access (must have admin privileges to create business rules) | String | Yes | `admin` or `integration_user` |
| `serviceNowPassword` | The password for ServiceNow API access | String | Yes | `********` |
| `logLevel` | The log level for Lambda functions | String | No | `info`, `debug`, or `error` (default) |

## Post Deployment

Create a test Case in AWS Security Incident Response and verify it appears as Incident in Service Now

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

### Integration Flow

The ServiceNow integration follows a similar pattern to the Jira integration, but with some key differences in implementation:

#### Flow 1: AWS Security Incident Response to ServiceNow

1. The **Security IR Poller Lambda** polls for incidents from AWS Security Incident Response
2. Events are published to EventBridge
3. The **ServiceNow Client Lambda** processes these events
4. The ServiceNow Client Lambda updates or creates incidents in ServiceNow via the ServiceNow API

#### Flow 2: ServiceNow to AWS Security Incident Response

1. ServiceNow incidents trigger a **Business Rule** when created, updated, or closed
2. The Business Rule sends the incident data to an **API Gateway webhook endpoint**
3. The **ServiceNow Notifications Handler Lambda** processes the webhook request and publishes events to EventBridge
4. The **Security IR Client Lambda** subscribes to these events and performs the appropriate operations in AWS Security Incident Response

#### Automatic ServiceNow Setup

The integration includes a **ServiceNow Resource Setup Lambda** that automatically configures the necessary components in ServiceNow during deployment:
- Business Rules for incident events
- Outbound REST Messages for API communication
- Script Includes for data formatting



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
   - Uses the API Gateway's REST API ID as a prefix for ServiceNow resource names
   - Environment variables include:
     - `SERVICE_NOW_INSTANCE_ID`: SSM parameter name for the ServiceNow instance ID
     - `SERVICE_NOW_USER`: SSM parameter name for the ServiceNow user
     - `SERVICE_NOW_PASSWORD_PARAM`: SSM parameter name for the ServiceNow password
     - `SERVICE_NOW_RESOURCE_PREFIX`: API Gateway REST API ID
     - `WEBHOOK_URL`: Complete URL for the webhook endpoint
     - `LOG_LEVEL`: Log level for the Lambda function

### API Gateway

- **ServiceNow Webhook API** (`ServiceNowWebhookApi`)
  - Provides an endpoint for ServiceNow to send events
  - Supports POST method (OPTIONS method is automatically added by CORS configuration)
  - Integrates with the ServiceNow Notifications Handler Lambda
  - Configured with CORS support for all origins and methods

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
- `/SecurityIncidentResponse/serviceNowPassword`

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

## Outputs

The stack provides the following outputs that can be used for integration:

| Output | Description | Usage |
|--------|-------------|-------|
| `ServiceNowClientLambdaArn` | ARN of the ServiceNow Client Lambda function | Reference for other AWS resources |
| `ServiceNowWebhookUrl` | URL of the API Gateway webhook endpoint | Configure in ServiceNow to send events to AWS |

## Setup and Configuration Summary

1. **Prepare ServiceNow**:
   - Ensure you have a ServiceNow instance with admin access
   - Create a dedicated service account for the integration if needed

2. **Deploy the Stack**:
   ```bash
   # Using the deploy-integrations-solution script
   deploy-integrations-solution service-now \
     --instance-id <your-servicenow-instance-id> \
     --username <your-servicenow-username> \
     --password <your-servicenow-password> \
     --log-level info
   ```
   
   Note: The `--log-level` parameter is optional and defaults to `error`. Valid values are `info`, `debug`, and `error`.

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

## Troubleshooting and Validation

For detailed information on outputs, validation, troubleshooting, and security considerations, please refer to the [ServiceNow Troubleshooting Guide](SERVICE_NOW_TROUBLESHOOTING.md).

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