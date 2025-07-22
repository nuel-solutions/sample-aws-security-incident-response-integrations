# AWS Security Incident Response Sample Integrations

This project provides sample integrations for AWS Security Incident Response, enabling customers to seamlessly integrate the service with their existing applications for incident response, stakeholder notifications, and case management. Currently, the solution provides integration with the following applications:

[![Jira Integration](https://img.shields.io/badge/Integration-Jira-0052CC)](JIRA.md)
```bash
deploy-integrations-solution jira \
  --email <your-jira-email> \
  --url <your-jira-url> \
  --token <your-jira-api-token> \
  --project-key <your-jira-project-key> \
  --log-level info
```

[![ServiceNow Integration](https://img.shields.io/badge/Integration-ServiceNow-81B5A1)](SERVICE_NOW.md)
```bash
deploy-integrations-solution service-now \
  --instance-id <your-servicenow-instance-id> \
  --username <your-servicenow-username> \
  --password <your-servicenow-password> \
  --log-level info
```

**Note: Follow the steps in Getting Started section below to perform the above deployments**

## Getting Started

### Prerequisites

- **AWS Account** with permissions to create the required resources
- **AWS CDK** v2.x installed (`npm install -g aws-cdk`)
- **Python 3.9+** installed
- **AWS CLI** configured with appropriate permissions
- **Jira Cloud** account (for Jira integration)
- **ServiceNow** instance with admin access (for ServiceNow integration)

### Installation

1. Clone the repository
2. Install dependencies
   ```
   pip install -r requirements.txt
   ```
3. Install development dependencies (optional):
   ```
   pip install -r requirements-dev.txt
   ```

### Deployment

For deployment of an integration pattern, install and use the `deploy-integrations-solution` supplementary python app
in the command-line using the following steps:

1. Add the `deploy-integrations-solution.py` script to the `bin` path using the following commands:
   ```
   sudo cp deploy-integrations-solution.py /usr/local/bin/deploy-integrations-solution
   ```
   ```
   sudo chmod +x /usr/local/bin/deploy-integrations-solution
   ```

2. Verify if the `deploy-integrations-solution` works in the command-line by running:
   ```
   deploy-integrations-solution --help
   ```
   You should see the following output:
   ```
   usage: deploy-integrations-solution [-h] [--log-level {info,debug,error}] {jira,service-now} ...

   Deploy AWS Security Incident Response Sample Integrations

   positional arguments:
   {jira,service-now}    Integration type
      jira                Deploy Jira integration
      service-now         Deploy ServiceNow integration

   options:
   -h, --help            show this help message and exit
   ```
3. Use the `jira` argument to deploy the JIRA integration:
   `deploy-integrations-solution jira -h`
   You should see the following output:
   ```
   usage: deploy-integrations-solution jira [-h] --email EMAIL --url URL --token TOKEN

   options:
      -h, --help     show this help message and exit
      --email EMAIL  Jira email
      --url URL      Jira URL
      --token TOKEN  Jira API token
      --project-key  Jira Project key
      --log-level    {info,debug,error} Log level for Lambda functions
   ```
   Provide the respective parameters for each of the above arguments to perform a deploy:
   `deploy-integrations-solution jira --email <email> --url <url> --token <token>`
4. Use the `service-now` argument to deploy the ServiceNow integration:
   `deploy-integrations-solution service-now -h`
   You should see the following output:
   ```
   usage: deploy-integrations-solution service-now [-h] --instance-id INSTANCE --username USERNAME --password PASSWORD

   options:
      -h, --help           show this help message and exit
      --instance-id INSTANCE ServiceNow instance ID
      --username USERNAME  ServiceNow username
      --password PASSWORD  ServiceNow password
      --log-level    {info,debug,error} Log level for Lambda functions
   ```
   Provide the respective parameters for each of the above arguments to perform a deploy:
   `deploy-integrations-solution service-now --instance <instance> --username <username> --password <password>`
5. Use the `--log-level` to set the value as `info`, `debug`, `error`. The default log-level is set to `error`
6. Alternatively, if you are not able to add the `deploy-integrations-solution.py` script to the `bin` path, you can
   use the script directly by replacing `deploy-integrations-solution` in the above examples with
   `./deploy-integrations-solution.py` command.

## Overview

AWS Security Incident Response helps customers respond when it matters the most. This project aims to address the gap between the service's public APIs/SDKs and direct connections to common applications like JIRA and ServiceNow. It enables customers to execute API actions directly from their preferred applications while preserving AWS Security Incident Response core capabilities.

This repository contains:

- **[Jira Integration](JIRA.md)**: Bidirectional integration between AWS Security Incident Response and Jira for issue tracking
- **[ServiceNow Integration](SERVICE_NOW.md)**: Bidirectional integration between AWS Security Incident Response and ServiceNow for incident management
- **Common Infrastructure**: Shared components like EventBridge event bus, DynamoDB tables, and Lambda layers
- **Deployment Scripts**: Easy-to-use deployment tools for quick setup

## Features

- **Bidirectional Connectivity**: Seamless two-way synchronization between AWS Security Incident Response and target applications
- **Real-time Updates**: Event-driven architecture ensures near-instantaneous updates across systems
- **Comprehensive Jira Integration**: 
  - Create, update, and delete issues in Jira based on AWS Security Incident Response cases
  - Sync comments, attachments, and status changes
  - [Detailed Jira integration documentation](JIRA.md)
- **Full-featured ServiceNow Integration**: 
  - Create, update, and delete incidents in ServiceNow based on AWS Security Incident Response cases
  - Automatic setup of ServiceNow components (Business Rules, REST Messages)
  - [Detailed ServiceNow integration documentation](SERVICE_NOW.md)
- **Robust Error Handling**: Dead-letter queues, CloudWatch alarms, and comprehensive logging
- **Secure by Design**: Least privilege permissions, secure credential storage, and encryption
- **Extensible Framework**: Modular architecture makes it easy to add new integrations

## Architecture

![JIRA Integration for AWS Security Incident Response Architecture](images/AWS-Security-Incident-Response-JIRA-architecture.png)

### Core AWS Services

The solution leverages the following AWS services:

- **Amazon EventBridge**: Custom event bus named "security-incident-event-bus" for routing events between systems
- **AWS Lambda**: Serverless compute for processing events and API calls, including a Security IR Poller that runs every minute
- **Amazon Simple Notification Service (SNS)**: Messaging service for receiving events from Jira
- **Amazon API Gateway**: Webhook endpoint for receiving events from ServiceNow
- **Amazon Simple Queue Service (SQS)**: Dead-letter queue for handling failed events
- **Amazon DynamoDB**: NoSQL database table with partition key "PK" and sort key "SK" for storing mapping information
- **Amazon CloudWatch**: Monitoring, logging (with one-week retention), and alerting
- **AWS Systems Manager Parameter Store**: Secure storage for credentials and configuration
- **AWS Lambda Layers**: Shared code layers for domain models, mappers, and wrappers
- **AWS Security Incident Response (SIR)**: Core security incident response service



## Usage

### Jira Integration

To use the Jira integration:

1. Deploy the integration using the instructions in the [Jira Integration Documentation](JIRA.md)
2. Configure Jira Automation to send events to the SNS topic
3. Test the integration by creating a security incident in AWS Security Incident Response
4. Verify that an issue is created in your Jira project

For detailed instructions on setting up the Jira integration, including automation rules, API token creation, and troubleshooting tips, refer to the [Jira Integration Documentation](JIRA.md).

### ServiceNow Integration

To use the ServiceNow integration:

1. Deploy the integration using the instructions in the [ServiceNow Integration Documentation](SERVICE_NOW.md)
2. The ServiceNow Resource Setup Lambda will automatically configure the necessary components in ServiceNow
3. Test the integration by creating a security incident in ServiceNow
4. Verify that a case is created in AWS Security Incident Response

For detailed instructions on setting up the ServiceNow integration, including business rules, outbound REST messages, and troubleshooting tips, refer to the [ServiceNow Integration Documentation](SERVICE_NOW.md).

## Troubleshooting

### Common Issues

#### Failed Event Delivery

**What happens if updates from AWS Security Incident Response or Jira/ServiceNow fail?**

The integration includes robust error handling mechanisms:

1. **Dead-Letter Queue (DLQ)**: Events that fail to be delivered to EventBridge are sent to a DLQ
2. **CloudWatch Alarms**: Alarms trigger when messages appear in the DLQ
3. **CloudWatch Dashboard**: Provides visibility into the integration's health

![AWS Security Incident Response CloudWatch Dashboard](images/cloud-watch.png)

**Where is the DLQ?**

The DLQ is a standard Amazon SQS queue that EventBridge uses to store events that couldn't be delivered to a target. Look for an SQS queue with a name similar to `AwsSecurityIncidentResponseSample-SecurityIncidentEventBusLoggerdead-*` and check for messages.

#### Processing Failed Events

To process failed events in the DLQ:

1. Navigate to the SQS console and find the DLQ
2. Select the messages and choose "View/Delete Messages"
3. Examine the message content to understand the failure
4. Manually process the events or use the AWS SDK to programmatically process them

### Integration-Specific Troubleshooting

- For Jira integration issues, see the [Jira Integration Troubleshooting Guide](JIRA.md#troubleshooting)
- For ServiceNow integration issues, see the [ServiceNow Integration Troubleshooting Guide](SERVICE_NOW.md#troubleshooting)

### Getting Help

If you encounter issues that aren't covered in the troubleshooting guides:

1. Check the CloudWatch Logs for the relevant Lambda functions
2. Review the EventBridge event bus for event delivery status
3. Open an issue in the GitHub repository with detailed information about the problem

## Development

To contribute to this project, please review the [CONTRIBUTING.md](CONTRIBUTING.md) file (not included in the provided files, but recommended to create).

### Testing

Run tests using pytest:

```
pytest
```

### Code Quality

This project uses [ruff](https://github.com/astral-sh/ruff) to enforce code quality standards. To set up ruff:

1. Install development dependencies:
```
pip install -r requirements-dev.txt
```

2. Format code
```
ruff format
```

## Security

This project implements various security measures to protect your data and infrastructure:

### Access Controls

- **Least Privilege Principle**: IAM roles with minimal permissions required for each function
- **Resource-Based Policies**: SNS topics and other resources have strict access policies
- **CDK Nag Suppressions**: Any security findings are explicitly documented and suppressed only when necessary

### Credential Management

- **AWS Systems Manager Parameter Store**: All credentials are stored securely in Parameter Store
- **No Hardcoded Secrets**: All sensitive values are passed as parameters during deployment
- **Secure String Parameters**: Sensitive values are stored as encrypted SecureString parameters

### Monitoring and Logging

- **CloudWatch Logs**: Comprehensive logging for all Lambda functions
- **CloudWatch Alarms**: Alerts for failed events and other issues
- **CloudWatch Dashboard**: Visibility into the integration's health and performance

### Data Protection

- **Data Encryption**: DynamoDB tables use encryption at rest
- **Secure Communication**: All API calls use HTTPS
- **Minimal Data Storage**: Only essential mapping information is stored

### Best Practices

- Regularly rotate API tokens and credentials
- Monitor CloudWatch Logs for suspicious activity
- Keep the integration components updated to the latest versions

## License

This project is licensed under the MIT-0 License. See the LICENSE file for details.

## Contributing

We welcome contributions! Please see the [CONTRIBUTING.md](CONTRIBUTING.md) file for details on how to contribute to this project.

## Frequently Asked Questions

### General Questions

**Q: Can I use both Jira and ServiceNow integrations simultaneously?**  
A: Yes, you can deploy both integrations to connect AWS Security Incident Response with both Jira and ServiceNow.

**Q: How much does it cost to run these integrations?**  
A: The cost depends on your usage of AWS services like Lambda, EventBridge, SNS, and DynamoDB. Most deployments will fall within the AWS Free Tier for these services with moderate usage.

**Q: Can I customize the integrations for my specific needs?**  
A: Yes, the integrations are designed to be extensible. You can modify the Lambda functions, event patterns, and other components to meet your specific requirements.

**Q: How secure are these integrations?**  
A: The integrations follow AWS security best practices, including least privilege access, secure credential storage, and encryption. See the [Security](#security) section for more details.

### Technical Questions

**Q: What happens if an integration component fails?**  
A: The integrations include error handling mechanisms like dead-letter queues and CloudWatch alarms. Failed events are stored for later processing.

**Q: Can I deploy these integrations in multiple AWS regions?**  
A: Yes, you can deploy the integrations in any AWS region where the required services are available.

**Q: How do I update an integration after deployment?**  
A: You can update an integration by running the deployment command again with the same or updated parameters.

**Q: Where can I find detailed logs for troubleshooting?**  
A: All Lambda functions write logs to CloudWatch Logs. You can find the log groups in the CloudWatch console or use the URLs provided in the CloudFormation outputs.

## Support

For support, please open an issue in the GitHub repository or contact AWS support.