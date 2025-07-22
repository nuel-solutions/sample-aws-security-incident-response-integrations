# AWS Security Incident Response ServiceNow Integration - Troubleshooting Guide

This document provides detailed information on troubleshooting, validation, and security considerations for the AWS Security Incident Response ServiceNow integration.

## Table of Contents

- [Setup and Configuration](#setup-and-configuration)
- [Outputs and Validation](#outputs-and-validation)
  - [Using CloudFormation Outputs](#using-cloudformation-outputs)
  - [Validating ServiceNow Resources](#validating-servicenow-resources)
- [Troubleshooting](#troubleshooting)
  - [Common Issues and Solutions](#common-issues-and-solutions)
  - [Diagnostic Steps](#diagnostic-steps)
- [Security Considerations](#security-considerations)

## Setup and Configuration

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

## Setup and Configuration

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