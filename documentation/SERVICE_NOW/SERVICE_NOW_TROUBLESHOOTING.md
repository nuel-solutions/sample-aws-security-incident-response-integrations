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
     --integration-module <itsm|ir> \
     --log-level info
   ```
   
   **Required Parameters:**
   - `--integration-module`: Choose `itsm` for IT Service Management or `ir` for Incident Response module
   
   **Optional Parameters:**
   - `--log-level`: Defaults to `error`. Valid values are `info`, `debug`, and `error`

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
   - Search for rules with names containing the resource prefix
   - Verify that the following rules exist:
     - **Incident Business Rule**: Monitors the appropriate table (`incident` for ITSM or `sn_si_incident` for IR) for create, update, and delete operations
     - **Attachment Business Rule**: Monitors the `sys_attachment` table for attachment changes on incidents
   - Check that both rules are active and properly configured
   - Verify the script content includes proper event type detection and payload formatting

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
   - Ensure the ServiceNow user has sufficient permissions to create business rules and REST messages
   - Check that the ServiceNow instance is accessible from AWS Lambda
   - Verify the API Gateway webhook URL is properly formatted

2. **Integration Module Configuration Issues**:
   - Verify the correct `--integration-module` parameter was used during deployment (`itsm` or `ir`)
   - Check that business rules are targeting the correct table (`incident` for ITSM, `sn_si_incident` for IR)
   - Ensure field mappings are appropriate for the selected integration module
   - Verify closure code handling is only applied for ITSM module

3. **Attachment Synchronization Issues**:
   - Check file size limits (5MB maximum for direct upload)
   - Verify attachment comments are not being duplicated
   - Review CloudWatch logs for attachment processing errors
   - Ensure ServiceNow attachment API permissions are properly configured
   - Check that attachment business rule is triggering correctly

4. **Authentication Failures**:
   - Verify Bearer token is properly configured in ServiceNow outbound REST message
   - Check AWS Secrets Manager for correct token value
   - Ensure API Gateway authorizer is functioning correctly
   - Test webhook authentication manually using curl or Postman

5. **Events Not Flowing from ServiceNow to AWS**:
   - Verify the business rules were created in ServiceNow
   - Check the outbound REST message configuration in ServiceNow
   - Examine ServiceNow system logs for errors in the business rules
   - Verify the API Gateway endpoint is accessible from ServiceNow
   - Check CloudWatch Logs for the ServiceNow Notifications Handler Lambda
   - Test the webhook endpoint directly with sample payloads
   - Verify Bearer token authentication is working correctly

6. **Events Not Flowing from AWS to ServiceNow**:
   - Check CloudWatch Logs for the ServiceNow Client Lambda
   - Verify the ServiceNow API is accessible from AWS
   - Ensure the ServiceNow credentials are still valid
   - Check EventBridge for event delivery status
   - Review DynamoDB table for proper incident mapping
   - Verify attachment upload permissions and file size limits

7. **Incident Mapping Issues**:
   - Examine the DynamoDB table for incident mapping information
   - Verify that incident IDs are being correctly stored and retrieved
   - Check for duplicate entries or missing mappings
   - Ensure proper partition key and sort key structure
   - Review incident details JSON format in DynamoDB

### Diagnostic Steps

1. Create a test incident in ServiceNow and monitor the logs
2. Check API Gateway access logs for incoming requests
3. Verify EventBridge events are being properly routed
4. Examine DynamoDB for proper incident mapping

### Specific Issue Troubleshooting

#### ServiceNow Business Rules Not Triggering
1. Verify the business rules were created successfully in ServiceNow
2. Check that the rules are active and properly configured
3. Ensure the ServiceNow user has sufficient permissions
4. Review ServiceNow system logs for rule execution errors
5. Test rule execution by manually creating/updating incidents and attachments
6. Verify the business rules are targeting the correct table based on integration module

#### Webhook Authentication Failures
1. Verify the API Gateway authorizer is properly configured
2. Check that the Bearer token in ServiceNow matches the AWS Secrets Manager value
3. Ensure the ServiceNow outbound REST message has the correct authorization headers
4. Test the webhook endpoint directly using the correct authentication
5. Check API Gateway logs for authentication-related errors

#### Attachment Upload Failures
1. Check file size limits (5MB maximum)
2. Verify ServiceNow API permissions for attachment operations
3. Review CloudWatch logs for specific error messages
4. Ensure temporary file cleanup is working properly
5. Check for duplicate attachment comments before adding new ones

#### Missing Incident Synchronization
1. Check EventBridge event delivery and processing
2. Verify DynamoDB table permissions and connectivity
3. Review Lambda function logs for processing errors
4. Ensure ServiceNow incident fields are properly mapped
5. Verify incident mapping entries in DynamoDB
6. Check that the correct integration module is being used for field mappings

### Enhanced Monitoring and Logging

#### CloudWatch Logs
- **ServiceNow Client Lambda**: `/aws/lambda/SecurityIncidentResponseServiceNowClient`
- **ServiceNow Notifications Handler**: `/aws/lambda/ServiceNowNotificationsHandler`
- **ServiceNow Resource Setup**: `/aws/lambda/ServiceNowResourceSetupLambda`

#### EventBridge Monitoring
- Monitor the `security-incident-event-bus` for event delivery
- Check for failed events in the dead letter queue
- Review event patterns and rule matching
- Verify event source and detail-type configurations

#### ServiceNow Monitoring
- Review ServiceNow system logs for business rule execution
- Monitor outbound REST message success/failure rates
- Check ServiceNow event logs for webhook delivery status
- Verify attachment business rule execution for incident attachments
- Ensure business rules are targeting the correct table based on integration module selection