# aws_security_incident_response_sample_integrations/constants.py

# JIRA Account ID/Service Principal for creating an SNS topic that receives notifications/events from JIRA
# see the detailed documentation here - https://support.atlassian.com/cloud-automation/docs/configure-aws-sns-for-jira-automation/
JIRA_AWS_ACCOUNT_ID = "815843069303"
JIRA_AUTOMATION_ROLE_ARN = "arn:aws:sts::815843069303:assumed-role/atlassian-automation-prod-outgoing/automation-sns-publish-action"
SERVICE_NOW_AWS_ACCOUNT_ID = "XXXXXXXXXXXX"

# Event sources
JIRA_EVENT_SOURCE = "jira"
SERVICE_NOW_EVENT_SOURCE = "service-now"
SLACK_EVENT_SOURCE = "slack"
SECURITY_IR_EVENT_SOURCE = "security-ir"

# Integration target constants
JIRA_ISSUE_TYPE = "Task"

# Slack integration constants
SLACK_CHANNEL_PREFIX = "aws-security-incident-response-case-"
SLACK_SYSTEM_COMMENT_TAG = "[Slack Update]"
SLACK_MAX_RETRIES = 5
SLACK_INITIAL_RETRY_DELAY = 1  # seconds
SLACK_MAX_RETRY_DELAY = 60  # seconds

# ServiceNow automation constants
