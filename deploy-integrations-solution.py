#!/usr/bin/env python3

import argparse
import sys
import os

def deploy_jira(args):
    # Use os.execvp which replaces the current process instead of spawning a shell
    # This is safer as it doesn't involve shell interpretation
    cmd = [
        "npx", "cdk", "deploy",
        "--app", "python app_jira.py",
        "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
        "AwsSecurityIncidentResponseJiraIntegrationStack",
        "--parameters", f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
        "--parameters", f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraEmail={args.email}",
        "--parameters", f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraUrl={args.url}",
        "--parameters", f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraToken={args.token}"
    ]
    os.execvp("npx", cmd)

def deploy_servicenow(args):
    print("Service Now integration is under development/maintenance...Please wait for its release")
    # TODO: enable the below commented out code for cdk deploy of Service Now integration once the implementation is complete
    # cmd = [
    #     "npx", "cdk", "deploy",
    #     "--app", "python app_service_now.py",
    #     "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
    #     "AwsSecurityIncidentResponseServiceNowIntegrationStack",
    #     "--parameters", f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
    #     "--parameters", f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowInstanceId={args.instance_id}",
    #     "--parameters", f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowUser={args.username}",
    #     "--parameters", f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowPassword={args.password}"
    # ]
    # os.execvp("npx", cmd)

def main():
    parser = argparse.ArgumentParser(description='Deploy AWS Security Incident Response Sample Integrations')
    subparsers = parser.add_subparsers(dest='integration', help='Integration type')
    
    # Common parameters
    parser.add_argument('--log-level', choices=['info', 'debug', 'error'], default='error',
                        help='Log level for Lambda functions')
    
    # Jira integration
    jira_parser = subparsers.add_parser('jira', help='Deploy Jira integration')
    jira_parser.add_argument('--email', required=True, help='Jira email')
    jira_parser.add_argument('--url', required=True, help='Jira URL')
    jira_parser.add_argument('--token', required=True, help='Jira API token')
    jira_parser.set_defaults(func=deploy_jira)
    
    # ServiceNow integration
    servicenow_parser = subparsers.add_parser('service-now', help='Deploy ServiceNow integration')
    servicenow_parser.add_argument('--instance-id', required=True, help='ServiceNow instance ID')
    servicenow_parser.add_argument('--username', required=True, help='ServiceNow username')
    servicenow_parser.add_argument('--password', required=True, help='ServiceNow password')
    servicenow_parser.set_defaults(func=deploy_servicenow)
    
    args = parser.parse_args()
    
    if not args.integration:
        parser.print_help()
        sys.exit(1)
    
    args.func(args)

if __name__ == '__main__':
    main()