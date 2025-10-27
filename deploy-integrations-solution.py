#!/usr/bin/env python3
"""Deployment script for AWS Security Incident Response Sample Integrations.

This script provides a command-line interface for deploying Jira and ServiceNow
integrations with AWS Security Incident Response. It handles CDK deployment
with proper parameter passing for different integration types.

Usage:
    ./deploy-integrations-solution.py jira --email user@example.com --url https://example.atlassian.net --token TOKEN --project-key PROJ
    ./deploy-integrations-solution.py service-now --instance-id example --username admin --password PASSWORD --integration-module itsm
"""

import argparse
import subprocess  # nosec B404
import sys
import textwrap


def deploy_jira(args):
    """Deploy Jira integration using CDK.

    Args:
        args: Parsed command line arguments containing Jira configuration

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    try:
        cmd = [
            "npx",
            "cdk",
            "deploy",
            "--app",
            "python3 app.py",
            "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
            "AwsSecurityIncidentResponseJiraIntegrationStack",
            "--parameters",
            f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
            "--parameters",
            f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraEmail={args.email}",
            "--parameters",
            f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraUrl={args.url}",
            "--parameters",
            f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraToken={args.token}",
            "--parameters",
            f"AwsSecurityIncidentResponseJiraIntegrationStack:jiraProjectKey={args.project_key}",
        ]
        print("\n🔄 Deploying Jira integration...\n")
        # Using subprocess with a list of arguments is safe from shell injection
        result = subprocess.run(cmd, check=True)  # nosec B603
        if result.returncode == 0:
            print("\n✅ Jira integration deployed successfully!")
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error deploying Jira integration: {e}")
        return e.returncode
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


def deploy_servicenow(args):
    """Deploy ServiceNow integration using CDK.

    Args:
        args: Parsed command line arguments containing ServiceNow configuration

    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    try:
        # print("Service Now integration is under development/maintenance...Please wait for its release")
        cmd = [
            "npx",
            "cdk",
            "deploy",
            "--app",
            "python3 app_service_now.py",
            "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
            "AwsSecurityIncidentResponseServiceNowIntegrationStack",
            "--parameters",
            f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
            "--parameters",
            f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:integrationModule={args.integration_module}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowInstanceId={args.instance_id}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowUser={args.username}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowPassword={args.password}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:integrationModule={args.integration_module}",
        ]
        print("\n🔄 Deploying ServiceNow integration...\n")
        # Using subprocess with a list of arguments is safe from shell injection
        result = subprocess.run(cmd, check=True)  # nosec B603
        if result.returncode == 0:
            print("\n✅ ServiceNow integration deployed successfully!")
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error deploying ServiceNow integration: {e}")
        return e.returncode
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


def main():
    """Main function to parse arguments and deploy integrations."""
    parser = argparse.ArgumentParser(
        description="Deploy AWS Security Incident Response Sample Integrations"
    )

    # Add global log-level argument
    parser.add_argument(
        "--log-level",
        choices=["info", "debug", "error"],
        default="error",
        help="Log level for Lambda functions",
    )

    subparsers = parser.add_subparsers(dest="integration", help="Integration type")

    # Jira integration
    jira_parser = subparsers.add_parser("jira", help="Deploy Jira integration")
    jira_parser.add_argument("--email", required=True, help="Jira email")
    jira_parser.add_argument("--url", required=True, help="Jira URL")
    jira_parser.add_argument("--token", required=True, help="Jira API token")
    jira_parser.add_argument("--project-key", required=True, help="Jira Project key")

    jira_parser.set_defaults(func=deploy_jira)

    # ServiceNow integration
    servicenow_parser = subparsers.add_parser(
        "service-now", help="Deploy ServiceNow integration"
    )
    servicenow_parser.add_argument(
        "--instance-id", required=True, help="ServiceNow instance ID"
    )
    servicenow_parser.add_argument(
        "--username", required=True, help="ServiceNow username"
    )
    servicenow_parser.add_argument(
        "--password", required=True, help="ServiceNow password"
    )
    servicenow_parser.add_argument(
        "--integration-module",
        choices=["itsm", "ir"],
        required=True,
        help="ServiceNow integration module: 'itsm' for IT Service Management or 'ir' for Incident Response",
    )

    servicenow_parser.set_defaults(func=deploy_servicenow)

    try:
        args = parser.parse_args()

        if not args.integration:
            print("\n❌ Error: Integration type is required")
            print(
                textwrap.dedent("""
                Please specify either 'jira' or 'service-now' as the integration type.
                Example: deploy-integrations-solution jira --email user@example.com --url https://example.atlassian.net --token YOUR_TOKEN --project-key PROJ
                Example: deploy-integrations-solution service-now --instance-id example --username admin --password YOUR_PASSWORD --integration-module itsm
            """)
            )
            parser.print_help()
            sys.exit(1)

        # The global --log-level argument is now used for all integrations
        print(f"DEBUG: args.log_level = {args.log_level}")

        exit_code = args.func(args)
        sys.exit(exit_code)

    except argparse.ArgumentError as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
    except SystemExit:
        # This is raised by argparse when --help is used or when required args are missing
        # We don't need to handle this as argparse will print the appropriate message
        raise
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
