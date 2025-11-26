#!/usr/bin/env python3

import argparse
import subprocess  # nosec B404
import sys
import textwrap


def deploy_jira(args):
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
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowInstanceId={args.instance_id}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowUser={args.username}",
            "--parameters",
            f"AwsSecurityIncidentResponseServiceNowIntegrationStack:serviceNowPassword={args.password}",
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


def deploy_slack(args):
    try:
        cmd = [
            "npx",
            "cdk",
            "deploy",
            "--app",
            "python3 app_slack.py",
            "AwsSecurityIncidentResponseSampleIntegrationsCommonStack",
            "AwsSecurityIncidentResponseSlackIntegrationStack",
            "--parameters",
            f"AwsSecurityIncidentResponseSampleIntegrationsCommonStack:logLevel={args.log_level}",
            "--parameters",
            f"AwsSecurityIncidentResponseSlackIntegrationStack:slackBotToken={args.bot_token}",
            "--parameters",
            f"AwsSecurityIncidentResponseSlackIntegrationStack:slackSigningSecret={args.signing_secret}",
            "--parameters",
            f"AwsSecurityIncidentResponseSlackIntegrationStack:slackWorkspaceId={args.workspace_id}",
        ]
        print("\n🔄 Deploying Slack integration...\n")
        # Using subprocess with a list of arguments is safe from shell injection
        result = subprocess.run(cmd, check=True)  # nosec B603
        if result.returncode == 0:
            print("\n✅ Slack integration deployed successfully!")
            
            # Run deployment verification if requested
            if not args.skip_verification:
                print("\n🔍 Running deployment verification...")
                verify_cmd = [
                    "python3",
                    "scripts/verify_slack_deployment.py",
                    "--region",
                    args.region if hasattr(args, 'region') and args.region else "us-east-1",
                ]
                verify_result = subprocess.run(verify_cmd)  # nosec B603
                if verify_result.returncode != 0:
                    print("\n⚠️  Deployment verification found some issues. Please review the output above.")
            else:
                print("\n📝 Next steps:")
                print("   1. Run verification: python3 scripts/verify_slack_deployment.py")
                print("   2. Configure your Slack app's Event Subscriptions URL with the API Gateway endpoint")
                print("   3. Configure your Slack app's Slash Commands with the /security-ir command")
                print("   4. Install the Slack app to your workspace")
                print("   5. Test the integration by creating a test AWS Security IR case")
        return result.returncode
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Error deploying Slack integration: {e}")
        return e.returncode
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        return 1


def main():
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
    jira_parser.add_argument(
        "--log-level",
        choices=["info", "debug", "error"],
        help="Log level for Lambda functions (overrides global setting)",
    )
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
        "--log-level",
        choices=["info", "debug", "error"],
        help="Log level for Lambda functions (overrides global setting)",
    )
    servicenow_parser.set_defaults(func=deploy_servicenow)

    # Slack integration
    slack_parser = subparsers.add_parser("slack", help="Deploy Slack integration")
    slack_parser.add_argument(
        "--bot-token", required=True, help="Slack Bot User OAuth Token (xoxb-...)"
    )
    slack_parser.add_argument(
        "--signing-secret", required=True, help="Slack App Signing Secret"
    )
    slack_parser.add_argument(
        "--workspace-id", required=True, help="Slack Workspace ID"
    )
    slack_parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region for deployment (default: us-east-1)",
    )
    slack_parser.add_argument(
        "--skip-verification",
        action="store_true",
        help="Skip post-deployment verification checks",
    )
    slack_parser.add_argument(
        "--log-level",
        choices=["info", "debug", "error"],
        help="Log level for Lambda functions (overrides global setting)",
    )
    slack_parser.set_defaults(func=deploy_slack)

    try:
        args = parser.parse_args()

        if not args.integration:
            print("\n❌ Error: Integration type is required")
            print(
                textwrap.dedent("""
                Please specify 'jira', 'service-now', or 'slack' as the integration type.
                Example: deploy-integrations-solution jira --email user@example.com --url https://example.atlassian.net --token YOUR_TOKEN --project-key PROJ
                Example: deploy-integrations-solution service-now --instance-id example --username admin --password YOUR_PASSWORD
                Example: deploy-integrations-solution slack --bot-token xoxb-... --signing-secret YOUR_SECRET --workspace-id YOUR_WORKSPACE_ID
            """)
            )
            parser.print_help()
            sys.exit(1)

        # If log-level is specified in subparser, it overrides the global one
        # Otherwise, use the global log-level
        if not hasattr(args, "log_level") or args.log_level is None:
            args.log_level = parser.get_default("log_level")

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
