import json
from typing import Optional
import boto3
import requests
import secrets
import string
import os
from base64 import b64encode
import logging
from botocore.exceptions import ClientError

# Configure logging
logger = logging.getLogger()

# Get log level from environment variable
log_level = os.environ.get("LOG_LEVEL", "error").lower()
if log_level == "debug":
    logger.setLevel(logging.DEBUG)
elif log_level == "info":
    logger.setLevel(logging.INFO)
else:
    # Default to ERROR level
    logger.setLevel(logging.ERROR)

ssm_client = boto3.client("ssm")
secrets_client = boto3.client("secretsmanager")
request_content = "application/json"

class ParameterService:
    """Class to handle parameter operations"""

    def __init__(self):
        """Initialize the parameter service"""

    def get_parameter(self, parameter_name: str) -> Optional[str]:
        """
        Get a parameter from SSM Parameter Store

        Args:
            parameter_name: The name of the parameter to retrieve

        Returns:
            Parameter value or None if retrieval fails
        """
        try:
            response = ssm_client.get_parameter(
                Name=parameter_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving parameter {parameter_name}: {error_code}")
            return None


class SecretsManagerService:
    """Class to handle Secrets Manager operations"""

    def __init__(self):
        """Initialize the secrets manager service"""

    def get_secret_value(self, secret_arn: str) -> Optional[str]:
        """
        Get a secret value from AWS Secrets Manager

        Args:
            secret_arn: The ARN of the secret to retrieve

        Returns:
            Secret token value or None if retrieval fails
        """
        try:
            response = secrets_client.get_secret_value(SecretId=secret_arn)
            secret_dict = json.loads(response["SecretString"])
            return secret_dict.get("token")
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(f"Error retrieving secret {secret_arn}: {error_code}")
            return None
        except Exception as e:
            logger.error(f"Error parsing secret value: {str(e)}")
            return None
        
class ServiceNowApiService:
    """Class to manage ServiceNow API operations"""

    def __init__(
        self, instance_id, username, password_param_name
    ):
        """Initialize the ServiceNow API service"""
        self.instance_id = instance_id
        self.username = username
        self.password_param_name = password_param_name
        self.secrets_manager_service = SecretsManagerService()

    def __get_password(self, password_param_name) -> Optional[str]:
        """
        Fetch the ServiceNow password from SSM Parameter Store

        Returns:
            Password or None if retrieval fails
        """
        try:
            if not password_param_name:
                logger.error("No ServiceNow password param name provided")
                return None

            response = ssm_client.get_parameter(
                Name=password_param_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(f"Error retrieving ServiceNow password from SSM: {str(e)}")
            return None

    def __get_request_headers(self):
        """Get headers for ServiceNow API requests"""
        try:
            password = self.__get_password(self.password_param_name)
            auth = b64encode(f"{self.username}:{password}".encode()).decode()
            return {
                "Authorization": f"Basic {auth}",
                "Content-Type": request_content,
                "Accept": request_content,
            }
        except Exception as e:
            logger.error(f"Error getting request headers: {str(e)}")
            return None

    def __get_request_base_url(self):
        """Get base url for ServiceNow API requests"""
        try:
            return f"https://{self.instance_id}.service-now.com"
        except Exception as e:
            logger.error(f"Error getting base url: {str(e)}")
            return None
        
    def _update_outbound_rest_message_request_function_headers(
            self,
            resource_prefix,
            api_auth_token,
        ):
            """Create/Update Http request headers to be used in the Outbound REST Message function resource in ServiceNow for integration"""
            try:
                logger.info(
                    "Updating Http request headers in the Outbound REST Message function resource in ServiceNow for integration with AWS Security Incident Response"
                )
                
                # Prepare the inputs for ServiceNow API requests
                # Get headers for ServiceNow API requests
                headers = self.__get_request_headers()
                # Get base url for ServiceNow API requests
                base_url = self.__get_request_base_url()
                request_type = "POST"

                # Update the Outbound REST Message resource
                # Prepare the Outbound REST Message resource and function names
                outbound_rest_message_name = f"{resource_prefix}-outbound-rest-message"
                outbound_rest_message_request_function_name = (
                f"{outbound_rest_message_name}-{request_type}-function"
                )
                
                # Update Authorization header if token is available
                if api_auth_token:
                    rest_message_post_function_headers_payload = { 
                                        "rest_message_function": f"{outbound_rest_message_request_function_name}",
                                        "name": "Authorization",
                                        "value": f"Bearer {api_auth_token}"
                                }
                
                rest_message_post_function_headers_response = requests.post(
                    f"{base_url}/api/now/table/sys_rest_message_fn_headers",
                    json=rest_message_post_function_headers_payload,
                    headers=headers,
                    timeout=30,
                )

                rest_message_post_function_headers_response_json = json.loads(
                    rest_message_post_function_headers_response.text
                )

                logger.info(
                    f"Http request function for Outbound REST Message created with response: {rest_message_post_function_headers_response_json}"
                )

                rest_message_post_function_sys_id = (
                    rest_message_post_function_headers_response_json.get("result").get("sys_id")
                )
                return rest_message_post_function_sys_id
            except Exception as e:
                logger.error(f"Error creating Http request function: {str(e)}")
                return None

def handler(event, context):
    """
    Lambda function to rotate API Gateway authorization token
    """    
    secret_arn = event['SecretId']
    token = event['ClientRequestToken']
    step = event['Step']
    
    if step == "createSecret":
        # Generate new token
        alphabet = string.ascii_letters + string.digits
        new_token = ''.join(secrets.choice(alphabet) for _ in range(32))
        
        secret_dict = {"token": new_token}
        secrets_client.put_secret_value(
            SecretId=secret_arn,
            ClientRequestToken=token,
            SecretString=json.dumps(secret_dict),
            VersionStage="AWSPENDING"
        )
        
        # Persist the new auth token in ServiceNow
        # Get environment variables
        service_now_resource_prefix = os.environ.get("SERVICE_NOW_RESOURCE_PREFIX")
        
        # Get credentials from SSM for ServiceNow
        parameter_service = ParameterService()
        service_now_instance_id = parameter_service.get_parameter(
            os.environ.get("SERVICE_NOW_INSTANCE_ID")
        )
        service_now_username = parameter_service.get_parameter(os.environ.get("SERVICE_NOW_USER"))
        service_now_password_param_name = os.environ.get("SERVICE_NOW_PASSWORD_PARAM")
        
        service_now_api_service = ServiceNowApiService(
            service_now_instance_id, service_now_username, service_now_password_param_name
        )
        
        service_now_api_service._update_outbound_rest_message_request_function_headers(service_now_resource_prefix, new_token)
        
    elif step == "setSecret":
        # No external service to update for this token
        pass
        
    elif step == "testSecret":
        # Test would be done by API Gateway validation
        pass
        
    elif step == "finishSecret":
        # Move AWSPENDING to AWSCURRENT
        secrets_client.update_secret_version_stage(
            SecretId=secret_arn,
            VersionStage="AWSCURRENT",
            ClientRequestToken=token,
            RemoveFromVersionId=secrets_client.describe_secret(SecretId=secret_arn)['VersionIdsToStages']
        )
        
    return {"statusCode": 200}




<record_update table="sys_rest_message_fn_headers" field="rest_message_function" query="rest_message_function=c0e6d1e9c383a210fca5b2ddd40131e8^ORDERBYname"><record sys_id="852680eec3cf2a10fca5b2ddd4013124" operation="add"><field name="name" modified="true" value_set="true" dsp_set="false"><value>basic_auth_password</value></field><field name="value" modified="true" value_set="false" dsp_set="true"><value></value><display_value>test</display_value></field><field name="rest_message_function" modified="false" value_set="true" dsp_set="false"><value>c0e6d1e9c383a210fca5b2ddd40131e8</value></field></record></record_update>

<record_update table="sys_rest_message_fn_param_defs" field="rest_message_function" query="rest_message_function=c0e6d1e9c383a210fca5b2ddd40131e8^ORDERBYorder"/>


rest_message_post_function_headers_response = requests.post(
                     f"{base_url}/api/now/table/sys_rest_message_fn_headers",
                     json=rest_message_post_function_headers_payload,
                     headers=headers,
                     timeout=30,
             )

headers = {
                 "Authorization": f"Basic {auth}",
                 "Content-Type": request_content,
                 "Accept": request_content,
             }

rest_message_post_function_headers_payload = { 
                     "rest_message_function": f"{outbound_rest_message_request_function_name}",
                     "name": "Authorization",
                     "value": "Bearer test"
             }