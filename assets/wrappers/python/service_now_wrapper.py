"""
ServiceNow API wrapper for AWS Security Incident Response integration.
This module provides a wrapper around the ServiceNow API for use in the Security Incident Response integration.
"""

import os
import logging
from typing import Dict, Optional, Any

import boto3
from pysnc import ServiceNowClient

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize AWS clients
ssm_client = boto3.client("ssm")


class ServiceNowClient:
    """Class to handle ServiceNow API interactions"""

    def __init__(self, instance_id, username, password_param_name):
        """
        Initialize the ServiceNow client
        
        Args:
            instance_id: ServiceNow instance ID
            username: ServiceNow username
            password: ServiceNow password
        """
        self.instance_id = instance_id
        self.username = username
        self.password_param_name = password_param_name
        self.client = self._create_client()

    def _create_client(self) -> Optional[ServiceNowClient]:
        """`
        Create a ServiceNow client instance
        
        Returns:
            ServiceNowClient or None if creation fails
        """
        try:
            # Use provided parameters or fetch from SSM
            instance = self.instance_id
            username = self.username
            password = self.__get_password()

            if not instance:
                logger.error("No ServiceNow instance id provided")
                return None
            elif not username:
                logger.error("No ServiceNow username provided")
                return None

            return ServiceNowClient(
                instance=instance,
                username=username,
                password=password
            )
        except Exception as e:
            logger.error(f"Error creating ServiceNow client: {str(e)}")
            return None

    def __get_password(self) -> Optional[str]:
        """
        Fetch the ServiceNow password from SSM Parameter Store
        
        Returns:
            Password or None if retrieval fails
        """
        try:
            if not password_param_name:
                logger.error("No ServiceNow password param name provided")
                return None
            
            password_param_name = self.password_param_name
            response = ssm_client.get_parameter(
                Name=password_param_name, WithDecryption=True
            )
            return response["Parameter"]["Value"]
        except Exception as e:
            logger.error(f"Error retrieving ServiceNow password from SSM: {str(e)}")
            return None

    def get_incident(self, incident_number: str) -> Optional[Dict[str, Any]]:
        """
        Get a ServiceNow incident by sys_id
        
        Args:
            sys_id: The ServiceNow incident sys_id
            
        Returns:
            Incident or None if retrieval fails
        """
        # TODO: This is a sample code for get_incident from Service Now using pysnc. The implementation for service_now_client event processing will cover this in detail.
        # TODO: see https://app.asana.com/1/8442528107068/project/1209571477232011/task/1210523986950471?focus=true
        try:
            glide_record = self.client.GlideRecord('incident')
            return glide_record.get(incident_number)
        except Exception as e:
            logger.error(f"Error getting incident {incident_number} from ServiceNow API: {str(e)}")
            return None