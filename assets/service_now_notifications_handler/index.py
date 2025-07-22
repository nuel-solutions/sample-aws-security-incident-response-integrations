"""
ServiceNow Notifications Handler Lambda function for AWS Security Incident Response integration.
This module processes notifications from ServiceNow and publishes events to EventBridge.
"""

import json
import html
import os
import sys
import datetime
import re
import traceback
import logging
from typing import Dict, Any, Optional, List, Union
import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import ClientError
from aws_lambda_powertools.utilities.typing import LambdaContext

try:
    # This import works for lambda function and imports the lambda layer at runtime
    from service_now_wrapper import ServiceNowClient
except ImportError:
    # This import works for local development and imports locally from the file system
    from ..wrappers.python.service_now_wrapper import ServiceNowClient

# Constants
EVENT_SOURCE = os.environ.get('EVENT_SOURCE', 'service-now')

# Configure logging
logger = logging.getLogger()

# Get log level from environment variable
log_level = os.environ.get('LOG_LEVEL', 'error').lower()
if log_level == 'debug':
    logger.setLevel(logging.DEBUG)
elif log_level == 'info':
    logger.setLevel(logging.INFO)
else:
    # Default to ERROR level
    logger.setLevel(logging.ERROR)

# Initialize AWS clients
events_client = boto3.client("events")
dynamodb = boto3.resource("dynamodb")


class DateTimeEncoder(json.JSONEncoder):
    """Custom JSON encoder for datetime objects"""

    def default(self, obj):
        """Convert datetime objects to ISO format strings"""
        if isinstance(obj, (datetime.date, datetime.datetime)):
            return obj.isoformat()
        return super().default(obj)


class BaseEvent:
    """Base class for domain events"""

    event_type = None
    event_source = EVENT_SOURCE

    def to_dict(self) -> Dict[str, Any]:
        """Convert the event to a dictionary"""
        raise NotImplementedError("Subclasses must implement to_dict()")


class IncidentCreatedEvent(BaseEvent):
    """Domain event for incident creation"""

    event_type = 'IncidentCreated'

    def __init__(self, incident: Dict[str, Any]):
        """
        Initialize an IncidentCreatedEvent

        Args:
            incident: The incident details dictionary
        """
        self.incident = incident

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary

        Returns:
            Dictionary representation of the event
        """
        return {
            'eventType': self.event_type,
            'eventSource': self.event_source,
            'id': self.incident.get('id', ''),
            'key': self.incident.get('key', ''),
            'summary': self.incident.get('summary', ''),
            'status': self.incident.get('status', ''),
            'updated': self.incident.get('updated', ''),
            'created': self.incident.get('created', ''),
            'description': self.incident.get('description', ''),
            'priority': self.incident.get('priority', ''),
            'assignee': self.incident.get('assignee', ''),
            'reporter': self.incident.get('reporter', ''),
            'comments': self.incident.get('comments', []),
            'attachments': self.incident.get('attachments', []),
            'incidentType': self.incident.get('incidenttype', ''),
            'project': self.incident.get('project', ''),
            'resolution': self.incident.get('resolution', ''),
            'securityLevel': self.incident.get('securityLevel', '')
        }


class IncidentUpdatedEvent(BaseEvent):
    """Domain event for incident update"""

    event_type = 'IncidentUpdated'

    def __init__(self, incident: Dict[str, Any]):
        """
        Initialize an IncidentUpdatedEvent

        Args:
            incident: The incident details dictionary
        """
        self.incident = incident

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary

        Returns:
            Dictionary representation of the event
        """
        return {
            'eventType': self.event_type,
            'eventSource': self.event_source,
            'id': self.incident.get('id', ''),
            'key': self.incident.get('key', ''),
            'summary': self.incident.get('summary', ''),
            'status': self.incident.get('status', ''),
            'updated': self.incident.get('updated', ''),
            'created': self.incident.get('created', ''),
            'description': self.incident.get('description', ''),
            'priority': self.incident.get('priority', ''),
            'assignee': self.incident.get('assignee', ''),
            'reporter': self.incident.get('reporter', ''),
            'comments': self.incident.get('comments', []),
            'attachments': self.incident.get('attachments', []),
            'incidentLinks': self.incident.get('incidentlinks', []),
            'incidentType': self.incident.get('incidenttype', ''),
            'project': self.incident.get('project', ''),
            'resolution': self.incident.get('resolution', ''),
        }


class IncidentDeletedEvent(BaseEvent):
    """Domain event for incident deletion"""

    event_type = 'IncidentDeleted'

    def __init__(self, incident_id: str):
        """
        Initialize an IncidentDeletedEvent

        Args:
            incident_id: The ID of the incident that was deleted
        """
        self.incident_id = incident_id

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the event to a dictionary

        Returns:
            Dictionary representation of the event
        """
        return {
            'eventType': self.event_type,
            'eventSource': self.event_source,
            'incidentId': self.incident_id
        }


class ParameterService:
    """Class to handle parameter operations"""

    def __init__(self):
        """Initialize the parameter service"""
        self.ssm_client = boto3.client("ssm")

    def _get_parameter(self, parameter_name: str) -> Optional[str]:
        """
        Get a parameter from SSM Parameter Store

        Args:
            parameter_name: The name of the parameter to retrieve

        Returns:
            Parameter value or None if retrieval fails
        """
        try:
            response = self.ssm_client.get_parameter(
                Name=parameter_name,
                WithDecryption=True
            )
            return response['Parameter']['Value']
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(
                f"Error retrieving parameter {parameter_name}: {error_code}")
            return None


class EventPublisherService:
    """Service for publishing events to EventBridge"""

    def __init__(self, event_bus_name: str):
        """
        Initialize an EventPublisherService

        Args:
            event_bus_name: Name of the EventBridge event bus
        """
        logger.debug(
            f"Initializing EventPublisherService with event bus: {event_bus_name}")
        self.events_client = events_client
        self.event_bus_name = event_bus_name

    def _publish_event(self, event: BaseEvent) -> Dict[str, Any]:
        """
        Publish an event to the EventBridge event bus

        Args:
            event: The event to publish

        Returns:
            Response from EventBridge
        """
        logger.info(f"Publishing event: {event.event_type}")
        event_dict = event.to_dict()

        try:
            # Convert the dictionary to a JSON string
            event_json = json.dumps(event_dict, cls=DateTimeEncoder)

            response = self.events_client.put_events(
                Entries=[
                    {
                        'Source': EVENT_SOURCE,
                        'DetailType': event.event_type,
                        'Detail': event_json,
                        'EventBusName': self.event_bus_name
                    }
                ]
            )
            logger.info(f"Event {event.event_type} published successfully")
            logger.debug(f"Event published successfully: {response}")
            return response
        except Exception as e:
            logger.error(f"Error publishing event: {str(e)}")
            logger.error(traceback.format_exc())
            raise


class DatabaseService:
    """Service for database operations"""

    def __init__(self, table_name):
        """Initialize the database service"""
        self.table = dynamodb.Table(table_name)

    def __scan_for_incident_id(self, service_now_incident_id: str) -> List[Dict[str, Any]]:
        """
        Scan DynamoDB table for ServiceNow incident ID

        Args:
            service_now_incident_id: The ServiceNow incident ID

        Returns:
            List of matching items
        """
        try:
            response = self.table.scan(
                FilterExpression=Attr('serviceNowIncidentId').eq(
                    service_now_incident_id)
            )
            items = response['Items']

            # Handle pagination if there are more items
            while 'LastEvaluatedKey' in response:
                response = self.table.scan(
                    FilterExpression=Attr('serviceNowIncidentId').eq(
                        service_now_incident_id),
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                items.extend(response['Items'])
            return items
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            logger.error(
                f"Error retrieving details from the DynamoDB table: {error_code}")
            return []
        except KeyError:
            logger.error(
                f"ServiceNow incident for {service_now_incident_id} not found in database")
            return []

    def _get_incident_details(self, service_now_incident_id: str) -> Optional[str]:
        """
        Get ServiceNow incident details from the database

        Args:
            service_now_incident_id: The ServiceNow incident ID

        Returns:
            ServiceNow incident details or None if not found
        """
        try:
            items = self.__scan_for_incident_id(service_now_incident_id)
            if not items:
                logger.info(
                    f"Incident details for {service_now_incident_id} not found in database.")
                return None

            service_now_incident_details = items[0]["serviceNowIncidentDetails"]
            logger.info(
                f"Incident details for {service_now_incident_id} found in database.")
            return service_now_incident_details
        except Exception as e:
            logger.error(
                f"Error retrieving details from the DynamoDB table: {e}")
            return None

    def _add_incident_details(self, service_now_incident_id: str, service_now_incident_details: Dict[str, Any]) -> bool:
        """
        Create a new entry with ServiceNow incident details

        Args:
            service_now_incident_id: The ServiceNow incident ID
            service_now_incident_details: The ServiceNow incident details

        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert the incident details to a JSON string for storage
            service_now_details_json = json.dumps(service_now_incident_details)

            # Use a composite key pattern with a prefix to maintain data model integrity
            case_id = f"ServiceNow#{service_now_incident_id}"

            # Create a new entry with the ServiceNow incident ID and details
            logger.info(
                f"Creating a new entry with CaseId {case_id} for ServiceNow incident {service_now_incident_id} in DynamoDb table")
            self.table.put_item(
                Item={
                    'PK': case_id,
                    'SK': 'latest',
                    'serviceNowIncidentId': service_now_incident_id,
                    'serviceNowIncidentDetails': service_now_details_json,
                }
            )

            logger.info(
                f"Successfully added details to DynamoDb table for ServiceNow incident {service_now_incident_id}")
            return True
        except Exception as e:
            logger.error(
                f"Error adding details to DynamoDb table for ServiceNow incident {service_now_incident_id}: {str(e)}")
            return False

    def _update_incident_details(self, service_now_incident_id: str, service_now_incident_details: Dict[str, Any]) -> bool:
        """
        Update an existing entry with ServiceNow incident details

        Args:
            service_now_incident_id: The ServiceNow incident ID
            service_now_incident_details: The ServiceNow incident details

        Returns:
            True if successful, False otherwise
        """
        try:
            # Convert the incident details to a JSON string for storage
            service_now_details_json = json.dumps(service_now_incident_details)

            # Use a composite key pattern with a prefix to maintain data model integrity
            case_id = f"ServiceNow#{service_now_incident_id}"

            # Update the existing entry with the ServiceNow incident ID and details
            logger.info(
                f"Updating entry with CaseId {case_id} for ServiceNow incident {service_now_incident_id} in DynamoDb table")
            self.table.update_item(
                Key={"PK": f"{case_id}", "SK": "latest"},
                UpdateExpression="set serviceNowIncidentDetails = :s",
                ExpressionAttributeValues={":s": service_now_details_json},
                ReturnValues="UPDATED_NEW",
            )

            logger.info(
                f"Successfully updated details in DynamoDb table for ServiceNow incident {service_now_incident_id}")
            return True
        except Exception as e:
            logger.error(
                f"Error updating details in DynamoDb table for ServiceNow incident {service_now_incident_id}: {str(e)}")
            return False


class ServiceNowService:
    """Service for ServiceNow operations"""

    def __init__(self, instance_id, username, password_param_name):
        """Initialize the ServiceNow service"""
        self.service_now_client = ServiceNowClient(
            instance_id, username, password_param_name)

    def __extract_incident_details(self, service_now_incident: Any) -> Dict[str, Any]:
        """
        Extract relevant details from a ServiceNow incident object into a serializable dictionary

        Args:
            service_now_incident: ServiceNow incident object

        Returns:
            Dictionary with serializable ServiceNow incident details
        """
        try:
            incident_dict = {
                "sys_id": service_now_incident.sys_id,
                "number": service_now_incident.number,
                "short_description": service_now_incident.short_description,
                "description": service_now_incident.description,
                "sys_updated_on": service_now_incident.sys_updated_on.get_display_value(),
                "sys_created_on": service_now_incident.sys_created_on.get_display_value(),
                "sys_created_by": service_now_incident.sys_created_by.get_display_value(),
                "resolved_by": service_now_incident.resolved_by.get_display_value(),
                "resolved_at": service_now_incident.resolved_at.get_display_value(),
                "opened_at": service_now_incident.opened_at.get_display_value(),
                "closed_at": service_now_incident.closed_at.get_display_value(),
                "state": service_now_incident.state.get_display_value(),
                "impact": service_now_incident.impact.get_display_value(),
                "active": service_now_incident.active.get_display_value(),
                "priority": service_now_incident.priority.get_display_value(),
                "caller_id": service_now_incident.caller_id.get_display_value(),
                "incident_state": service_now_incident.incident_state.get_display_value(),
                "urgency": service_now_incident.urgency.get_display_value(),
                "severity": service_now_incident.severity.get_display_value(),
                "comments_and_work_notes": service_now_incident.comments_and_work_notes.get_display_value(),
                "close_code": service_now_incident.close_code.get_display_value(),
                "close_notes": service_now_incident.close_notes.get_display_value(),
                "closed_by": service_now_incident.closed_by.get_display_value(),
                "reopened_by": service_now_incident.reopened_by.get_display_value(),
                "assigned_to": service_now_incident.assigned_to.get_display_value(),
                "due_date": service_now_incident.due_date.get_display_value(),
                "sys_tags": service_now_incident.sys_tags.get_display_value(),
                "category": service_now_incident.subcategory.get_display_value(),
                "subcategory": service_now_incident.subcategory.get_display_value(),
            }
            return incident_dict
        except Exception as e:
            logger.error(
                f"Error extracting ServiceNow incident details: {str(e)}")
            # Return minimal details if extraction fails
            return {
                "id": service_now_incident.id if hasattr(service_now_incident, 'id') else None,
                "key": service_now_incident.key if hasattr(service_now_incident, 'key') else None,
                "error": str(e)
            }

    def _get_incident_details(self, service_now_incident_id: str) -> Optional[Dict[str, Any]]:
        """
        Get incident details from ServiceNow

        Args:
            service_now_incident_id: The ServiceNow incident ID

        Returns:
            Dictionary of incident details or None if retrieval fails
        """
        try:
            service_now_incident = self.service_now_client.get_incident(
                service_now_incident_id)
            if not service_now_incident:
                logger.error(
                    f"Failed to get incident {service_now_incident_id} from ServiceNow")
                return None

            return self.__extract_incident_details(service_now_incident)
        except Exception as e:
            logger.error(
                f"Error getting incident details from ServiceNow: {str(e)}")
            return None


class ServiceNowMessageProcessorService:
    """Class to handle ServiceNow message processing"""

    def __init__(self, instance_id, username, password_param_name, table_name, event_bus_name):
        """Initialize the message processor"""
        self.db_service = DatabaseService(table_name)
        self.service_now_service = ServiceNowService(
            instance_id, username, password_param_name)
        self.event_publisher_service = EventPublisherService(event_bus_name)

    def _extract_event_body(self, event):
        """
        Extract the request body from the event

        Args:
            event: The event payload

        Returns:
            Request body from the event payload
        """
        try:
            # Extract the request body from API Gateway event
            body = event.get('body', '{}')
            if event.get('isBase64Encoded', False):
                import base64
                body = base64.b64decode(body).decode('utf-8')
            return body
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse message: {str(e)}")
            return {}

    def _parse_message(self, message: str) -> Dict[str, Any]:
        """
        Parse a JSON string message

        Args:
            message: The message string to parse

        Returns:
            Dictionary containing parsed message or empty dict if parsing fails
        """
        try:
            return json.loads(message)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse message: {str(e)}")
            return {}

    def _process_webhook_payload(self, payload: Dict[str, Any]) -> bool:
        """
        Process webhook payload from ServiceNow

        Args:
            payload: The parsed webhook payload

        Returns:
            True if processing was successful, False otherwise
        """
        # Extract incident_number and event_type from the payload
        incident_number = payload.get('incident_number')
        event_type = payload.get('event_type')

        if not incident_number:
            logger.error("No incident_number found in payload")
            return False

        logger.info(
            f"Processing incident: {incident_number} with event_type: {event_type}")

        # Get incident details and process based on event type
        return self.__process_incident(incident_number)

    def __process_incident(self, incident_number: str) -> bool:
        """
        Process a ServiceNow incident

        Args:
            incident_number: The ServiceNow incident number

        Returns:
            True if processing was successful, False otherwise
        """
        # Get ServiceNow incident details
        service_now_incident_details = self.service_now_service._get_incident_details(
            incident_number)
        if not service_now_incident_details:
            logger.error(
                f"Failed to get incident details for {incident_number} from ServiceNow")
            return False

        # Get existing incident details from database
        service_now_incident_details_ddb = self.db_service._get_incident_details(
            incident_number)

        # Process based on whether the incident exists in the database
        if not service_now_incident_details_ddb:
            return self.__handle_new_incident(incident_number, service_now_incident_details)
        else:
            return self.__handle_existing_incident(incident_number, service_now_incident_details,
                                                 service_now_incident_details_ddb)

    def __handle_new_incident(self, incident_number: str, incident_details: Dict[str, Any]) -> bool:
        """
        Handle a new incident that doesn't exist in the database

        Args:
            incident_number: The ServiceNow incident number
            incident_details: The incident details from ServiceNow

        Returns:
            True if processing was successful, False otherwise
        """
        try:
            logger.info(
                f"Publishing IncidentCreatedEvent for ServiceNow incident {incident_number}")
            self.event_publisher_service._publish_event(
                IncidentCreatedEvent(incident_details))
            self.db_service._add_incident_details(
                incident_number, incident_details)
            return True
        except Exception as e:
            logger.error(
                f"Error handling new incident {incident_number}: {str(e)}")
            return False

    def __handle_existing_incident(self, incident_number: str, incident_details: Dict[str, Any],
                                 existing_details: str) -> bool:
        """
        Handle an existing incident that's already in the database

        Args:
            incident_number: The ServiceNow incident number
            incident_details: The incident details from ServiceNow
            existing_details: The existing incident details from the database

        Returns:
            True if processing was successful, False otherwise
        """
        try:
            # Compare incident details to detect changes
            incident_details_json = json.dumps(incident_details)
            if json.loads(incident_details_json) != json.loads(existing_details):
                logger.info(
                    f"Publishing IncidentUpdatedEvent for ServiceNow incident {incident_number}")
                self.event_publisher_service._publish_event(
                    IncidentUpdatedEvent(incident_details))
                self.db_service._update_incident_details(
                    incident_number, incident_details)
            else:
                logger.info(
                    f"No changes detected for incident {incident_number}")
            return True
        except Exception as e:
            logger.error(
                f"Error handling existing incident {incident_number}: {str(e)}")
            return False

    # def process_automation_data(self, automation_data: Dict[str, Any], event_bus_name: str = 'default') -> bool:
    #     """
    #     Process the automation data

    #     Args:
    #         automation_data: The automation data to process
    #         event_bus_name: Name of the EventBridge event bus

    #     Returns:
    #         True if processing was successful, False otherwise
    #     """
    #     if not automation_data:
    #         logger.warning("No data received in ServiceNow event")
    #         return False

    #     try:
    #         # Log the automation data (sanitized)
    #         logger.info(f"Processing automation data: {html.escape(json.dumps(automation_data))}")

    #         # Create an EventPublisherService instance
    #         event_publisher = EventPublisherService(event_bus_name)

    #         # Get ServiceNow incident ID from the automation data
    #         service_now_incident_id = automation_data.get("IncidentId")
    #         if not service_now_incident_id:
    #             logger.error("No IncidentId found in automation data")
    #             return False

    #         # Get ServiceNow incident details from ServiceNow first
    #         service_now_incident_details = self.service_now_service._get_incident_details(service_now_incident_id)
    #         if not service_now_incident_details:
    #             logger.error(f"Failed to get incident details for {service_now_incident_id} from ServiceNow")
    #             return False

    #         # Get ServiceNow incident details from database
    #         service_now_incident_details_ddb = self.db_service._get_incident_details(service_now_incident_id)

    #         # If incident not found in database, publish created event and update the database
    #         if not service_now_incident_details_ddb:
    #             logger.info(f"ServiceNow incident details for {service_now_incident_id} not found in database")
    #             # Update the database with the ServiceNow incident ID and details
    #             try:
    #                 logger.info(f"Publishing IncidentCreatedEvent for ServiceNow incident {service_now_incident_id}")
    #                 event_publisher._publish_event(IncidentCreatedEvent(service_now_incident_details))
    #                 # Use a composite key pattern to maintain data model integrity
    #                 logger.info(f"Adding ServiceNow incident details for {service_now_incident_id} to database")
    #                 self.db_service._add_incident_details(service_now_incident_id, service_now_incident_details)
    #                 return True
    #             except Exception as e:
    #                 logger.error(f"Error updating database with ServiceNow incident details: {str(e)}")
    #                 return False

    #         logger.info(f"ServiceNow incident details for {service_now_incident_id} found in database. Comparing it with the incident details from ServiceNow")
    #         # Compare incident details to detect changes
    #         service_now_details_json = json.dumps(service_now_incident_details)
    #         if json.loads(service_now_details_json) != json.loads(service_now_incident_details_ddb):
    #             logger.info(f"ServiceNow incident details for {service_now_incident_id} have changed. Publishing IncidentUpdatedEvent")
    #             event_publisher._publish_event(IncidentUpdatedEvent(service_now_incident_details))
    #             logger.info(f"Storing the updated incident details for ServiceNow incident {service_now_incident_id} in the database")
    #             self.db_service._update_incident_details(service_now_incident_id, service_now_incident_details)
    #             return True

    #         logger.info(f"No changes detected for incident {service_now_incident_id}")
    #         return True

    #     except Exception as e:
    #         logger.error(f"Error processing automation data: {str(e)}")
    #         logger.error(traceback.format_exc())
    #         return False


class ResponseBuilderService:
    """Class to handle response building"""

    @staticmethod
    def _build_success_response(message: str) -> Dict[str, Any]:
        """
        Build a success response

        Args:
            message: Success message

        Returns:
            API Gateway compatible response
        """
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST,OPTIONS'
            },
            'body': json.dumps({
                'message': message
            })
        }

    @staticmethod
    def _build_error_response(error: str) -> Dict[str, Any]:
        """
        Build an error response

        Args:
            error: Error message

        Returns:
            API Gateway compatible response
        """
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST,OPTIONS'
            },
            'body': json.dumps({
                'error': error
            })
        }


@logger.inject_lambda_context
def handler(event: Dict[str, Any], context: LambdaContext) -> Dict[str, Any]:
    """
    Lambda handler for processing API Gateway webhook events from ServiceNow

    Args:
        event: The Lambda event from API Gateway
        context: The Lambda context

    Returns:
        API Gateway compatible response
    """
    try:
        # Log incoming event
        logger.info(f"Received event: {json.dumps(event)}")

        # Handle OPTIONS request for CORS
        if event.get('httpMethod') == 'OPTIONS':
            return {
                'statusCode': 200,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': '*',
                    'Access-Control-Allow-Headers': 'Content-Type',
                    'Access-Control-Allow-Methods': 'POST,OPTIONS'
                },
                'body': ''
            }

        # Validate event structure
        if not isinstance(event, dict):
            raise ValueError(f"Expected dict event, got {type(event)}")

        # Get environment variables
        table_name = os.environ["INCIDENTS_TABLE_NAME"]
        event_bus_name = os.environ.get('EVENT_BUS_NAME', 'default')

        parameter_service = ParameterService()
        # Get credentials from SSM
        instance_id = parameter_service._get_parameter(
            os.environ.get("SERVICE_NOW_INSTANCE_ID"))
        username = parameter_service._get_parameter(
            os.environ.get("SERVICE_NOW_USER"))
        password_param_name = parameter_service._get_parameter(
            os.environ.get("SERVICE_NOW_PASSWORD_PARAM"))

        # Create processor
        processor = ServiceNowMessageProcessorService(
            instance_id, username, password_param_name, table_name, event_bus_name)
        processed_count = 0

        # Extract the request body from API Gateway event
        body = processor._extract_event_body(event)
        if body is None:
            return ResponseBuilderService._build_error_response("Failed to extract event body")

        # Parse the request body
        payload = processor._parse_message(body)
        logger.info(f"Parsed event payload: {payload}")

        # Process the webhook payload
        success = processor._process_webhook_payload(payload)

        if not success:
            return ResponseBuilderService._build_error_response("Failed to process ServiceNow webhook payload")

        if success:
            processed_count += 1

        return ResponseBuilderService._build_success_response(
            f"Successfully processed {processed_count} records"
        )

    except Exception as e:
        logger.error(f"Error in Lambda handler: {str(e)}")
        logger.error(traceback.format_exc())
        return ResponseBuilderService._build_error_response(str(e))
