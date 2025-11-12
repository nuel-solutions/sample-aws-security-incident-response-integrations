"""
Unit tests for Slack Command Handler Lambda function.
"""

import json
import pytest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add the slack_command_handler directory to the path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', 'assets', 'slack_command_handler'))

# Mock AWS clients before importing
with patch('boto3.client'), patch('boto3.resource'):
    # Import the module under test
    import index
    
    # Get the functions we need to test
    parse_command = index.parse_command
    validate_user_permissions = index.validate_user_permissions
    get_case_id_from_channel = index.get_case_id_from_channel
    get_case_details = index.get_case_details
    send_slack_response = index.send_slack_response
    handle_status_command = index.handle_status_command
    handle_summarize_command = index.handle_summarize_command
    handle_update_status_command = index.handle_update_status_command
    handle_update_description_command = index.handle_update_description_command
    handle_update_title_command = index.handle_update_title_command
    handle_close_command = index.handle_close_command
    process_command = index.process_command
    lambda_handler = index.lambda_handler


class TestParseCommand:
    """Test cases for parse_command function"""
    
    def test_parse_command_with_args(self):
        """Test parsing command with arguments"""
        subcommand, args = parse_command("update-status Acknowledged")
        assert subcommand == "update-status"
        assert args == "Acknowledged"
    
    def test_parse_command_without_args(self):
        """Test parsing command without arguments"""
        subcommand, args = parse_command("status")
        assert subcommand == "status"
        assert args == ""
    
    def test_parse_command_empty(self):
        """Test parsing empty command"""
        subcommand, args = parse_command("")
        assert subcommand == ""
        assert args == ""
    
    def test_parse_command_with_multiple_spaces(self):
        """Test parsing command with multiple spaces"""
        subcommand, args = parse_command("update-description   New description with spaces")
        assert subcommand == "update-description"
        assert args == "New description with spaces"
    
    def test_parse_command_case_insensitive(self):
        """Test that command parsing is case insensitive"""
        subcommand, args = parse_command("STATUS")
        assert subcommand == "status"


class TestValidateUserPermissions:
    """Test cases for validate_user_permissions function"""
    
    def test_validate_user_permissions_returns_true(self):
        """Test that user permission validation returns True (placeholder implementation)"""
        result = validate_user_permissions("U1234567890", "12345")
        assert result is True


class TestGetCaseIdFromChannel:
    """Test cases for get_case_id_from_channel function"""
    
    @patch('index.incidents_table')
    def test_get_case_id_success(self, mock_table):
        """Test successful case ID retrieval"""
        mock_table.scan.return_value = {
            "Items": [
                {"PK": "Case#12345", "SK": "latest", "slackChannelId": "C1234567890"}
            ]
        }
        
        result = get_case_id_from_channel("C1234567890")
        assert result == "12345"
    
    @patch('index.incidents_table')
    def test_get_case_id_not_found(self, mock_table):
        """Test case ID not found"""
        mock_table.scan.return_value = {"Items": []}
        
        result = get_case_id_from_channel("C1234567890")
        assert result is None
    
    @patch('index.incidents_table', None)
    def test_get_case_id_no_table(self):
        """Test when incidents table is not configured"""
        result = get_case_id_from_channel("C1234567890")
        assert result is None


class TestGetCaseDetails:
    """Test cases for get_case_details function"""
    
    @patch('index.security_incident_response_client')
    def test_get_case_details_success(self, mock_client):
        """Test successful case details retrieval"""
        mock_client.get_case.return_value = {
            "caseId": "12345",
            "title": "Test Case",
            "caseStatus": "Acknowledged",
            "severity": "High"
        }
        
        result = get_case_details("12345")
        assert result is not None
        assert result["caseId"] == "12345"
        assert result["title"] == "Test Case"
    
    @patch('index.security_incident_response_client')
    def test_get_case_details_client_error(self, mock_client):
        """Test case details retrieval with client error"""
        from botocore.exceptions import ClientError
        mock_client.get_case.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException"}},
            "GetCase"
        )
        
        result = get_case_details("12345")
        assert result is None


class TestSendSlackResponse:
    """Test cases for send_slack_response function"""
    
    @patch('requests.post')
    def test_send_slack_response_success(self, mock_post):
        """Test successful Slack response"""
        mock_response = Mock()
        mock_response.raise_for_status.return_value = None
        mock_post.return_value = mock_response
        
        result = send_slack_response("https://hooks.slack.com/test", "Test message")
        assert result is True
        mock_post.assert_called_once()
    
    @patch('requests.post')
    def test_send_slack_response_failure(self, mock_post):
        """Test failed Slack response"""
        mock_post.side_effect = Exception("Network error")
        
        result = send_slack_response("https://hooks.slack.com/test", "Test message")
        assert result is False


class TestHandleStatusCommand:
    """Test cases for handle_status_command function"""
    
    @patch('index.get_case_details')
    @patch('index.send_slack_response')
    def test_handle_status_command_success(self, mock_send, mock_get_case):
        """Test successful status command"""
        mock_get_case.return_value = {
            "caseId": "12345",
            "title": "Test Case",
            "caseStatus": "Acknowledged",
            "severity": "High",
            "description": "Test description",
            "createdDate": "2025-01-15T10:30:00Z"
        }
        mock_send.return_value = True
        
        result = handle_status_command("12345", "https://hooks.slack.com/test")
        assert result is True
        mock_send.assert_called_once()
        
        # Verify the response contains case details
        call_args = mock_send.call_args[0]
        assert "Test Case" in call_args[1]
        assert "Acknowledged" in call_args[1]
        assert "High" in call_args[1]
    
    @patch('index.get_case_details')
    @patch('index.send_slack_response')
    def test_handle_status_command_case_not_found(self, mock_send, mock_get_case):
        """Test status command when case not found"""
        mock_get_case.return_value = None
        mock_send.return_value = True
        
        result = handle_status_command("12345", "https://hooks.slack.com/test")
        assert result is False
        mock_send.assert_called_once()
        
        # Verify error message
        call_args = mock_send.call_args[0]
        assert "Error" in call_args[1]


class TestHandleSummarizeCommand:
    """Test cases for handle_summarize_command function"""
    
    @patch('index.get_case_details')
    @patch('index.send_slack_response')
    @patch('index.incidents_table')
    def test_handle_summarize_command_success(self, mock_table, mock_send, mock_get_case):
        """Test successful summarize command"""
        mock_get_case.return_value = {
            "caseId": "12345",
            "title": "Test Case",
            "caseStatus": "Acknowledged",
            "severity": "High",
            "createdDate": "2025-01-15T10:30:00Z",
            "watchers": ["user1@example.com", "user2@example.com"]
        }
        mock_table.get_item.return_value = {
            "Item": {
                "slackChannelCaseComments": ["comment1", "comment2", "comment3"]
            }
        }
        mock_send.return_value = True
        
        result = handle_summarize_command("12345", "https://hooks.slack.com/test")
        assert result is True
        mock_send.assert_called_once()
        
        # Verify the response contains summary info
        call_args = mock_send.call_args[0]
        assert "Test Case" in call_args[1]
        assert "Acknowledged" in call_args[1]
        assert "2" in call_args[1]  # Watcher count
        assert "3" in call_args[1]  # Comment count


class TestHandleUpdateStatusCommand:
    """Test cases for handle_update_status_command function"""
    
    @patch('index.security_incident_response_client')
    @patch('index.send_slack_response')
    def test_handle_update_status_command_success(self, mock_send, mock_client):
        """Test successful status update"""
        mock_client.update_case_status.return_value = {}
        mock_send.return_value = True
        
        result = handle_update_status_command("12345", "Detection and Analysis", "https://hooks.slack.com/test")
        assert result is True
        mock_client.update_case_status.assert_called_once_with(
            caseId="12345",
            caseStatus="Detection and Analysis"
        )
        
        # Verify success message
        call_args = mock_send.call_args[0]
        assert "✅" in call_args[1]
        assert "Detection and Analysis" in call_args[1]
    
    @patch('index.send_slack_response')
    def test_handle_update_status_command_invalid_status(self, mock_send):
        """Test status update with invalid status"""
        mock_send.return_value = True
        
        result = handle_update_status_command("12345", "InvalidStatus", "https://hooks.slack.com/test")
        assert result is False
        
        # Verify error message
        call_args = mock_send.call_args[0]
        assert "Error" in call_args[1]
        assert "Invalid status" in call_args[1]
    
    @patch('index.send_slack_response')
    def test_handle_update_status_command_empty_status(self, mock_send):
        """Test status update with empty status"""
        mock_send.return_value = True
        
        result = handle_update_status_command("12345", "", "https://hooks.slack.com/test")
        assert result is False
        
        # Verify error message
        call_args = mock_send.call_args[0]
        assert "Error" in call_args[1]
        assert "required" in call_args[1]


class TestHandleUpdateDescriptionCommand:
    """Test cases for handle_update_description_command function"""
    
    @patch('index.security_incident_response_client')
    @patch('index.send_slack_response')
    def test_handle_update_description_command_success(self, mock_send, mock_client):
        """Test successful description update"""
        mock_client.update_case.return_value = {}
        mock_send.return_value = True
        
        result = handle_update_description_command("12345", "New description", "https://hooks.slack.com/test")
        assert result is True
        mock_client.update_case.assert_called_once_with(
            caseId="12345",
            description="New description"
        )
    
    @patch('index.send_slack_response')
    def test_handle_update_description_command_empty_description(self, mock_send):
        """Test description update with empty description"""
        mock_send.return_value = True
        
        result = handle_update_description_command("12345", "", "https://hooks.slack.com/test")
        assert result is False


class TestHandleUpdateTitleCommand:
    """Test cases for handle_update_title_command function"""
    
    @patch('index.security_incident_response_client')
    @patch('index.send_slack_response')
    def test_handle_update_title_command_success(self, mock_send, mock_client):
        """Test successful title update"""
        mock_client.update_case.return_value = {}
        mock_send.return_value = True
        
        result = handle_update_title_command("12345", "New title", "https://hooks.slack.com/test")
        assert result is True
        mock_client.update_case.assert_called_once_with(
            caseId="12345",
            title="New title"
        )
    
    @patch('index.send_slack_response')
    def test_handle_update_title_command_empty_title(self, mock_send):
        """Test title update with empty title"""
        mock_send.return_value = True
        
        result = handle_update_title_command("12345", "", "https://hooks.slack.com/test")
        assert result is False


class TestHandleCloseCommand:
    """Test cases for handle_close_command function"""
    
    @patch('index.security_incident_response_client')
    @patch('index.send_slack_response')
    def test_handle_close_command_success(self, mock_send, mock_client):
        """Test successful case close"""
        mock_client.update_case_status.return_value = {}
        mock_send.return_value = True
        
        result = handle_close_command("12345", "https://hooks.slack.com/test")
        assert result is True
        mock_client.update_case_status.assert_called_once_with(
            caseId="12345",
            caseStatus="Resolved"
        )
        
        # Verify success message
        call_args = mock_send.call_args[0]
        assert "✅" in call_args[1]
        assert "closed" in call_args[1].lower()


class TestProcessCommand:
    """Test cases for process_command function"""
    
    @patch('index.validate_user_permissions')
    @patch('index.handle_status_command')
    def test_process_command_status(self, mock_handle, mock_validate):
        """Test processing status command"""
        mock_validate.return_value = True
        mock_handle.return_value = True
        
        command_payload = {
            "text": "status",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test",
            "case_id": "12345"
        }
        
        result = process_command(command_payload)
        assert result is True
        mock_handle.assert_called_once()
    
    @patch('index.validate_user_permissions')
    @patch('index.handle_summarize_command')
    def test_process_command_summarize(self, mock_handle, mock_validate):
        """Test processing summarize command"""
        mock_validate.return_value = True
        mock_handle.return_value = True
        
        command_payload = {
            "text": "summarize",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test",
            "case_id": "12345"
        }
        
        result = process_command(command_payload)
        assert result is True
        mock_handle.assert_called_once()
    
    @patch('index.validate_user_permissions')
    @patch('index.handle_update_status_command')
    def test_process_command_update_status(self, mock_handle, mock_validate):
        """Test processing update-status command"""
        mock_validate.return_value = True
        mock_handle.return_value = True
        
        command_payload = {
            "text": "update-status Acknowledged",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test",
            "case_id": "12345"
        }
        
        result = process_command(command_payload)
        assert result is True
        mock_handle.assert_called_once_with("12345", "Acknowledged", "https://hooks.slack.com/test")
    
    @patch('index.validate_user_permissions')
    @patch('index.send_slack_response')
    def test_process_command_help(self, mock_send, mock_validate):
        """Test processing help command"""
        mock_validate.return_value = True
        mock_send.return_value = True
        
        command_payload = {
            "text": "help",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test",
            "case_id": "12345"
        }
        
        result = process_command(command_payload)
        assert result is True
        mock_send.assert_called_once()
        
        # Verify help text is sent
        call_args = mock_send.call_args[0]
        assert "Available" in call_args[1]
    
    @patch('index.validate_user_permissions')
    @patch('index.send_slack_response')
    def test_process_command_unknown(self, mock_send, mock_validate):
        """Test processing unknown command"""
        mock_validate.return_value = True
        mock_send.return_value = True
        
        command_payload = {
            "text": "unknown-command",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test",
            "case_id": "12345"
        }
        
        result = process_command(command_payload)
        assert result is False
        mock_send.assert_called_once()
        
        # Verify error message
        call_args = mock_send.call_args[0]
        assert "Unknown command" in call_args[1]
    
    @patch('index.validate_user_permissions')
    @patch('index.send_slack_response')
    def test_process_command_no_permissions(self, mock_send, mock_validate):
        """Test processing command without permissions"""
        mock_validate.return_value = False
        mock_send.return_value = True
        
        command_payload = {
            "text": "status",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test",
            "case_id": "12345"
        }
        
        result = process_command(command_payload)
        assert result is False
        mock_send.assert_called_once()
        
        # Verify permission error message
        call_args = mock_send.call_args[0]
        assert "permission" in call_args[1].lower()
    
    @patch('index.send_slack_response')
    def test_process_command_no_case_id(self, mock_send):
        """Test processing command without case ID"""
        mock_send.return_value = True
        
        command_payload = {
            "text": "status",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test"
            # No case_id
        }
        
        result = process_command(command_payload)
        assert result is False


class TestLambdaHandler:
    """Test cases for lambda_handler function"""
    
    @patch('index.process_command')
    def test_lambda_handler_success(self, mock_process):
        """Test successful lambda handler execution"""
        mock_process.return_value = True
        
        event = {
            "text": "status",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test",
            "case_id": "12345"
        }
        
        result = lambda_handler(event, None)
        assert result["statusCode"] == 200
        assert json.loads(result["body"])["success"] is True
    
    @patch('index.process_command')
    def test_lambda_handler_failure(self, mock_process):
        """Test lambda handler with command processing failure"""
        mock_process.return_value = False
        
        event = {
            "text": "invalid",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test",
            "case_id": "12345"
        }
        
        result = lambda_handler(event, None)
        assert result["statusCode"] == 500
        assert json.loads(result["body"])["success"] is False
    
    @patch('index.process_command')
    def test_lambda_handler_exception(self, mock_process):
        """Test lambda handler with exception"""
        mock_process.side_effect = Exception("Test error")
        
        event = {
            "text": "status",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "response_url": "https://hooks.slack.com/test",
            "case_id": "12345"
        }
        
        result = lambda_handler(event, None)
        assert result["statusCode"] == 500
        assert "error" in json.loads(result["body"])
