"""
Unit tests for Slack domain models.
"""

import datetime
import pytest
from unittest.mock import patch

# Import the domain models
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../assets/domain/python'))

from slack_domain import SlackChannel, SlackMessage, SlackAttachment, SlackCommand


class TestSlackChannel:
    """Test cases for SlackChannel domain model"""

    def test_slack_channel_initialization(self):
        """Test SlackChannel initialization with required parameters"""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="aws-security-incident-response-case-123",
            case_id="123"
        )
        
        assert channel.channel_id == "C1234567890"
        assert channel.channel_name == "aws-security-incident-response-case-123"
        assert channel.case_id == "123"
        assert channel.members == []
        assert isinstance(channel.created_at, datetime.datetime)
        assert channel.topic is None
        assert channel.purpose is None

    def test_slack_channel_initialization_with_optional_params(self):
        """Test SlackChannel initialization with optional parameters"""
        created_at = datetime.datetime.now()
        members = ["U1234567890", "U0987654321"]
        
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="test-channel",
            case_id="123",
            members=members,
            created_at=created_at,
            topic="Test topic",
            purpose="Test purpose"
        )
        
        assert channel.members == members
        assert channel.created_at == created_at
        assert channel.topic == "Test topic"
        assert channel.purpose == "Test purpose"

    def test_slack_channel_validation_success(self):
        """Test successful validation of SlackChannel"""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="aws-security-incident-response-case-123",
            case_id="123"
        )
        
        assert channel.validate() is True

    def test_slack_channel_validation_missing_channel_id(self):
        """Test validation failure when channel_id is missing"""
        channel = SlackChannel(
            channel_id="",
            channel_name="test-channel",
            case_id="123"
        )
        
        with pytest.raises(ValueError, match="Channel ID is required"):
            channel.validate()

    def test_slack_channel_validation_missing_channel_name(self):
        """Test validation failure when channel_name is missing"""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="",
            case_id="123"
        )
        
        with pytest.raises(ValueError, match="Channel name is required"):
            channel.validate()

    def test_slack_channel_validation_missing_case_id(self):
        """Test validation failure when case_id is missing"""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="test-channel",
            case_id=""
        )
        
        with pytest.raises(ValueError, match="Case ID is required"):
            channel.validate()

    def test_slack_channel_validation_invalid_channel_id_format(self):
        """Test validation failure with invalid channel ID format"""
        channel = SlackChannel(
            channel_id="invalid-id",
            channel_name="test-channel",
            case_id="123"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack channel ID format"):
            channel.validate()

    def test_slack_channel_validation_invalid_channel_name_format(self):
        """Test validation failure with invalid channel name format"""
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="Invalid Channel Name!",
            case_id="123"
        )
        
        with pytest.raises(ValueError, match="Invalid channel name format"):
            channel.validate()

    def test_slack_channel_to_dict(self):
        """Test SlackChannel to_dict conversion"""
        created_at = datetime.datetime(2025, 1, 15, 10, 30, 0)
        channel = SlackChannel(
            channel_id="C1234567890",
            channel_name="test-channel",
            case_id="123",
            members=["U1234567890"],
            created_at=created_at,
            topic="Test topic",
            purpose="Test purpose"
        )
        
        expected_dict = {
            "channelId": "C1234567890",
            "channelName": "test-channel",
            "caseId": "123",
            "members": ["U1234567890"],
            "createdAt": "2025-01-15T10:30:00",
            "topic": "Test topic",
            "purpose": "Test purpose"
        }
        
        assert channel.to_dict() == expected_dict

    def test_slack_channel_from_slack_response(self):
        """Test creating SlackChannel from Slack API response"""
        slack_response = {
            "id": "C1234567890",
            "name": "test-channel",
            "created": 1642248600,  # Unix timestamp
            "members": ["U1234567890", "U0987654321"],
            "topic": {"value": "Test topic"},
            "purpose": {"value": "Test purpose"}
        }
        
        channel = SlackChannel.from_slack_response(slack_response, "123")
        
        assert channel.channel_id == "C1234567890"
        assert channel.channel_name == "test-channel"
        assert channel.case_id == "123"
        assert channel.members == ["U1234567890", "U0987654321"]
        assert channel.topic == "Test topic"
        assert channel.purpose == "Test purpose"
        assert isinstance(channel.created_at, datetime.datetime)


class TestSlackMessage:
    """Test cases for SlackMessage domain model"""

    def test_slack_message_initialization(self):
        """Test SlackMessage initialization with required parameters"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Test message",
            timestamp="1642248600.123456"
        )
        
        assert message.message_id == "1642248600.123456"
        assert message.channel_id == "C1234567890"
        assert message.user_id == "U1234567890"
        assert message.text == "Test message"
        assert message.timestamp == "1642248600.123456"
        assert message.thread_ts is None
        assert message.message_type == "message"
        assert message.subtype is None
        assert message.user_name is None
        assert message.attachments == []

    def test_slack_message_initialization_with_optional_params(self):
        """Test SlackMessage initialization with optional parameters"""
        attachments = [{"text": "attachment"}]
        
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Test message",
            timestamp="1642248600.123456",
            thread_ts="1642248500.123456",
            message_type="message",
            subtype="bot_message",
            user_name="testuser",
            attachments=attachments
        )
        
        assert message.thread_ts == "1642248500.123456"
        assert message.subtype == "bot_message"
        assert message.user_name == "testuser"
        assert message.attachments == attachments

    def test_slack_message_validation_success(self):
        """Test successful validation of SlackMessage"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Test message",
            timestamp="1642248600.123456"
        )
        
        assert message.validate() is True

    def test_slack_message_validation_missing_message_id(self):
        """Test validation failure when message_id is missing"""
        message = SlackMessage(
            message_id="",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Test message",
            timestamp="1642248600.123456"
        )
        
        with pytest.raises(ValueError, match="Message ID is required"):
            message.validate()

    def test_slack_message_validation_invalid_channel_id(self):
        """Test validation failure with invalid channel ID"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="invalid-id",
            user_id="U1234567890",
            text="Test message",
            timestamp="1642248600.123456"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack channel ID format"):
            message.validate()

    def test_slack_message_validation_invalid_user_id(self):
        """Test validation failure with invalid user ID"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id="invalid-id",
            text="Test message",
            timestamp="1642248600.123456"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack user ID format"):
            message.validate()

    def test_slack_message_validation_invalid_timestamp(self):
        """Test validation failure with invalid timestamp"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Test message",
            timestamp="invalid-timestamp"
        )
        
        with pytest.raises(ValueError, match="Invalid timestamp format"):
            message.validate()

    def test_slack_message_to_dict(self):
        """Test SlackMessage to_dict conversion"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Test message",
            timestamp="1642248600.123456",
            thread_ts="1642248500.123456",
            message_type="message",
            subtype="bot_message",
            user_name="testuser",
            attachments=[{"text": "attachment"}]
        )
        
        expected_dict = {
            "messageId": "1642248600.123456",
            "channelId": "C1234567890",
            "userId": "U1234567890",
            "text": "Test message",
            "timestamp": "1642248600.123456",
            "threadTs": "1642248500.123456",
            "messageType": "message",
            "subtype": "bot_message",
            "userName": "testuser",
            "attachments": [{"text": "attachment"}]
        }
        
        assert message.to_dict() == expected_dict

    def test_slack_message_from_slack_event(self):
        """Test creating SlackMessage from Slack event"""
        slack_event = {
            "ts": "1642248600.123456",
            "channel": "C1234567890",
            "user": "U1234567890",
            "text": "Test message",
            "thread_ts": "1642248500.123456",
            "type": "message",
            "subtype": "bot_message",
            "attachments": [{"text": "attachment"}]
        }
        
        message = SlackMessage.from_slack_event(slack_event)
        
        assert message.message_id == "1642248600.123456"
        assert message.channel_id == "C1234567890"
        assert message.user_id == "U1234567890"
        assert message.text == "Test message"
        assert message.timestamp == "1642248600.123456"
        assert message.thread_ts == "1642248500.123456"
        assert message.message_type == "message"
        assert message.subtype == "bot_message"
        assert message.attachments == [{"text": "attachment"}]

    def test_slack_message_is_bot_message_with_bot_subtype(self):
        """Test is_bot_message returns True for bot_message subtype"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Test message",
            timestamp="1642248600.123456",
            subtype="bot_message"
        )
        
        assert message.is_bot_message() is True

    def test_slack_message_is_bot_message_with_bot_user_id(self):
        """Test is_bot_message returns True for bot user ID"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id="B1234567890",  # Bot user ID starts with 'B'
            text="Test message",
            timestamp="1642248600.123456"
        )
        
        assert message.is_bot_message() is True

    def test_slack_message_is_bot_message_with_none_user_id(self):
        """Test is_bot_message returns True for None user ID"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id=None,
            text="Test message",
            timestamp="1642248600.123456"
        )
        
        assert message.is_bot_message() is True

    def test_slack_message_is_bot_message_regular_user(self):
        """Test is_bot_message returns False for regular user message"""
        message = SlackMessage(
            message_id="1642248600.123456",
            channel_id="C1234567890",
            user_id="U1234567890",
            text="Test message",
            timestamp="1642248600.123456"
        )
        
        assert message.is_bot_message() is False


class TestSlackAttachment:
    """Test cases for SlackAttachment domain model"""

    def test_slack_attachment_initialization(self):
        """Test SlackAttachment initialization with required parameters"""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/files-pri/T1234567890-F1234567890/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        
        assert attachment.file_id == "F1234567890"
        assert attachment.filename == "test.txt"
        assert attachment.url == "https://files.slack.com/files-pri/T1234567890-F1234567890/test.txt"
        assert attachment.size == 1024
        assert attachment.mimetype == "text/plain"
        assert attachment.title == "test.txt"  # Defaults to filename
        assert attachment.timestamp is None
        assert attachment.user_id is None
        assert attachment.channel_id is None
        assert attachment.initial_comment is None

    def test_slack_attachment_initialization_with_optional_params(self):
        """Test SlackAttachment initialization with optional parameters"""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/files-pri/T1234567890-F1234567890/test.txt",
            size=1024,
            mimetype="text/plain",
            title="Custom Title",
            timestamp="1642248600",
            user_id="U1234567890",
            channel_id="C1234567890",
            initial_comment="Initial comment"
        )
        
        assert attachment.title == "Custom Title"
        assert attachment.timestamp == "1642248600"
        assert attachment.user_id == "U1234567890"
        assert attachment.channel_id == "C1234567890"
        assert attachment.initial_comment == "Initial comment"

    def test_slack_attachment_validation_success(self):
        """Test successful validation of SlackAttachment"""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/files-pri/T1234567890-F1234567890/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        
        assert attachment.validate() is True

    def test_slack_attachment_validation_missing_file_id(self):
        """Test validation failure when file_id is missing"""
        attachment = SlackAttachment(
            file_id="",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        
        with pytest.raises(ValueError, match="File ID is required"):
            attachment.validate()

    def test_slack_attachment_validation_invalid_file_id_format(self):
        """Test validation failure with invalid file ID format"""
        attachment = SlackAttachment(
            file_id="invalid-id",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain"
        )
        
        with pytest.raises(ValueError, match="Invalid Slack file ID format"):
            attachment.validate()

    def test_slack_attachment_validation_negative_size(self):
        """Test validation failure with negative file size"""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=-1,
            mimetype="text/plain"
        )
        
        with pytest.raises(ValueError, match="File size cannot be negative"):
            attachment.validate()

    def test_slack_attachment_validation_invalid_url(self):
        """Test validation failure with invalid URL"""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="invalid-url",
            size=1024,
            mimetype="text/plain"
        )
        
        with pytest.raises(ValueError, match="Invalid URL format"):
            attachment.validate()

    def test_slack_attachment_to_dict(self):
        """Test SlackAttachment to_dict conversion"""
        attachment = SlackAttachment(
            file_id="F1234567890",
            filename="test.txt",
            url="https://files.slack.com/test.txt",
            size=1024,
            mimetype="text/plain",
            title="Custom Title",
            timestamp="1642248600",
            user_id="U1234567890",
            channel_id="C1234567890",
            initial_comment="Initial comment"
        )
        
        expected_dict = {
            "fileId": "F1234567890",
            "filename": "test.txt",
            "url": "https://files.slack.com/test.txt",
            "size": 1024,
            "mimetype": "text/plain",
            "title": "Custom Title",
            "timestamp": "1642248600",
            "userId": "U1234567890",
            "channelId": "C1234567890",
            "initialComment": "Initial comment"
        }
        
        assert attachment.to_dict() == expected_dict

    def test_slack_attachment_from_slack_file(self):
        """Test creating SlackAttachment from Slack file data"""
        file_data = {
            "id": "F1234567890",
            "name": "test.txt",
            "url_private_download": "https://files.slack.com/test.txt",
            "size": 1024,
            "mimetype": "text/plain",
            "title": "Custom Title",
            "timestamp": 1642248600,
            "user": "U1234567890",
            "initial_comment": {"comment": "Initial comment"}
        }
        
        attachment = SlackAttachment.from_slack_file(file_data, "C1234567890")
        
        assert attachment.file_id == "F1234567890"
        assert attachment.filename == "test.txt"
        assert attachment.url == "https://files.slack.com/test.txt"
        assert attachment.size == 1024
        assert attachment.mimetype == "text/plain"
        assert attachment.title == "Custom Title"
        assert attachment.timestamp == "1642248600"
        assert attachment.user_id == "U1234567890"
        assert attachment.channel_id == "C1234567890"
        assert attachment.initial_comment == "Initial comment"


class TestSlackCommand:
    """Test cases for SlackCommand domain model"""

    def test_slack_command_initialization(self):
        """Test SlackCommand initialization with required parameters"""
        command = SlackCommand(
            command="/security-ir",
            text="status",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.123456.abcdefghijklmnop"
        )
        
        assert command.command == "/security-ir"
        assert command.text == "status"
        assert command.user_id == "U1234567890"
        assert command.channel_id == "C1234567890"
        assert command.team_id == "T1234567890"
        assert command.response_url == "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop"
        assert command.trigger_id == "1234567890.123456.abcdefghijklmnop"
        assert command.user_name is None
        assert command.channel_name is None

    def test_slack_command_initialization_with_optional_params(self):
        """Test SlackCommand initialization with optional parameters"""
        command = SlackCommand(
            command="/security-ir",
            text="status",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.123456.abcdefghijklmnop",
            user_name="testuser",
            channel_name="test-channel"
        )
        
        assert command.user_name == "testuser"
        assert command.channel_name == "test-channel"

    def test_slack_command_validation_success(self):
        """Test successful validation of SlackCommand"""
        command = SlackCommand(
            command="/security-ir",
            text="status",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.123456.abcdefghijklmnop"
        )
        
        assert command.validate() is True

    def test_slack_command_validation_invalid_command_format(self):
        """Test validation failure with invalid command format"""
        command = SlackCommand(
            command="security-ir",  # Missing '/' prefix
            text="status",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.123456.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Invalid command format"):
            command.validate()

    def test_slack_command_validation_invalid_response_url(self):
        """Test validation failure with invalid response URL"""
        command = SlackCommand(
            command="/security-ir",
            text="status",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://invalid.com/webhook",
            trigger_id="1234567890.123456.abcdefghijklmnop"
        )
        
        with pytest.raises(ValueError, match="Invalid response URL format"):
            command.validate()

    def test_slack_command_to_dict(self):
        """Test SlackCommand to_dict conversion"""
        command = SlackCommand(
            command="/security-ir",
            text="status",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.123456.abcdefghijklmnop",
            user_name="testuser",
            channel_name="test-channel"
        )
        
        expected_dict = {
            "command": "/security-ir",
            "text": "status",
            "userId": "U1234567890",
            "channelId": "C1234567890",
            "teamId": "T1234567890",
            "responseUrl": "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            "triggerId": "1234567890.123456.abcdefghijklmnop",
            "userName": "testuser",
            "channelName": "test-channel"
        }
        
        assert command.to_dict() == expected_dict

    def test_slack_command_from_slack_payload(self):
        """Test creating SlackCommand from Slack payload"""
        payload = {
            "command": "/security-ir",
            "text": "status",
            "user_id": "U1234567890",
            "channel_id": "C1234567890",
            "team_id": "T1234567890",
            "response_url": "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            "trigger_id": "1234567890.123456.abcdefghijklmnop",
            "user_name": "testuser",
            "channel_name": "test-channel"
        }
        
        command = SlackCommand.from_slack_payload(payload)
        
        assert command.command == "/security-ir"
        assert command.text == "status"
        assert command.user_id == "U1234567890"
        assert command.channel_id == "C1234567890"
        assert command.team_id == "T1234567890"
        assert command.response_url == "https://hooks.slack.com/commands/1234567890/abcdefghijklmnop"
        assert command.trigger_id == "1234567890.123456.abcdefghijklmnop"
        assert command.user_name == "testuser"
        assert command.channel_name == "test-channel"

    def test_slack_command_parse_subcommand_with_args(self):
        """Test parsing subcommand with arguments"""
        command = SlackCommand(
            command="/security-ir",
            text="update-status Resolved",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.123456.abcdefghijklmnop"
        )
        
        subcommand, args = command.parse_subcommand()
        assert subcommand == "update-status"
        assert args == "Resolved"

    def test_slack_command_parse_subcommand_without_args(self):
        """Test parsing subcommand without arguments"""
        command = SlackCommand(
            command="/security-ir",
            text="status",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.123456.abcdefghijklmnop"
        )
        
        subcommand, args = command.parse_subcommand()
        assert subcommand == "status"
        assert args == ""

    def test_slack_command_parse_subcommand_empty_text(self):
        """Test parsing subcommand with empty text"""
        command = SlackCommand(
            command="/security-ir",
            text="",
            user_id="U1234567890",
            channel_id="C1234567890",
            team_id="T1234567890",
            response_url="https://hooks.slack.com/commands/1234567890/abcdefghijklmnop",
            trigger_id="1234567890.123456.abcdefghijklmnop"
        )
        
        subcommand, args = command.parse_subcommand()
        assert subcommand == ""
        assert args == ""


if __name__ == "__main__":
    pytest.main([__file__])