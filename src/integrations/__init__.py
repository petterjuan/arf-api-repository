"""
Integration module for ARF notifications.
Psychology: Factory pattern for creating integration instances.
Intention: Centralized integration management with consistent interface.
"""
from typing import Dict, Any, Optional, Type

# Import from base - remove duplicate IntegrationType definition
from src.integrations.base import (
    BaseIntegration, 
    IntegrationType,  # Now imported from base.py
    IntegrationStatus,
    IntegrationHealth
)

# Import models that actually exist in webhook.py
from src.models.webhook import (
    SlackConfiguration, TeamsConfiguration, EmailConfiguration,
    DiscordConfiguration, PagerDutyConfiguration, OpsGenieConfiguration,
    NotificationChannel
)

# Import integrations
from src.integrations.slack_integration import SlackIntegration
from src.integrations.teams import TeamsIntegration
from src.integrations.email import EmailIntegration
from src.integrations.discord import DiscordIntegration
from src.integrations.pagerduty import PagerDutyIntegration
from src.integrations.opsgenie import OpsGenieIntegration

class IntegrationFactory:
    """Factory for creating integration instances"""
    
    _integration_classes = {
        IntegrationType.SLACK: SlackIntegration,
        IntegrationType.TEAMS: TeamsIntegration,
        IntegrationType.EMAIL: EmailIntegration,
        IntegrationType.DISCORD: DiscordIntegration,
        IntegrationType.PAGERDUTY: PagerDutyIntegration,
        IntegrationType.OPSGENIE: OpsGenieIntegration,
    }
    
    _config_classes = {
        IntegrationType.SLACK: SlackConfiguration,
        IntegrationType.TEAMS: TeamsConfiguration,
        IntegrationType.EMAIL: EmailConfiguration,
        IntegrationType.DISCORD: DiscordConfiguration,
        IntegrationType.PAGERDUTY: PagerDutyConfiguration,
        IntegrationType.OPSGENIE: OpsGenieConfiguration,
    }
    
    @classmethod
    def create_integration(cls, 
                          integration_type: IntegrationType,
                          config_data: Dict[str, Any]) -> BaseIntegration:
        """Create an integration instance"""
        if integration_type not in cls._integration_classes:
            raise ValueError(f"Unsupported integration type: {integration_type}")
        
        # Get config class and validate
        config_class = cls._config_classes[integration_type]
        config = config_class(**config_data)
        
        # Create integration instance
        integration_class = cls._integration_classes[integration_type]
        return integration_class(config)
    
    @classmethod
    def create_integration_from_channel(cls,
                                       channel: NotificationChannel,
                                       config_data: Dict[str, Any]) -> Optional[BaseIntegration]:
        """Create integration from notification channel"""
        channel_to_type = {
            NotificationChannel.SLACK: IntegrationType.SLACK,
            NotificationChannel.TEAMS: IntegrationType.TEAMS,
            NotificationChannel.EMAIL: IntegrationType.EMAIL,
            NotificationChannel.DISCORD: IntegrationType.DISCORD,
            NotificationChannel.PAGERDUTY: IntegrationType.PAGERDUTY,
            NotificationChannel.OPSGENIE: IntegrationType.OPSGENIE,
        }
        
        if channel not in channel_to_type:
            return None
        
        integration_type = channel_to_type[channel]
        return cls.create_integration(integration_type, config_data)
    
    @classmethod
    def validate_configuration(cls,
                              integration_type: IntegrationType,
                              config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate integration configuration"""
        try:
            # Create integration to validate
            integration = cls.create_integration(integration_type, config_data)
            
            # Test connection
            connected = integration.connect()
            
            return {
                "valid": True,
                "integration_type": integration_type.value,
                "status": IntegrationStatus.CONNECTED.value if connected else IntegrationStatus.ERROR.value,
                "health": integration.health_check()
            }
        
        except Exception as e:
            return {
                "valid": False,
                "integration_type": integration_type.value,
                "error": str(e)
            }
    
    @classmethod
    def get_supported_integrations(cls) -> Dict[str, Any]:
        """Get list of supported integrations"""
        return {
            integration_type.value: {
                "name": integration_type.value.title(),
                "description": cls._get_integration_description(integration_type),
                "config_class": config_class.__name__,
                "required_fields": cls._get_required_fields(config_class)
            }
            for integration_type, config_class in cls._config_classes.items()
        }
    
    @classmethod
    def _get_integration_description(cls, integration_type: IntegrationType) -> str:
        """Get integration description"""
        descriptions = {
            IntegrationType.SLACK: "Slack webhook integration for team notifications",
            IntegrationType.TEAMS: "Microsoft Teams adaptive cards integration",
            IntegrationType.EMAIL: "SMTP email integration with HTML templates",
            IntegrationType.DISCORD: "Discord webhook integration with rich embeds",
            IntegrationType.PAGERDUTY: "PagerDuty integration for incident management",
            IntegrationType.OPSGENIE: "OpsGenie integration for alerting and on-call"
        }
        return descriptions.get(integration_type, "Unknown integration")
    
    @classmethod
    def _get_required_fields(cls, config_class: Type) -> Dict[str, str]:
        """Get required fields for configuration"""
        # Extract from Pydantic model
        required_fields = {}
        
        for field_name, field_info in config_class.model_fields.items():
            if not field_info.is_required():
                continue
            
            field_type = str(field_info.annotation).split("'")[1] if "'" in str(field_info.annotation) else str(field_info.annotation)
            required_fields[field_name] = field_type
        
        return required_fields

# Export commonly used classes
__all__ = [
    'BaseIntegration',
    'IntegrationType',
    'IntegrationStatus',
    'IntegrationHealth',
    'IntegrationFactory',
    'SlackIntegration',
    'TeamsIntegration',
    'EmailIntegration',
    'DiscordIntegration',
    'PagerDutyIntegration',
    'OpsGenieIntegration',
]
