#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
Mode Manager - Demo/Production Mode System

Handles switching between demo and production modes with automatic fallback.
"""

import os
import json
import logging
from datetime import datetime
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class APIKeyStatus:
    """Status of an API key"""
    name: str
    required: bool
    available: bool
    description: str
    last_validated: Optional[str] = None
    validation_error: Optional[str] = None

@dataclass
class ModeConfiguration:
    """Configuration for demo/production modes"""
    current_mode: str  # "demo" or "production"
    auto_fallback_enabled: bool
    required_api_keys: List[str]
    optional_api_keys: List[str]
    demo_features_enabled: List[str]
    last_mode_switch: Optional[str] = None
    user_preference: Optional[str] = None

class ModeManager:
    """Manages demo/production mode switching and API key validation"""
    
    def __init__(self):
        data_dir = os.environ.get('APP_DATA_DIR', '/app/data')
        self.config_file = Path(data_dir) / 'mode_config.json'
        self.config_file.parent.mkdir(exist_ok=True, parents=True)
        self.config = self._load_config()
        self.api_key_status: Dict[str, APIKeyStatus] = {}
        self._validate_all_keys()
        
    def _load_config(self) -> ModeConfiguration:
        """Load mode configuration from file"""
        default_config = ModeConfiguration(
            current_mode="demo",  # Start in demo mode by default
            auto_fallback_enabled=True,
            required_api_keys=[
                # No keys are truly required - all features should work in demo mode
            ],
            optional_api_keys=[
                "OPENAI_API_KEY",
                "VIRUSTOTAL_API_KEY", 
                "SHODAN_API_KEY",
                "ABUSEIPDB_API_KEY",
                "TWITTER_API_KEY",
                "REDDIT_API_KEY"
            ],
            demo_features_enabled=[
                "mock_investigations",
                "sample_data",
                "synthetic_intelligence",
                "demo_reports"
            ]
        )
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    return ModeConfiguration(**data)
            except Exception as e:
                logger.warning(f"Failed to load mode config, using defaults: {e}")
                
        return default_config
    
    def _save_config(self):
        """Save current configuration to file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump(asdict(self.config), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save mode config: {e}")
    
    def _validate_all_keys(self):
        """Validate all API keys"""
        all_keys = self.config.required_api_keys + self.config.optional_api_keys
        
        for key_name in all_keys:
            self.api_key_status[key_name] = self._validate_single_key(key_name)
    
    def _validate_single_key(self, key_name: str) -> APIKeyStatus:
        """Validate a single API key"""
        is_required = key_name in self.config.required_api_keys
        key_value = os.getenv(key_name)
        available = bool(key_value and len(key_value.strip()) > 0)
        
        descriptions = {
            "OPENAI_API_KEY": "OpenAI GPT API for advanced analysis",
            "VIRUSTOTAL_API_KEY": "VirusTotal API for malware scanning",
            "SHODAN_API_KEY": "Shodan API for network intelligence", 
            "ABUSEIPDB_API_KEY": "AbuseIPDB API for IP reputation",
            "TWITTER_API_KEY": "Twitter/X API for social intelligence",
            "REDDIT_API_KEY": "Reddit API for social media analysis"
        }
        
        return APIKeyStatus(
            name=key_name,
            required=is_required,
            available=available,
            description=descriptions.get(key_name, f"API key: {key_name}"),
            last_validated=datetime.utcnow().isoformat(),
            validation_error=None if available else "Key not found or empty"
        )
    
    def get_current_mode(self) -> str:
        """Get current operating mode"""
        return self.config.current_mode
    
    def set_mode(self, mode: str, user_initiated: bool = False) -> Tuple[bool, str]:
        """Set operating mode"""
        if mode not in ["demo", "production"]:
            return False, f"Invalid mode: {mode}"
        
        # Check if production mode is viable
        if mode == "production":
            missing_required = [
                key for key in self.config.required_api_keys 
                if not self.api_key_status.get(key, APIKeyStatus("", True, False, "")).available
            ]
            
            if missing_required and not user_initiated:
                logger.info(f"Cannot switch to production: missing required keys {missing_required}")
                return False, f"Missing required API keys: {', '.join(missing_required)}"
        
        old_mode = self.config.current_mode
        self.config.current_mode = mode
        self.config.last_mode_switch = datetime.utcnow().isoformat()
        
        if user_initiated:
            self.config.user_preference = mode
        
        self._save_config()
        
        logger.info(f"Mode switched from {old_mode} to {mode} (user_initiated={user_initiated})")
        return True, f"Switched to {mode} mode"
    
    def check_and_auto_fallback(self) -> Tuple[bool, Optional[str]]:
        """Check if auto-fallback to demo mode is needed"""
        if not self.config.auto_fallback_enabled:
            return False, None
        
        if self.config.current_mode == "demo":
            return False, None  # Already in demo mode
        
        # Check if required keys are available
        missing_required = []
        for key_name in self.config.required_api_keys:
            status = self.api_key_status.get(key_name)
            if not status or not status.available:
                missing_required.append(key_name)
        
        if missing_required:
            success, message = self.set_mode("demo", user_initiated=False)
            if success:
                return True, f"Auto-switched to demo mode: {message}. Missing keys: {', '.join(missing_required)}"
        
        return False, None
    
    def get_mode_status(self) -> Dict:
        """Get comprehensive mode status"""
        # Refresh key validation
        self._validate_all_keys()
        
        # Check for auto-fallback
        fallback_occurred, fallback_message = self.check_and_auto_fallback()
        
        available_keys = sum(1 for status in self.api_key_status.values() if status.available)
        total_keys = len(self.api_key_status)
        
        return {
            "current_mode": self.config.current_mode,
            "user_preference": self.config.user_preference,
            "auto_fallback_enabled": self.config.auto_fallback_enabled,
            "last_mode_switch": self.config.last_mode_switch,
            "fallback_occurred": fallback_occurred,
            "fallback_message": fallback_message,
            "api_keys": {
                "available_count": available_keys,
                "total_count": total_keys,
                "details": [asdict(status) for status in self.api_key_status.values()]
            },
            "features": {
                "demo_features_enabled": self.config.demo_features_enabled,
                "production_capable": len([k for k in self.config.required_api_keys 
                                         if not self.api_key_status.get(k, APIKeyStatus("", True, False, "")).available]) == 0
            }
        }
    
    def get_demo_data_config(self) -> Dict:
        """Get configuration for demo data"""
        return {
            "enabled": self.config.current_mode == "demo",
            "features": self.config.demo_features_enabled,
            "mock_investigations_count": 5,
            "sample_data_categories": [
                "infrastructure_intelligence",
                "threat_intelligence", 
                "social_intelligence"
            ]
        }
    
    def is_demo_mode(self) -> bool:
        """Check if currently in demo mode"""
        return self.config.current_mode == "demo"
    
    def is_production_mode(self) -> bool:
        """Check if currently in production mode"""
        return self.config.current_mode == "production"
    
    def get_api_key_if_available(self, key_name: str) -> Optional[str]:
        """Get API key value if available and mode allows it"""
        if self.config.current_mode == "demo":
            return None  # Never use real API keys in demo mode
        
        status = self.api_key_status.get(key_name)
        if status and status.available:
            return os.getenv(key_name)
        
        return None

# Global instance
mode_manager = ModeManager()